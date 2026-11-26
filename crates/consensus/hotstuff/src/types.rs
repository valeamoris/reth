//! Core data types and RLP wire encoding for Chained `HotStuff` consensus.

use alloy_primitives::{keccak256, Address, Bytes, FixedBytes, B256};
use alloy_rlp::{Encodable, RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};

use crate::error::HotStuffError;

/// Magic bytes prefixing every `HotStuff` 32-byte `header.extra_data` seal.
pub const HOTSTUFF_SEAL_MAGIC: [u8; 4] = *b"HS01";

/// Exact length of a `HotStuff` seal stored in Ethereum `header.extra_data`.
///
/// Must not exceed Ethereum's 32-byte `MAXIMUM_EXTRA_DATA_SIZE`.
pub const HOTSTUFF_SEAL_LEN: usize = 32;

/// Maximum permitted byte size of a single `HotStuff` `RLPx` wire message (12 MiB).
pub const MAX_HOTSTUFF_MESSAGE_SIZE: usize = 12 * 1024 * 1024;

/// Maximum number of validators supported in a single epoch validator set.
pub const MAX_VALIDATORS: usize = 256;

/// Maximum number of blocks delivered in a single [`SyncBlocksResponse`] batch.
pub const MAX_SYNC_BATCH: usize = 32;

/// Fixed 65-byte recoverable secp256k1 signature (`r || s || v`).
pub type HotStuffSignature = FixedBytes<65>;

/// Compact 32-byte consensus metadata embedded in Ethereum `header.extra_data`.
///
/// Layout (big-endian):
/// - `0..4`: [`HOTSTUFF_SEAL_MAGIC`] (`b"HS01"`)
/// - `4..12`: `epoch` (`u64`)
/// - `12..20`: `view` (`u64`)
/// - `20..28`: `justify_view` (`u64`)
/// - `28..32`: `validator_set_hash_prefix` (first 4 bytes of `ValidatorSet::hash()`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HotStuffHeaderSeal {
    /// Epoch index of this block.
    pub epoch: u64,
    /// `HotStuff` view in which this block was proposed.
    pub view: u64,
    /// View of the `justify_qc` embedded in this block.
    pub justify_view: u64,
    /// First 4 bytes of the epoch's [`ValidatorSet::hash`](crate::ValidatorSet::hash).
    pub validator_set_hash_prefix: [u8; 4],
}

impl HotStuffHeaderSeal {
    /// Encodes the seal into a fixed 32-byte array.
    pub fn encode(&self) -> [u8; HOTSTUFF_SEAL_LEN] {
        let mut out = [0u8; HOTSTUFF_SEAL_LEN];
        out[0..4].copy_from_slice(&HOTSTUFF_SEAL_MAGIC);
        out[4..12].copy_from_slice(&self.epoch.to_be_bytes());
        out[12..20].copy_from_slice(&self.view.to_be_bytes());
        out[20..28].copy_from_slice(&self.justify_view.to_be_bytes());
        out[28..32].copy_from_slice(&self.validator_set_hash_prefix);
        out
    }

    /// Decodes a 32-byte slice from `header.extra_data` into a [`HotStuffHeaderSeal`].
    pub fn decode(bytes: &[u8]) -> Result<Self, HotStuffError> {
        if bytes.len() != HOTSTUFF_SEAL_LEN {
            return Err(HotStuffError::InvalidSealLength {
                expected: HOTSTUFF_SEAL_LEN,
                got: bytes.len(),
            });
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        if magic != HOTSTUFF_SEAL_MAGIC {
            return Err(HotStuffError::InvalidSealMagic(magic));
        }

        let epoch = u64::from_be_bytes(bytes[4..12].try_into().expect("slice is 8 bytes"));
        let view = u64::from_be_bytes(bytes[12..20].try_into().expect("slice is 8 bytes"));
        let justify_view = u64::from_be_bytes(bytes[20..28].try_into().expect("slice is 8 bytes"));
        let mut validator_set_hash_prefix = [0u8; 4];
        validator_set_hash_prefix.copy_from_slice(&bytes[28..32]);

        Ok(Self { epoch, view, justify_view, validator_set_hash_prefix })
    }
}

/// Consensus-layer node header in the Chained `HotStuff` block tree.
///
/// Binds the `HotStuff` consensus chain (`parent_node_hash`, `justify_qc_hash`) to the Ethereum
/// execution block (`exec_block_hash`, `exec_block_number`). During epoch boundary finalization,
/// `is_nil` may be `true`, in which case `exec_block_hash` and `exec_block_number` repeat the
/// parent's execution block so no new EVM blocks are created past the epoch boundary before the
/// new validator set is finalized.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct HotStuffNodeHeader {
    /// Consensus epoch index.
    pub epoch: u64,
    /// `HotStuff` view number within `epoch`.
    pub view: u64,
    /// Consensus hash of the parent [`HotStuffNodeHeader`].
    pub parent_node_hash: B256,
    /// Hash of the [`QuorumCertificate`] justifying the parent node.
    pub justify_qc_hash: B256,
    /// Execution-layer block hash (or repeated boundary hash when `is_nil` is `true`).
    pub exec_block_hash: B256,
    /// Execution-layer block number (or repeated boundary number when `is_nil` is `true`).
    pub exec_block_number: u64,
    /// Address of the leader that proposed this node (zero for genesis/epoch-genesis).
    pub proposer: Address,
    /// Whether this is a consensus-only NIL suffix node advancing the 3-chain at epoch end.
    pub is_nil: bool,
}

impl HotStuffNodeHeader {
    /// Computes the canonical consensus hash `keccak256(rlp(self))` of this node header.
    pub fn node_hash(&self) -> B256 {
        let mut buf = Vec::with_capacity(160);
        self.encode(&mut buf);
        keccak256(&buf)
    }

    /// Creates the synthetic epoch-genesis node at `(epoch, view = 0)` anchored at the given
    /// finalized execution block.
    pub const fn epoch_genesis(epoch: u64, exec_block_hash: B256, exec_block_number: u64) -> Self {
        Self {
            epoch,
            view: 0,
            parent_node_hash: B256::ZERO,
            justify_qc_hash: B256::ZERO,
            exec_block_hash,
            exec_block_number,
            proposer: Address::ZERO,
            is_nil: false,
        }
    }
}

/// Signable payload of a validator vote for a `HotStuff` node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct VoteData {
    /// Epoch in which the vote is cast.
    pub epoch: u64,
    /// View in which the vote is cast.
    pub view: u64,
    /// Consensus hash (`HotStuffNodeHeader::node_hash`) being voted for.
    pub node_hash: B256,
    /// Execution block hash referenced by the voted node.
    pub exec_block_hash: B256,
    /// Execution block number referenced by the voted node.
    pub exec_block_number: u64,
}

/// A single validator's signed vote for a [`HotStuffNodeHeader`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct Vote {
    /// Vote target data.
    pub data: VoteData,
    /// Validator address that signed `data`.
    pub voter: Address,
    /// Recoverable secp256k1 signature over the domain-separated vote digest.
    pub signature: HotStuffSignature,
}

/// Single validator signature entry inside a [`QuorumCertificate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct ValidatorSignature {
    /// Signing validator address.
    pub signer: Address,
    /// Recoverable secp256k1 signature over the [`VoteData`] digest.
    pub signature: HotStuffSignature,
}

/// Quorum Certificate proving at least `2f + 1` validators voted for a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct QuorumCertificate {
    /// Epoch of the certified node.
    pub epoch: u64,
    /// View of the certified node (`0` for epoch-genesis QC).
    pub view: u64,
    /// Consensus hash of the certified [`HotStuffNodeHeader`].
    pub node_hash: B256,
    /// Execution block hash of the certified node.
    pub exec_block_hash: B256,
    /// Execution block number of the certified node.
    pub exec_block_number: u64,
    /// Distinct validator signatures meeting the quorum threshold (`empty` for epoch-genesis QC).
    pub signatures: Vec<ValidatorSignature>,
}

impl QuorumCertificate {
    /// Creates the bootstrap epoch-genesis QC at `view = 0` anchored to `exec_block_hash`.
    pub fn epoch_genesis(epoch: u64, exec_block_hash: B256, exec_block_number: u64) -> Self {
        let genesis_node =
            HotStuffNodeHeader::epoch_genesis(epoch, exec_block_hash, exec_block_number);
        Self {
            epoch,
            view: 0,
            node_hash: genesis_node.node_hash(),
            exec_block_hash,
            exec_block_number,
            signatures: Vec::new(),
        }
    }

    /// Computes `keccak256(rlp(self))`.
    ///
    /// Embedded as `prev_randao` in Ethereum execution headers to bind the EL block to its
    /// parent QC.
    pub fn hash(&self) -> B256 {
        let mut buf = Vec::with_capacity(256);
        self.encode(&mut buf);
        keccak256(&buf)
    }

    /// Returns the [`VoteData`] certified by this QC.
    pub const fn vote_data(&self) -> VoteData {
        VoteData {
            epoch: self.epoch,
            view: self.view,
            node_hash: self.node_hash,
            exec_block_hash: self.exec_block_hash,
            exec_block_number: self.exec_block_number,
        }
    }
}

/// Signable payload of a Pacemaker timeout message.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct TimeoutData {
    /// Current consensus epoch.
    pub epoch: u64,
    /// View that timed out.
    pub view: u64,
    /// View of the sender's highest known QC.
    pub high_qc_view: u64,
}

/// Signed Pacemaker timeout message broadcast when a view timer expires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct TimeoutMsg {
    /// Timeout epoch/view metadata.
    pub data: TimeoutData,
    /// Sender's highest known QC so the next leader can adopt it.
    pub high_qc: QuorumCertificate,
    /// Validator address casting the timeout.
    pub voter: Address,
    /// Recoverable secp256k1 signature over the domain-separated timeout digest.
    pub signature: HotStuffSignature,
}

/// Individual timeout signature entry inside a [`TimeoutCertificate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct TimeoutSignature {
    /// Signing validator address.
    pub signer: Address,
    /// Highest QC view reported by `signer` when timing out.
    pub high_qc_view: u64,
    /// Recoverable secp256k1 signature over `TimeoutData { epoch, view, high_qc_view }`.
    pub signature: HotStuffSignature,
}

/// Timeout Certificate proving `2f + 1` validators timed out in `(epoch, view)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct TimeoutCertificate {
    /// Epoch in which the view timed out.
    pub epoch: u64,
    /// Timed-out view.
    pub view: u64,
    /// Distinct validator timeout signatures meeting quorum.
    pub signatures: Vec<TimeoutSignature>,
}

/// Leader proposal carrying a [`HotStuffNodeHeader`], parent QC, and optional execution payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
#[rlp(trailing)]
pub struct Proposal {
    /// Consensus node metadata.
    pub header: HotStuffNodeHeader,
    /// QC justifying `header.parent_node_hash`.
    pub justify_qc: QuorumCertificate,
    /// RLP-encoded Ethereum block (`empty` when `header.is_nil` is `true`).
    pub block_rlp: Bytes,
    /// Prague EIP-7685 execution requests associated with the payload (empty pre-Prague/NIL).
    pub requests: Vec<Bytes>,
    /// Leader signature over `header.node_hash()`.
    pub signature: HotStuffSignature,
    /// Timeout certificate for `header.view - 1` when `header.view > justify_qc.view + 1`.
    pub timeout_cert: Option<TimeoutCertificate>,
}

/// New-view notification carrying a validator's highest QC after advancing view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
#[rlp(trailing)]
pub struct NewView {
    /// Consensus epoch.
    pub epoch: u64,
    /// Target view being entered.
    pub new_view: u64,
    /// Sender's highest known QC.
    pub high_qc: QuorumCertificate,
    /// Sender validator address.
    pub sender: Address,
    /// Signature over `(epoch, new_view, high_qc.hash())`.
    pub signature: HotStuffSignature,
    /// Optional timeout certificate justifying entry into `new_view`.
    pub timeout_cert: Option<TimeoutCertificate>,
}

/// Proof that an epoch boundary execution block was 3-chain finalized under `from_epoch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct EpochChangeCert {
    /// Epoch that finalized the boundary block.
    pub from_epoch: u64,
    /// Finalized epoch boundary execution block hash.
    pub boundary_block_hash: B256,
    /// Finalized epoch boundary execution block number.
    pub boundary_block_number: u64,
    /// First node (`b`) of the consecutive 3-chain commit sequence.
    pub node0: HotStuffNodeHeader,
    /// Second node (`b'`) of the consecutive 3-chain commit sequence.
    pub node1: HotStuffNodeHeader,
    /// Third node (`b''`) of the consecutive 3-chain commit sequence.
    pub node2: HotStuffNodeHeader,
    /// QC certifying `node2` (`b''`) under `from_epoch`'s validator set.
    pub commit_qc: QuorumCertificate,
}

impl EpochChangeCert {
    /// Returns references to the three consecutive `HotStuff` nodes `[b, b', b'']`.
    pub const fn nodes(&self) -> [&HotStuffNodeHeader; 3] {
        [&self.node0, &self.node1, &self.node2]
    }
}

/// Authenticated peer identity handshake associating a validator address with an `RLPx` `PeerId`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct PeerHello {
    /// Validator address claimed by the sender.
    pub validator: Address,
    /// 64-byte secp256k1 `RLPx` peer ID of the sender.
    pub peer_id: FixedBytes<64>,
    /// Recoverable secp256k1 signature proving control of `validator`.
    pub signature: HotStuffSignature,
}

/// Compact consensus sync status exchanged when `hotstuff/1` peers connect or advance epochs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct SyncStatus {
    /// Peer's active consensus epoch.
    pub epoch: u64,
    /// Peer's current `HotStuff` view.
    pub view: u64,
    /// Highest 3-chain finalized execution block number.
    pub finalized_number: u64,
    /// Highest 3-chain finalized execution block hash.
    pub finalized_hash: B256,
}

/// Request for a sequential batch of certified execution blocks starting at `from_block`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct SyncBlocksRequest {
    /// First execution block number requested.
    pub from_block: u64,
    /// Maximum number of blocks requested (clamped to [`MAX_SYNC_BATCH`]).
    pub max_blocks: u64,
}

/// Single certified execution block paired with its `HotStuff` header and [`QuorumCertificate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct SyncedBlock {
    /// RLP-encoded Ethereum block.
    pub block_rlp: Bytes,
    /// Prague EIP-7685 execution requests associated with the block.
    pub requests: Vec<Bytes>,
    /// `HotStuff` node header bound to this block.
    pub header: HotStuffNodeHeader,
    /// Quorum certificate certifying `header`.
    pub qc: QuorumCertificate,
}

/// Batch response of certified blocks within one epoch, optionally ending with an
/// [`EpochChangeCert`] when the batch reaches the epoch boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
#[rlp(trailing)]
pub struct SyncBlocksResponse {
    /// Sequential certified blocks in ascending block number order.
    pub blocks: Vec<SyncedBlock>,
    /// Epoch finalization proof if the batch reaches the epoch boundary.
    pub epoch_cert: Option<EpochChangeCert>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rlp::Decodable;

    #[test]
    fn header_seal_roundtrip_and_errors() {
        let seal = HotStuffHeaderSeal {
            epoch: 3,
            view: 42,
            justify_view: 41,
            validator_set_hash_prefix: [0xaa, 0xbb, 0xcc, 0xdd],
        };
        let encoded = seal.encode();
        assert_eq!(encoded.len(), HOTSTUFF_SEAL_LEN);
        let decoded = HotStuffHeaderSeal::decode(&encoded).unwrap();
        assert_eq!(decoded, seal);

        let err = HotStuffHeaderSeal::decode(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, HotStuffError::InvalidSealLength { expected: 32, got: 16 }));

        let mut bad_magic = encoded;
        bad_magic[0..4].copy_from_slice(b"NOPE");
        let err = HotStuffHeaderSeal::decode(&bad_magic).unwrap_err();
        assert!(matches!(err, HotStuffError::InvalidSealMagic([b'N', b'O', b'P', b'E'])));
    }

    #[test]
    fn rlp_roundtrip_proposal_and_new_view() {
        let genesis_qc = QuorumCertificate::epoch_genesis(0, B256::repeat_byte(0x11), 0);
        let header = HotStuffNodeHeader {
            epoch: 0,
            view: 2,
            parent_node_hash: genesis_qc.node_hash,
            justify_qc_hash: genesis_qc.hash(),
            exec_block_hash: B256::repeat_byte(0x22),
            exec_block_number: 1,
            proposer: Address::repeat_byte(0x01),
            is_nil: false,
        };
        let tc = TimeoutCertificate {
            epoch: 0,
            view: 1,
            signatures: vec![TimeoutSignature {
                signer: Address::repeat_byte(0x01),
                high_qc_view: 0,
                signature: FixedBytes::repeat_byte(0x55),
            }],
        };

        for timeout_cert in [None, Some(tc)] {
            let proposal = Proposal {
                header: header.clone(),
                justify_qc: genesis_qc.clone(),
                block_rlp: Bytes::from_static(&[1, 2, 3]),
                requests: vec![Bytes::from_static(&[9, 8])],
                signature: FixedBytes::repeat_byte(0x77),
                timeout_cert: timeout_cert.clone(),
            };
            let mut buf = Vec::new();
            proposal.encode(&mut buf);
            let decoded = Proposal::decode(&mut buf.as_slice()).unwrap();
            assert_eq!(decoded, proposal);

            let new_view = NewView {
                epoch: 0,
                new_view: 2,
                high_qc: genesis_qc.clone(),
                sender: Address::repeat_byte(0x02),
                signature: FixedBytes::repeat_byte(0x88),
                timeout_cert,
            };
            let mut nv_buf = Vec::new();
            new_view.encode(&mut nv_buf);
            let decoded_nv = NewView::decode(&mut nv_buf.as_slice()).unwrap();
            assert_eq!(decoded_nv, new_view);
        }
    }
}
