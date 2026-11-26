//! Cryptographic signing and verification helpers using `secp256k1`.

use alloy_primitives::{keccak256, Address, FixedBytes, B256};
use alloy_rlp::Encodable;
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, PublicKey, SecretKey,
};
use std::{collections::HashSet, fmt};

use crate::{
    error::HotStuffError,
    types::{
        HotStuffSignature, NewView, PeerHello, Proposal, QuorumCertificate, TimeoutCertificate,
        TimeoutData, VoteData,
    },
    validator::ValidatorSet,
};

const DOMAIN_PROPOSAL: &[u8] = b"RETH_HOTSTUFF_PROPOSAL_V1";
const DOMAIN_VOTE: &[u8] = b"RETH_HOTSTUFF_VOTE_V1";
const DOMAIN_TIMEOUT: &[u8] = b"RETH_HOTSTUFF_TIMEOUT_V1";
const DOMAIN_NEW_VIEW: &[u8] = b"RETH_HOTSTUFF_NEW_VIEW_V1";
const DOMAIN_PEER_HELLO: &[u8] = b"RETH_HOTSTUFF_HELLO_V1";

/// secp256k1 signing key wrapper for a `HotStuff` validator.
///
/// Secret key material is redacted in [`fmt::Debug`].
#[derive(Clone)]
pub struct ValidatorSigner {
    secret_key: SecretKey,
    address: Address,
}

impl fmt::Debug for ValidatorSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatorSigner")
            .field("address", &self.address)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

impl ValidatorSigner {
    /// Creates a [`ValidatorSigner`] from a raw `secp256k1::SecretKey`.
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        let public_key = PublicKey::from_secret_key(&secret_key);
        let address = Address::from_raw_public_key(&public_key.serialize_uncompressed()[1..]);
        Self { secret_key, address }
    }

    /// Creates a [`ValidatorSigner`] from 32 secret key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, HotStuffError> {
        let secret_key = SecretKey::from_secret_bytes(bytes)
            .map_err(|err| HotStuffError::InvalidSignature(err.to_string()))?;
        Ok(Self::from_secret_key(secret_key))
    }

    /// Parses a [`ValidatorSigner`] from a hex string (with or without `0x` prefix).
    pub fn from_hex(hex_str: &str) -> Result<Self, HotStuffError> {
        let trimmed = hex_str.trim().strip_prefix("0x").unwrap_or_else(|| hex_str.trim());
        let bytes = alloy_primitives::hex::decode(trimmed)
            .map_err(|err| HotStuffError::InvalidSignature(err.to_string()))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            HotStuffError::InvalidSignature("validator secret key must be 32 bytes".to_string())
        })?;
        Self::from_bytes(arr)
    }

    /// Generates a fresh random [`ValidatorSigner`].
    pub fn random() -> Self {
        Self::from_secret_key(SecretKey::new(&mut rand::rng()))
    }

    /// Returns the Ethereum address corresponding to this validator's public key.
    pub const fn address(&self) -> Address {
        self.address
    }

    /// Signs a 32-byte digest and returns a 65-byte recoverable signature (`r || s || v`).
    pub fn sign_digest(&self, digest: B256) -> HotStuffSignature {
        let msg = Message::from_digest(digest.0);
        let sig = RecoverableSignature::sign_ecdsa_recoverable(msg, &self.secret_key);
        let (rec_id, compact) = sig.serialize_compact();
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&compact);
        out[64] = rec_id.to_u8();
        FixedBytes::new(out)
    }
}

/// Recovers the Ethereum signer address from a 32-byte digest and 65-byte recoverable signature.
pub fn recover_signer(digest: B256, sig: &HotStuffSignature) -> Result<Address, HotStuffError> {
    let rec_id = RecoveryId::try_from(sig[64] as i32)
        .map_err(|err| HotStuffError::InvalidSignature(err.to_string()))?;
    let recoverable = RecoverableSignature::from_compact(&sig[..64], rec_id)
        .map_err(|err| HotStuffError::InvalidSignature(err.to_string()))?;
    let pubkey = recoverable
        .recover_ecdsa(Message::from_digest(digest.0))
        .map_err(|err| HotStuffError::InvalidSignature(err.to_string()))?;
    Ok(Address::from_raw_public_key(&pubkey.serialize_uncompressed()[1..]))
}

/// Domain-separated signing digest for a proposal's node hash.
pub fn proposal_digest(node_hash: B256) -> B256 {
    let mut buf = Vec::with_capacity(DOMAIN_PROPOSAL.len() + 32);
    buf.extend_from_slice(DOMAIN_PROPOSAL);
    buf.extend_from_slice(node_hash.as_slice());
    keccak256(&buf)
}

/// Domain-separated signing digest for a validator vote.
pub fn vote_digest(data: &VoteData) -> B256 {
    let mut buf = Vec::with_capacity(DOMAIN_VOTE.len() + 128);
    buf.extend_from_slice(DOMAIN_VOTE);
    data.encode(&mut buf);
    keccak256(&buf)
}

/// Domain-separated signing digest for a Pacemaker timeout message.
pub fn timeout_digest(data: &TimeoutData) -> B256 {
    let mut buf = Vec::with_capacity(DOMAIN_TIMEOUT.len() + 48);
    buf.extend_from_slice(DOMAIN_TIMEOUT);
    data.encode(&mut buf);
    keccak256(&buf)
}

/// Domain-separated signing digest for a `NewView` message.
pub fn new_view_digest(epoch: u64, new_view: u64, high_qc_hash: B256) -> B256 {
    let mut buf = Vec::with_capacity(DOMAIN_NEW_VIEW.len() + 48);
    buf.extend_from_slice(DOMAIN_NEW_VIEW);
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(&new_view.to_be_bytes());
    buf.extend_from_slice(high_qc_hash.as_slice());
    keccak256(&buf)
}

/// Domain-separated signing digest for a [`PeerHello`] identity binding.
pub fn peer_hello_digest(validator: Address, peer_id: &FixedBytes<64>) -> B256 {
    let mut buf = Vec::with_capacity(DOMAIN_PEER_HELLO.len() + 20 + 64);
    buf.extend_from_slice(DOMAIN_PEER_HELLO);
    buf.extend_from_slice(validator.as_slice());
    buf.extend_from_slice(peer_id.as_slice());
    keccak256(&buf)
}

/// Verifies that a [`Proposal`] is signed by the expected epoch/view leader.
pub fn verify_proposal_signature(
    proposal: &Proposal,
    validator_set: &ValidatorSet,
) -> Result<(), HotStuffError> {
    if proposal.header.epoch != validator_set.epoch() {
        return Err(HotStuffError::EpochMismatch {
            expected: validator_set.epoch(),
            got: proposal.header.epoch,
        });
    }
    if proposal.header.view == 0 {
        return Err(HotStuffError::InvalidView {
            view: 0,
            reason: "proposal view must be at least 1",
        });
    }
    let expected_leader = validator_set.leader_for_view(proposal.header.view);
    if proposal.header.proposer != expected_leader {
        return Err(HotStuffError::InvalidProposer {
            epoch: validator_set.epoch(),
            view: proposal.header.view,
            expected: expected_leader,
            got: proposal.header.proposer,
        });
    }
    let digest = proposal_digest(proposal.header.node_hash());
    let recovered = recover_signer(digest, &proposal.signature)?;
    if recovered != proposal.header.proposer {
        return Err(HotStuffError::InvalidSignature(format!(
            "proposal signer {recovered} does not match proposer {}",
            proposal.header.proposer
        )));
    }
    Ok(())
}

/// Verifies that a [`QuorumCertificate`] is valid against `validator_set`.
///
/// View-0 epoch-genesis QCs require zero signatures when their node hash matches the synthetic
/// epoch-genesis node header; all positive-view QCs require `validator_set.quorum_size()` distinct
/// valid signatures from members of `validator_set`.
pub fn verify_qc(
    qc: &QuorumCertificate,
    validator_set: &ValidatorSet,
) -> Result<(), HotStuffError> {
    if qc.epoch != validator_set.epoch() {
        return Err(HotStuffError::EpochMismatch { expected: validator_set.epoch(), got: qc.epoch });
    }

    if qc.view == 0 {
        if !qc.signatures.is_empty() {
            return Err(HotStuffError::InvalidSignature(
                "view-0 genesis QC must not carry signatures".to_string(),
            ));
        }
        let expected =
            QuorumCertificate::epoch_genesis(qc.epoch, qc.exec_block_hash, qc.exec_block_number);
        if qc.node_hash != expected.node_hash {
            return Err(HotStuffError::InvalidBlockHash(format!(
                "genesis QC node hash mismatch: expected {}, got {}",
                expected.node_hash, qc.node_hash
            )));
        }
        return Ok(());
    }

    let required = validator_set.quorum_size();
    if qc.signatures.len() < required {
        return Err(HotStuffError::InsufficientQuorum { required, got: qc.signatures.len() });
    }
    if qc.signatures.len() > validator_set.len() {
        return Err(HotStuffError::InvalidValidatorSet(format!(
            "signature count {} exceeds validator set size {}",
            qc.signatures.len(),
            validator_set.len()
        )));
    }

    let digest = vote_digest(&qc.vote_data());
    let mut seen = HashSet::with_capacity(qc.signatures.len());
    for entry in &qc.signatures {
        if !validator_set.contains(&entry.signer) {
            return Err(HotStuffError::NonValidator { epoch: qc.epoch, address: entry.signer });
        }
        if !seen.insert(entry.signer) {
            return Err(HotStuffError::DuplicateSigner(entry.signer));
        }
        let recovered = recover_signer(digest, &entry.signature)?;
        if recovered != entry.signer {
            return Err(HotStuffError::InvalidSignature(format!(
                "QC signer mismatch: expected {}, recovered {recovered}",
                entry.signer
            )));
        }
    }

    Ok(())
}

/// Verifies that a [`TimeoutCertificate`] holds `quorum_size()` distinct valid validator timeout
/// signatures for `(epoch, view)`.
pub fn verify_tc(
    tc: &TimeoutCertificate,
    validator_set: &ValidatorSet,
) -> Result<(), HotStuffError> {
    if tc.epoch != validator_set.epoch() {
        return Err(HotStuffError::EpochMismatch { expected: validator_set.epoch(), got: tc.epoch });
    }
    if tc.view == 0 {
        return Err(HotStuffError::InvalidView {
            view: 0,
            reason: "timeout certificate view must be at least 1",
        });
    }

    let required = validator_set.quorum_size();
    if tc.signatures.len() < required {
        return Err(HotStuffError::InsufficientQuorum { required, got: tc.signatures.len() });
    }
    if tc.signatures.len() > validator_set.len() {
        return Err(HotStuffError::InvalidValidatorSet(format!(
            "TC signature count {} exceeds validator set size {}",
            tc.signatures.len(),
            validator_set.len()
        )));
    }

    let mut seen = HashSet::with_capacity(tc.signatures.len());
    for entry in &tc.signatures {
        if !validator_set.contains(&entry.signer) {
            return Err(HotStuffError::NonValidator { epoch: tc.epoch, address: entry.signer });
        }
        if !seen.insert(entry.signer) {
            return Err(HotStuffError::DuplicateSigner(entry.signer));
        }
        if entry.high_qc_view >= tc.view {
            return Err(HotStuffError::InvalidView {
                view: entry.high_qc_view,
                reason: "timeout high_qc_view must be strictly below timed-out view",
            });
        }
        let digest = timeout_digest(&TimeoutData {
            epoch: tc.epoch,
            view: tc.view,
            high_qc_view: entry.high_qc_view,
        });
        let recovered = recover_signer(digest, &entry.signature)?;
        if recovered != entry.signer {
            return Err(HotStuffError::InvalidSignature(format!(
                "TC signer mismatch: expected {}, recovered {recovered}",
                entry.signer
            )));
        }
    }

    Ok(())
}

/// Verifies a [`NewView`] message signature, membership, and any embedded [`TimeoutCertificate`].
pub fn verify_new_view(msg: &NewView, validator_set: &ValidatorSet) -> Result<(), HotStuffError> {
    if msg.epoch != validator_set.epoch() {
        return Err(HotStuffError::EpochMismatch {
            expected: validator_set.epoch(),
            got: msg.epoch,
        });
    }
    if !validator_set.contains(&msg.sender) {
        return Err(HotStuffError::NonValidator { epoch: msg.epoch, address: msg.sender });
    }
    let digest = new_view_digest(msg.epoch, msg.new_view, msg.high_qc.hash());
    let recovered = recover_signer(digest, &msg.signature)?;
    if recovered != msg.sender {
        return Err(HotStuffError::InvalidSignature(format!(
            "NewView signer mismatch: expected {}, recovered {recovered}",
            msg.sender
        )));
    }
    verify_qc(&msg.high_qc, validator_set)?;
    if let Some(tc) = &msg.timeout_cert {
        if tc.epoch != msg.epoch || tc.view + 1 != msg.new_view {
            return Err(HotStuffError::InvalidView {
                view: msg.new_view,
                reason: "NewView timeout certificate view does not precede new_view",
            });
        }
        verify_tc(tc, validator_set)?;
    }
    Ok(())
}

/// Verifies a [`PeerHello`] signature binding a validator address to its `RLPx` `PeerId`.
pub fn verify_peer_hello(hello: &PeerHello) -> Result<(), HotStuffError> {
    let digest = peer_hello_digest(hello.validator, &hello.peer_id);
    let recovered = recover_signer(digest, &hello.signature)?;
    if recovered != hello.validator {
        return Err(HotStuffError::InvalidSignature(format!(
            "PeerHello signer {recovered} does not match {}",
            hello.validator
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HotStuffNodeHeader, TimeoutSignature, ValidatorSignature};
    use alloy_primitives::Bytes;

    fn test_signers(count: usize) -> (Vec<ValidatorSigner>, ValidatorSet) {
        let signers: Vec<_> = (0..count).map(|_| ValidatorSigner::random()).collect();
        let addrs: Vec<_> = signers.iter().map(ValidatorSigner::address).collect();
        let vs = ValidatorSet::new(0, addrs).unwrap();
        (signers, vs)
    }

    #[test]
    fn sign_and_recover_roundtrip() {
        let signer = ValidatorSigner::random();
        let digest = keccak256(b"hello hotstuff");
        let sig = signer.sign_digest(digest);
        assert_eq!(recover_signer(digest, &sig).unwrap(), signer.address());
    }

    #[test]
    fn qc_verification_rejects_insufficient_duplicate_and_non_validator() {
        let (signers, vs) = test_signers(4);
        assert_eq!(vs.quorum_size(), 3);

        let vote_data = VoteData {
            epoch: 0,
            view: 1,
            node_hash: B256::repeat_byte(0x10),
            exec_block_hash: B256::repeat_byte(0x20),
            exec_block_number: 1,
        };
        let digest = vote_digest(&vote_data);

        let valid_sigs: Vec<_> = signers[..3]
            .iter()
            .map(|s| ValidatorSignature { signer: s.address(), signature: s.sign_digest(digest) })
            .collect();
        let valid_qc = QuorumCertificate {
            epoch: 0,
            view: 1,
            node_hash: vote_data.node_hash,
            exec_block_hash: vote_data.exec_block_hash,
            exec_block_number: 1,
            signatures: valid_sigs,
        };
        assert!(verify_qc(&valid_qc, &vs).is_ok());

        let mut short_qc = valid_qc.clone();
        short_qc.signatures.pop();
        assert!(matches!(
            verify_qc(&short_qc, &vs).unwrap_err(),
            HotStuffError::InsufficientQuorum { required: 3, got: 2 }
        ));

        let mut dup_qc = valid_qc.clone();
        dup_qc.signatures[2] = dup_qc.signatures[0].clone();
        assert!(matches!(
            verify_qc(&dup_qc, &vs).unwrap_err(),
            HotStuffError::DuplicateSigner(addr) if addr == signers[0].address()
        ));

        let outsider = ValidatorSigner::random();
        let mut outsider_qc = valid_qc;
        outsider_qc.signatures[2] = ValidatorSignature {
            signer: outsider.address(),
            signature: outsider.sign_digest(digest),
        };
        assert!(matches!(
            verify_qc(&outsider_qc, &vs).unwrap_err(),
            HotStuffError::NonValidator { epoch: 0, address } if address == outsider.address()
        ));
    }

    #[test]
    fn proposal_and_tc_verification() {
        let (signers, vs) = test_signers(4);
        let leader_idx = vs.validators().iter().position(|a| *a == vs.leader_for_view(2)).unwrap();
        let leader = &signers[leader_idx];
        let header = HotStuffNodeHeader {
            epoch: 0,
            view: 2,
            parent_node_hash: B256::repeat_byte(0x01),
            justify_qc_hash: B256::repeat_byte(0x02),
            exec_block_hash: B256::repeat_byte(0x03),
            exec_block_number: 1,
            proposer: leader.address(),
            is_nil: false,
        };
        let sig = leader.sign_digest(proposal_digest(header.node_hash()));
        let proposal = Proposal {
            header,
            justify_qc: QuorumCertificate::epoch_genesis(0, B256::ZERO, 0),
            block_rlp: Bytes::new(),
            requests: Vec::new(),
            signature: sig,
            timeout_cert: None,
        };
        assert!(verify_proposal_signature(&proposal, &vs).is_ok());

        let tc_sigs: Vec<_> = signers[..3]
            .iter()
            .map(|s| {
                let d = timeout_digest(&TimeoutData { epoch: 0, view: 1, high_qc_view: 0 });
                TimeoutSignature {
                    signer: s.address(),
                    high_qc_view: 0,
                    signature: s.sign_digest(d),
                }
            })
            .collect();
        let tc = TimeoutCertificate { epoch: 0, view: 1, signatures: tc_sigs };
        assert!(verify_tc(&tc, &vs).is_ok());
    }
}
