//! Reth [`Consensus`] and [`HeaderValidator`] implementation for `HotStuff`.

use alloy_primitives::{map::B256Map, B256};
use parking_lot::RwLock;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_consensus::{
    Consensus, ConsensusError, FullConsensus, HeaderValidator, ReceiptRootBloom, TransactionRoot,
};
use reth_ethereum_consensus::EthBeaconConsensus;
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{
    Block, BlockHeader, NodePrimitives, RecoveredBlock, SealedBlock, SealedHeader,
};
use std::{collections::VecDeque, sync::Arc};

use crate::{
    error::HotStuffError,
    types::{HotStuffHeaderSeal, QuorumCertificate},
    validator::EpochManager,
};

const MAX_STORED_QCS: usize = 256;

#[derive(Debug, Default)]
struct QcStoreInner {
    qcs: B256Map<QuorumCertificate>,
    order: VecDeque<B256>,
}

/// Bounded store of verified [`QuorumCertificate`]s keyed by `qc.hash()`.
///
/// Used by [`HotStuffConsensus`] to cross-check `header.mix_hash` (`prev_randao`) and
/// `justify_view` during block header validation.
#[derive(Debug, Clone, Default)]
pub struct QcStore {
    inner: Arc<RwLock<QcStoreInner>>,
}

impl QcStore {
    /// Creates a new empty [`QcStore`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a verified [`QuorumCertificate`] under `qc.hash()`.
    pub fn insert(&self, qc: QuorumCertificate) {
        let hash = qc.hash();
        let mut guard = self.inner.write();
        if guard.qcs.insert(hash, qc).is_none() {
            guard.order.push_back(hash);
            while guard.order.len() > MAX_STORED_QCS {
                if let Some(evicted) = guard.order.pop_front() {
                    guard.qcs.remove(&evicted);
                }
            }
        }
    }

    /// Returns the stored [`QuorumCertificate`] for `qc_hash`, if available.
    pub fn get(&self, qc_hash: &B256) -> Option<QuorumCertificate> {
        self.inner.read().qcs.get(qc_hash).cloned()
    }
}

/// Reth consensus engine enforcing `HotStuff` header seals, leader schedule, and parent-child
/// view/epoch monotonicity on top of [`EthBeaconConsensus`].
#[derive(Debug, Clone)]
pub struct HotStuffConsensus<ChainSpec> {
    inner: EthBeaconConsensus<ChainSpec>,
    epoch_manager: EpochManager,
    qc_store: QcStore,
}

impl<ChainSpec: EthChainSpec + EthereumHardforks> HotStuffConsensus<ChainSpec> {
    /// Creates a new [`HotStuffConsensus`] wrapping [`EthBeaconConsensus`].
    pub const fn new(
        chain_spec: Arc<ChainSpec>,
        epoch_manager: EpochManager,
        qc_store: QcStore,
    ) -> Self {
        Self { inner: EthBeaconConsensus::new(chain_spec), epoch_manager, qc_store }
    }

    /// Returns the underlying [`EpochManager`].
    pub const fn epoch_manager(&self) -> &EpochManager {
        &self.epoch_manager
    }

    /// Returns the shared [`QcStore`].
    pub const fn qc_store(&self) -> &QcStore {
        &self.qc_store
    }
}

impl<ChainSpec, N> FullConsensus<N> for HotStuffConsensus<ChainSpec>
where
    ChainSpec: Send + EthChainSpec<Header = N::BlockHeader> + EthereumHardforks,
    N: NodePrimitives,
{
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<N::Block>,
        result: &BlockExecutionResult<N::Receipt>,
        receipt_root_bloom: Option<ReceiptRootBloom>,
        block_access_list_hash: Option<B256>,
    ) -> Result<(), ConsensusError> {
        <EthBeaconConsensus<ChainSpec> as FullConsensus<N>>::validate_block_post_execution(
            &self.inner,
            block,
            result,
            receipt_root_bloom,
            block_access_list_hash,
        )
    }
}

impl<B, ChainSpec> Consensus<B> for HotStuffConsensus<ChainSpec>
where
    B: Block,
    ChainSpec: EthChainSpec<Header = B::Header> + EthereumHardforks,
{
    fn validate_body_against_header(
        &self,
        body: &B::Body,
        header: &SealedHeader<B::Header>,
    ) -> Result<(), ConsensusError> {
        <EthBeaconConsensus<ChainSpec> as Consensus<B>>::validate_body_against_header(
            &self.inner,
            body,
            header,
        )
    }

    fn validate_block_pre_execution(&self, block: &SealedBlock<B>) -> Result<(), ConsensusError> {
        self.inner.validate_block_pre_execution(block)
    }

    fn validate_block_pre_execution_with_tx_root(
        &self,
        block: &SealedBlock<B>,
        transaction_root: Option<TransactionRoot>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_block_pre_execution_with_tx_root(block, transaction_root)
    }
}

impl<H, ChainSpec> HeaderValidator<H> for HotStuffConsensus<ChainSpec>
where
    H: BlockHeader,
    ChainSpec: EthChainSpec<Header = H> + EthereumHardforks,
{
    fn validate_header(&self, header: &SealedHeader<H>) -> Result<(), ConsensusError> {
        self.inner.validate_header(header)?;

        let raw = header.header();
        if raw.number() == 0 {
            return Ok(());
        }

        let seal = HotStuffHeaderSeal::decode(raw.extra_data()).map_err(ConsensusError::other)?;
        let expected_epoch = self.epoch_manager.epoch_for_block(raw.number());
        if seal.epoch != expected_epoch {
            return Err(ConsensusError::other(HotStuffError::EpochMismatch {
                expected: expected_epoch,
                got: seal.epoch,
            }));
        }
        if seal.view <= seal.justify_view {
            return Err(ConsensusError::other(HotStuffError::InvalidView {
                view: seal.view,
                reason: "header view must exceed justify_view",
            }));
        }

        let validator_set = self.epoch_manager.validator_set(seal.epoch).ok_or_else(|| {
            ConsensusError::other(HotStuffError::InvalidValidatorSet(format!(
                "missing validator set for epoch {}",
                seal.epoch
            )))
        })?;

        let expected_leader = validator_set.leader_for_view(seal.view);
        if raw.beneficiary() != expected_leader {
            return Err(ConsensusError::other(HotStuffError::InvalidProposer {
                epoch: seal.epoch,
                view: seal.view,
                expected: expected_leader,
                got: raw.beneficiary(),
            }));
        }
        if seal.validator_set_hash_prefix != validator_set.hash_prefix() {
            return Err(ConsensusError::other(HotStuffError::InvalidValidatorSet(
                "header validator set hash prefix mismatch".to_string(),
            )));
        }

        #[expect(
            clippy::suspicious_operation_groupings,
            reason = "qc.view is compared against header seal.justify_view"
        )]
        if let Some(mix_hash) = raw.mix_hash() &&
            let Some(qc) = self.qc_store.get(&mix_hash) &&
            (qc.epoch != seal.epoch ||
                qc.view != seal.justify_view ||
                qc.exec_block_hash != raw.parent_hash())
        {
            return Err(ConsensusError::other(HotStuffError::InvalidBlockHash(
                "header mix_hash QC does not match seal or parent_hash".to_string(),
            )));
        }

        Ok(())
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<H>,
        parent: &SealedHeader<H>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_header_against_parent(header, parent)?;

        if parent.number() == 0 {
            return Ok(());
        }

        let child_seal =
            HotStuffHeaderSeal::decode(header.extra_data()).map_err(ConsensusError::other)?;
        let parent_seal =
            HotStuffHeaderSeal::decode(parent.extra_data()).map_err(ConsensusError::other)?;

        if child_seal.epoch == parent_seal.epoch {
            if child_seal.view <= parent_seal.view {
                return Err(ConsensusError::other(HotStuffError::InvalidView {
                    view: child_seal.view,
                    reason: "child view must be strictly greater than parent view",
                }));
            }
            if child_seal.justify_view < parent_seal.view {
                return Err(ConsensusError::other(HotStuffError::InvalidView {
                    view: child_seal.justify_view,
                    reason: "child justify_view must be at least parent view",
                }));
            }
        } else if child_seal.epoch == parent_seal.epoch + 1 {
            let boundary = self.epoch_manager.epoch_boundary_block(parent_seal.epoch);
            if parent.number() != boundary {
                return Err(ConsensusError::other(HotStuffError::EpochMismatch {
                    expected: parent_seal.epoch,
                    got: child_seal.epoch,
                }));
            }
            if child_seal.justify_view != 0 {
                return Err(ConsensusError::other(HotStuffError::InvalidView {
                    view: child_seal.justify_view,
                    reason: "first block of new epoch must justify view 0",
                }));
            }
        } else {
            return Err(ConsensusError::other(HotStuffError::EpochMismatch {
                expected: parent_seal.epoch,
                got: child_seal.epoch,
            }));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, EMPTY_OMMER_ROOT_HASH};
    use alloy_primitives::{Address, Bytes};
    use reth_chainspec::ChainSpecBuilder;
    use reth_primitives_traits::proofs;

    use crate::validator::DEFAULT_VALIDATOR_REGISTRY_ADDRESS;

    fn test_chain_spec() -> Arc<reth_chainspec::ChainSpec> {
        Arc::new(ChainSpecBuilder::mainnet().cancun_activated().build())
    }

    fn base_cancun_header(number: u64, parent_hash: B256, timestamp: u64) -> Header {
        Header {
            number,
            parent_hash,
            timestamp,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            withdrawals_root: Some(proofs::calculate_withdrawals_root(&[])),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            ..Default::default()
        }
    }

    #[test]
    fn validates_seal_leader_view_and_epoch_transitions() {
        let validators: Vec<_> = (1u8..=4).map(Address::with_last_byte).collect();
        let mgr = EpochManager::new(2, DEFAULT_VALIDATOR_REGISTRY_ADDRESS, validators).unwrap();
        let vs0 = mgr.validator_set(0).unwrap();
        let consensus = HotStuffConsensus::new(test_chain_spec(), mgr.clone(), QcStore::new());

        let genesis = SealedHeader::new(base_cancun_header(0, B256::ZERO, 100), B256::ZERO);

        let seal1 = HotStuffHeaderSeal {
            epoch: 0,
            view: 1,
            justify_view: 0,
            validator_set_hash_prefix: vs0.hash_prefix(),
        };
        let mut h1 = base_cancun_header(1, genesis.hash(), 101);
        h1.beneficiary = vs0.leader_for_view(1);
        h1.extra_data = Bytes::copy_from_slice(&seal1.encode());
        let sh1 = SealedHeader::seal_slow(h1.clone());
        assert!(consensus.validate_header(&sh1).is_ok());

        // Bad magic fails.
        let mut bad_magic = h1.clone();
        bad_magic.extra_data = Bytes::from_static(&[0u8; 32]);
        let err = consensus.validate_header(&SealedHeader::seal_slow(bad_magic)).unwrap_err();
        assert!(err.downcast_other_ref::<HotStuffError>().is_some());

        // Wrong leader fails.
        let mut bad_leader = h1.clone();
        bad_leader.beneficiary = vs0.leader_for_view(2);
        let err = consensus.validate_header(&SealedHeader::seal_slow(bad_leader)).unwrap_err();
        assert!(matches!(
            err.downcast_other_ref::<HotStuffError>(),
            Some(HotStuffError::InvalidProposer { .. })
        ));

        // Wrong epoch fails.
        let mut bad_epoch = h1;
        bad_epoch.extra_data =
            Bytes::copy_from_slice(&HotStuffHeaderSeal { epoch: 1, ..seal1 }.encode());
        let err = consensus.validate_header(&SealedHeader::seal_slow(bad_epoch)).unwrap_err();
        assert!(matches!(
            err.downcast_other_ref::<HotStuffError>(),
            Some(HotStuffError::EpochMismatch { expected: 0, got: 1 })
        ));

        // Block 2 (epoch 0 boundary) -> Block 3 (epoch 1).
        let seal2 = HotStuffHeaderSeal {
            epoch: 0,
            view: 2,
            justify_view: 1,
            validator_set_hash_prefix: vs0.hash_prefix(),
        };
        let mut h2 = base_cancun_header(2, sh1.hash(), 102);
        h2.beneficiary = vs0.leader_for_view(2);
        h2.extra_data = Bytes::copy_from_slice(&seal2.encode());
        let sh2 = SealedHeader::seal_slow(h2);
        assert!(consensus.validate_header_against_parent(&sh2, &sh1).is_ok());

        // Non-monotonic view fails against parent.
        let mut bad_view = base_cancun_header(2, sh1.hash(), 102);
        bad_view.beneficiary = vs0.leader_for_view(1);
        bad_view.extra_data = Bytes::copy_from_slice(&seal1.encode());
        assert!(consensus
            .validate_header_against_parent(&SealedHeader::seal_slow(bad_view), &sh1)
            .is_err());

        // Epoch 1 transition after boundary block 2 succeeds.
        let vs1 = mgr.insert_epoch(crate::ValidatorSet::new(1, vs0.validators().to_vec()).unwrap());
        let seal3 = HotStuffHeaderSeal {
            epoch: 1,
            view: 1,
            justify_view: 0,
            validator_set_hash_prefix: vs1.hash_prefix(),
        };
        let mut h3 = base_cancun_header(3, sh2.hash(), 103);
        h3.beneficiary = vs1.leader_for_view(1);
        h3.extra_data = Bytes::copy_from_slice(&seal3.encode());
        let sh3 = SealedHeader::seal_slow(h3);
        assert!(consensus.validate_header(&sh3).is_ok());
        assert!(consensus.validate_header_against_parent(&sh3, &sh2).is_ok());
    }
}
