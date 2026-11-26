//! `HotStuff` payload builder injecting the 32-byte [`HotStuffHeaderSeal`] into `extra_data`.

use alloy_primitives::{Bytes, B256};
use alloy_rpc_types_engine::PayloadAttributes as EthPayloadAttributes;
use parking_lot::Mutex;
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder, PayloadConfig,
};
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_ethereum_payload_builder::{default_ethereum_payload, EthereumBuilderConfig};
use reth_ethereum_primitives::{EthPrimitives, TransactionSigned};
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use reth_evm_ethereum::EthEvmConfig;
use reth_payload_builder_primitives::PayloadBuilderError;
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{
    BestTransactions, PoolTransaction, TransactionPool, ValidPoolTransaction,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use crate::types::HOTSTUFF_SEAL_LEN;

const MAX_PENDING_SEALS: usize = 64;

type BestTransactionsIter<Pool> = Box<
    dyn BestTransactions<Item = Arc<ValidPoolTransaction<<Pool as TransactionPool>::Transaction>>>,
>;

#[derive(Debug, Default)]
struct SealStoreInner {
    seals: HashMap<(B256, B256), [u8; HOTSTUFF_SEAL_LEN]>,
    order: VecDeque<(B256, B256)>,
}

/// Bounded shared store passing the 32-byte `HotStuff` seal from the consensus driver into the
/// payload builder, keyed by `(parent_hash, prev_randao)`.
#[derive(Debug, Clone, Default)]
pub struct HotStuffSealStore {
    inner: Arc<Mutex<SealStoreInner>>,
}

impl HotStuffSealStore {
    /// Creates an empty [`HotStuffSealStore`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a 32-byte seal for the given `(parent_hash, prev_randao)` payload key.
    pub fn insert(&self, parent_hash: B256, prev_randao: B256, seal: [u8; HOTSTUFF_SEAL_LEN]) {
        let key = (parent_hash, prev_randao);
        let mut guard = self.inner.lock();
        if guard.seals.insert(key, seal).is_none() {
            guard.order.push_back(key);
            while guard.order.len() > MAX_PENDING_SEALS {
                if let Some(evicted) = guard.order.pop_front() {
                    guard.seals.remove(&evicted);
                }
            }
        }
    }

    /// Returns the stored 32-byte seal for `(parent_hash, prev_randao)`, if present.
    pub fn get(&self, parent_hash: B256, prev_randao: B256) -> Option<[u8; HOTSTUFF_SEAL_LEN]> {
        self.inner.lock().seals.get(&(parent_hash, prev_randao)).copied()
    }
}

/// Ethereum payload builder wrapped with `HotStuff` 32-byte `extra_data` seal injection.
#[derive(Debug, Clone)]
pub struct HotStuffPayloadBuilder<Pool, Client, EvmConfig = EthEvmConfig> {
    client: Client,
    pool: Pool,
    evm_config: EvmConfig,
    builder_config: EthereumBuilderConfig,
    seal_store: HotStuffSealStore,
}

impl<Pool, Client, EvmConfig> HotStuffPayloadBuilder<Pool, Client, EvmConfig> {
    /// Creates a new [`HotStuffPayloadBuilder`].
    pub const fn new(
        client: Client,
        pool: Pool,
        evm_config: EvmConfig,
        builder_config: EthereumBuilderConfig,
        seal_store: HotStuffSealStore,
    ) -> Self {
        Self { client, pool, evm_config, builder_config, seal_store }
    }

    fn config_for(&self, parent_hash: B256, prev_randao: B256) -> EthereumBuilderConfig {
        let mut config = self.builder_config.clone();
        if let Some(seal) = self.seal_store.get(parent_hash, prev_randao) {
            config = config.with_extra_data(Bytes::copy_from_slice(&seal));
        }
        config
    }
}

impl<Pool, Client, EvmConfig> PayloadBuilder for HotStuffPayloadBuilder<Pool, Client, EvmConfig>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks> + Clone,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
{
    type Attributes = EthPayloadAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<EthPayloadAttributes, EthBuiltPayload>,
    ) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError> {
        let config =
            self.config_for(args.config.parent_header.hash(), args.config.attributes.prev_randao);
        default_ethereum_payload(
            self.evm_config.clone(),
            self.client.clone(),
            self.pool.clone(),
            config,
            args,
            |attributes| self.pool.best_transactions_with_attributes(attributes),
        )
    }

    fn on_missing_payload(
        &self,
        _args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        if self.builder_config.await_payload_on_missing {
            MissingPayloadBehaviour::AwaitInProgress
        } else {
            MissingPayloadBehaviour::RaceEmptyPayload
        }
    }

    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<EthBuiltPayload, PayloadBuilderError> {
        let builder_config =
            self.config_for(config.parent_header.hash(), config.attributes.prev_randao);
        let args = BuildArguments::new(
            Default::default(),
            Default::default(),
            None,
            config,
            Default::default(),
            None,
        );

        default_ethereum_payload(
            self.evm_config.clone(),
            self.client.clone(),
            self.pool.clone(),
            builder_config,
            args,
            |_| -> BestTransactionsIter<Pool> { Box::new(std::iter::empty()) },
        )?
        .into_payload()
        .ok_or(PayloadBuilderError::MissingPayload)
    }
}
