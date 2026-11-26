//! Reth [`Node`] and component builders wiring `HotStuff` into a full Reth node.

use alloy_primitives::Address;
use parking_lot::Mutex;
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks, Hardforks};
use reth_engine_local::LocalPayloadAttributesBuilder;
use reth_ethereum_engine_primitives::{EthBuiltPayload, EthEngineTypes, EthPayloadAttributes};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_ethereum_primitives::{Block as EthBlock, EthPrimitives};
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use reth_network::{
    primitives::BasicNetworkPrimitives, protocol::IntoRlpxSubProtocol, NetworkHandle, PeersInfo,
};
use reth_node_api::{
    FullNodeComponents, FullNodeTypes, NodeTypes, PayloadAttributesBuilder, PayloadTypes,
    PrimitivesTy, TxTy,
};
use reth_node_builder::{
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ConsensusBuilder, NetworkBuilder,
        PayloadBuilderBuilder,
    },
    BuilderContext, DebugNode, FullNode, Node, NodeAdapter, PayloadBuilderConfig,
};
use reth_node_ethereum::node::{
    EthereumAddOns, EthereumEngineValidatorBuilder, EthereumEthApiBuilder, EthereumExecutorBuilder,
    EthereumPoolBuilder,
};
use reth_provider::EthStorage;
use reth_transaction_pool::{PoolPooledTx, PoolTransaction, TransactionPool};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::mpsc;
use tracing::{info, Instrument, Span};

use crate::{
    config::HotStuffConfig,
    consensus::{HotStuffConsensus, QcStore},
    driver::HotStuffDriver,
    network::{HotStuffPeerEvent, HotStuffRlpxHandler},
    payload::{HotStuffPayloadBuilder, HotStuffSealStore},
    validator::EpochManager,
};

/// Shared `HotStuff` state connecting the node's Consensus, `PayloadBuilder`, Network, and Driver.
#[derive(Debug, Clone)]
pub struct HotStuffNodeContext {
    config: HotStuffConfig,
    epoch_manager: EpochManager,
    seal_store: HotStuffSealStore,
    qc_store: QcStore,
    protocol_handler: HotStuffRlpxHandler,
    peer_events_rx: Arc<Mutex<Option<mpsc::Receiver<HotStuffPeerEvent>>>>,
    wal_halted: Arc<AtomicBool>,
}

impl HotStuffNodeContext {
    /// Creates a new [`HotStuffNodeContext`] from [`HotStuffConfig`].
    pub fn new(config: HotStuffConfig) -> Result<Self, crate::HotStuffError> {
        config.validate()?;
        let epoch_manager = EpochManager::new(
            config.epoch_length,
            config.validator_registry,
            config.genesis_validators.clone(),
        )?;
        let (protocol_handler, rx) = HotStuffRlpxHandler::new();

        Ok(Self {
            config,
            epoch_manager,
            seal_store: HotStuffSealStore::new(),
            qc_store: QcStore::new(),
            protocol_handler,
            peer_events_rx: Arc::new(Mutex::new(Some(rx))),
            wal_halted: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Returns the [`HotStuffConfig`].
    pub const fn config(&self) -> &HotStuffConfig {
        &self.config
    }

    /// Returns the shared [`EpochManager`].
    pub const fn epoch_manager(&self) -> &EpochManager {
        &self.epoch_manager
    }

    /// Returns the shared [`HotStuffSealStore`].
    pub const fn seal_store(&self) -> &HotStuffSealStore {
        &self.seal_store
    }

    /// Returns the shared [`QcStore`].
    pub const fn qc_store(&self) -> &QcStore {
        &self.qc_store
    }

    /// Returns `true` if the consensus driver halted due to a fatal WAL persistence failure.
    pub fn is_wal_halted(&self) -> bool {
        self.wal_halted.load(Ordering::Acquire)
    }

    /// Takes ownership of the inbound `hotstuff/1` `RLPx` event stream.
    ///
    /// Intended for custom consensus drivers or adversarial test harnesses; [`Self::spawn_driver`]
    /// consumes this receiver internally.
    pub fn take_peer_events(&self) -> Option<mpsc::Receiver<HotStuffPeerEvent>> {
        self.peer_events_rx.lock().take()
    }

    /// Spawns the [`HotStuffDriver`] task on the launched [`FullNode`]'s task executor.
    ///
    /// Must be called once after the node launches.
    pub fn spawn_driver<N>(
        &self,
        node: &FullNode<NodeAdapter<N>, <HotStuffNode as Node<N>>::AddOns>,
    ) -> eyre::Result<()>
    where
        N: FullNodeTypes<Types = HotStuffNode>,
    {
        let peer_events = self
            .take_peer_events()
            .ok_or_else(|| eyre::eyre!("HotStuffDriver already spawned for this node"))?;

        let storage_dir = self
            .config
            .storage_dir
            .clone()
            .unwrap_or_else(|| node.data_dir.data_dir().join("hotstuff"));

        let driver = HotStuffDriver::new(
            *node.network.peer_id(),
            peer_events,
            node.add_ons_handle.beacon_engine_handle.clone(),
            node.payload_builder_handle.clone(),
            node.provider.clone(),
            node.chain_spec(),
            self.epoch_manager.clone(),
            self.seal_store.clone(),
            self.qc_store.clone(),
            self.config.clone(),
            storage_dir,
            Arc::clone(&self.wal_halted),
        )?;

        let span = Span::current();
        node.task_executor.spawn_critical_with_graceful_shutdown_signal(
            "hotstuff consensus driver",
            move |shutdown| driver.run(shutdown).instrument(span),
        );

        Ok(())
    }
}

/// Reth [`Node`] configured with Chained `HotStuff` consensus, `hotstuff/1` `RLPx` subprotocol,
/// and 32-byte `extra_data` seal injection.
#[derive(Debug, Clone)]
pub struct HotStuffNode {
    ctx: HotStuffNodeContext,
}

impl HotStuffNode {
    /// Creates a new [`HotStuffNode`] from [`HotStuffConfig`].
    pub fn new(config: HotStuffConfig) -> Result<Self, crate::HotStuffError> {
        Ok(Self { ctx: HotStuffNodeContext::new(config)? })
    }

    /// Returns the shared [`HotStuffNodeContext`].
    pub const fn context(&self) -> &HotStuffNodeContext {
        &self.ctx
    }

    /// Spawns the `HotStuff` consensus driver against a launched [`FullNode`].
    pub fn spawn_driver<N>(
        &self,
        node: &FullNode<NodeAdapter<N>, <Self as Node<N>>::AddOns>,
    ) -> eyre::Result<()>
    where
        N: FullNodeTypes<Types = Self>,
    {
        self.ctx.spawn_driver(node)
    }

    /// Builds the [`ComponentsBuilder`] for [`HotStuffNode`].
    pub fn components<Node>(
        &self,
    ) -> ComponentsBuilder<
        Node,
        EthereumPoolBuilder,
        BasicPayloadServiceBuilder<HotStuffPayloadBuilderBuilder>,
        HotStuffNetworkBuilder,
        EthereumExecutorBuilder,
        HotStuffConsensusBuilder,
    >
    where
        Node: FullNodeTypes<
            Types: NodeTypes<ChainSpec: Hardforks + EthereumHardforks, Primitives = EthPrimitives>,
        >,
        <Node::Types as NodeTypes>::Payload:
            PayloadTypes<BuiltPayload = EthBuiltPayload, PayloadAttributes = EthPayloadAttributes>,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(EthereumPoolBuilder::default())
            .executor(EthereumExecutorBuilder::default())
            .payload(BasicPayloadServiceBuilder::new(HotStuffPayloadBuilderBuilder {
                seal_store: self.ctx.seal_store.clone(),
            }))
            .network(HotStuffNetworkBuilder { protocol_handler: self.ctx.protocol_handler.clone() })
            .consensus(HotStuffConsensusBuilder {
                epoch_manager: self.ctx.epoch_manager.clone(),
                qc_store: self.ctx.qc_store.clone(),
            })
    }
}

impl Default for HotStuffNode {
    fn default() -> Self {
        Self::new(HotStuffConfig::new(vec![Address::with_last_byte(1)]))
            .expect("default HotStuffConfig is valid")
    }
}

impl NodeTypes for HotStuffNode {
    type Primitives = EthPrimitives;
    type ChainSpec = ChainSpec;
    type Storage = EthStorage;
    type Payload = EthEngineTypes;
}

impl<N> Node<N> for HotStuffNode
where
    N: FullNodeTypes<Types = Self>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        BasicPayloadServiceBuilder<HotStuffPayloadBuilderBuilder>,
        HotStuffNetworkBuilder,
        EthereumExecutorBuilder,
        HotStuffConsensusBuilder,
    >;

    type AddOns =
        EthereumAddOns<NodeAdapter<N>, EthereumEthApiBuilder, EthereumEngineValidatorBuilder>;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        self.components()
    }

    fn add_ons(&self) -> Self::AddOns {
        EthereumAddOns::default()
    }
}

impl<N: FullNodeComponents<Types = Self>> DebugNode<N> for HotStuffNode {
    type RpcBlock = alloy_rpc_types_eth::Block;

    fn rpc_to_primitive_block(rpc_block: Self::RpcBlock) -> EthBlock {
        rpc_block.into_consensus().convert_transactions()
    }

    fn local_payload_attributes_builder(
        chain_spec: &Self::ChainSpec,
    ) -> impl PayloadAttributesBuilder<<Self::Payload as PayloadTypes>::PayloadAttributes> {
        LocalPayloadAttributesBuilder::new(Arc::new(chain_spec.clone()))
    }
}

/// Consensus builder constructing [`HotStuffConsensus`].
#[derive(Debug, Clone)]
pub struct HotStuffConsensusBuilder {
    epoch_manager: EpochManager,
    qc_store: QcStore,
}

impl<Node> ConsensusBuilder<Node> for HotStuffConsensusBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypes<ChainSpec: EthChainSpec + EthereumHardforks, Primitives = EthPrimitives>,
    >,
{
    type Consensus = Arc<HotStuffConsensus<<Node::Types as NodeTypes>::ChainSpec>>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(Arc::new(HotStuffConsensus::new(ctx.chain_spec(), self.epoch_manager, self.qc_store)))
    }
}

/// Payload builder constructing [`HotStuffPayloadBuilder`].
#[derive(Debug, Clone)]
pub struct HotStuffPayloadBuilderBuilder {
    seal_store: HotStuffSealStore,
}

impl<Types, Node, Pool, Evm> PayloadBuilderBuilder<Node, Pool, Evm>
    for HotStuffPayloadBuilderBuilder
where
    Types: NodeTypes<ChainSpec: EthereumHardforks, Primitives = EthPrimitives>,
    Node: FullNodeTypes<Types = Types>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
    Evm: ConfigureEvm<Primitives = PrimitivesTy<Types>, NextBlockEnvCtx = NextBlockEnvAttributes>
        + 'static,
    Types::Payload:
        PayloadTypes<BuiltPayload = EthBuiltPayload, PayloadAttributes = EthPayloadAttributes>,
{
    type PayloadBuilder = HotStuffPayloadBuilder<Pool, Node::Provider, Evm>;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        evm_config: Evm,
    ) -> eyre::Result<Self::PayloadBuilder> {
        let conf = ctx.payload_builder_config();
        let chain = ctx.chain_spec().chain();
        let gas_limit = conf.gas_limit_for(chain);
        let skip_state_root = ctx.config().tree_config().skip_state_root();

        Ok(HotStuffPayloadBuilder::new(
            ctx.provider().clone(),
            pool,
            evm_config,
            EthereumBuilderConfig::new()
                .with_gas_limit(gas_limit)
                .with_max_blobs_per_block(conf.max_blobs_per_block())
                .with_extra_data(conf.extra_data())
                .with_skip_state_root(skip_state_root),
            self.seal_store,
        ))
    }
}

/// Network builder registering the `hotstuff/1` `RLPx` subprotocol before starting the swarm.
#[derive(Debug, Clone)]
pub struct HotStuffNetworkBuilder {
    protocol_handler: HotStuffRlpxHandler,
}

impl<Node, Pool> NetworkBuilder<Node, Pool> for HotStuffNetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec: Hardforks>>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
{
    type Network =
        NetworkHandle<BasicNetworkPrimitives<PrimitivesTy<Node::Types>, PoolPooledTx<Pool>>>;

    async fn build_network(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<Self::Network> {
        let mut network = ctx.network_builder().await?;
        network.network_mut().add_rlpx_sub_protocol(self.protocol_handler.into_rlpx_sub_protocol());
        let handle = ctx.start_network(network, pool);
        info!(
            target: "consensus::hotstuff",
            enode = %handle.local_node_record(),
            "HotStuff P2P networking initialized with hotstuff/1 subprotocol"
        );
        Ok(handle)
    }
}
