//! Async `HotStuff` consensus driver bridging `RLPx` networking, WAL storage, and Reth's
//! execution engine.

use alloy_consensus::BlockHeader;
use alloy_eips::eip7685::Requests;
use alloy_primitives::{map::B256Map, Bytes, B256};
use alloy_rlp::{Decodable, Encodable};
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadSidecar, ForkchoiceState,
    PraguePayloadFields,
};
use reth_chainspec::{ChainSpec, EthereumHardforks};
use reth_engine_primitives::ConsensusEngineHandle;
use reth_ethereum_engine_primitives::{EthEngineTypes, EthPayloadAttributes};
use reth_ethereum_primitives::Block as EthBlock;
use reth_network_api::PeerId;
use reth_payload_builder::PayloadBuilderHandle;
use reth_payload_primitives::{BuiltPayload, PayloadKind};
use reth_primitives_traits::SealedBlock;
use reth_storage_api::{BlockNumReader, BlockReader, StateProviderFactory};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    future::Future,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::mpsc, time::Instant};
use tracing::{debug, error, info, warn};

use crate::{
    config::HotStuffConfig,
    consensus::QcStore,
    crypto::{new_view_digest, proposal_digest, verify_qc},
    error::HotStuffError,
    network::{HotStuffNetworkBridge, HotStuffPeerEvent, HotStuffWireMessage},
    payload::HotStuffSealStore,
    state_machine::{HotStuffAction, HotStuffCore},
    storage::{BlockQcRecord, HotStuffStore, MAX_PERSISTED_EPOCH_CERTS},
    types::{
        EpochChangeCert, HotStuffHeaderSeal, HotStuffNodeHeader, NewView, Proposal,
        QuorumCertificate, SyncBlocksRequest, SyncBlocksResponse, SyncStatus, SyncedBlock,
        TimeoutCertificate, MAX_SYNC_BATCH,
    },
    validator::{EpochManager, ValidatorSet},
};

const MAX_PROPOSAL_CACHE: usize = 128;
const MAX_PENDING_PARENTS: usize = 64;
const MAX_PENDING_CHILDREN_PER_PARENT: usize = 16;
const MAX_FUTURE_EPOCH_PROPOSALS: usize = 32;
const MAX_PERSISTED_QC_HASH_CACHE: usize = 512;
const SYNC_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Async consensus driver connecting [`HotStuffCore`], [`HotStuffNetworkBridge`],
/// [`HotStuffStore`], and Reth's internal Engine API ([`ConsensusEngineHandle`]).
#[derive(Debug)]
pub struct HotStuffDriver<Provider> {
    core: HotStuffCore,
    network: HotStuffNetworkBridge,
    peer_events: mpsc::Receiver<HotStuffPeerEvent>,
    engine: ConsensusEngineHandle<EthEngineTypes>,
    payload_builder: PayloadBuilderHandle<EthEngineTypes>,
    provider: Provider,
    chain_spec: Arc<ChainSpec>,
    epoch_manager: EpochManager,
    seal_store: HotStuffSealStore,
    qc_store: QcStore,
    store: HotStuffStore,
    config: HotStuffConfig,
    wal_halted: Arc<AtomicBool>,

    proposal_cache: B256Map<Proposal>,
    proposal_order: VecDeque<B256>,
    pending_proposals: B256Map<Vec<Proposal>>,
    pending_order: VecDeque<B256>,
    future_epoch_proposals: Vec<Proposal>,
    epoch_certs: BTreeMap<u64, EpochChangeCert>,
    pending_epoch_cert: Option<EpochChangeCert>,
    persisted_qc_hashes: HashSet<B256>,

    peer_statuses: HashMap<PeerId, SyncStatus>,
    sync_in_flight: Option<(PeerId, u64, Instant)>,

    pacemaker_deadline: Instant,
    scheduled_proposal: Option<ScheduledProposal>,
    proposed_in_current_view: Option<Proposal>,
    last_block_at: Instant,
}

#[derive(Debug, Clone)]
struct ScheduledProposal {
    epoch: u64,
    view: u64,
    justify_qc: QuorumCertificate,
    timeout_cert: Option<TimeoutCertificate>,
    is_nil: bool,
    fire_at: Instant,
}

impl<Provider> HotStuffDriver<Provider>
where
    Provider: BlockReader<Block = EthBlock, Header = alloy_consensus::Header>
        + BlockNumReader
        + StateProviderFactory
        + Clone
        + Send
        + Sync
        + 'static,
{
    /// Constructs a new [`HotStuffDriver`], recovering consensus WAL state and historical epoch
    /// validator sets from `storage_dir` if present, or bootstrapping from genesis block `0`.
    #[expect(clippy::too_many_arguments, reason = "constructor wires all consensus dependencies")]
    pub fn new(
        local_peer_id: PeerId,
        peer_events: mpsc::Receiver<HotStuffPeerEvent>,
        engine: ConsensusEngineHandle<EthEngineTypes>,
        payload_builder: PayloadBuilderHandle<EthEngineTypes>,
        provider: Provider,
        chain_spec: Arc<ChainSpec>,
        epoch_manager: EpochManager,
        seal_store: HotStuffSealStore,
        qc_store: QcStore,
        config: HotStuffConfig,
        storage_dir: PathBuf,
        wal_halted: Arc<AtomicBool>,
    ) -> Result<Self, HotStuffError> {
        config.validate()?;

        let store = HotStuffStore::open(storage_dir)?;
        let epoch_certs = store.load_epoch_certs()?;

        let genesis_header = provider
            .sealed_header(0)
            .map_err(|err| HotStuffError::StateProvider(err.to_string()))?
            .ok_or_else(|| HotStuffError::StateProvider("missing genesis header".to_string()))?;
        let genesis_hash = genesis_header.hash();

        let vs0 = epoch_manager
            .load_epoch_from_provider(&provider, 0, genesis_hash)
            .unwrap_or_else(|_| {
                epoch_manager.validator_set(0).expect("EpochManager always initializes epoch 0")
            });

        let core = if let Some(persisted) = store.load_state()? {
            for target_epoch in 1..=persisted.epoch {
                let boundary_num = target_epoch.saturating_mul(config.epoch_length);
                let boundary_hash = provider
                    .block_hash(boundary_num)
                    .map_err(|err| HotStuffError::StateProvider(err.to_string()))?
                    .or_else(|| {
                        epoch_certs.get(&(target_epoch - 1)).map(|c| c.boundary_block_hash)
                    });

                let loaded_from_provider = boundary_hash.and_then(|hash| {
                    epoch_manager.load_epoch_from_provider(&provider, target_epoch, hash).ok()
                });
                if loaded_from_provider.is_none() {
                    let Some(addrs) = persisted.epoch_validators.get(&target_epoch).cloned() else {
                        return Err(HotStuffError::Storage(format!(
                            "missing epoch boundary block {boundary_num} and cached validators while recovering epoch {target_epoch}"
                        )));
                    };
                    warn!(
                        target: "consensus::hotstuff",
                        target_epoch,
                        boundary_num,
                        "Execution DB lags behind HotStuff WAL; restoring cached epoch validators until sync backfills boundary block"
                    );
                    let vs = ValidatorSet::new(target_epoch, addrs)?;
                    epoch_manager.insert_epoch(vs);
                }
            }

            let vs_current = epoch_manager.validator_set(persisted.epoch).ok_or_else(|| {
                HotStuffError::InvalidValidatorSet(format!(
                    "missing validator set for recovered epoch {}",
                    persisted.epoch
                ))
            })?;

            for qc in &persisted.active_qcs {
                if qc.view > 0 {
                    qc_store.insert(qc.clone());
                }
            }
            if persisted.locked_qc.view > 0 {
                qc_store.insert(persisted.locked_qc.clone());
            }
            if persisted.high_qc.view > 0 {
                qc_store.insert(persisted.high_qc.clone());
            }

            let restored = HotStuffCore::from_snapshot(
                persisted,
                config.epoch_length,
                vs_current,
                config.signer.clone(),
            )?;
            info!(
                target: "consensus::hotstuff",
                epoch = restored.epoch(),
                view = restored.view(),
                committed_block = restored.committed_exec().1,
                "Recovered HotStuff consensus state from WAL"
            );
            restored
        } else {
            let fresh = HotStuffCore::new(
                0,
                config.epoch_length,
                vs0,
                config.signer.clone(),
                genesis_hash,
                0,
            );
            let mut snapshot = fresh.snapshot();
            snapshot.epoch_validators = epoch_manager.snapshot_validators();
            store.save_state(&snapshot)?;
            fresh
        };

        let network = HotStuffNetworkBridge::new(local_peer_id, config.signer.clone());
        let now = Instant::now();

        Ok(Self {
            core,
            network,
            peer_events,
            engine,
            payload_builder,
            provider,
            chain_spec,
            epoch_manager,
            seal_store,
            qc_store,
            store,
            wal_halted,
            pacemaker_deadline: now + config.view_timeout,
            config,
            proposal_cache: B256Map::default(),
            proposal_order: VecDeque::new(),
            pending_proposals: B256Map::default(),
            pending_order: VecDeque::new(),
            future_epoch_proposals: Vec::new(),
            epoch_certs,
            pending_epoch_cert: None,
            persisted_qc_hashes: HashSet::new(),
            peer_statuses: HashMap::new(),
            sync_in_flight: None,
            scheduled_proposal: None,
            proposed_in_current_view: None,
            last_block_at: now,
        })
    }

    /// Runs the `HotStuff` consensus event loop until `shutdown` completes.
    pub async fn run<F>(mut self, shutdown: F)
    where
        F: Future + Send,
    {
        let mut shutdown = std::pin::pin!(shutdown);

        self.send_initial_forkchoice().await;

        let start_actions = self.core.start();
        self.execute_actions(start_actions).await;

        let shutdown_guard = loop {
            let pacemaker_sleep = tokio::time::sleep_until(self.pacemaker_deadline);
            tokio::pin!(pacemaker_sleep);

            let proposal_deadline = self.scheduled_proposal.as_ref().map(|req| req.fire_at);
            let proposal_sleep = async {
                match proposal_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::pin!(proposal_sleep);

            tokio::select! {
                guard = &mut shutdown => {
                    info!(target: "consensus::hotstuff", "HotStuff consensus driver shutting down");
                    break guard;
                }
                event = self.peer_events.recv() => {
                    match event {
                        Some(ev) => self.handle_peer_event(ev).await,
                        None => {
                            info!(target: "consensus::hotstuff", "HotStuff RLPx event stream closed");
                            return;
                        }
                    }
                }
                _ = &mut pacemaker_sleep => {
                    if self.is_local_db_behind_wal() {
                        self.pacemaker_deadline = Instant::now() + self.config.view_timeout;
                        self.maybe_retry_sync_from_any_peer();
                    } else {
                        debug!(
                            target: "consensus::hotstuff",
                            epoch = self.core.epoch(),
                            view = self.core.view(),
                            "Pacemaker view timeout fired"
                        );
                        let actions = self.core.on_local_timeout();
                        if self.persist_wal().is_ok() {
                            self.execute_actions(actions).await;
                            if let Some(tc) = self.core.timeout_cert_for_view(self.core.view()) &&
                                let Some(signer) = &self.config.signer
                            {
                                let epoch = self.core.epoch();
                                let view = self.core.view();
                                let high_qc = self.core.high_qc().clone();
                                let sig =
                                    signer.sign_digest(new_view_digest(epoch, view, high_qc.hash()));
                                let nv = NewView {
                                    epoch,
                                    new_view: view,
                                    high_qc,
                                    sender: signer.address(),
                                    signature: sig,
                                    timeout_cert: Some(tc),
                                };
                                self.network
                                    .broadcast(&HotStuffWireMessage::NewView(Box::new(nv)));
                            }
                            self.maybe_retry_sync_from_any_peer();
                        }
                    }
                }
                _ = &mut proposal_sleep => {
                    if let Some(req) = self.scheduled_proposal.take() &&
                        req.epoch == self.core.epoch() &&
                        req.view == self.core.view()
                    {
                        self.build_and_propose(req).await;
                    }
                }
            }

            if self.is_wal_halted() {
                error!(
                    target: "consensus::hotstuff",
                    "Stopping HotStuff consensus driver after fatal WAL persistence error"
                );
                return;
            }
        };

        let _ = self.persist_wal();
        // Drop driver (and its provider reference) before releasing the shutdown guard so
        // restartable nodes release the MDBX/RocksDB handles immediately.
        drop(self);
        drop(shutdown_guard);
    }

    async fn send_initial_forkchoice(&self) {
        let genesis_hash = self
            .provider
            .sealed_header(0)
            .ok()
            .flatten()
            .map(|h| h.hash())
            .unwrap_or_else(|| self.core.committed_exec().0);

        let finalized_candidate = self.core.committed_exec().0;
        let finalized_block_hash = if self.has_local_header(finalized_candidate) {
            finalized_candidate
        } else {
            let best_num = self.local_execution_tip().min(self.core.committed_exec().1);
            if best_num > 0 {
                self.provider.block_hash(best_num).ok().flatten().unwrap_or(genesis_hash)
            } else {
                genesis_hash
            }
        };

        let safe_candidate = self.core.locked_qc().exec_block_hash;
        let safe_block_hash = if self.has_local_header(safe_candidate) {
            safe_candidate
        } else {
            finalized_block_hash
        };

        let head_candidate = self.core.high_qc().exec_block_hash;
        let head_block_hash =
            if self.has_local_header(head_candidate) { head_candidate } else { safe_block_hash };

        let state = ForkchoiceState { head_block_hash, safe_block_hash, finalized_block_hash };
        if let Err(err) = self.engine.fork_choice_updated(state, None).await {
            warn!(target: "consensus::hotstuff", %err, ?state, "Initial forkchoice update failed");
        }
    }

    fn has_local_header(&self, hash: B256) -> bool {
        !hash.is_zero() && self.provider.sealed_header_by_hash(hash).ok().flatten().is_some()
    }

    fn local_execution_tip(&self) -> u64 {
        self.provider.best_block_number().unwrap_or(0)
    }

    fn is_local_db_behind_wal(&self) -> bool {
        let (_, committed_num) = self.core.committed_exec();
        let high_qc = self.core.high_qc();
        (committed_num > 0 && !self.has_local_header(self.core.committed_exec().0)) ||
            (high_qc.exec_block_number > 0 && !self.has_local_header(high_qc.exec_block_hash))
    }

    fn effective_sync_status(&self) -> SyncStatus {
        let (committed_hash, committed_num) = self.core.committed_exec();
        if committed_num == 0 || self.has_local_header(committed_hash) {
            return self.core.sync_status();
        }
        let db_tip = self.local_execution_tip().min(committed_num);
        let db_hash = self.provider.block_hash(db_tip).ok().flatten().unwrap_or_default();
        let db_epoch = if db_tip == 0 { 0 } else { self.epoch_manager.epoch_for_block(db_tip) };
        SyncStatus { epoch: db_epoch, view: 0, finalized_number: db_tip, finalized_hash: db_hash }
    }

    fn is_wal_halted(&self) -> bool {
        self.wal_halted.load(Ordering::Acquire)
    }

    fn persist_wal(&self) -> Result<(), HotStuffError> {
        let mut snapshot = self.core.snapshot();
        let mut validators = self.epoch_manager.snapshot_validators();
        if validators.len() > MAX_PERSISTED_EPOCH_CERTS {
            let current_epoch = self.core.epoch();
            let mut bounded: BTreeMap<u64, _> = validators
                .iter()
                .rev()
                .take(MAX_PERSISTED_EPOCH_CERTS)
                .map(|(&k, v)| (k, v.clone()))
                .collect();
            if let Some(v0) = validators.remove(&0) {
                bounded.insert(0, v0);
            }
            if let Some(vc) = validators.remove(&current_epoch) {
                bounded.insert(current_epoch, vc);
            }
            validators = bounded;
        }
        snapshot.epoch_validators = validators;

        if let Err(err) = self.store.save_state(&snapshot) {
            error!(
                target: "consensus::hotstuff",
                %err,
                "Fatal HotStuff WAL persistence failure; halting consensus driver to prevent equivocation"
            );
            self.wal_halted.store(true, Ordering::Release);
            return Err(err);
        }
        Ok(())
    }

    async fn handle_peer_event(&mut self, event: HotStuffPeerEvent) {
        match event {
            HotStuffPeerEvent::Connected { peer_id, outbound } => {
                self.network.on_peer_connected(peer_id, outbound);
                self.send_sync_hints_to_peer(peer_id);
            }
            HotStuffPeerEvent::Disconnected { peer_id } => {
                self.network.on_peer_disconnected(peer_id);
                self.peer_statuses.remove(&peer_id);
                if self.sync_in_flight.is_some_and(|(pid, _, _)| pid == peer_id) {
                    self.sync_in_flight = None;
                }
            }
            HotStuffPeerEvent::Message { peer_id, message } => {
                self.handle_wire_message(peer_id, message).await;
            }
        }
    }

    fn send_sync_hints_to_peer(&self, peer_id: PeerId) {
        self.network
            .send_to_peer(peer_id, &HotStuffWireMessage::Status(self.effective_sync_status()));

        if let Some(signer) = &self.config.signer {
            let epoch = self.core.epoch();
            let view = self.core.view();
            let high_qc = self.core.high_qc().clone();
            let sig = signer.sign_digest(new_view_digest(epoch, view, high_qc.hash()));
            let nv = NewView {
                epoch,
                new_view: view,
                high_qc,
                sender: signer.address(),
                signature: sig,
                timeout_cert: self.core.timeout_cert_for_view(view),
            };
            self.network.send_to_peer(peer_id, &HotStuffWireMessage::NewView(Box::new(nv)));
        }
        if let Some((&_epoch, cert)) = self.epoch_certs.iter().next_back() {
            self.network
                .send_to_peer(peer_id, &HotStuffWireMessage::EpochChange(Box::new(cert.clone())));
        }
        if let Some(proposal) = &self.proposed_in_current_view &&
            proposal.header.epoch == self.core.epoch() &&
            proposal.header.view == self.core.view()
        {
            self.network
                .send_to_peer(peer_id, &HotStuffWireMessage::Proposal(Box::new(proposal.clone())));
        }
    }

    async fn handle_wire_message(&mut self, peer_id: PeerId, message: HotStuffWireMessage) {
        match message {
            HotStuffWireMessage::Hello(hello) => {
                if let Err(err) = self.network.on_peer_hello(peer_id, hello) {
                    warn!(target: "consensus::hotstuff", %peer_id, %err, "Invalid PeerHello");
                }
            }
            HotStuffWireMessage::Proposal(proposal) |
            HotStuffWireMessage::BlockResponse(proposal) => {
                self.handle_peer_proposal(Some(peer_id), *proposal).await;
            }
            HotStuffWireMessage::Vote(vote) => match self.core.on_vote(vote) {
                Ok(actions) => {
                    if self.persist_wal().is_err() {
                        return;
                    }
                    self.execute_actions(actions).await;
                }
                Err(err) => {
                    debug!(target: "consensus::hotstuff", %peer_id, %err, "Rejected vote");
                }
            },
            HotStuffWireMessage::Timeout(msg) => match self.core.on_timeout(*msg) {
                Ok(actions) => {
                    if self.persist_wal().is_err() {
                        return;
                    }
                    self.execute_actions(actions).await;
                }
                Err(err) => {
                    debug!(target: "consensus::hotstuff", %peer_id, %err, "Rejected timeout");
                }
            },
            HotStuffWireMessage::NewView(msg) => match self.core.on_new_view(*msg) {
                Ok(actions) => {
                    if self.persist_wal().is_err() {
                        return;
                    }
                    self.execute_actions(actions).await;
                }
                Err(err) => {
                    debug!(target: "consensus::hotstuff", %peer_id, %err, "Rejected NewView");
                }
            },
            HotStuffWireMessage::BlockRequest(node_hash) => {
                if let Some(proposal) = self.proposal_cache.get(&node_hash) {
                    self.network.send_to_peer(
                        peer_id,
                        &HotStuffWireMessage::BlockResponse(Box::new(proposal.clone())),
                    );
                }
            }
            HotStuffWireMessage::EpochChange(cert) => {
                self.handle_epoch_change_cert(Some(peer_id), *cert).await;
            }
            HotStuffWireMessage::Status(status) => {
                self.handle_peer_status(peer_id, status);
            }
            HotStuffWireMessage::SyncBlocksRequest(req) => {
                self.handle_sync_blocks_request(peer_id, req);
            }
            HotStuffWireMessage::SyncBlocksResponse(resp) => {
                self.handle_sync_blocks_response(peer_id, *resp).await;
            }
        }
    }

    fn is_behind_status(&self, status: &SyncStatus) -> bool {
        let local_high_missing = !self.has_local_header(self.core.high_qc().exec_block_hash);
        (self.is_local_db_behind_wal() && status.finalized_number > self.local_execution_tip()) ||
            status.epoch > self.core.epoch() ||
            status.finalized_number > self.core.committed_exec().1 ||
            (local_high_missing && status.finalized_number >= self.core.committed_exec().1)
    }

    fn next_sync_block_number(&self) -> u64 {
        if self.is_local_db_behind_wal() {
            return self
                .local_execution_tip()
                .min(self.core.high_qc().exec_block_number.max(self.core.committed_exec().1))
                .saturating_add(1);
        }
        let high_qc = self.core.high_qc();
        let local_tip = if self.has_local_header(high_qc.exec_block_hash) {
            high_qc.exec_block_number
        } else {
            self.core.committed_exec().1
        };
        let boundary = self.core.epoch_boundary_block();
        if local_tip >= boundary {
            boundary
        } else {
            local_tip.saturating_add(1)
        }
    }

    fn handle_peer_status(&mut self, peer_id: PeerId, status: SyncStatus) {
        self.peer_statuses.insert(peer_id, status.clone());
        if self.is_behind_status(&status) {
            self.maybe_request_sync(peer_id);
        }
    }

    fn maybe_retry_sync_from_any_peer(&mut self) {
        let best_peer = self
            .peer_statuses
            .iter()
            .filter(|(_, status)| self.is_behind_status(status))
            .max_by_key(|(_, status)| (status.epoch, status.finalized_number, status.view))
            .map(|(&pid, _)| pid);
        if let Some(peer_id) = best_peer {
            self.maybe_request_sync(peer_id);
        }
    }

    fn maybe_request_sync(&mut self, peer_id: PeerId) {
        if let Some((_, _, started_at)) = self.sync_in_flight &&
            started_at.elapsed() < SYNC_REQUEST_TIMEOUT
        {
            return;
        }
        let from_block = self.next_sync_block_number();
        self.sync_in_flight = Some((peer_id, from_block, Instant::now()));
        debug!(
            target: "consensus::hotstuff",
            %peer_id,
            epoch = self.core.epoch(),
            from_block,
            "Requesting HotStuff sync batch from peer"
        );
        self.network.send_to_peer(
            peer_id,
            &HotStuffWireMessage::SyncBlocksRequest(SyncBlocksRequest {
                from_block,
                max_blocks: MAX_SYNC_BATCH as u64,
            }),
        );
    }

    fn handle_sync_blocks_request(&self, peer_id: PeerId, req: SyncBlocksRequest) {
        if req.from_block == 0 {
            return;
        }
        let count = (req.max_blocks as usize).clamp(1, MAX_SYNC_BATCH);
        let req_epoch = self.epoch_manager.epoch_for_block(req.from_block);
        let epoch_end = self.epoch_manager.epoch_boundary_block(req_epoch);
        let max_local = self
            .core
            .high_qc()
            .exec_block_number
            .max(self.core.committed_exec().1)
            .min(self.local_execution_tip());

        let mut records = match self.store.load_epoch_block_qcs(req_epoch) {
            Ok(map) => map,
            Err(err) => {
                warn!(target: "consensus::hotstuff", %err, req_epoch, "Failed loading persisted QCs for sync");
                return;
            }
        };

        // Include the current high_qc in case it has not been flushed to the epoch JSONL yet.
        let high_qc = self.core.high_qc();
        if req_epoch == self.core.epoch() &&
            high_qc.view > 0 &&
            let Some(header) = self.core.node(&high_qc.node_hash) &&
            !header.is_nil
        {
            records
                .entry(header.exec_block_number)
                .or_insert_with(|| BlockQcRecord { header: header.clone(), qc: high_qc.clone() });
        }

        let end_block = req
            .from_block
            .saturating_add(count as u64)
            .saturating_sub(1)
            .min(epoch_end)
            .min(max_local);

        let mut blocks = Vec::new();
        let mut last_included = req.from_block.saturating_sub(1);
        for num in req.from_block..=end_block {
            let Some(record) = records.get(&num) else {
                break;
            };
            let Ok(Some(block)) = self.provider.block_by_number(num) else {
                break;
            };
            let mut block_rlp = Vec::new();
            block.encode(&mut block_rlp);
            blocks.push(SyncedBlock {
                block_rlp: Bytes::from(block_rlp),
                requests: Vec::new(),
                header: record.header.clone(),
                qc: record.qc.clone(),
            });
            last_included = num;
        }

        let epoch_cert =
            if last_included == epoch_end || (blocks.is_empty() && req.from_block == epoch_end) {
                self.epoch_certs.get(&req_epoch).cloned()
            } else {
                None
            };

        self.network.send_to_peer(
            peer_id,
            &HotStuffWireMessage::SyncBlocksResponse(Box::new(SyncBlocksResponse {
                blocks,
                epoch_cert,
            })),
        );
    }

    async fn handle_sync_blocks_response(&mut self, peer_id: PeerId, resp: SyncBlocksResponse) {
        if self.sync_in_flight.is_some_and(|(pid, _, _)| pid == peer_id) {
            self.sync_in_flight = None;
        }

        let mut progressed = false;
        for synced in resp.blocks {
            if synced.header.epoch > self.core.epoch() {
                break;
            }
            if let Err(err) = self.apply_one_synced_block(synced).await {
                warn!(target: "consensus::hotstuff", %peer_id, %err, "Failed applying synced block");
                break;
            }
            if self.is_wal_halted() {
                return;
            }
            progressed = true;
        }

        if let Some(cert) = resp.epoch_cert {
            self.handle_epoch_change_cert(Some(peer_id), cert).await;
            if self.is_wal_halted() {
                return;
            }
            progressed = true;
        }

        if progressed {
            if self.persist_wal().is_err() {
                return;
            }
            let still_behind = self
                .peer_statuses
                .get(&peer_id)
                .is_some_and(|status| self.is_behind_status(status));
            if still_behind {
                self.maybe_request_sync(peer_id);
            }
        }
    }

    async fn apply_one_synced_block(&mut self, synced: SyncedBlock) -> Result<(), HotStuffError> {
        let block = EthBlock::decode(&mut synced.block_rlp.as_ref())
            .map_err(|err| HotStuffError::RlpDecode(err.to_string()))?;
        let sealed = SealedBlock::seal_slow(block);
        let block_hash = sealed.hash();
        let block_num = sealed.number();

        if block_hash != synced.header.exec_block_hash ||
            block_num != synced.header.exec_block_number
        {
            return Err(HotStuffError::InvalidBlockHash(format!(
                "synced block ({block_hash}, #{block_num}) mismatches header ({}, #{})",
                synced.header.exec_block_hash, synced.header.exec_block_number
            )));
        }

        let vs = self.epoch_manager.validator_set(synced.header.epoch).ok_or_else(|| {
            HotStuffError::InvalidValidatorSet(format!(
                "missing validator set for synced epoch {}",
                synced.header.epoch
            ))
        })?;
        verify_qc(&synced.qc, &vs)?;

        if !self.has_local_header(block_hash) {
            let exec_data = self.block_to_execution_data(sealed, &synced.requests);
            let status = self
                .engine
                .new_payload(exec_data)
                .await
                .map_err(|err| HotStuffError::Engine(err.to_string()))?;
            if !status.is_valid() {
                return Err(HotStuffError::Engine(format!(
                    "engine rejected synced block: {status:?}"
                )));
            }
        }

        self.qc_store.insert(synced.qc.clone());
        self.persist_block_qc_record(&synced.header, &synced.qc);

        // Historical epoch backfill: advance the local execution DB canonically without mutating
        // newer-epoch safety state in HotStuffCore.
        if synced.header.epoch < self.core.epoch() {
            let state = ForkchoiceState {
                head_block_hash: block_hash,
                safe_block_hash: block_hash,
                finalized_block_hash: block_hash,
            };
            self.engine
                .fork_choice_updated(state, None)
                .await
                .map_err(|err| HotStuffError::Engine(err.to_string()))?;

            if block_num == self.epoch_manager.epoch_boundary_block(synced.header.epoch) {
                let next_epoch = synced.header.epoch + 1;
                let refreshed = self.epoch_manager.load_epoch_from_provider(
                    &self.provider,
                    next_epoch,
                    block_hash,
                )?;
                debug!(
                    target: "consensus::hotstuff",
                    next_epoch,
                    boundary_block_number = block_num,
                    validators = ?refreshed.validators(),
                    "Verified next-epoch validators from backfilled boundary state"
                );
            }
            return Ok(());
        }

        let actions = self.core.apply_synced_block(synced.header, synced.qc)?;
        if self.persist_wal().is_err() {
            return Ok(());
        }
        let emitted_fcu =
            actions.iter().any(|action| matches!(action, HotStuffAction::UpdateForkchoice { .. }));
        self.execute_actions(actions).await;

        if !emitted_fcu && block_num <= self.core.committed_exec().1 {
            let state = ForkchoiceState {
                head_block_hash: block_hash,
                safe_block_hash: block_hash,
                finalized_block_hash: block_hash,
            };
            self.engine
                .fork_choice_updated(state, None)
                .await
                .map_err(|err| HotStuffError::Engine(err.to_string()))?;
        } else if !emitted_fcu && block_num <= self.core.high_qc().exec_block_number {
            let finalized_candidate = self.core.committed_exec().0;
            let finalized_block_hash = if self.has_local_header(finalized_candidate) {
                finalized_candidate
            } else {
                block_hash
            };
            let safe_candidate = self.core.locked_qc().exec_block_hash;
            let safe_block_hash = if self.has_local_header(safe_candidate) {
                safe_candidate
            } else {
                finalized_block_hash
            };
            let state = ForkchoiceState {
                head_block_hash: block_hash,
                safe_block_hash,
                finalized_block_hash,
            };
            self.engine
                .fork_choice_updated(state, None)
                .await
                .map_err(|err| HotStuffError::Engine(err.to_string()))?;
        }

        self.try_apply_pending_epoch_cert().await;
        Ok(())
    }

    async fn handle_peer_proposal(&mut self, from_peer: Option<PeerId>, proposal: Proposal) {
        if self.is_local_db_behind_wal() {
            if let Some(pid) = from_peer {
                self.maybe_request_sync(pid);
            } else {
                self.maybe_retry_sync_from_any_peer();
            }
            return;
        }
        let current_epoch = self.core.epoch();
        if proposal.header.epoch < current_epoch {
            return;
        }
        if proposal.header.epoch > current_epoch {
            if self.future_epoch_proposals.len() < MAX_FUTURE_EPOCH_PROPOSALS {
                self.future_epoch_proposals.push(proposal);
            }
            if let Some(pid) = from_peer {
                self.maybe_request_sync(pid);
            }
            return;
        }

        let node_hash = proposal.header.node_hash();
        if self.core.has_node(&node_hash) {
            return;
        }

        if !self.core.has_node(&proposal.header.parent_node_hash) {
            let parent_hash = proposal.header.parent_node_hash;
            let parent_gap = proposal
                .header
                .exec_block_number
                .saturating_sub(self.core.high_qc().exec_block_number);
            if parent_gap > 2 &&
                let Some(pid) = from_peer
            {
                self.maybe_request_sync(pid);
                return;
            }
            self.buffer_pending_proposal(parent_hash, proposal);
            let req = HotStuffWireMessage::BlockRequest(parent_hash);
            if let Some(pid) = from_peer {
                self.network.send_to_peer(pid, &req);
            } else {
                self.network.broadcast(&req);
            }
            return;
        }

        if !proposal.header.is_nil &&
            let Err(err) = self.validate_and_insert_execution_block(&proposal).await
        {
            warn!(
                target: "consensus::hotstuff",
                epoch = proposal.header.epoch,
                view = proposal.header.view,
                %err,
                "Execution engine rejected proposed block"
            );
            return;
        }

        self.cache_proposal(node_hash, proposal.clone());

        match self.core.on_proposal(&proposal) {
            Ok(actions) => {
                if self.persist_wal().is_err() {
                    return;
                }
                self.execute_actions(actions).await;
                self.try_apply_pending_epoch_cert().await;
                if let Some(children) = self.pending_proposals.remove(&node_hash) {
                    for child in children {
                        Box::pin(self.handle_peer_proposal(None, child)).await;
                    }
                }
            }
            Err(err) => {
                warn!(
                    target: "consensus::hotstuff",
                    epoch = proposal.header.epoch,
                    view = proposal.header.view,
                    %err,
                    "HotStuff rejected proposal"
                );
            }
        }
    }

    async fn validate_and_insert_execution_block(
        &self,
        proposal: &Proposal,
    ) -> Result<(), HotStuffError> {
        let block = EthBlock::decode(&mut proposal.block_rlp.as_ref())
            .map_err(|err| HotStuffError::RlpDecode(err.to_string()))?;
        let sealed = SealedBlock::seal_slow(block);

        if sealed.hash() != proposal.header.exec_block_hash ||
            sealed.number() != proposal.header.exec_block_number
        {
            return Err(HotStuffError::InvalidBlockHash(format!(
                "proposal block ({}, #{}) mismatches decoded ({}, #{})",
                proposal.header.exec_block_hash,
                proposal.header.exec_block_number,
                sealed.hash(),
                sealed.number()
            )));
        }

        self.qc_store.insert(proposal.justify_qc.clone());
        let exec_data = self.block_to_execution_data(sealed, &proposal.requests);
        let status = self
            .engine
            .new_payload(exec_data)
            .await
            .map_err(|err| HotStuffError::Engine(err.to_string()))?;

        if !status.is_valid() {
            return Err(HotStuffError::Engine(format!(
                "engine returned non-valid status: {status:?}"
            )));
        }

        Ok(())
    }

    fn block_to_execution_data(
        &self,
        sealed: SealedBlock<EthBlock>,
        requests: &[Bytes],
    ) -> ExecutionData {
        let block_hash = sealed.hash();
        let block = sealed.into_block();
        let timestamp = block.header.timestamp;
        let (payload, _) =
            ExecutionPayload::from_block_unchecked_with_extras(block_hash, &block, None);

        let sidecar = if self.chain_spec.is_cancun_active_at_timestamp(timestamp) {
            let cancun = CancunPayloadFields {
                parent_beacon_block_root: block.header.parent_beacon_block_root.unwrap_or_default(),
                versioned_hashes: block.body.blob_versioned_hashes_iter().copied().collect(),
            };
            if self.chain_spec.is_prague_active_at_timestamp(timestamp) {
                ExecutionPayloadSidecar::v4(
                    cancun,
                    PraguePayloadFields::new(Requests::new(requests.to_vec())),
                )
            } else {
                ExecutionPayloadSidecar::v3(cancun)
            }
        } else {
            ExecutionPayloadSidecar::none()
        };

        ExecutionData::new(payload, sidecar)
    }

    async fn build_and_propose(&mut self, req: ScheduledProposal) {
        if self.is_local_db_behind_wal() {
            self.maybe_retry_sync_from_any_peer();
            return;
        }
        let Some(signer) = self.config.signer.clone() else {
            return;
        };

        let proposal = if req.is_nil {
            let header = HotStuffNodeHeader {
                epoch: req.epoch,
                view: req.view,
                parent_node_hash: req.justify_qc.node_hash,
                justify_qc_hash: req.justify_qc.hash(),
                exec_block_hash: req.justify_qc.exec_block_hash,
                exec_block_number: req.justify_qc.exec_block_number,
                proposer: signer.address(),
                is_nil: true,
            };
            let signature = signer.sign_digest(proposal_digest(header.node_hash()));
            Proposal {
                header,
                justify_qc: req.justify_qc,
                block_rlp: Bytes::new(),
                requests: Vec::new(),
                signature,
                timeout_cert: req.timeout_cert,
            }
        } else {
            match self.build_execution_proposal(&signer, &req).await {
                Ok(prop) => prop,
                Err(err) => {
                    error!(
                        target: "consensus::hotstuff",
                        epoch = req.epoch,
                        view = req.view,
                        %err,
                        "Failed to build HotStuff execution proposal"
                    );
                    return;
                }
            }
        };

        let node_hash = proposal.header.node_hash();
        self.core.mark_proposed(req.view);
        self.proposed_in_current_view = Some(proposal.clone());
        self.cache_proposal(node_hash, proposal.clone());

        if self.persist_wal().is_err() {
            return;
        }
        self.network.broadcast(&HotStuffWireMessage::Proposal(Box::new(proposal.clone())));
        match self.core.on_proposal(&proposal) {
            Ok(actions) => {
                if self.persist_wal().is_err() {
                    return;
                }
                self.execute_actions(actions).await;
            }
            Err(err) => {
                error!(target: "consensus::hotstuff", %err, "Locally built proposal rejected by HotStuffCore");
            }
        }
    }

    async fn build_execution_proposal(
        &self,
        signer: &crate::ValidatorSigner,
        req: &ScheduledProposal,
    ) -> Result<Proposal, HotStuffError> {
        let parent_exec_hash = req.justify_qc.exec_block_hash;
        let parent_header = self
            .provider
            .sealed_header_by_hash(parent_exec_hash)
            .map_err(|err| HotStuffError::StateProvider(err.to_string()))?
            .ok_or_else(|| {
                HotStuffError::StateProvider(format!("missing parent block {parent_exec_hash}"))
            })?;

        let now_secs =
            SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let timestamp = now_secs.max(parent_header.timestamp().saturating_add(1));

        let vs = self.epoch_manager.validator_set(req.epoch).ok_or_else(|| {
            HotStuffError::InvalidValidatorSet(format!(
                "missing validator set for epoch {}",
                req.epoch
            ))
        })?;
        let seal = HotStuffHeaderSeal {
            epoch: req.epoch,
            view: req.view,
            justify_view: req.justify_qc.view,
            validator_set_hash_prefix: vs.hash_prefix(),
        };
        let prev_randao = req.justify_qc.hash();

        self.seal_store.insert(parent_header.hash(), prev_randao, seal.encode());
        self.qc_store.insert(req.justify_qc.clone());

        let attrs = EthPayloadAttributes {
            timestamp,
            prev_randao,
            suggested_fee_recipient: signer.address(),
            withdrawals: self
                .chain_spec
                .is_shanghai_active_at_timestamp(timestamp)
                .then(Default::default),
            parent_beacon_block_root: self
                .chain_spec
                .is_cancun_active_at_timestamp(timestamp)
                .then_some(req.justify_qc.node_hash),
            slot_number: self
                .chain_spec
                .is_amsterdam_active_at_timestamp(timestamp)
                .then_some(req.view),
            ..Default::default()
        };

        let fcu_state = ForkchoiceState {
            head_block_hash: parent_header.hash(),
            safe_block_hash: self.core.locked_qc().exec_block_hash,
            finalized_block_hash: self.core.committed_exec().0,
        };
        let fcu_res = self
            .engine
            .fork_choice_updated(fcu_state, Some(attrs))
            .await
            .map_err(|err| HotStuffError::Engine(err.to_string()))?;

        if !fcu_res.is_valid() {
            return Err(HotStuffError::Engine(format!(
                "FCU invalid while starting payload build: {fcu_res:?}"
            )));
        }
        let payload_id = fcu_res
            .payload_id
            .ok_or_else(|| HotStuffError::PayloadBuild("FCU returned no payload_id".to_string()))?;

        if !self.config.payload_wait_time.is_zero() {
            tokio::time::sleep(self.config.payload_wait_time).await;
        }

        let payload = self
            .payload_builder
            .resolve_kind(payload_id, PayloadKind::WaitForPending)
            .await
            .ok_or_else(|| HotStuffError::PayloadBuild("payload job dropped".to_string()))?
            .map_err(|err| HotStuffError::PayloadBuild(err.to_string()))?;

        let sealed = payload.block().clone();
        let exec_block_hash = sealed.hash();
        let exec_block_number = sealed.number();
        let requests = payload.requests().map(|r| r.iter().cloned().collect()).unwrap_or_default();

        let mut block_rlp = Vec::new();
        sealed.clone_block().encode(&mut block_rlp);

        let status = self
            .engine
            .new_payload(payload.into())
            .await
            .map_err(|err| HotStuffError::Engine(err.to_string()))?;
        if !status.is_valid() {
            return Err(HotStuffError::Engine(format!(
                "newly built payload failed validation: {status:?}"
            )));
        }

        let header = HotStuffNodeHeader {
            epoch: req.epoch,
            view: req.view,
            parent_node_hash: req.justify_qc.node_hash,
            justify_qc_hash: prev_randao,
            exec_block_hash,
            exec_block_number,
            proposer: signer.address(),
            is_nil: false,
        };
        let signature = signer.sign_digest(proposal_digest(header.node_hash()));

        Ok(Proposal {
            header,
            justify_qc: req.justify_qc.clone(),
            block_rlp: Bytes::from(block_rlp),
            requests,
            signature,
            timeout_cert: req.timeout_cert.clone(),
        })
    }

    fn persist_block_qc_record(&mut self, header: &HotStuffNodeHeader, qc: &QuorumCertificate) {
        if header.is_nil || qc.view == 0 {
            return;
        }
        let qc_hash = qc.hash();
        if self.persisted_qc_hashes.contains(&qc_hash) {
            return;
        }
        if let Err(err) =
            self.store.append_block_qc(&BlockQcRecord { header: header.clone(), qc: qc.clone() })
        {
            warn!(target: "consensus::hotstuff", %err, "Failed persisting block QC record");
            return;
        }
        if self.persisted_qc_hashes.len() >= MAX_PERSISTED_QC_HASH_CACHE {
            self.persisted_qc_hashes.clear();
        }
        self.persisted_qc_hashes.insert(qc_hash);
    }

    async fn execute_actions(&mut self, actions: Vec<HotStuffAction>) {
        if self.is_wal_halted() {
            return;
        }
        for action in actions {
            if self.is_wal_halted() {
                return;
            }
            match action {
                HotStuffAction::NeedBuildProposal {
                    epoch,
                    view,
                    justify_qc,
                    timeout_cert,
                    is_nil,
                } => {
                    let fire_at = if is_nil {
                        Instant::now()
                    } else {
                        let target = self.last_block_at + self.config.block_time;
                        let now = Instant::now();
                        if target > now {
                            target
                        } else {
                            now
                        }
                    };
                    self.scheduled_proposal = Some(ScheduledProposal {
                        epoch,
                        view,
                        justify_qc,
                        timeout_cert,
                        is_nil,
                        fire_at,
                    });
                }
                HotStuffAction::SendVote { leader: _, vote } => {
                    // Broadcast votes so any honest validator can form a QC even if the
                    // next-view leader is offline.
                    self.network.broadcast(&HotStuffWireMessage::Vote(vote.clone()));
                    if self.core.local_address().is_some() {
                        match self.core.on_vote(vote) {
                            Ok(follow_up) => {
                                if self.persist_wal().is_err() {
                                    return;
                                }
                                Box::pin(self.execute_actions(follow_up)).await;
                            }
                            Err(err) => {
                                warn!(target: "consensus::hotstuff", %err, "Failed to process local vote");
                            }
                        }
                    }
                }
                HotStuffAction::BroadcastTimeout(msg) => {
                    self.network.broadcast(&HotStuffWireMessage::Timeout(Box::new(msg)));
                }
                HotStuffAction::SendNewView { leader: _, new_view } => {
                    self.network.broadcast(&HotStuffWireMessage::NewView(Box::new(new_view)));
                }
                HotStuffAction::UpdateForkchoice {
                    head_block_hash,
                    safe_block_hash,
                    finalized_block_hash,
                } => {
                    let state =
                        ForkchoiceState { head_block_hash, safe_block_hash, finalized_block_hash };
                    if let Err(err) = self.engine.fork_choice_updated(state, None).await {
                        warn!(target: "consensus::hotstuff", %err, ?state, "Forkchoice update failed");
                    }
                }
                HotStuffAction::StoreQc(qc) => {
                    if let Some(header) = self.core.node(&qc.node_hash).cloned() {
                        self.persist_block_qc_record(&header, &qc);
                    }
                    self.qc_store.insert(qc);
                }
                HotStuffAction::BlockCommitted {
                    epoch,
                    view,
                    node_hash,
                    exec_block_hash,
                    exec_block_number,
                } => {
                    self.last_block_at = Instant::now();
                    info!(
                        target: "consensus::hotstuff",
                        epoch,
                        view,
                        %node_hash,
                        %exec_block_hash,
                        exec_block_number,
                        "Finalized block via 3-chain HotStuff commit"
                    );
                }
                HotStuffAction::EpochBoundaryFinalized { next_epoch, cert } => {
                    self.handle_epoch_transition(next_epoch, *cert).await;
                }
                HotStuffAction::ResetPacemaker { view, timeout_exponent } => {
                    let mult = 1u32.checked_shl(timeout_exponent).unwrap_or(16);
                    let dur = self
                        .config
                        .view_timeout
                        .saturating_mul(mult)
                        .min(self.config.max_view_timeout);
                    self.pacemaker_deadline = Instant::now() + dur;
                    if self
                        .scheduled_proposal
                        .as_ref()
                        .is_some_and(|p| p.view < view || p.epoch != self.core.epoch())
                    {
                        self.scheduled_proposal = None;
                    }
                    if self.proposed_in_current_view.as_ref().is_some_and(|p| {
                        p.header.view < view || p.header.epoch != self.core.epoch()
                    }) {
                        self.proposed_in_current_view = None;
                    }
                }
                HotStuffAction::RequestMissingNode { node_hash } => {
                    self.network.broadcast(&HotStuffWireMessage::BlockRequest(node_hash));
                }
            }
        }
    }

    async fn handle_epoch_change_cert(&mut self, from_peer: Option<PeerId>, cert: EpochChangeCert) {
        if cert.from_epoch != self.core.epoch() {
            return;
        }
        if let Err(err) = self.core.verify_epoch_change_cert(&cert) {
            warn!(target: "consensus::hotstuff", ?from_peer, %err, "Invalid EpochChangeCert");
            return;
        }

        if !self.has_local_header(cert.boundary_block_hash) {
            self.pending_epoch_cert = Some(cert);
            if let Some(pid) = from_peer {
                self.maybe_request_sync(pid);
            } else {
                self.maybe_retry_sync_from_any_peer();
            }
            return;
        }

        let next_epoch = cert.from_epoch + 1;
        self.handle_epoch_transition(next_epoch, cert).await;
    }

    async fn try_apply_pending_epoch_cert(&mut self) {
        let Some(cert) = self.pending_epoch_cert.clone() else {
            return;
        };
        if cert.from_epoch != self.core.epoch() {
            self.pending_epoch_cert = None;
            return;
        }
        if self.has_local_header(cert.boundary_block_hash) {
            self.pending_epoch_cert = None;
            self.handle_epoch_transition(cert.from_epoch + 1, cert).await;
        }
    }

    async fn handle_epoch_transition(&mut self, next_epoch: u64, cert: EpochChangeCert) {
        if next_epoch != self.core.epoch() + 1 {
            return;
        }

        let fcu_state = ForkchoiceState {
            head_block_hash: cert.boundary_block_hash,
            safe_block_hash: cert.boundary_block_hash,
            finalized_block_hash: cert.boundary_block_hash,
        };
        if let Err(err) = self.engine.fork_choice_updated(fcu_state, None).await {
            error!(target: "consensus::hotstuff", %err, "Failed finalizing epoch boundary block");
            return;
        }

        let new_vs = match self.epoch_manager.load_epoch_from_provider(
            &self.provider,
            next_epoch,
            cert.boundary_block_hash,
        ) {
            Ok(vs) => vs,
            Err(err) => {
                error!(target: "consensus::hotstuff", %err, next_epoch, "Failed loading validator set for new epoch");
                return;
            }
        };

        self.epoch_certs.insert(cert.from_epoch, cert.clone());
        while self.epoch_certs.len() > MAX_PERSISTED_EPOCH_CERTS {
            if let Some(&oldest) = self.epoch_certs.keys().next() {
                self.epoch_certs.remove(&oldest);
            }
        }
        if let Err(err) = self.store.save_epoch_certs(&self.epoch_certs) {
            error!(
                target: "consensus::hotstuff",
                %err,
                "Fatal failure persisting epoch change certs; halting consensus driver"
            );
            self.wal_halted.store(true, Ordering::Release);
            return;
        }

        self.network.broadcast(&HotStuffWireMessage::EpochChange(Box::new(cert.clone())));

        info!(
            target: "consensus::hotstuff",
            next_epoch,
            boundary_block_number = cert.boundary_block_number,
            boundary_block_hash = %cert.boundary_block_hash,
            validators = ?new_vs.validators(),
            "Transitioning HotStuff consensus to new epoch"
        );

        self.scheduled_proposal = None;
        self.proposed_in_current_view = None;

        let actions = self.core.advance_epoch(
            next_epoch,
            new_vs,
            cert.boundary_block_hash,
            cert.boundary_block_number,
        );
        if self.persist_wal().is_err() {
            return;
        }
        self.network.broadcast(&HotStuffWireMessage::Status(self.effective_sync_status()));
        Box::pin(self.execute_actions(actions)).await;

        let pending_future: Vec<_> = self
            .future_epoch_proposals
            .drain(..)
            .filter(|p| p.header.epoch >= next_epoch)
            .collect();
        for prop in pending_future {
            Box::pin(self.handle_peer_proposal(None, prop)).await;
        }
    }

    fn cache_proposal(&mut self, node_hash: B256, proposal: Proposal) {
        if self.proposal_cache.insert(node_hash, proposal).is_none() {
            self.proposal_order.push_back(node_hash);
            while self.proposal_order.len() > MAX_PROPOSAL_CACHE {
                if let Some(oldest) = self.proposal_order.pop_front() {
                    self.proposal_cache.remove(&oldest);
                }
            }
        }
    }

    fn buffer_pending_proposal(&mut self, parent_hash: B256, proposal: Proposal) {
        if !self.pending_proposals.contains_key(&parent_hash) {
            self.pending_order.push_back(parent_hash);
            while self.pending_order.len() > MAX_PENDING_PARENTS {
                if let Some(oldest) = self.pending_order.pop_front() {
                    self.pending_proposals.remove(&oldest);
                }
            }
        }
        let children = self.pending_proposals.entry(parent_hash).or_default();
        if children.len() < MAX_PENDING_CHILDREN_PER_PARENT &&
            !children.iter().any(|p| p.header.node_hash() == proposal.header.node_hash())
        {
            children.push(proposal);
        }
    }
}
