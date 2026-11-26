//! Pure, deterministic Chained `HotStuff` (3-chain) state machine and Pacemaker.

use alloy_primitives::{map::B256Map, Address, B256};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::Arc,
};

use crate::{
    crypto::{
        new_view_digest, timeout_digest, verify_new_view, verify_proposal_signature, verify_qc,
        verify_tc, vote_digest, ValidatorSigner,
    },
    error::HotStuffError,
    storage::{
        HotStuffPersistedState, HOTSTUFF_WAL_VERSION, MAX_PERSISTED_ACTIVE_NODES,
        MAX_PERSISTED_ACTIVE_QCS,
    },
    types::{
        EpochChangeCert, HotStuffNodeHeader, NewView, Proposal, QuorumCertificate, SyncStatus,
        TimeoutCertificate, TimeoutData, TimeoutMsg, TimeoutSignature, ValidatorSignature, Vote,
        VoteData,
    },
    validator::ValidatorSet,
};

const MAX_CACHED_NODES: usize = 256;
const MAX_CACHED_QCS: usize = 256;
const MAX_BUFFERED_VIEWS: usize = 64;
const MAX_BACKOFF_EXPONENT: u32 = 4;

/// Side-effect actions emitted by [`HotStuffCore`] for the async engine/network driver to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotStuffAction {
    /// Leader should build (or emit NIL) and broadcast a new proposal for `(epoch, view)`.
    NeedBuildProposal {
        /// Target epoch.
        epoch: u64,
        /// Target view.
        view: u64,
        /// Highest known QC to embed as `justify_qc`.
        justify_qc: QuorumCertificate,
        /// Timeout certificate for `view - 1` when `view > justify_qc.view + 1`.
        timeout_cert: Option<TimeoutCertificate>,
        /// Whether this proposal must be a consensus-only NIL suffix node.
        is_nil: bool,
    },
    /// Send a signed vote to the leader of `view + 1`.
    SendVote {
        /// Next-view leader address.
        leader: Address,
        /// Signed vote.
        vote: Vote,
    },
    /// Broadcast a Pacemaker timeout message to all peers.
    BroadcastTimeout(TimeoutMsg),
    /// Send a `NewView` message to the leader of `new_view` (and broadcast).
    SendNewView {
        /// Leader of `new_view`.
        leader: Address,
        /// Signed `NewView` message.
        new_view: NewView,
    },
    /// Update Reth's execution engine `ForkchoiceState`.
    UpdateForkchoice {
        /// `high_qc.exec_block_hash`.
        head_block_hash: B256,
        /// `locked_qc.exec_block_hash`.
        safe_block_hash: B256,
        /// `committed_exec_hash`.
        finalized_block_hash: B256,
    },
    /// Persist a newly observed or formed QC in [`QcStore`](crate::QcStore).
    StoreQc(QuorumCertificate),
    /// A real execution block was 3-chain committed.
    BlockCommitted {
        /// Epoch of the committed block.
        epoch: u64,
        /// Consensus view of the committed block.
        view: u64,
        /// `HotStuff` consensus node hash.
        node_hash: B256,
        /// Execution block hash.
        exec_block_hash: B256,
        /// Execution block number.
        exec_block_number: u64,
    },
    /// The epoch's boundary execution block was 3-chain finalized; transition to `next_epoch`.
    EpochBoundaryFinalized {
        /// Next epoch index (`epoch + 1`).
        next_epoch: u64,
        /// Proof of 3-chain finalization of the boundary block.
        cert: Box<EpochChangeCert>,
    },
    /// Reset the Pacemaker timer for `view` with exponential backoff `timeout_exponent`.
    ResetPacemaker {
        /// View being timed.
        view: u64,
        /// Exponential backoff exponent (`0..=4`).
        timeout_exponent: u32,
    },
    /// Request a missing parent `HotStuff` node from peers.
    RequestMissingNode {
        /// Missing consensus node hash.
        node_hash: B256,
    },
}

/// Pure, synchronous Chained `HotStuff` state machine for one active epoch at a time.
#[derive(Debug)]
pub struct HotStuffCore {
    epoch: u64,
    epoch_length: u64,
    view: u64,
    last_voted_view: u64,
    last_proposed_view: u64,
    last_timeout_view: u64,
    consecutive_timeouts: u32,
    epoch_finalized: bool,

    validator_set: Arc<ValidatorSet>,
    signer: Option<ValidatorSigner>,

    high_qc: QuorumCertificate,
    locked_qc: QuorumCertificate,
    committed_node_hash: B256,
    committed_view: u64,
    committed_exec_hash: B256,
    committed_exec_number: u64,

    nodes: B256Map<HotStuffNodeHeader>,
    node_order: VecDeque<B256>,
    qcs: B256Map<QuorumCertificate>,
    qc_order: VecDeque<B256>,

    /// Votes collected by `(view, node_hash)` -> `(voter -> Vote)`.
    votes: HashMap<(u64, B256), HashMap<Address, Vote>>,
    formed_qc_keys: HashSet<(u64, B256)>,

    /// Pacemaker timeouts collected by `view` -> `(voter -> TimeoutMsg)`.
    timeouts: HashMap<u64, HashMap<Address, TimeoutMsg>>,
    tcs: HashMap<u64, TimeoutCertificate>,
    last_timeout_msg: Option<TimeoutMsg>,
}

impl HotStuffCore {
    /// Creates a new [`HotStuffCore`] anchored at `(anchor_exec_hash, anchor_exec_number)`.
    pub fn new(
        epoch: u64,
        epoch_length: u64,
        validator_set: Arc<ValidatorSet>,
        signer: Option<ValidatorSigner>,
        anchor_exec_hash: B256,
        anchor_exec_number: u64,
    ) -> Self {
        let genesis_node =
            HotStuffNodeHeader::epoch_genesis(epoch, anchor_exec_hash, anchor_exec_number);
        let genesis_hash = genesis_node.node_hash();
        let genesis_qc =
            QuorumCertificate::epoch_genesis(epoch, anchor_exec_hash, anchor_exec_number);
        let genesis_qc_hash = genesis_qc.hash();

        let mut nodes = B256Map::default();
        nodes.insert(genesis_hash, genesis_node);
        let mut node_order = VecDeque::new();
        node_order.push_back(genesis_hash);

        let mut qcs = B256Map::default();
        qcs.insert(genesis_qc_hash, genesis_qc.clone());
        let mut qc_order = VecDeque::new();
        qc_order.push_back(genesis_qc_hash);

        Self {
            epoch,
            epoch_length,
            view: 1,
            last_voted_view: 0,
            last_proposed_view: 0,
            last_timeout_view: 0,
            consecutive_timeouts: 0,
            epoch_finalized: false,
            validator_set,
            signer,
            high_qc: genesis_qc.clone(),
            locked_qc: genesis_qc,
            committed_node_hash: genesis_hash,
            committed_view: 0,
            committed_exec_hash: anchor_exec_hash,
            committed_exec_number: anchor_exec_number,
            nodes,
            node_order,
            qcs,
            qc_order,
            votes: HashMap::new(),
            formed_qc_keys: HashSet::new(),
            timeouts: HashMap::new(),
            tcs: HashMap::new(),
            last_timeout_msg: None,
        }
    }

    /// Starts consensus in view 1, emitting pacemaker reset and proposal request if leader.
    pub fn start(&mut self) -> Vec<HotStuffAction> {
        let mut actions = vec![HotStuffAction::ResetPacemaker {
            view: self.view,
            timeout_exponent: self.backoff_exponent(),
        }];
        self.maybe_request_proposal(&mut actions);
        actions
    }

    /// Returns the current consensus epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the current `HotStuff` view.
    pub const fn view(&self) -> u64 {
        self.view
    }

    /// Returns the configured epoch boundary execution block number.
    pub const fn epoch_boundary_block(&self) -> u64 {
        self.epoch.saturating_add(1).saturating_mul(self.epoch_length)
    }

    /// Returns the current [`ValidatorSet`].
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// Returns the local validator address, if configured as a signer.
    pub fn local_address(&self) -> Option<Address> {
        self.signer.as_ref().map(ValidatorSigner::address)
    }

    /// Returns `true` if `addr` is the leader for `(self.epoch, view)`.
    pub fn is_leader_for_view(&self, view: u64) -> bool {
        self.local_address().is_some_and(|addr| addr == self.validator_set.leader_for_view(view))
    }

    /// Returns `true` if `node_hash` is already cached in the node tree.
    pub fn has_node(&self, node_hash: &B256) -> bool {
        self.nodes.contains_key(node_hash)
    }

    /// Returns a cached node header by consensus `node_hash`.
    pub fn node(&self, node_hash: &B256) -> Option<&HotStuffNodeHeader> {
        self.nodes.get(node_hash)
    }

    /// Returns the highest known [`QuorumCertificate`].
    pub const fn high_qc(&self) -> &QuorumCertificate {
        &self.high_qc
    }

    /// Returns the 2-chain locked [`QuorumCertificate`].
    pub const fn locked_qc(&self) -> &QuorumCertificate {
        &self.locked_qc
    }

    /// Returns the latest committed execution block hash and number.
    pub const fn committed_exec(&self) -> (B256, u64) {
        (self.committed_exec_hash, self.committed_exec_number)
    }

    /// Returns `true` if the next proposal built atop `self.high_qc` must be a NIL suffix.
    pub const fn next_proposal_is_nil(&self) -> bool {
        self.high_qc.exec_block_number >= self.epoch_boundary_block()
    }

    /// Records that this node has already proposed in `view` so duplicate triggers are suppressed.
    pub const fn mark_proposed(&mut self, view: u64) {
        if view > self.last_proposed_view {
            self.last_proposed_view = view;
        }
    }

    /// Returns the timeout certificate for `view - 1` if view `view` followed a Pacemaker timeout.
    pub fn timeout_cert_for_view(&self, view: u64) -> Option<TimeoutCertificate> {
        view.checked_sub(1).and_then(|prev| self.tcs.get(&prev).cloned())
    }

    /// Returns the compact [`SyncStatus`] describing this node's current epoch, view, and
    /// finalized tip.
    pub const fn sync_status(&self) -> SyncStatus {
        SyncStatus {
            epoch: self.epoch,
            view: self.view,
            finalized_number: self.committed_exec_number,
            finalized_hash: self.committed_exec_hash,
        }
    }

    /// Captures a bounded [`HotStuffPersistedState`] WAL snapshot of the current safety and
    /// liveness state.
    pub fn snapshot(&self) -> HotStuffPersistedState {
        let committed_view = self.committed_view;
        let locked_node = self.locked_qc.node_hash;
        let high_node = self.high_qc.node_hash;
        let mut active_nodes: Vec<HotStuffNodeHeader> = self
            .node_order
            .iter()
            .filter_map(|hash| {
                let node = self.nodes.get(hash)?;
                (node.view >= committed_view ||
                    *hash == self.committed_node_hash ||
                    *hash == locked_node ||
                    *hash == high_node)
                    .then(|| node.clone())
            })
            .collect();
        if active_nodes.len() > MAX_PERSISTED_ACTIVE_NODES {
            let drain = active_nodes.len() - MAX_PERSISTED_ACTIVE_NODES;
            active_nodes.drain(..drain);
        }

        let locked_qc_hash = self.locked_qc.hash();
        let high_qc_hash = self.high_qc.hash();
        let mut active_qcs: Vec<QuorumCertificate> = self
            .qc_order
            .iter()
            .filter_map(|hash| {
                let qc = self.qcs.get(hash)?;
                (qc.view >= committed_view || *hash == locked_qc_hash || *hash == high_qc_hash)
                    .then(|| qc.clone())
            })
            .collect();
        if !active_qcs.iter().any(|qc| qc.hash() == locked_qc_hash) {
            active_qcs.push(self.locked_qc.clone());
        }
        if !active_qcs.iter().any(|qc| qc.hash() == high_qc_hash) {
            active_qcs.push(self.high_qc.clone());
        }
        if active_qcs.len() > MAX_PERSISTED_ACTIVE_QCS {
            let drain = active_qcs.len() - MAX_PERSISTED_ACTIVE_QCS;
            active_qcs.drain(..drain);
        }

        HotStuffPersistedState {
            version: HOTSTUFF_WAL_VERSION,
            epoch: self.epoch,
            view: self.view,
            last_voted_view: self.last_voted_view,
            last_proposed_view: self.last_proposed_view,
            last_timeout_view: self.last_timeout_view,
            high_qc: self.high_qc.clone(),
            locked_qc: self.locked_qc.clone(),
            committed_node_hash: self.committed_node_hash,
            committed_view: self.committed_view,
            committed_exec_hash: self.committed_exec_hash,
            committed_exec_number: self.committed_exec_number,
            active_nodes,
            active_qcs,
            last_tc: self.timeout_cert_for_view(self.view),
            epoch_validators: BTreeMap::from([(
                self.epoch,
                self.validator_set.validators().to_vec(),
            )]),
        }
    }

    /// Restores a [`HotStuffCore`] from a persisted WAL snapshot, verifying QCs against
    /// `validator_set` and preserving `last_voted_view`, `last_timeout_view`, and `locked_qc`.
    pub fn from_snapshot(
        snapshot: HotStuffPersistedState,
        epoch_length: u64,
        validator_set: Arc<ValidatorSet>,
        signer: Option<ValidatorSigner>,
    ) -> Result<Self, HotStuffError> {
        if snapshot.version != HOTSTUFF_WAL_VERSION {
            return Err(HotStuffError::Storage(format!(
                "unsupported HotStuff WAL version {}, expected {HOTSTUFF_WAL_VERSION}",
                snapshot.version
            )));
        }
        if snapshot.epoch != validator_set.epoch() {
            return Err(HotStuffError::EpochMismatch {
                expected: validator_set.epoch(),
                got: snapshot.epoch,
            });
        }
        verify_qc(&snapshot.high_qc, &validator_set)?;
        verify_qc(&snapshot.locked_qc, &validator_set)?;
        if let Some(tc) = &snapshot.last_tc {
            verify_tc(tc, &validator_set)?;
        }

        let mut nodes = B256Map::default();
        let mut node_order = VecDeque::new();
        for node in snapshot.active_nodes {
            let hash = node.node_hash();
            if nodes.insert(hash, node).is_none() {
                node_order.push_back(hash);
            }
        }

        let mut qcs = B256Map::default();
        let mut qc_order = VecDeque::new();
        for qc in snapshot.active_qcs {
            let hash = qc.hash();
            if qcs.insert(hash, qc).is_none() {
                qc_order.push_back(hash);
            }
        }
        for qc in [&snapshot.locked_qc, &snapshot.high_qc] {
            let hash = qc.hash();
            if qcs.insert(hash, qc.clone()).is_none() {
                qc_order.push_back(hash);
            }
        }

        let mut tcs = HashMap::new();
        if let Some(tc) = snapshot.last_tc {
            tcs.insert(tc.view, tc);
        }

        let boundary = snapshot.epoch.saturating_add(1).saturating_mul(epoch_length);
        let epoch_finalized = snapshot.committed_exec_number >= boundary;

        Ok(Self {
            epoch: snapshot.epoch,
            epoch_length,
            view: snapshot.view.max(1),
            last_voted_view: snapshot.last_voted_view,
            last_proposed_view: snapshot.last_proposed_view,
            last_timeout_view: snapshot.last_timeout_view,
            consecutive_timeouts: 0,
            epoch_finalized,
            validator_set,
            signer,
            high_qc: snapshot.high_qc,
            locked_qc: snapshot.locked_qc,
            committed_node_hash: snapshot.committed_node_hash,
            committed_view: snapshot.committed_view,
            committed_exec_hash: snapshot.committed_exec_hash,
            committed_exec_number: snapshot.committed_exec_number,
            nodes,
            node_order,
            qcs,
            qc_order,
            votes: HashMap::new(),
            formed_qc_keys: HashSet::new(),
            timeouts: HashMap::new(),
            tcs,
            last_timeout_msg: None,
        })
    }

    /// Applies a historically synced block header and its verified [`QuorumCertificate`] during
    /// catch-up sync, updating `high_qc`, `locked_qc`, and 3-chain finality.
    pub fn apply_synced_block(
        &mut self,
        header: HotStuffNodeHeader,
        qc: QuorumCertificate,
    ) -> Result<Vec<HotStuffAction>, HotStuffError> {
        if header.epoch != self.epoch {
            return Err(HotStuffError::EpochMismatch { expected: self.epoch, got: header.epoch });
        }
        if header.is_nil {
            return Err(HotStuffError::SafetyViolation("synced block header must not be NIL"));
        }
        let node_hash = header.node_hash();
        if qc.node_hash != node_hash ||
            qc.view != header.view ||
            qc.exec_block_hash != header.exec_block_hash ||
            qc.exec_block_number != header.exec_block_number
        {
            return Err(HotStuffError::InvalidBlockHash(
                "synced QC does not match HotStuff node header".to_string(),
            ));
        }
        verify_qc(&qc, &self.validator_set)?;

        self.insert_node(node_hash, header);
        let mut actions = Vec::new();
        self.process_qc(&qc, &mut actions);

        if qc.view > self.last_voted_view {
            self.last_voted_view = qc.view;
        }
        self.consecutive_timeouts = 0;
        if qc.view >= self.view {
            self.view = qc.view + 1;
            actions.push(HotStuffAction::ResetPacemaker { view: self.view, timeout_exponent: 0 });
        }

        Ok(actions)
    }

    /// Processes a leader [`Proposal`] (either locally built or received from a peer).
    pub fn on_proposal(
        &mut self,
        proposal: &Proposal,
    ) -> Result<Vec<HotStuffAction>, HotStuffError> {
        if proposal.header.epoch != self.epoch {
            return Err(HotStuffError::EpochMismatch {
                expected: self.epoch,
                got: proposal.header.epoch,
            });
        }

        verify_proposal_signature(proposal, &self.validator_set)?;

        if proposal.header.view <= proposal.justify_qc.view {
            return Err(HotStuffError::InvalidView {
                view: proposal.header.view,
                reason: "proposal view must exceed justify_qc.view",
            });
        }
        if proposal.justify_qc.node_hash != proposal.header.parent_node_hash {
            return Err(HotStuffError::InvalidBlockHash(
                "proposal justify_qc.node_hash does not match parent_node_hash".to_string(),
            ));
        }
        if proposal.justify_qc.hash() != proposal.header.justify_qc_hash {
            return Err(HotStuffError::InvalidBlockHash(
                "proposal justify_qc hash does not match justify_qc_hash".to_string(),
            ));
        }
        verify_qc(&proposal.justify_qc, &self.validator_set)?;

        if proposal.header.view > proposal.justify_qc.view + 1 {
            let tc = proposal
                .timeout_cert
                .as_ref()
                .ok_or(HotStuffError::MissingTimeoutCertificate(proposal.header.view - 1))?;
            if tc.epoch != self.epoch || tc.view + 1 != proposal.header.view {
                return Err(HotStuffError::InvalidView {
                    view: proposal.header.view,
                    reason: "proposal timeout_cert does not match view - 1",
                });
            }
            verify_tc(tc, &self.validator_set)?;
            self.store_tc(tc.clone());
        }

        let Some(parent) = self.nodes.get(&proposal.header.parent_node_hash).cloned() else {
            return Err(HotStuffError::MissingParent(proposal.header.parent_node_hash));
        };

        let boundary = self.epoch_boundary_block();
        if parent.exec_block_number == boundary {
            if !proposal.header.is_nil ||
                proposal.header.exec_block_hash != parent.exec_block_hash ||
                proposal.header.exec_block_number != parent.exec_block_number
            {
                return Err(HotStuffError::SafetyViolation(
                    "proposals extending epoch boundary block must be NIL suffix nodes",
                ));
            }
        } else if parent.exec_block_number < boundary {
            if proposal.header.is_nil ||
                proposal.header.exec_block_number != parent.exec_block_number + 1
            {
                return Err(HotStuffError::SafetyViolation(
                    "non-boundary proposal must advance exec_block_number by 1",
                ));
            }
        } else {
            return Err(HotStuffError::SafetyViolation(
                "proposal cannot extend past epoch boundary block",
            ));
        }

        let node_hash = proposal.header.node_hash();
        self.insert_node(node_hash, proposal.header.clone());

        let mut actions = Vec::new();
        self.process_qc(&proposal.justify_qc, &mut actions);

        if proposal.header.view > self.view {
            self.view = proposal.header.view;
            self.consecutive_timeouts = 0;
            actions.push(HotStuffAction::ResetPacemaker { view: self.view, timeout_exponent: 0 });
        }

        if proposal.header.view <= self.last_voted_view {
            return Ok(actions);
        }

        // Chained HotStuff SafeNode rule: extend locked_qc OR justify_qc.view > locked_qc.view.
        let extends_locked = self.extends(&node_hash, &self.locked_qc.node_hash);
        let liveness_ok = proposal.justify_qc.view > self.locked_qc.view;
        if !extends_locked && !liveness_ok {
            return Err(HotStuffError::SafetyViolation("proposal violates HotStuff SafeNode rule"));
        }

        if let Some(signer) = &self.signer &&
            self.validator_set.contains(&signer.address())
        {
            self.last_voted_view = proposal.header.view;
            let vote_data = VoteData {
                epoch: self.epoch,
                view: proposal.header.view,
                node_hash,
                exec_block_hash: proposal.header.exec_block_hash,
                exec_block_number: proposal.header.exec_block_number,
            };
            let signature = signer.sign_digest(vote_digest(&vote_data));
            let vote = Vote { data: vote_data, voter: signer.address(), signature };
            let next_leader = self.validator_set.leader_for_view(proposal.header.view + 1);
            actions.push(HotStuffAction::SendVote { leader: next_leader, vote });
        }

        Ok(actions)
    }

    /// Processes a validator [`Vote`], forming a [`QuorumCertificate`] once `2f + 1` votes arrive.
    pub fn on_vote(&mut self, vote: Vote) -> Result<Vec<HotStuffAction>, HotStuffError> {
        if vote.data.epoch != self.epoch {
            return Err(HotStuffError::EpochMismatch { expected: self.epoch, got: vote.data.epoch });
        }
        if !self.validator_set.contains(&vote.voter) {
            return Err(HotStuffError::NonValidator { epoch: self.epoch, address: vote.voter });
        }
        let recovered = crate::crypto::recover_signer(vote_digest(&vote.data), &vote.signature)?;
        if recovered != vote.voter {
            return Err(HotStuffError::InvalidSignature(format!(
                "vote signer {recovered} does not match voter {}",
                vote.voter
            )));
        }

        if let Some(node) = self.nodes.get(&vote.data.node_hash) &&
            (node.epoch != vote.data.epoch ||
                node.view != vote.data.view ||
                node.exec_block_hash != vote.data.exec_block_hash ||
                node.exec_block_number != vote.data.exec_block_number)
        {
            return Err(HotStuffError::InvalidBlockHash(
                "vote data does not match cached proposal node".to_string(),
            ));
        }

        let key = (vote.data.view, vote.data.node_hash);
        if self.formed_qc_keys.contains(&key) || vote.data.view < self.committed_view {
            return Ok(Vec::new());
        }

        let entry = self.votes.entry(key).or_default();
        entry.entry(vote.voter).or_insert_with(|| vote.clone());

        if entry.len() < self.validator_set.quorum_size() {
            return Ok(Vec::new());
        }

        let mut signatures: Vec<_> = entry
            .values()
            .take(self.validator_set.quorum_size())
            .map(|v| ValidatorSignature { signer: v.voter, signature: v.signature })
            .collect();
        signatures.sort_by_key(|s| s.signer);

        self.formed_qc_keys.insert(key);
        self.votes.remove(&key);

        let qc = QuorumCertificate {
            epoch: vote.data.epoch,
            view: vote.data.view,
            node_hash: vote.data.node_hash,
            exec_block_hash: vote.data.exec_block_hash,
            exec_block_number: vote.data.exec_block_number,
            signatures,
        };

        let mut actions = Vec::new();
        self.process_qc(&qc, &mut actions);
        self.consecutive_timeouts = 0;

        if qc.view >= self.view {
            self.view = qc.view + 1;
            actions.push(HotStuffAction::ResetPacemaker { view: self.view, timeout_exponent: 0 });
            self.maybe_request_proposal(&mut actions);
        }

        Ok(actions)
    }

    /// Triggers a local Pacemaker timeout for `self.view` and broadcasts a signed `TimeoutMsg`.
    pub fn on_local_timeout(&mut self) -> Vec<HotStuffAction> {
        let mut actions = Vec::new();
        let current_view = self.view;
        let next_exp = self.consecutive_timeouts.saturating_add(1).min(MAX_BACKOFF_EXPONENT);

        if let Some(signer) = &self.signer &&
            self.validator_set.contains(&signer.address()) &&
            current_view >= self.last_timeout_view &&
            current_view > self.high_qc.view
        {
            let msg = if let Some(cached) = &self.last_timeout_msg &&
                cached.data.epoch == self.epoch &&
                cached.data.view == current_view
            {
                cached.clone()
            } else {
                self.last_timeout_view = current_view;
                let data = TimeoutData {
                    epoch: self.epoch,
                    view: current_view,
                    high_qc_view: self.high_qc.view,
                };
                let signature = signer.sign_digest(timeout_digest(&data));
                let built = TimeoutMsg {
                    data,
                    high_qc: self.high_qc.clone(),
                    voter: signer.address(),
                    signature,
                };
                self.last_timeout_msg = Some(built.clone());
                built
            };
            actions.push(HotStuffAction::BroadcastTimeout(msg.clone()));
            if let Ok(mut inner) = self.on_timeout(msg) {
                actions.append(&mut inner);
            }
        }

        // Re-arm the pacemaker with exponential backoff if the view has not yet advanced.
        if self.view == current_view {
            self.consecutive_timeouts = next_exp;
            actions.push(HotStuffAction::ResetPacemaker {
                view: self.view,
                timeout_exponent: next_exp,
            });
        }

        actions
    }

    /// Processes a received Pacemaker [`TimeoutMsg`], advancing view upon forming a
    /// [`TimeoutCertificate`].
    pub fn on_timeout(&mut self, msg: TimeoutMsg) -> Result<Vec<HotStuffAction>, HotStuffError> {
        if msg.data.epoch != self.epoch {
            return Err(HotStuffError::EpochMismatch { expected: self.epoch, got: msg.data.epoch });
        }
        if !self.validator_set.contains(&msg.voter) {
            return Err(HotStuffError::NonValidator { epoch: self.epoch, address: msg.voter });
        }
        if msg.data.view == 0 ||
            msg.data.high_qc_view != msg.high_qc.view ||
            msg.data.high_qc_view >= msg.data.view
        {
            return Err(HotStuffError::InvalidView {
                view: msg.data.view,
                reason: "invalid timeout view or high_qc_view",
            });
        }
        let recovered = crate::crypto::recover_signer(timeout_digest(&msg.data), &msg.signature)?;
        if recovered != msg.voter {
            return Err(HotStuffError::InvalidSignature(format!(
                "timeout signer {recovered} does not match voter {}",
                msg.voter
            )));
        }
        verify_qc(&msg.high_qc, &self.validator_set)?;

        let mut actions = Vec::new();
        self.process_qc(&msg.high_qc, &mut actions);
        if msg.high_qc.view >= self.view {
            self.view = msg.high_qc.view + 1;
            self.consecutive_timeouts = 0;
            actions.push(HotStuffAction::ResetPacemaker { view: self.view, timeout_exponent: 0 });
            self.maybe_request_proposal(&mut actions);
        }

        if msg.data.view < self.view || self.tcs.contains_key(&msg.data.view) {
            return Ok(actions);
        }

        let view_timeouts = self.timeouts.entry(msg.data.view).or_default();
        view_timeouts.entry(msg.voter).or_insert_with(|| msg.clone());

        if view_timeouts.len() < self.validator_set.quorum_size() {
            return Ok(actions);
        }

        let mut sigs: Vec<_> = view_timeouts
            .values()
            .take(self.validator_set.quorum_size())
            .map(|t| TimeoutSignature {
                signer: t.voter,
                high_qc_view: t.data.high_qc_view,
                signature: t.signature,
            })
            .collect();
        sigs.sort_by_key(|s| s.signer);

        let tc = TimeoutCertificate { epoch: self.epoch, view: msg.data.view, signatures: sigs };
        self.timeouts.remove(&msg.data.view);
        self.store_tc(tc.clone());

        let next_view = msg.data.view + 1;
        if next_view > self.view {
            self.view = next_view;
            self.consecutive_timeouts =
                self.consecutive_timeouts.saturating_add(1).min(MAX_BACKOFF_EXPONENT);
            actions.push(HotStuffAction::ResetPacemaker {
                view: self.view,
                timeout_exponent: self.consecutive_timeouts,
            });
            if let Some(signer) = &self.signer &&
                self.validator_set.contains(&signer.address())
            {
                let sig =
                    signer.sign_digest(new_view_digest(self.epoch, self.view, self.high_qc.hash()));
                let nv = NewView {
                    epoch: self.epoch,
                    new_view: self.view,
                    high_qc: self.high_qc.clone(),
                    sender: signer.address(),
                    signature: sig,
                    timeout_cert: Some(tc),
                };
                actions.push(HotStuffAction::SendNewView {
                    leader: self.validator_set.leader_for_view(self.view),
                    new_view: nv,
                });
            }
            self.maybe_request_proposal(&mut actions);
        }

        Ok(actions)
    }

    /// Processes a [`NewView`] message from a peer, updating `high_qc` and triggering a proposal
    /// if this node is the leader of the new view.
    pub fn on_new_view(&mut self, msg: NewView) -> Result<Vec<HotStuffAction>, HotStuffError> {
        verify_new_view(&msg, &self.validator_set)?;

        let mut actions = Vec::new();
        self.process_qc(&msg.high_qc, &mut actions);
        if let Some(tc) = msg.timeout_cert {
            self.store_tc(tc);
        }

        let target_view = msg.new_view.max(msg.high_qc.view.saturating_add(1));
        if target_view > self.view {
            let qc_advanced = msg.high_qc.view.saturating_add(1) >= target_view;
            self.view = target_view;
            if qc_advanced {
                self.consecutive_timeouts = 0;
            }
            actions.push(HotStuffAction::ResetPacemaker {
                view: self.view,
                timeout_exponent: if qc_advanced { 0 } else { self.backoff_exponent() },
            });
            self.maybe_request_proposal(&mut actions);
        } else if target_view == self.view {
            self.maybe_request_proposal(&mut actions);
        }

        Ok(actions)
    }

    /// Validates an [`EpochChangeCert`] received from a peer against the current epoch's
    /// validator set.
    pub fn verify_epoch_change_cert(&self, cert: &EpochChangeCert) -> Result<(), HotStuffError> {
        if cert.from_epoch != self.epoch {
            return Err(HotStuffError::EpochMismatch { expected: self.epoch, got: cert.from_epoch });
        }
        let expected_boundary = self.epoch_boundary_block();
        if cert.boundary_block_number != expected_boundary {
            return Err(HotStuffError::InvalidBlockHash(format!(
                "epoch change cert boundary number {} != expected {expected_boundary}",
                cert.boundary_block_number
            )));
        }
        let [b0, b1, b2] = cert.nodes();
        if b0.epoch != self.epoch || b1.epoch != self.epoch || b2.epoch != self.epoch {
            return Err(HotStuffError::EpochMismatch { expected: self.epoch, got: b0.epoch });
        }
        if b0.view == 0 || b1.view != b0.view + 1 || b2.view != b1.view + 1 {
            return Err(HotStuffError::InvalidView {
                view: b0.view,
                reason: "epoch change cert nodes must have consecutive positive views",
            });
        }
        if b1.parent_node_hash != b0.node_hash() || b2.parent_node_hash != b1.node_hash() {
            return Err(HotStuffError::InvalidBlockHash(
                "epoch change cert nodes do not form a parent-child chain".to_string(),
            ));
        }
        if b0.exec_block_hash != cert.boundary_block_hash ||
            b0.exec_block_number != cert.boundary_block_number
        {
            return Err(HotStuffError::InvalidBlockHash(
                "epoch change cert anchor node does not match boundary block".to_string(),
            ));
        }
        if cert.commit_qc.node_hash != b2.node_hash() || cert.commit_qc.view != b2.view {
            return Err(HotStuffError::InvalidBlockHash(
                "epoch change cert commit_qc does not certify nodes[2]".to_string(),
            ));
        }
        verify_qc(&cert.commit_qc, &self.validator_set)
    }

    /// Transitions the state machine into `new_epoch` anchored at the finalized boundary block.
    pub fn advance_epoch(
        &mut self,
        new_epoch: u64,
        new_validator_set: Arc<ValidatorSet>,
        boundary_block_hash: B256,
        boundary_block_number: u64,
    ) -> Vec<HotStuffAction> {
        let genesis_node = HotStuffNodeHeader::epoch_genesis(
            new_epoch,
            boundary_block_hash,
            boundary_block_number,
        );
        let genesis_hash = genesis_node.node_hash();
        let genesis_qc =
            QuorumCertificate::epoch_genesis(new_epoch, boundary_block_hash, boundary_block_number);
        let genesis_qc_hash = genesis_qc.hash();

        self.epoch = new_epoch;
        self.view = 1;
        self.last_voted_view = 0;
        self.last_proposed_view = 0;
        self.last_timeout_view = 0;
        self.consecutive_timeouts = 0;
        self.epoch_finalized = false;
        self.validator_set = new_validator_set;

        self.high_qc = genesis_qc.clone();
        self.locked_qc = genesis_qc;
        self.committed_node_hash = genesis_hash;
        self.committed_view = 0;
        self.committed_exec_hash = boundary_block_hash;
        self.committed_exec_number = boundary_block_number;

        self.nodes.clear();
        self.node_order.clear();
        self.nodes.insert(genesis_hash, genesis_node);
        self.node_order.push_back(genesis_hash);

        self.qcs.clear();
        self.qc_order.clear();
        self.qcs.insert(genesis_qc_hash, self.high_qc.clone());
        self.qc_order.push_back(genesis_qc_hash);

        self.votes.clear();
        self.formed_qc_keys.clear();
        self.timeouts.clear();
        self.tcs.clear();
        self.last_timeout_msg = None;

        let mut actions = vec![
            HotStuffAction::UpdateForkchoice {
                head_block_hash: boundary_block_hash,
                safe_block_hash: boundary_block_hash,
                finalized_block_hash: boundary_block_hash,
            },
            HotStuffAction::ResetPacemaker { view: 1, timeout_exponent: 0 },
        ];
        self.maybe_request_proposal(&mut actions);
        actions
    }

    fn backoff_exponent(&self) -> u32 {
        self.consecutive_timeouts.min(MAX_BACKOFF_EXPONENT)
    }

    fn maybe_request_proposal(&self, actions: &mut Vec<HotStuffAction>) {
        if !self.epoch_finalized &&
            self.is_leader_for_view(self.view) &&
            self.last_proposed_view < self.view
        {
            let timeout_cert = if self.view > self.high_qc.view + 1 {
                self.timeout_cert_for_view(self.view)
            } else {
                None
            };
            if self.view == self.high_qc.view + 1 || timeout_cert.is_some() {
                actions.push(HotStuffAction::NeedBuildProposal {
                    epoch: self.epoch,
                    view: self.view,
                    justify_qc: self.high_qc.clone(),
                    timeout_cert,
                    is_nil: self.next_proposal_is_nil(),
                });
            }
        }
    }

    fn process_qc(&mut self, qc: &QuorumCertificate, actions: &mut Vec<HotStuffAction>) {
        let prev_high = self.high_qc.exec_block_hash;
        let prev_locked = self.locked_qc.exec_block_hash;
        let prev_committed = self.committed_exec_hash;

        if qc.view > 0 {
            self.insert_qc(qc.clone());
            actions.push(HotStuffAction::StoreQc(qc.clone()));
        }

        if qc.view > self.high_qc.view {
            self.high_qc = qc.clone();
        }

        // Trace b0 <- b1 <- b2 where qc certifies b2.
        let Some(b2) = self.nodes.get(&qc.node_hash).cloned() else {
            self.emit_forkchoice_if_changed(prev_high, prev_locked, prev_committed, actions);
            return;
        };

        // 2-chain lock update: lock on b2's justify_qc (which certifies b1).
        if let Some(qc_b1) = self.qcs.get(&b2.justify_qc_hash).cloned() &&
            qc_b1.view > self.locked_qc.view
        {
            self.locked_qc = qc_b1;
        } else if let Some(b1) = self.nodes.get(&b2.parent_node_hash) &&
            b1.view > self.locked_qc.view
        {
            // Fallback if parent QC was stored under vote data hash via parent header.
            if let Some(qc_b1) = self.qcs.get(&b2.justify_qc_hash).cloned() {
                self.locked_qc = qc_b1;
            }
        }

        let Some(b1) = self.nodes.get(&b2.parent_node_hash).cloned() else {
            self.emit_forkchoice_if_changed(prev_high, prev_locked, prev_committed, actions);
            return;
        };
        let Some(b0) = self.nodes.get(&b1.parent_node_hash).cloned() else {
            self.emit_forkchoice_if_changed(prev_high, prev_locked, prev_committed, actions);
            return;
        };

        // 3-chain commit rule: b0, b1, b2 have strictly consecutive views (v, v+1, v+2).
        if b2.view == b1.view + 1 &&
            b1.view == b0.view + 1 &&
            b0.view > 0 &&
            b0.view > self.committed_view
        {
            let b0_hash = b0.node_hash();
            if b0_hash != self.committed_node_hash {
                let mut to_commit = Vec::new();
                let mut cursor = Some(b0.clone());
                while let Some(node) = cursor {
                    let h = node.node_hash();
                    if h == self.committed_node_hash || node.view <= self.committed_view {
                        break;
                    }
                    to_commit.push((h, node.clone()));
                    cursor = self.nodes.get(&node.parent_node_hash).cloned();
                }
                to_commit.reverse();

                for (hash, node) in to_commit {
                    if !node.is_nil {
                        self.committed_exec_hash = node.exec_block_hash;
                        self.committed_exec_number = node.exec_block_number;
                        actions.push(HotStuffAction::BlockCommitted {
                            epoch: self.epoch,
                            view: node.view,
                            node_hash: hash,
                            exec_block_hash: node.exec_block_hash,
                            exec_block_number: node.exec_block_number,
                        });
                    }
                }

                self.committed_node_hash = b0_hash;
                self.committed_view = b0.view;

                let boundary = self.epoch_boundary_block();
                if self.committed_exec_number >= boundary && !self.epoch_finalized {
                    self.epoch_finalized = true;
                    let cert = EpochChangeCert {
                        from_epoch: self.epoch,
                        boundary_block_hash: self.committed_exec_hash,
                        boundary_block_number: self.committed_exec_number,
                        node0: b0,
                        node1: b1,
                        node2: b2,
                        commit_qc: qc.clone(),
                    };
                    actions.push(HotStuffAction::EpochBoundaryFinalized {
                        next_epoch: self.epoch + 1,
                        cert: Box::new(cert),
                    });
                }

                self.prune_below_committed();
            }
        }

        self.emit_forkchoice_if_changed(prev_high, prev_locked, prev_committed, actions);
    }

    fn emit_forkchoice_if_changed(
        &self,
        prev_high: B256,
        prev_locked: B256,
        prev_committed: B256,
        actions: &mut Vec<HotStuffAction>,
    ) {
        if self.high_qc.exec_block_hash != prev_high ||
            self.locked_qc.exec_block_hash != prev_locked ||
            self.committed_exec_hash != prev_committed
        {
            actions.push(HotStuffAction::UpdateForkchoice {
                head_block_hash: self.high_qc.exec_block_hash,
                safe_block_hash: self.locked_qc.exec_block_hash,
                finalized_block_hash: self.committed_exec_hash,
            });
        }
    }

    fn extends(&self, descendant: &B256, ancestor: &B256) -> bool {
        if descendant == ancestor {
            return true;
        }
        let Some(ancestor_view) = self.nodes.get(ancestor).map(|n| n.view) else {
            return false;
        };
        let mut current = *descendant;
        let mut steps = 0usize;
        while let Some(node) = self.nodes.get(&current) {
            if node.view <= ancestor_view {
                return &current == ancestor;
            }
            if node.parent_node_hash == *ancestor {
                return true;
            }
            current = node.parent_node_hash;
            steps += 1;
            if steps > MAX_CACHED_NODES {
                break;
            }
        }
        false
    }

    fn insert_node(&mut self, hash: B256, node: HotStuffNodeHeader) {
        if self.nodes.insert(hash, node).is_none() {
            self.node_order.push_back(hash);
            while self.node_order.len() > MAX_CACHED_NODES {
                if let Some(oldest) = self.node_order.pop_front() &&
                    oldest != self.committed_node_hash
                {
                    self.nodes.remove(&oldest);
                }
            }
        }
    }

    fn insert_qc(&mut self, qc: QuorumCertificate) {
        let hash = qc.hash();
        if self.qcs.insert(hash, qc).is_none() {
            self.qc_order.push_back(hash);
            while self.qc_order.len() > MAX_CACHED_QCS {
                if let Some(oldest) = self.qc_order.pop_front() {
                    self.qcs.remove(&oldest);
                }
            }
        }
    }

    fn store_tc(&mut self, tc: TimeoutCertificate) {
        let view = tc.view;
        self.tcs.insert(view, tc);
        if self.tcs.len() > MAX_BUFFERED_VIEWS {
            let min_keep = self.view.saturating_sub(MAX_BUFFERED_VIEWS as u64);
            self.tcs.retain(|v, _| *v >= min_keep);
        }
    }

    fn prune_below_committed(&mut self) {
        let cutoff = self.committed_view;
        self.votes.retain(|(v, _), _| *v >= cutoff);
        self.formed_qc_keys.retain(|(v, _)| *v >= cutoff);
        self.timeouts.retain(|v, _| *v >= cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::proposal_digest;
    use alloy_primitives::Bytes;

    fn make_validators(n: usize) -> (Vec<ValidatorSigner>, Arc<ValidatorSet>) {
        let signers: Vec<_> = (0..n).map(|_| ValidatorSigner::random()).collect();
        let addrs: Vec<_> = signers.iter().map(ValidatorSigner::address).collect();
        let vs = Arc::new(ValidatorSet::new(0, addrs).unwrap());
        (signers, vs)
    }

    #[expect(clippy::too_many_arguments, reason = "test helper building custom proposals")]
    fn make_proposal(
        signers: &[ValidatorSigner],
        vs: &ValidatorSet,
        view: u64,
        justify_qc: QuorumCertificate,
        exec_hash: B256,
        exec_number: u64,
        is_nil: bool,
        timeout_cert: Option<TimeoutCertificate>,
    ) -> Proposal {
        let leader_addr = vs.leader_for_view(view);
        let leader = signers.iter().find(|s| s.address() == leader_addr).unwrap();
        let header = HotStuffNodeHeader {
            epoch: vs.epoch(),
            view,
            parent_node_hash: justify_qc.node_hash,
            justify_qc_hash: justify_qc.hash(),
            exec_block_hash: exec_hash,
            exec_block_number: exec_number,
            proposer: leader.address(),
            is_nil,
        };
        let signature = leader.sign_digest(proposal_digest(header.node_hash()));
        Proposal {
            header,
            justify_qc,
            block_rlp: Bytes::new(),
            requests: Vec::new(),
            signature,
            timeout_cert,
        }
    }

    fn form_qc_for_proposal(signers: &[ValidatorSigner], proposal: &Proposal) -> QuorumCertificate {
        let node_hash = proposal.header.node_hash();
        let data = VoteData {
            epoch: proposal.header.epoch,
            view: proposal.header.view,
            node_hash,
            exec_block_hash: proposal.header.exec_block_hash,
            exec_block_number: proposal.header.exec_block_number,
        };
        let digest = vote_digest(&data);
        let mut signatures: Vec<_> = signers
            .iter()
            .take(3)
            .map(|s| ValidatorSignature { signer: s.address(), signature: s.sign_digest(digest) })
            .collect();
        signatures.sort_by_key(|s| s.signer);
        QuorumCertificate {
            epoch: data.epoch,
            view: data.view,
            node_hash,
            exec_block_hash: data.exec_block_hash,
            exec_block_number: data.exec_block_number,
            signatures,
        }
    }

    #[test]
    fn three_chain_commit_and_non_consecutive_gap_safety() {
        let (signers, vs) = make_validators(4);
        let genesis = B256::repeat_byte(0x00);
        let mut core = HotStuffCore::new(0, 10, vs.clone(), Some(signers[0].clone()), genesis, 0);

        // View 1 -> b1
        let p1 = make_proposal(
            &signers,
            &vs,
            1,
            core.high_qc().clone(),
            B256::repeat_byte(0x01),
            1,
            false,
            None,
        );
        core.on_proposal(&p1).unwrap();
        let qc1 = form_qc_for_proposal(&signers, &p1);

        // View 2 -> b2 (no commit yet: only 2-chain)
        let p2 = make_proposal(&signers, &vs, 2, qc1, B256::repeat_byte(0x02), 2, false, None);
        let actions2 = core.on_proposal(&p2).unwrap();
        assert!(!actions2.iter().any(|a| matches!(a, HotStuffAction::BlockCommitted { .. })));
        let qc2 = form_qc_for_proposal(&signers, &p2);

        // View 3 -> b3 (carries QC(b2); still only b1 locked, not committed until QC(b3))
        let p3 = make_proposal(&signers, &vs, 3, qc2, B256::repeat_byte(0x03), 3, false, None);
        let actions3 = core.on_proposal(&p3).unwrap();
        assert_eq!(core.locked_qc().view, 1);
        assert!(!actions3.iter().any(|a| matches!(a, HotStuffAction::BlockCommitted { .. })));

        // Vote on p3 to form QC(b3) -> 3-chain (b1 <- b2 <- b3) commits b1!
        for s in &signers[..3] {
            let data = VoteData {
                epoch: 0,
                view: 3,
                node_hash: p3.header.node_hash(),
                exec_block_hash: p3.header.exec_block_hash,
                exec_block_number: 3,
            };
            let vote = Vote {
                data: data.clone(),
                voter: s.address(),
                signature: s.sign_digest(vote_digest(&data)),
            };
            let actions = core.on_vote(vote).unwrap();
            if s.address() == signers[2].address() {
                assert!(actions.iter().any(|a| matches!(
                    a,
                    HotStuffAction::BlockCommitted { exec_block_number: 1, .. }
                )));
            }
        }
        assert_eq!(core.committed_exec(), (B256::repeat_byte(0x01), 1));
    }

    #[test]
    fn non_consecutive_views_do_not_commit() {
        let (signers, vs) = make_validators(4);
        let genesis = B256::repeat_byte(0x00);
        let mut core = HotStuffCore::new(0, 10, vs.clone(), Some(signers[0].clone()), genesis, 0);

        let p1 = make_proposal(
            &signers,
            &vs,
            1,
            core.high_qc().clone(),
            B256::repeat_byte(0x01),
            1,
            false,
            None,
        );
        core.on_proposal(&p1).unwrap();
        let qc1 = form_qc_for_proposal(&signers, &p1);

        // View 2 times out -> TC(view 2)
        let tc2 = TimeoutCertificate {
            epoch: 0,
            view: 2,
            signatures: signers[..3]
                .iter()
                .map(|s| {
                    let d = TimeoutData { epoch: 0, view: 2, high_qc_view: 1 };
                    TimeoutSignature {
                        signer: s.address(),
                        high_qc_view: 1,
                        signature: s.sign_digest(timeout_digest(&d)),
                    }
                })
                .collect(),
        };

        // View 3 extends view 1 (gap between view 1 and view 3).
        let p3 = make_proposal(&signers, &vs, 3, qc1, B256::repeat_byte(0x02), 2, false, Some(tc2));
        core.on_proposal(&p3).unwrap();
        let qc3 = form_qc_for_proposal(&signers, &p3);

        let p4 = make_proposal(&signers, &vs, 4, qc3, B256::repeat_byte(0x03), 3, false, None);
        core.on_proposal(&p4).unwrap();
        let qc4 = form_qc_for_proposal(&signers, &p4);

        // Proposal at view 5 carries qc4 (b1@1 <- b2@3 <- b3@4): non-consecutive so b1 must NOT
        // commit yet!
        let p5 = make_proposal(&signers, &vs, 5, qc4, B256::repeat_byte(0x04), 4, false, None);
        let actions5 = core.on_proposal(&p5).unwrap();
        assert!(!actions5.iter().any(|a| matches!(a, HotStuffAction::BlockCommitted { .. })));
        assert_eq!(core.committed_exec().1, 0);
    }

    #[test]
    fn safenode_prevents_conflicting_vote_and_prevents_double_vote() {
        let (signers, vs) = make_validators(4);
        let genesis = B256::repeat_byte(0x00);
        let mut core = HotStuffCore::new(0, 10, vs.clone(), Some(signers[0].clone()), genesis, 0);
        let genesis_qc = core.high_qc().clone();

        // Build chain A: b1(1) -> b2(2) -> b3(3) so locked_qc becomes view 1 (b1).
        let a1 = make_proposal(
            &signers,
            &vs,
            1,
            genesis_qc.clone(),
            B256::repeat_byte(0xa1),
            1,
            false,
            None,
        );
        let act1 = core.on_proposal(&a1).unwrap();
        assert!(act1.iter().any(|a| matches!(a, HotStuffAction::SendVote { .. })));

        // Re-proposing another block in same view 1 must NOT produce a second vote.
        let a1_dup = make_proposal(
            &signers,
            &vs,
            1,
            genesis_qc.clone(),
            B256::repeat_byte(0xb1),
            1,
            false,
            None,
        );
        let act_dup = core.on_proposal(&a1_dup).unwrap();
        assert!(!act_dup.iter().any(|a| matches!(a, HotStuffAction::SendVote { .. })));

        let qc_a1 = form_qc_for_proposal(&signers, &a1);
        let a2 = make_proposal(&signers, &vs, 2, qc_a1, B256::repeat_byte(0xa2), 2, false, None);
        core.on_proposal(&a2).unwrap();
        let qc_a2 = form_qc_for_proposal(&signers, &a2);
        let a3 = make_proposal(&signers, &vs, 3, qc_a2, B256::repeat_byte(0xa3), 3, false, None);
        core.on_proposal(&a3).unwrap();
        assert_eq!(core.locked_qc().view, 1);

        // Conflicting branch B extending genesis_qc (view 0 < locked_qc.view 1) at view 4 must fail
        // SafeNode!
        let tc3 = TimeoutCertificate {
            epoch: 0,
            view: 3,
            signatures: signers[..3]
                .iter()
                .map(|s| {
                    let d = TimeoutData { epoch: 0, view: 3, high_qc_view: 0 };
                    TimeoutSignature {
                        signer: s.address(),
                        high_qc_view: 0,
                        signature: s.sign_digest(timeout_digest(&d)),
                    }
                })
                .collect(),
        };
        let b4 = make_proposal(
            &signers,
            &vs,
            4,
            genesis_qc,
            B256::repeat_byte(0xb4),
            1,
            false,
            Some(tc3),
        );
        let err = core.on_proposal(&b4).unwrap_err();
        assert!(matches!(err, HotStuffError::SafetyViolation(_)));
    }

    #[test]
    fn pacemaker_timeout_and_epoch_boundary_nil_finalization() {
        let (signers, vs) = make_validators(4);
        let genesis = B256::repeat_byte(0x00);
        let mut core = HotStuffCore::new(0, 2, vs.clone(), Some(signers[0].clone()), genesis, 0);

        // Local timeout -> collects 3 timeouts -> forms TC and advances to view 2.
        let mut local_actions = core.on_local_timeout();
        assert!(local_actions.iter().any(|a| matches!(a, HotStuffAction::BroadcastTimeout(_))));
        for s in &signers[1..3] {
            let data = TimeoutData { epoch: 0, view: 1, high_qc_view: 0 };
            let msg = TimeoutMsg {
                data: data.clone(),
                high_qc: core.high_qc().clone(),
                voter: s.address(),
                signature: s.sign_digest(timeout_digest(&data)),
            };
            let act = core.on_timeout(msg).unwrap();
            local_actions.extend(act);
        }
        assert_eq!(core.view(), 2);
        assert!(local_actions.iter().any(|a| matches!(a, HotStuffAction::SendNewView { .. })));

        // Propose blocks 1 & 2 (boundary = 2), then NIL1 & NIL2 to finalize block 2!
        let tc1 = core.timeout_cert_for_view(2).unwrap();
        let p1 = make_proposal(
            &signers,
            &vs,
            2,
            core.high_qc().clone(),
            B256::repeat_byte(0x11),
            1,
            false,
            Some(tc1),
        );
        core.on_proposal(&p1).unwrap();
        let qc1 = form_qc_for_proposal(&signers, &p1);

        let p2 = make_proposal(&signers, &vs, 3, qc1, B256::repeat_byte(0x22), 2, false, None);
        core.on_proposal(&p2).unwrap();
        let qc2 = form_qc_for_proposal(&signers, &p2);

        // Next proposal extending boundary block 2 MUST be NIL!
        let bad_non_nil =
            make_proposal(&signers, &vs, 4, qc2.clone(), B256::repeat_byte(0x33), 3, false, None);
        assert!(matches!(
            core.on_proposal(&bad_non_nil).unwrap_err(),
            HotStuffError::SafetyViolation(_)
        ));

        let nil1 = make_proposal(&signers, &vs, 4, qc2, B256::repeat_byte(0x22), 2, true, None);
        core.on_proposal(&nil1).unwrap();
        let qc_nil1 = form_qc_for_proposal(&signers, &nil1);

        let nil2 = make_proposal(&signers, &vs, 5, qc_nil1, B256::repeat_byte(0x22), 2, true, None);
        core.on_proposal(&nil2).unwrap();

        // Votes on nil2 form QC(nil2) -> 3-chain (p2 <- nil1 <- nil2) finalizes boundary block 2!
        let mut finalized_cert = None;
        for s in &signers[..3] {
            let data = VoteData {
                epoch: 0,
                view: 5,
                node_hash: nil2.header.node_hash(),
                exec_block_hash: B256::repeat_byte(0x22),
                exec_block_number: 2,
            };
            let vote = Vote {
                data: data.clone(),
                voter: s.address(),
                signature: s.sign_digest(vote_digest(&data)),
            };
            for action in core.on_vote(vote).unwrap() {
                if let HotStuffAction::EpochBoundaryFinalized { next_epoch, cert } = action {
                    assert_eq!(next_epoch, 1);
                    finalized_cert = Some(cert);
                }
            }
        }
        let cert = finalized_cert.expect("boundary block must finalize");
        assert!(core.verify_epoch_change_cert(&cert).is_ok());

        // Advance to epoch 1 with rotated validator set.
        let vs1 = Arc::new(
            ValidatorSet::new(
                1,
                vec![signers[0].address(), signers[1].address(), signers[2].address()],
            )
            .unwrap(),
        );
        let actions =
            core.advance_epoch(1, vs1, cert.boundary_block_hash, cert.boundary_block_number);
        assert_eq!(core.epoch(), 1);
        assert_eq!(core.view(), 1);
        assert!(actions.iter().any(|a| matches!(a, HotStuffAction::UpdateForkchoice { .. })));
    }

    #[test]
    fn snapshot_restore_preserves_safety_locks_and_prevents_double_vote() {
        let (signers, vs) = make_validators(4);
        let genesis = B256::repeat_byte(0x00);
        let mut core = HotStuffCore::new(0, 10, vs.clone(), Some(signers[0].clone()), genesis, 0);

        let p1 = make_proposal(
            &signers,
            &vs,
            1,
            core.high_qc().clone(),
            B256::repeat_byte(0x01),
            1,
            false,
            None,
        );
        let actions1 = core.on_proposal(&p1).unwrap();
        assert!(actions1.iter().any(|a| matches!(a, HotStuffAction::SendVote { .. })));
        let qc1 = form_qc_for_proposal(&signers, &p1);

        let p2 = make_proposal(&signers, &vs, 2, qc1, B256::repeat_byte(0x02), 2, false, None);
        let actions2 = core.on_proposal(&p2).unwrap();
        assert!(actions2.iter().any(|a| matches!(a, HotStuffAction::SendVote { .. })));

        // Persist snapshot and restore into a brand new HotStuffCore instance.
        let snapshot = core.snapshot();
        let mut restored =
            HotStuffCore::from_snapshot(snapshot, 10, vs.clone(), Some(signers[0].clone()))
                .unwrap();

        assert_eq!(restored.high_qc().view, 1);
        assert_eq!(restored.view(), 2);

        // Re-receiving a conflicting proposal in already-voted view 2 must NOT produce a vote!
        let conflicting_p2 = make_proposal(
            &signers,
            &vs,
            2,
            restored.high_qc().clone(),
            B256::repeat_byte(0x99),
            2,
            false,
            None,
        );
        let dup_actions = restored.on_proposal(&conflicting_p2).unwrap();
        assert!(!dup_actions.iter().any(|a| matches!(a, HotStuffAction::SendVote { .. })));
    }

    #[test]
    fn apply_synced_block_commits_three_chain_and_advances_view() {
        let (signers, vs) = make_validators(4);
        let genesis = B256::repeat_byte(0x00);
        let mut core = HotStuffCore::new(0, 10, vs.clone(), Some(signers[0].clone()), genesis, 0);

        let p1 = make_proposal(
            &signers,
            &vs,
            1,
            core.high_qc().clone(),
            B256::repeat_byte(0x01),
            1,
            false,
            None,
        );
        let qc1 = form_qc_for_proposal(&signers, &p1);

        let p2 =
            make_proposal(&signers, &vs, 2, qc1.clone(), B256::repeat_byte(0x02), 2, false, None);
        let qc2 = form_qc_for_proposal(&signers, &p2);

        let p3 =
            make_proposal(&signers, &vs, 3, qc2.clone(), B256::repeat_byte(0x03), 3, false, None);
        let qc3 = form_qc_for_proposal(&signers, &p3);

        core.apply_synced_block(p1.header, qc1).unwrap();
        core.apply_synced_block(p2.header, qc2).unwrap();
        let actions3 = core.apply_synced_block(p3.header, qc3).unwrap();

        assert_eq!(core.view(), 4);
        assert_eq!(core.high_qc().view, 3);
        assert_eq!(core.locked_qc().view, 2);
        assert_eq!(core.committed_exec(), (B256::repeat_byte(0x01), 1));
        assert!(actions3
            .iter()
            .any(|a| matches!(a, HotStuffAction::BlockCommitted { exec_block_number: 1, .. })));
    }

    #[test]
    fn pacemaker_rebroadcasts_timeout_across_retry_and_snapshot_restore() {
        let (signers, vs) = make_validators(4);
        let genesis = B256::repeat_byte(0x00);
        let mut core = HotStuffCore::new(0, 10, vs.clone(), Some(signers[0].clone()), genesis, 0);

        let first = core.on_local_timeout();
        let msg1 = first
            .iter()
            .find_map(|a| match a {
                HotStuffAction::BroadcastTimeout(m) => Some(m.clone()),
                _ => None,
            })
            .expect("first timeout must broadcast TimeoutMsg");

        // Second timer firing while still in the same view re-emits the cached TimeoutMsg.
        let retry = core.on_local_timeout();
        let msg2 = retry
            .iter()
            .find_map(|a| match a {
                HotStuffAction::BroadcastTimeout(m) => Some(m.clone()),
                _ => None,
            })
            .expect("retry timeout must re-broadcast TimeoutMsg");
        assert_eq!(msg1, msg2);

        // Restoring from WAL while still stuck at view 1 also allows re-broadcasting TimeoutMsg.
        let mut restored =
            HotStuffCore::from_snapshot(core.snapshot(), 10, vs, Some(signers[0].clone())).unwrap();
        let post_crash = restored.on_local_timeout();
        let msg3 = post_crash
            .iter()
            .find_map(|a| match a {
                HotStuffAction::BroadcastTimeout(m) => Some(m.clone()),
                _ => None,
            })
            .expect("post-restart timeout must re-broadcast TimeoutMsg");
        assert_eq!(msg3.data.view, 1);
    }

    #[test]
    fn on_timeout_with_higher_high_qc_advances_lagging_view() {
        let (signers, vs) = make_validators(4);
        let genesis = B256::repeat_byte(0x00);
        let mut core = HotStuffCore::new(0, 20, vs.clone(), Some(signers[0].clone()), genesis, 0);

        // Advance chain up to view 5 with a valid QC(5), simulating peers jumping ahead to view 6.
        let mut prev_qc = core.high_qc().clone();
        let mut qc5 = prev_qc.clone();
        for v in 1u64..=5 {
            let prop = make_proposal(
                &signers,
                &vs,
                v,
                prev_qc,
                B256::repeat_byte(v as u8),
                v,
                false,
                None,
            );
            qc5 = form_qc_for_proposal(&signers, &prop);
            if v < 5 {
                core.apply_synced_block(prop.header, qc5.clone()).unwrap();
            }
            prev_qc = qc5.clone();
        }
        assert_eq!(core.view(), 5);
        assert_eq!(core.high_qc().view, 4);

        let data = TimeoutData { epoch: 0, view: 6, high_qc_view: 5 };
        let sig = signers[1].sign_digest(timeout_digest(&data));
        let msg = TimeoutMsg { data, high_qc: qc5, voter: signers[1].address(), signature: sig };

        let actions = core.on_timeout(msg).unwrap();
        assert_eq!(core.view(), 6);
        assert_eq!(core.high_qc().view, 5);
        assert_eq!(core.timeouts.get(&6).map(HashMap::len), Some(1));
        assert!(actions
            .iter()
            .any(|a| matches!(a, HotStuffAction::ResetPacemaker { view: 6, .. })));
    }
}
