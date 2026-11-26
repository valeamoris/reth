//! Property-based and fuzz-style adversarial tests for Chained `HotStuff`.

use alloy_primitives::{Address, Bytes, B256};
use proptest::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use reth_consensus_hotstuff::{
    crypto::{new_view_digest, proposal_digest, timeout_digest, vote_digest},
    types::{HotStuffHeaderSeal, HotStuffNodeHeader, Proposal, QuorumCertificate, Vote, VoteData},
    HotStuffAction, HotStuffCore, HotStuffError, HotStuffPersistedState, HotStuffStore,
    HotStuffWireMessage, NewView, TimeoutCertificate, TimeoutData, TimeoutMsg, TimeoutSignature,
    ValidatorSet, ValidatorSignature, ValidatorSigner,
};

#[derive(Debug, Clone)]
enum SimOp {
    Deliver(usize),
    Drop(usize),
    Duplicate(usize),
    LocalTimeout(usize),
    CrashAndRestore(usize),
    ByzantineEquivocate(u64),
}

#[derive(Debug, Clone)]
enum SimMsg {
    Proposal(Proposal),
    Vote(Vote),
    Timeout(TimeoutMsg),
    NewView(NewView),
}

fn arb_sim_op() -> impl Strategy<Value = SimOp> {
    prop_oneof![
        6 => any::<usize>().prop_map(SimOp::Deliver),
        2 => any::<usize>().prop_map(SimOp::Drop),
        1 => any::<usize>().prop_map(SimOp::Duplicate),
        2 => (0usize..3).prop_map(SimOp::LocalTimeout),
        1 => (0usize..3).prop_map(SimOp::CrashAndRestore),
        2 => (0u64..8).prop_map(SimOp::ByzantineEquivocate),
    ]
}

fn deterministic_signers() -> (Vec<ValidatorSigner>, ArcValidatorSet) {
    let signers: Vec<_> = (1u8..=4u8)
        .map(|b| ValidatorSigner::from_bytes([b; 32]).expect("valid secret key"))
        .collect();
    let addrs: Vec<Address> = signers.iter().map(ValidatorSigner::address).collect();
    let vs = std::sync::Arc::new(ValidatorSet::new(0, addrs).expect("valid validator set"));
    (signers, vs)
}

type ArcValidatorSet = std::sync::Arc<ValidatorSet>;

fn synthetic_exec_hash(epoch: u64, view: u64, height: u64, salt: u8) -> B256 {
    let mut buf = [0u8; 32];
    buf[0..8].copy_from_slice(&epoch.to_be_bytes());
    buf[8..16].copy_from_slice(&view.to_be_bytes());
    buf[16..24].copy_from_slice(&height.to_be_bytes());
    buf[31] = salt;
    alloy_primitives::keccak256(buf)
}

fn build_signed_proposal(
    signer: &ValidatorSigner,
    epoch: u64,
    view: u64,
    justify_qc: QuorumCertificate,
    timeout_cert: Option<TimeoutCertificate>,
    is_nil: bool,
    salt: u8,
) -> Proposal {
    let (exec_block_number, exec_block_hash) = if is_nil {
        (justify_qc.exec_block_number, justify_qc.exec_block_hash)
    } else {
        let h = justify_qc.exec_block_number + 1;
        (h, synthetic_exec_hash(epoch, view, h, salt))
    };
    let header = HotStuffNodeHeader {
        epoch,
        view,
        parent_node_hash: justify_qc.node_hash,
        justify_qc_hash: justify_qc.hash(),
        exec_block_hash,
        exec_block_number,
        proposer: signer.address(),
        is_nil,
    };
    let signature = signer.sign_digest(proposal_digest(header.node_hash()));
    Proposal {
        header,
        justify_qc,
        block_rlp: Bytes::new(),
        requests: Vec::new(),
        signature,
        timeout_cert,
    }
}

fn build_signed_vote(signer: &ValidatorSigner, prop: &Proposal) -> Vote {
    let data = VoteData {
        epoch: prop.header.epoch,
        view: prop.header.view,
        node_hash: prop.header.node_hash(),
        exec_block_hash: prop.header.exec_block_hash,
        exec_block_number: prop.header.exec_block_number,
    };
    Vote { signature: signer.sign_digest(vote_digest(&data)), voter: signer.address(), data }
}

struct SimHarness {
    signers: Vec<ValidatorSigner>,
    vs: ArcValidatorSet,
    cores: Vec<HotStuffCore>,
    queue: VecDeque<(usize, SimMsg)>,
    proposals: HashMap<B256, Proposal>,
    pending_children: Vec<HashMap<B256, Vec<Proposal>>>,
    best_qc: QuorumCertificate,
    latest_tc_by_view: HashMap<u64, TimeoutCertificate>,
    proposed_by_node: HashSet<(usize, u64)>,
    honest_votes: HashMap<(usize, u64), B256>,
    committed_by_height: BTreeMap<u64, B256>,
    prev_committed_height: [u64; 3],
    prev_locked_view: [u64; 3],
}

impl SimHarness {
    fn new() -> Self {
        let (signers, vs) = deterministic_signers();
        let genesis = B256::repeat_byte(0x00);
        let cores = (0..3)
            .map(|i| HotStuffCore::new(0, 200, vs.clone(), Some(signers[i].clone()), genesis, 0))
            .collect::<Vec<_>>();
        let best_qc = cores[0].high_qc().clone();
        Self {
            signers,
            vs,
            cores,
            queue: VecDeque::new(),
            proposals: HashMap::new(),
            pending_children: vec![HashMap::new(); 3],
            best_qc,
            latest_tc_by_view: HashMap::new(),
            proposed_by_node: HashSet::new(),
            honest_votes: HashMap::new(),
            committed_by_height: BTreeMap::new(),
            prev_committed_height: [0; 3],
            prev_locked_view: [0; 3],
        }
    }

    fn process_actions(&mut self, node_idx: usize, actions: Vec<HotStuffAction>) {
        // Verify node monotonicity invariants after every transition.
        let locked_view = self.cores[node_idx].locked_qc().view;
        assert!(
            locked_view >= self.prev_locked_view[node_idx],
            "node {node_idx} locked_qc regressed: {locked_view} < {}",
            self.prev_locked_view[node_idx]
        );
        self.prev_locked_view[node_idx] = locked_view;

        let committed_height = self.cores[node_idx].committed_exec().1;
        assert!(
            committed_height >= self.prev_committed_height[node_idx],
            "node {node_idx} committed height regressed: {committed_height} < {}",
            self.prev_committed_height[node_idx]
        );
        self.prev_committed_height[node_idx] = committed_height;

        if self.cores[node_idx].high_qc().view > self.best_qc.view {
            self.best_qc = self.cores[node_idx].high_qc().clone();
        }
        if let Some(tc) = self.cores[node_idx].timeout_cert_for_view(self.cores[node_idx].view()) {
            self.latest_tc_by_view.insert(tc.view, tc);
        }

        for action in actions {
            match action {
                HotStuffAction::NeedBuildProposal {
                    epoch,
                    view,
                    justify_qc,
                    timeout_cert,
                    is_nil,
                } => {
                    if !self.proposed_by_node.insert((node_idx, view)) {
                        continue;
                    }
                    if let Some(tc) = &timeout_cert {
                        self.latest_tc_by_view.insert(tc.view, tc.clone());
                    }
                    self.cores[node_idx].mark_proposed(view);
                    let prop = build_signed_proposal(
                        &self.signers[node_idx],
                        epoch,
                        view,
                        justify_qc,
                        timeout_cert,
                        is_nil,
                        (node_idx as u8) + 1,
                    );
                    self.proposals.insert(prop.header.node_hash(), prop.clone());
                    for target in 0..3 {
                        if target == node_idx {
                            if let Ok(follow) = self.cores[target].on_proposal(&prop) {
                                self.process_actions(target, follow);
                            }
                        } else {
                            self.queue.push_back((target, SimMsg::Proposal(prop.clone())));
                        }
                    }
                }
                HotStuffAction::SendVote { leader: _, vote } => {
                    // Enforce single-vote-per-view per honest validator across all restarts.
                    if let Some(prev_hash) =
                        self.honest_votes.insert((node_idx, vote.data.view), vote.data.node_hash)
                    {
                        assert_eq!(
                            prev_hash, vote.data.node_hash,
                            "HONEST SAFETY VIOLATION: node {node_idx} voted twice in view {}",
                            vote.data.view
                        );
                    }
                    for target in 0..3 {
                        if target == node_idx {
                            if let Ok(follow) = self.cores[target].on_vote(vote.clone()) {
                                self.process_actions(target, follow);
                            }
                        } else {
                            self.queue.push_back((target, SimMsg::Vote(vote.clone())));
                        }
                    }
                }
                HotStuffAction::BroadcastTimeout(msg) => {
                    for target in 0..3 {
                        if target != node_idx {
                            self.queue.push_back((target, SimMsg::Timeout(msg.clone())));
                        }
                    }
                }
                HotStuffAction::SendNewView { leader, new_view } => {
                    if let Some(tc) = &new_view.timeout_cert {
                        self.latest_tc_by_view.insert(tc.view, tc.clone());
                    }
                    for target in 0..3 {
                        if self.signers[target].address() == leader {
                            self.queue.push_back((target, SimMsg::NewView(new_view.clone())));
                        }
                    }
                }
                HotStuffAction::StoreQc(qc) => {
                    if qc.view > self.best_qc.view {
                        self.best_qc = qc;
                    }
                }
                HotStuffAction::BlockCommitted { exec_block_hash, exec_block_number, .. } => {
                    if let Some(existing) =
                        self.committed_by_height.insert(exec_block_number, exec_block_hash)
                    {
                        assert_eq!(
                            existing, exec_block_hash,
                            "AGREEMENT VIOLATION: conflicting blocks committed at height {exec_block_number}"
                        );
                    }
                }
                HotStuffAction::RequestMissingNode { node_hash } => {
                    if let Some(prop) = self.proposals.get(&node_hash).cloned() {
                        self.queue.push_back((node_idx, SimMsg::Proposal(prop)));
                    }
                }
                HotStuffAction::UpdateForkchoice { .. } |
                HotStuffAction::EpochBoundaryFinalized { .. } |
                HotStuffAction::ResetPacemaker { .. } => {}
            }
        }
    }

    fn deliver_msg(&mut self, target: usize, msg: SimMsg) {
        match msg {
            SimMsg::Proposal(prop) => {
                let node_hash = prop.header.node_hash();
                self.proposals.insert(node_hash, prop.clone());
                match self.cores[target].on_proposal(&prop) {
                    Ok(actions) => {
                        self.process_actions(target, actions);
                        if let Some(children) = self.pending_children[target].remove(&node_hash) {
                            for child in children {
                                self.queue.push_front((target, SimMsg::Proposal(child)));
                            }
                        }
                    }
                    Err(HotStuffError::MissingParent(parent_hash)) => {
                        self.pending_children[target].entry(parent_hash).or_default().push(prop);
                        if let Some(parent_prop) = self.proposals.get(&parent_hash).cloned() {
                            self.queue.push_front((target, SimMsg::Proposal(parent_prop)));
                        }
                    }
                    Err(_) => {}
                }
            }
            SimMsg::Vote(vote) => {
                if let Ok(actions) = self.cores[target].on_vote(vote) {
                    self.process_actions(target, actions);
                }
            }
            SimMsg::Timeout(t) => {
                if let Ok(actions) = self.cores[target].on_timeout(t) {
                    self.process_actions(target, actions);
                }
            }
            SimMsg::NewView(nv) => {
                if let Ok(actions) = self.cores[target].on_new_view(nv) {
                    self.process_actions(target, actions);
                }
            }
        }
    }

    fn ensure_node_has_qc_chain(&mut self, target: usize, qc: &QuorumCertificate) {
        let mut stack = Vec::new();
        let mut cursor = qc.node_hash;
        while !self.cores[target].has_node(&cursor) &&
            let Some(prop) = self.proposals.get(&cursor).cloned()
        {
            cursor = prop.header.parent_node_hash;
            stack.push(prop);
            if stack.len() > 64 {
                break;
            }
        }
        while let Some(prop) = stack.pop() {
            if let Ok(actions) = self.cores[target].on_proposal(&prop) {
                self.process_actions(target, actions);
            }
        }
    }

    fn byzantine_equivocate(&mut self, view_offset: u64) {
        // Pick a view >= best_qc.view + 1 where validator 3 is leader so its proposals have a valid
        // leader signature and attempt to split honest nodes {0} vs {1, 2}.
        let base_view = self.best_qc.view + 1 + view_offset;
        let rem = base_view % 4;
        let target_view = if rem <= 3 { base_view + (3 - rem) } else { base_view + 4 };
        let tc = if target_view > self.best_qc.view + 1 {
            let Some(tc) = self.latest_tc_by_view.get(&(target_view - 1)).cloned() else {
                // If no TC is available for a gap view, equivocate as Byzantine voter on active
                // views instead, plus send an uncertified proposal that honest nodes must reject.
                let prop_a = build_signed_proposal(
                    &self.signers[3],
                    0,
                    target_view,
                    self.best_qc.clone(),
                    None,
                    false,
                    0xAA,
                );
                let prop_b = build_signed_proposal(
                    &self.signers[3],
                    0,
                    target_view,
                    self.best_qc.clone(),
                    None,
                    false,
                    0xBB,
                );
                self.queue.push_back((0, SimMsg::Proposal(prop_a.clone())));
                self.queue.push_back((1, SimMsg::Proposal(prop_b.clone())));
                self.queue.push_back((2, SimMsg::Proposal(prop_b.clone())));
                let vote_a = build_signed_vote(&self.signers[3], &prop_a);
                let vote_b = build_signed_vote(&self.signers[3], &prop_b);
                for target in 0..3 {
                    self.queue.push_back((target, SimMsg::Vote(vote_a.clone())));
                    self.queue.push_back((target, SimMsg::Vote(vote_b.clone())));
                }
                return;
            };
            Some(tc)
        } else {
            None
        };

        let prop_a = build_signed_proposal(
            &self.signers[3],
            0,
            target_view,
            self.best_qc.clone(),
            tc.clone(),
            false,
            0xAA,
        );
        let prop_b = build_signed_proposal(
            &self.signers[3],
            0,
            target_view,
            self.best_qc.clone(),
            tc,
            false,
            0xBB,
        );
        self.proposals.insert(prop_a.header.node_hash(), prop_a.clone());
        self.proposals.insert(prop_b.header.node_hash(), prop_b.clone());

        self.queue.push_back((0, SimMsg::Proposal(prop_a.clone())));
        self.queue.push_back((1, SimMsg::Proposal(prop_b.clone())));
        self.queue.push_back((2, SimMsg::Proposal(prop_b.clone())));

        let vote_a = build_signed_vote(&self.signers[3], &prop_a);
        let vote_b = build_signed_vote(&self.signers[3], &prop_b);
        for target in 0..3 {
            self.queue.push_back((target, SimMsg::Vote(vote_a.clone())));
            self.queue.push_back((target, SimMsg::Vote(vote_b.clone())));
        }
    }

    fn sync_and_drive_liveness(&mut self, min_additional_commits: u64) {
        let initial_min_commit = self.cores.iter().map(|c| c.committed_exec().1).min().unwrap_or(0);
        let target_commit = initial_min_commit + min_additional_commits;

        for _round in 0..96 {
            // Drain queued messages reliably; fulfill missing ancestor requests on the spot.
            let mut drained = 0usize;
            while let Some((target, msg)) = self.queue.pop_front() {
                self.deliver_msg(target, msg);
                drained += 1;
                if drained > 512 {
                    break;
                }
            }

            if self.cores.iter().all(|c| c.committed_exec().1 >= target_commit) {
                break;
            }

            // Bring all honest nodes' QC ancestry and views in sync via NewView, advancing stalled
            // or Byzantine-led views cleanly via Pacemaker timeout.
            let qc_snapshot = self.best_qc.clone();
            for target in 0..3 {
                self.ensure_node_has_qc_chain(target, &qc_snapshot);
            }

            let max_view = self.cores.iter().map(HotStuffCore::view).max().unwrap_or(1);
            let tc_for_max = self
                .cores
                .iter()
                .find_map(|c| c.timeout_cert_for_view(max_view))
                .or_else(|| self.latest_tc_by_view.get(&(max_view.saturating_sub(1))).cloned());

            for sender in 0..3 {
                let nv = NewView {
                    epoch: 0,
                    new_view: max_view,
                    high_qc: self.best_qc.clone(),
                    sender: self.signers[sender].address(),
                    signature: self.signers[sender].sign_digest(new_view_digest(
                        0,
                        max_view,
                        self.best_qc.hash(),
                    )),
                    timeout_cert: tc_for_max.clone(),
                };
                for target in 0..3 {
                    if let Ok(actions) = self.cores[target].on_new_view(nv.clone()) {
                        self.process_actions(target, actions);
                    }
                }
            }

            let min_view = self.cores.iter().map(HotStuffCore::view).min().unwrap_or(1);
            if self.queue.is_empty() ||
                min_view < self.cores.iter().map(HotStuffCore::view).max().unwrap_or(1)
            {
                for i in 0..3 {
                    let actions = self.cores[i].on_local_timeout();
                    self.process_actions(i, actions);
                }
            }
        }

        // Drain any trailing votes/commits after the final round.
        let mut tail = 0usize;
        while let Some((target, msg)) = self.queue.pop_front() {
            self.deliver_msg(target, msg);
            tail += 1;
            if tail > 512 {
                break;
            }
        }

        for (i, core) in self.cores.iter().enumerate() {
            assert!(
                core.committed_exec().1 >= target_commit,
                "post-GST liveness failure on node {i}: committed {} < expected {target_commit} (view={}, high_qc_v={}, locked_qc_v={}, best_qc_v={}, queue_len={})",
                core.committed_exec().1,
                core.view(),
                core.high_qc().view,
                core.locked_qc().view,
                self.best_qc.view,
                self.queue.len(),
            );
        }
    }
}

fn form_qc(signers: &[ValidatorSigner], prop: &Proposal) -> QuorumCertificate {
    let data = VoteData {
        epoch: prop.header.epoch,
        view: prop.header.view,
        node_hash: prop.header.node_hash(),
        exec_block_hash: prop.header.exec_block_hash,
        exec_block_number: prop.header.exec_block_number,
    };
    let digest = vote_digest(&data);
    let signatures = signers[..3]
        .iter()
        .map(|s| ValidatorSignature { signer: s.address(), signature: s.sign_digest(digest) })
        .collect();
    QuorumCertificate {
        epoch: prop.header.epoch,
        view: prop.header.view,
        node_hash: prop.header.node_hash(),
        exec_block_hash: prop.header.exec_block_hash,
        exec_block_number: prop.header.exec_block_number,
        signatures,
    }
}

fn form_tc(signers: &[ValidatorSigner], epoch: u64, view: u64) -> TimeoutCertificate {
    let data = TimeoutData { epoch, view, high_qc_view: 0 };
    let digest = timeout_digest(&data);
    let signatures = signers[..3]
        .iter()
        .map(|s| TimeoutSignature {
            signer: s.address(),
            signature: s.sign_digest(digest),
            high_qc_view: 0,
        })
        .collect();
    TimeoutCertificate { epoch, view, signatures }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn hotstuff_safety_and_liveness_under_adversarial_network_and_byzantine_leader(
        ops in proptest::collection::vec(arb_sim_op(), 32..72)
    ) {
        let mut sim = SimHarness::new();
        for i in 0..3 {
            let actions = sim.cores[i].start();
            sim.process_actions(i, actions);
        }

        for op in ops {
            match op {
                SimOp::Deliver(idx) => {
                    if !sim.queue.is_empty() {
                        let pick = idx % sim.queue.len();
                        if let Some((target, msg)) = sim.queue.remove(pick) {
                            sim.deliver_msg(target, msg);
                        }
                    }
                }
                SimOp::Drop(idx) => {
                    if !sim.queue.is_empty() {
                        let pick = idx % sim.queue.len();
                        sim.queue.remove(pick);
                    }
                }
                SimOp::Duplicate(idx) => {
                    if !sim.queue.is_empty() && sim.queue.len() < 1024 {
                        let pick = idx % sim.queue.len();
                        if let Some(item) = sim.queue.get(pick).cloned() {
                            sim.queue.push_back(item);
                        }
                    }
                }
                SimOp::LocalTimeout(node_idx) => {
                    let actions = sim.cores[node_idx].on_local_timeout();
                    sim.process_actions(node_idx, actions);
                }
                SimOp::CrashAndRestore(node_idx) => {
                    let prev_voted = sim.cores[node_idx].sync_status();
                    let snap = sim.cores[node_idx].snapshot();
                    let restored = HotStuffCore::from_snapshot(
                        snap,
                        200,
                        sim.vs.clone(),
                        Some(sim.signers[node_idx].clone()),
                    )
                    .expect("snapshot restore must succeed");
                    prop_assert!(
                        restored.committed_exec().1 >= prev_voted.finalized_number,
                        "restored committed height regressed"
                    );
                    sim.cores[node_idx] = restored;
                }
                SimOp::ByzantineEquivocate(offset) => {
                    sim.byzantine_equivocate(offset);
                }
            }
        }

        // GST: network heals and messages flow reliably; verify Liveness recovers cleanly.
        sim.sync_and_drive_liveness(2);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn hotstuff_three_chain_commit_only_on_strictly_consecutive_views(
        gaps in proptest::collection::vec(1u64..=4u64, 6..18)
    ) {
        let (signers, vs) = deterministic_signers();
        let genesis = B256::repeat_byte(0x00);
        let mut core = HotStuffCore::new(0, 200, vs, Some(signers[0].clone()), genesis, 0);

        let mut qc = core.high_qc().clone();
        let mut prev_view = 0u64;
        let mut certified_views: HashMap<u64, B256> = HashMap::new();
        let mut expected_commits: HashMap<u64, B256> = HashMap::new();
        let mut window: Vec<(u64, B256)> = Vec::new();

        for (step, gap) in gaps.into_iter().enumerate() {
            let view = prev_view + gap;
            let tc = (view > qc.view + 1).then(|| form_tc(&signers, 0, view - 1));
            let proposer = &signers[(view as usize) % signers.len()];
            let prop = build_signed_proposal(
                proposer,
                0,
                view,
                qc,
                tc,
                false,
                (step as u8) + 1,
            );
            core.on_proposal(&prop).expect("proposal accepted");
            let next_qc = form_qc(&signers, &prop);
            certified_views.insert(view, prop.header.exec_block_hash);

            window.push((view, prop.header.exec_block_hash));
            if window.len() >= 3 {
                let n = window.len();
                let (v0, h0) = window[n - 3];
                let (v1, _) = window[n - 2];
                let (v2, _) = window[n - 1];
                if v1 == v0 + 1 && v2 == v1 + 1 {
                    expected_commits.insert(v0, h0);
                }
            }

            let actions = core.apply_synced_block(prop.header, next_qc.clone()).expect("qc applied");
            for action in actions {
                if let HotStuffAction::BlockCommitted { view: committed_v, exec_block_hash, .. } =
                    action
                {
                    let backed_by_three_chain = window.windows(3).any(|w| {
                        w[1].0 == w[0].0 + 1 && w[2].0 == w[1].0 + 1 && w[0].0 >= committed_v
                    });
                    prop_assert!(
                        certified_views.get(&committed_v) == Some(&exec_block_hash) &&
                            backed_by_three_chain,
                        "committed view {committed_v} without a 3-chain on strictly consecutive views"
                    );
                    expected_commits.remove(&committed_v);
                }
            }

            qc = next_qc;
            prev_view = view;
        }

        prop_assert!(
            expected_commits.is_empty(),
            "missed expected 3-chain commits at consecutive views: {expected_commits:?}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn hotstuff_wire_message_decode_never_panics_on_arbitrary_bytes(
        raw in proptest::collection::vec(any::<u8>(), 0..2048)
    ) {
        if let Ok(seal) = HotStuffHeaderSeal::decode(&raw) {
            let reencoded = seal.encode();
            prop_assert_eq!(
                HotStuffHeaderSeal::decode(&reencoded).expect("re-encoded seal must decode"),
                seal
            );
        }

        if let Ok(msg) = HotStuffWireMessage::decode(&raw) {
            let reencoded = msg.encode().expect("decoded wire msg must re-encode cleanly");
            prop_assert_eq!(
                HotStuffWireMessage::decode(&reencoded).expect("re-encoded wire msg must decode"),
                msg
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn hotstuff_wal_and_qc_jsonl_parser_never_panics_on_corrupted_bytes(
        wal_bytes in proptest::collection::vec(any::<u8>(), 0..512),
        certs_bytes in proptest::collection::vec(any::<u8>(), 0..512),
        qc_jsonl_bytes in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = HotStuffStore::open(tmp.path()).expect("open store");
        let dir = store.dir();

        std::fs::write(dir.join("consensus_state.json"), &wal_bytes).expect("write wal");
        std::fs::write(dir.join("epoch_certs.json"), &certs_bytes).expect("write certs");
        std::fs::write(dir.join("qcs_epoch_0.jsonl"), &qc_jsonl_bytes).expect("write qcs");

        let _ = store.load_state();
        let _ = store.load_epoch_certs();
        let _ = store.load_epoch_block_qcs(0);

        // Smoke-check zero-allocation version rejection type remains usable.
        let _: Option<HotStuffPersistedState> = None;
    }
}
