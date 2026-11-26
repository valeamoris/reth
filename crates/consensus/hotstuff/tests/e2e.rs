//! Multi-node end-to-end tests for Chained `HotStuff` BFT consensus in Reth.

use alloy_consensus::BlockHeader;
use alloy_genesis::GenesisAccount;
use alloy_primitives::{bytes::BytesMut, Address, Bytes, B256, U256};
use alloy_rlp::{Decodable, Encodable};
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadSidecar, ForkchoiceState,
};
use parking_lot::Mutex;
use reth_chainspec::{ChainSpec, ChainSpecBuilder, EthereumHardfork, MAINNET};
use reth_consensus_hotstuff::{
    crypto::{peer_hello_digest, proposal_digest, vote_digest},
    encode_set_validators_calldata, encode_validator_registry_storage, validator_registry_bytecode,
    HotStuffConfig, HotStuffHeaderSeal, HotStuffNode, HotStuffNodeHeader, HotStuffPeerEvent,
    HotStuffStore, HotStuffWireMessage, PeerHello, Proposal, QuorumCertificate, ValidatorSet,
    ValidatorSignature, ValidatorSigner, Vote, VoteData, DEFAULT_VALIDATOR_REGISTRY_ADDRESS,
};
use reth_e2e_test_utils::{
    test_genesis,
    wait::{assert_holds_for, poll_until},
    E2ETestSetupExt, NodeHelperType,
};
use reth_ethereum_engine_primitives::EthPayloadAttributes;
use reth_ethereum_primitives::Block as EthBlock;
use reth_network_api::{PeerId, PeerKind, Peers, PeersInfo};
use reth_payload_primitives::PayloadKind;
use reth_primitives_traits::SealedBlock;
use reth_provider::StateProviderFactory;
use reth_storage_api::{BlockHashReader, BlockNumReader, BlockReader, HeaderProvider};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::mpsc;

fn make_signers(count: usize) -> (Vec<ValidatorSigner>, Vec<Address>) {
    let signers: Vec<_> = (0..count).map(|_| ValidatorSigner::random()).collect();
    let addrs = signers.iter().map(ValidatorSigner::address).collect();
    (signers, addrs)
}

async fn connect_full_mesh(nodes: &mut [NodeHelperType<HotStuffNode>]) {
    for i in 0..nodes.len() {
        for j in (i + 1)..nodes.len() {
            let (left, right) = nodes.split_at_mut(j);
            left[i].connect(&mut right[0]).await;
        }
    }
}

async fn wait_for_finalized_number(
    nodes: &[NodeHelperType<HotStuffNode>],
    target_number: u64,
    what: &str,
) -> eyre::Result<B256> {
    poll_until(what.to_string(), || async {
        for node in nodes {
            let fcu = node.current_forkchoice_state()?;
            if fcu.finalized_block_hash.is_zero() {
                return Ok(None);
            }
            let Some(header) =
                node.inner.provider.sealed_header_by_hash(fcu.finalized_block_hash)?
            else {
                return Ok(None);
            };
            if header.number < target_number {
                return Ok(None);
            }
        }

        let target_hash = nodes[0]
            .inner
            .provider
            .block_hash(target_number)?
            .ok_or_else(|| eyre::eyre!("missing block {target_number} on node 0"))?;
        for node in &nodes[1..] {
            if node.inner.provider.block_hash(target_number)? != Some(target_hash) {
                return Ok(None);
            }
        }
        Ok(Some(target_hash))
    })
    .await
}

fn spawn_hotstuff_nodes(
    hotstuff_nodes: &[HotStuffNode],
    test_nodes: &[NodeHelperType<HotStuffNode>],
) -> eyre::Result<()> {
    for (hs, node) in hotstuff_nodes.iter().zip(test_nodes.iter()) {
        hs.spawn_driver(&node.inner)?;
    }
    Ok(())
}

#[tokio::test]
async fn four_node_hotstuff_finalizes_blocks_and_executes_transactions() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (signers, validators) = make_signers(4);
    let hotstuff_nodes: Vec<_> = signers
        .into_iter()
        .map(|signer| {
            let cfg = HotStuffConfig::new(validators.clone())
                .with_epoch_length(20)
                .with_view_timeout(Duration::from_secs(3))
                .with_block_time(Duration::from_millis(100))
                .with_payload_wait_time(Duration::from_millis(20))
                .with_signer(Some(signer));
            HotStuffNode::new(cfg).unwrap()
        })
        .collect();

    let factories = hotstuff_nodes.clone();
    let (mut nodes, wallet) = HotStuffNode::test_setup_for(EthereumHardfork::Cancun)
        .with_num_nodes(4)
        .with_connect_nodes(false)
        .with_node(move |idx| factories[idx].clone())
        .build()
        .await?;

    connect_full_mesh(&mut nodes).await;
    spawn_hotstuff_nodes(&hotstuff_nodes, &nodes)?;

    let recipient = Address::with_last_byte(0x99);
    let transfer_amount = U256::from(1_000_000_000_000_000u64);
    let mut account = wallet.account(0);
    let raw_tx = account.transfer(recipient, transfer_amount).await;
    let tx_hash = nodes[0].rpc.inject_tx(raw_tx).await?;

    // Wait for transaction inclusion and HotStuff 3-chain finalization across all 4 nodes.
    let included_block = poll_until("transaction receipt and 3-chain finalization", || async {
        let mut included_num = None;
        for node in &nodes {
            let Some(block_info) = node
                .inner
                .provider
                .block_by_hash(node.current_forkchoice_state()?.finalized_block_hash)?
            else {
                return Ok(None);
            };
            let _ = block_info;
            let best = node.inner.provider.best_block_number()?;
            for num in 1..=best {
                if let Some(block) = node.inner.provider.block_by_number(num)? &&
                    block.body.transactions.iter().any(|t| *t.tx_hash() == tx_hash)
                {
                    included_num = Some(num);
                    break;
                }
            }
        }
        let Some(num) = included_num else {
            return Ok(None);
        };
        for node in &nodes {
            let fcu = node.current_forkchoice_state()?;
            let Some(fin) = node.inner.provider.sealed_header_by_hash(fcu.finalized_block_hash)?
            else {
                return Ok(None);
            };
            if fin.number < num {
                return Ok(None);
            }
        }
        Ok(Some(num))
    })
    .await?;

    let expected_hash = nodes[0].block_hash(included_block);
    for (idx, node) in nodes.iter().enumerate() {
        assert_eq!(
            node.block_hash(included_block),
            expected_hash,
            "node {idx} diverged at finalized block {included_block}"
        );
        let state = node.inner.provider.state_by_block_hash(expected_hash)?;
        let balance = state.account_balance(&recipient)?;
        assert_eq!(balance, Some(transfer_amount), "node {idx} balance mismatch");
    }

    Ok(())
}

#[tokio::test]
async fn hotstuff_pacemaker_survives_offline_validator() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // 4 validators configured, only 3 online (f = 1 tolerated).
    let (signers, validators) = make_signers(4);
    let hotstuff_nodes: Vec<_> = signers
        .into_iter()
        .take(3)
        .map(|signer| {
            let cfg = HotStuffConfig::new(validators.clone())
                .with_epoch_length(20)
                .with_view_timeout(Duration::from_millis(600))
                .with_max_view_timeout(Duration::from_secs(4))
                .with_block_time(Duration::from_millis(80))
                .with_payload_wait_time(Duration::from_millis(20))
                .with_signer(Some(signer));
            HotStuffNode::new(cfg).unwrap()
        })
        .collect();

    let factories = hotstuff_nodes.clone();
    let (mut nodes, _) = HotStuffNode::test_setup_for(EthereumHardfork::Cancun)
        .with_num_nodes(3)
        .with_connect_nodes(false)
        .with_node(move |idx| factories[idx].clone())
        .build()
        .await?;

    connect_full_mesh(&mut nodes).await;
    spawn_hotstuff_nodes(&hotstuff_nodes, &nodes)?;

    // Must finalize past block 4 (crosses the offline 4th validator's leader views via Pacemaker
    // TCs).
    wait_for_finalized_number(&nodes, 4, "3 online nodes finalizing block 4 past offline leader")
        .await?;

    Ok(())
}

#[tokio::test]
async fn dynamic_validator_set_rotates_on_epoch_boundary() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (signers, all_validators) = make_signers(5);
    let initial_validators = all_validators[0..4].to_vec();
    let rotated_validators =
        vec![all_validators[0], all_validators[1], all_validators[2], all_validators[4]];

    let mut genesis = test_genesis();
    let wallet = reth_e2e_test_utils::wallet::Wallet::default();
    let admin = wallet.account(0).address();

    genesis.alloc.insert(
        DEFAULT_VALIDATOR_REGISTRY_ADDRESS,
        GenesisAccount {
            code: Some(validator_registry_bytecode()),
            storage: Some(encode_validator_registry_storage(&initial_validators, Some(admin))),
            ..Default::default()
        },
    );

    let chain_spec: Arc<ChainSpec> = Arc::new(
        ChainSpecBuilder::default()
            .chain(MAINNET.chain)
            .genesis(genesis)
            .cancun_activated()
            .build(),
    );

    let epoch_length = 4u64;
    let hotstuff_nodes: Vec<_> = signers
        .into_iter()
        .map(|signer| {
            let cfg = HotStuffConfig::new(initial_validators.clone())
                .with_epoch_length(epoch_length)
                .with_validator_registry(DEFAULT_VALIDATOR_REGISTRY_ADDRESS)
                .with_view_timeout(Duration::from_millis(900))
                .with_block_time(Duration::from_millis(120))
                .with_payload_wait_time(Duration::from_millis(20))
                .with_signer(Some(signer));
            HotStuffNode::new(cfg).unwrap()
        })
        .collect();

    let factories = hotstuff_nodes.clone();
    let (mut nodes, wallet) = HotStuffNode::test_setup(5, chain_spec)
        .with_connect_nodes(false)
        .with_node(move |idx| factories[idx].clone())
        .build()
        .await?;

    connect_full_mesh(&mut nodes).await;

    // Submit setValidators([v0, v1, v2, v4]) into node 0's pool BEFORE starting consensus so it
    // lands in epoch 0 (blocks 1..=4).
    let mut account = wallet.account(0);
    let calldata = encode_set_validators_calldata(&rotated_validators);
    let tx_bytes = account.call(DEFAULT_VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    let tx_hash = nodes[0].rpc.inject_tx(tx_bytes).await?;

    spawn_hotstuff_nodes(&hotstuff_nodes, &nodes)?;

    // Wait until epoch 0 boundary (block 4) is finalized and epoch 1 produces finalized blocks
    // signed by rotated_validators (including v4, with v4's block beneficiary appearing).
    let epoch1_hash =
        wait_for_finalized_number(&nodes, 7, "epoch 1 blocks finalized after validator rotation")
            .await?;

    // Verify the registry tx was mined before or at the epoch 0 boundary (block <= 4).
    let mut found_in_epoch0 = false;
    for num in 1..=epoch_length {
        if let Some(block) = nodes[0].inner.provider.block_by_number(num)? &&
            block.body.transactions.iter().any(|t| *t.tx_hash() == tx_hash)
        {
            found_in_epoch0 = true;
            break;
        }
    }
    assert!(found_in_epoch0, "setValidators tx must execute in epoch 0 (blocks 1..=4)");

    // Verify epoch 1 validator set on every node equals rotated_validators (v4 active, v3 removed).
    for (idx, hs) in hotstuff_nodes.iter().enumerate() {
        let vs1 = hs
            .context()
            .epoch_manager()
            .validator_set(1)
            .expect("epoch 1 validator set must be loaded");
        assert_eq!(
            vs1.validators(),
            rotated_validators.as_slice(),
            "node {idx} did not load rotated epoch 1 validator set"
        );
    }

    // Verify all 5 nodes agree on finalized block 7.
    for (idx, node) in nodes.iter().enumerate() {
        assert_eq!(node.block_hash(7), epoch1_hash, "node {idx} diverged at block 7");
    }

    Ok(())
}

#[tokio::test]
async fn validator_crash_restart_recovers_wal_and_resumes_consensus() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (signers, validators) = make_signers(4);
    let epoch_length = 4u64;
    let configs: Arc<Vec<HotStuffConfig>> = Arc::new(
        signers
            .into_iter()
            .map(|signer| {
                HotStuffConfig::new(validators.clone())
                    .with_epoch_length(epoch_length)
                    .with_view_timeout(Duration::from_millis(600))
                    .with_block_time(Duration::from_millis(80))
                    .with_payload_wait_time(Duration::from_millis(20))
                    .with_signer(Some(signer))
            })
            .collect(),
    );

    let latest_nodes: Arc<Mutex<Vec<Option<HotStuffNode>>>> =
        Arc::new(Mutex::new(vec![None; configs.len()]));
    let configs_for_builder = Arc::clone(&configs);
    let latest_for_builder = Arc::clone(&latest_nodes);

    let (mut nodes, _wallet) = HotStuffNode::test_setup_for(EthereumHardfork::Cancun)
        .with_num_nodes(4)
        .with_connect_nodes(false)
        .with_restartable_nodes()
        .with_tree_config_modifier(|c| {
            c.with_persistence_threshold(0).with_memory_block_buffer_target(0)
        })
        .with_node(move |idx| {
            let hs = HotStuffNode::new(configs_for_builder[idx].clone()).unwrap();
            latest_for_builder.lock()[idx] = Some(hs.clone());
            hs
        })
        .build()
        .await?;

    connect_full_mesh(&mut nodes).await;
    for (idx, node) in nodes.iter().enumerate() {
        let hs = latest_nodes.lock()[idx].take().expect("initial HotStuffNode handle");
        hs.spawn_driver(&node.inner)?;
    }

    wait_for_finalized_number(&nodes, 2, "all 4 nodes finalize block 2 before crash").await?;

    // Crash/stop validator 3 cleanly and verify its WAL exists on disk.
    let crashed = nodes.pop().expect("validator 3");
    let stopped = crashed.stop().await?;
    assert!(
        stopped.data_dir().data_dir().join("hotstuff/consensus_state.json").is_file(),
        "consensus WAL file must exist on disk after shutdown"
    );

    // Wait until the 3 remaining nodes observe node 3's disconnect and advance past epoch 0.
    poll_until("remaining nodes notice validator 3 disconnect", || async {
        if nodes.iter().all(|node| node.inner.network.num_connected_peers() == 2) {
            return Ok(Some(()));
        }
        Ok(None)
    })
    .await?;

    wait_for_finalized_number(&nodes, 6, "remaining 3 nodes cross epoch boundary to block 6")
        .await?;

    // Restart validator 3 on the same datadir, recover WAL, and reconnect to peers.
    let mut restarted = stopped.start().await?;
    let restarted_hs = latest_nodes.lock()[3].take().expect("restarted HotStuffNode handle");
    restarted_hs.spawn_driver(&restarted.inner)?;
    for peer in &mut nodes {
        restarted.connect(peer).await;
    }
    nodes.push(restarted);

    let final_hash = wait_for_finalized_number(
        &nodes,
        8,
        "restarted node recovers WAL, catches up, and resumes consensus to block 8",
    )
    .await?;

    for (idx, node) in nodes.iter().enumerate() {
        assert_eq!(node.block_hash(8), final_hash, "node {idx} diverged at block 8");
    }
    assert!(
        restarted_hs.context().epoch_manager().validator_set(1).is_some(),
        "restarted node must load epoch 1 validator set after recovery"
    );

    Ok(())
}

#[tokio::test]
async fn late_joining_node_syncs_across_multiple_epochs() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (signers, all_validators) = make_signers(5);
    let initial_validators = all_validators[0..4].to_vec();
    let rotated_validators =
        vec![all_validators[0], all_validators[1], all_validators[2], all_validators[4]];

    let mut genesis = test_genesis();
    let wallet = reth_e2e_test_utils::wallet::Wallet::default();
    let admin = wallet.account(0).address();

    genesis.alloc.insert(
        DEFAULT_VALIDATOR_REGISTRY_ADDRESS,
        GenesisAccount {
            code: Some(validator_registry_bytecode()),
            storage: Some(encode_validator_registry_storage(&initial_validators, Some(admin))),
            ..Default::default()
        },
    );

    let chain_spec: Arc<ChainSpec> = Arc::new(
        ChainSpecBuilder::default()
            .chain(MAINNET.chain)
            .genesis(genesis)
            .cancun_activated()
            .build(),
    );

    let epoch_length = 4u64;
    let hotstuff_nodes: Vec<_> = signers
        .into_iter()
        .map(|signer| {
            let cfg = HotStuffConfig::new(initial_validators.clone())
                .with_epoch_length(epoch_length)
                .with_validator_registry(DEFAULT_VALIDATOR_REGISTRY_ADDRESS)
                .with_view_timeout(Duration::from_millis(800))
                .with_block_time(Duration::from_millis(100))
                .with_payload_wait_time(Duration::from_millis(20))
                .with_signer(Some(signer));
            HotStuffNode::new(cfg).unwrap()
        })
        .collect();

    let factories = hotstuff_nodes.clone();
    let (mut nodes, wallet) = HotStuffNode::test_setup(5, chain_spec.clone())
        .with_connect_nodes(false)
        .with_node(move |idx| factories[idx].clone())
        .build()
        .await?;

    connect_full_mesh(&mut nodes).await;

    // Submit validator rotation tx to all initial validators so it commits inside epoch 0 (1..=4).
    let mut account = wallet.account(0);
    let calldata = encode_set_validators_calldata(&rotated_validators);
    let tx_bytes = account.call(DEFAULT_VALIDATOR_REGISTRY_ADDRESS, calldata).await;
    for node in &nodes[0..4] {
        let _ = node.rpc.inject_tx(tx_bytes.clone()).await;
    }

    spawn_hotstuff_nodes(&hotstuff_nodes, &nodes)?;

    // Advance the cluster through Epoch 0 (1..=4) and Epoch 1 (5..=8) well into Epoch 2 (>= 10).
    let cluster_hash_10 =
        wait_for_finalized_number(&nodes, 10, "cluster advances across 3 epochs to block 10")
            .await?;

    // Launch a brand-new late-joining non-validator node from genesis on the same chain spec.
    let late_cfg = HotStuffConfig::new(initial_validators)
        .with_epoch_length(epoch_length)
        .with_validator_registry(DEFAULT_VALIDATOR_REGISTRY_ADDRESS)
        .with_view_timeout(Duration::from_millis(800))
        .with_block_time(Duration::from_millis(100))
        .with_payload_wait_time(Duration::from_millis(20))
        .with_signer(None);
    let late_hs = HotStuffNode::new(late_cfg)?;
    let late_hs_clone = late_hs.clone();

    let (mut late_node, _late_wallet) = HotStuffNode::test_setup(1, chain_spec)
        .with_connect_nodes(false)
        .with_node(move |_| late_hs_clone.clone())
        .build_single()
        .await?;
    late_hs.spawn_driver(&late_node.inner)?;

    for peer in &mut nodes {
        late_node.connect(peer).await;
    }

    let late_hash_10 = wait_for_finalized_number(
        std::slice::from_ref(&late_node),
        10,
        "late-joining node syncs across epochs 0, 1, and 2 to block 10",
    )
    .await?;

    assert_eq!(late_hash_10, cluster_hash_10, "late joiner finalized block 10 mismatch");
    assert_eq!(
        late_node.block_hash(4),
        nodes[0].block_hash(4),
        "epoch 0 boundary block 4 mismatch"
    );
    assert_eq!(
        late_node.block_hash(8),
        nodes[0].block_hash(8),
        "epoch 1 boundary block 8 mismatch"
    );

    let vs1 = late_hs
        .context()
        .epoch_manager()
        .validator_set(1)
        .expect("late joiner must derive epoch 1 validator set during catch-up");
    assert_eq!(vs1.validators(), rotated_validators.as_slice());

    let vs2 = late_hs
        .context()
        .epoch_manager()
        .validator_set(2)
        .expect("late joiner must derive epoch 2 validator set during catch-up");
    assert_eq!(vs2.validators(), rotated_validators.as_slice());

    Ok(())
}

#[tokio::test]
async fn wal_persistence_failure_halts_driver_fail_closed() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (signers, validators) = make_signers(4);
    let configs: Arc<Vec<HotStuffConfig>> = Arc::new(
        signers
            .into_iter()
            .map(|signer| {
                HotStuffConfig::new(validators.clone())
                    .with_epoch_length(20)
                    .with_view_timeout(Duration::from_millis(600))
                    .with_block_time(Duration::from_millis(80))
                    .with_payload_wait_time(Duration::from_millis(20))
                    .with_signer(Some(signer))
            })
            .collect(),
    );

    let latest_nodes: Arc<Mutex<Vec<Option<HotStuffNode>>>> =
        Arc::new(Mutex::new(vec![None; configs.len()]));
    let configs_for_builder = Arc::clone(&configs);
    let latest_for_builder = Arc::clone(&latest_nodes);

    let (mut nodes, _wallet) = HotStuffNode::test_setup_for(EthereumHardfork::Cancun)
        .with_num_nodes(4)
        .with_connect_nodes(false)
        .with_restartable_nodes()
        .with_tree_config_modifier(|c| {
            c.with_persistence_threshold(0).with_memory_block_buffer_target(0)
        })
        .with_node(move |idx| {
            let hs = HotStuffNode::new(configs_for_builder[idx].clone()).unwrap();
            latest_for_builder.lock()[idx] = Some(hs.clone());
            hs
        })
        .build()
        .await?;

    connect_full_mesh(&mut nodes).await;
    for (idx, node) in nodes.iter().enumerate() {
        let hs = latest_nodes.lock()[idx].take().expect("initial HotStuffNode handle");
        hs.spawn_driver(&node.inner)?;
    }

    wait_for_finalized_number(&nodes, 2, "all 4 nodes finalize block 2 before WAL fault").await?;

    let crashed = nodes.pop().expect("validator 3");
    let stopped = crashed.stop().await?;
    let wal_dir = stopped.data_dir().data_dir().join("hotstuff");
    let saved_before = HotStuffStore::open(&wal_dir)?.load_state()?.expect("WAL before fault");

    // Inject an atomic_write_file failure by blocking consensus_state.tmp with a directory.
    let blocker_tmp_dir = wal_dir.join("consensus_state.tmp");
    reth_fs_util::create_dir_all(&blocker_tmp_dir)?;

    poll_until("remaining nodes notice validator 3 disconnect", || async {
        if nodes.iter().all(|node| node.inner.network.num_connected_peers() == 2) {
            return Ok(Some(()));
        }
        Ok(None)
    })
    .await?;

    let mut restarted = stopped.start().await?;
    let restarted_hs = latest_nodes.lock()[3].take().expect("restarted HotStuffNode handle");
    restarted_hs.spawn_driver(&restarted.inner)?;
    for peer in &mut nodes {
        restarted.connect(peer).await;
    }

    poll_until("validator 3 halts fail-closed on WAL write error", || async {
        if restarted_hs.context().is_wal_halted() {
            return Ok(Some(()));
        }
        Ok(None)
    })
    .await?;

    // Remaining 3 honest validators must stay live and keep finalizing blocks cleanly.
    wait_for_finalized_number(&nodes, 6, "remaining 3 validators keep finalizing to block 6")
        .await?;

    // Previously committed WAL snapshot must remain intact and uncorrupted on disk.
    let saved_after = HotStuffStore::open(&wal_dir)?.load_state()?.expect("WAL after halt");
    assert_eq!(saved_after, saved_before);

    let _ = reth_fs_util::remove_dir_all(&blocker_tmp_dir);
    Ok(())
}

#[tokio::test]
async fn wal_ahead_of_execution_db_backfills_across_epoch_and_recovers() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (signers, validators) = make_signers(4);
    let epoch_length = 4u64;
    let configs: Arc<Vec<HotStuffConfig>> = Arc::new(
        signers
            .into_iter()
            .map(|signer| {
                HotStuffConfig::new(validators.clone())
                    .with_epoch_length(epoch_length)
                    .with_view_timeout(Duration::from_millis(600))
                    .with_block_time(Duration::from_millis(80))
                    .with_payload_wait_time(Duration::from_millis(20))
                    .with_signer(Some(signer))
            })
            .collect(),
    );

    let latest_nodes: Arc<Mutex<Vec<Option<HotStuffNode>>>> =
        Arc::new(Mutex::new(vec![None; configs.len()]));
    let configs_for_builder = Arc::clone(&configs);
    let latest_for_builder = Arc::clone(&latest_nodes);

    let (mut nodes, _wallet) = HotStuffNode::test_setup_for(EthereumHardfork::Cancun)
        .with_num_nodes(4)
        .with_connect_nodes(false)
        .with_restartable_nodes()
        .with_tree_config_modifier(|c| {
            c.with_persistence_threshold(0).with_memory_block_buffer_target(0)
        })
        .with_node(move |idx| {
            let hs = HotStuffNode::new(configs_for_builder[idx].clone()).unwrap();
            latest_for_builder.lock()[idx] = Some(hs.clone());
            hs
        })
        .build()
        .await?;

    connect_full_mesh(&mut nodes).await;
    for (idx, node) in nodes.iter().enumerate() {
        let hs = latest_nodes.lock()[idx].take().expect("initial HotStuffNode handle");
        hs.spawn_driver(&node.inner)?;
    }

    wait_for_finalized_number(&nodes, 2, "all 4 nodes finalize block 2 before crash").await?;

    // Stop validator 3 while its execution DB is still in epoch 0 (before boundary block 4).
    let crashed = nodes.pop().expect("validator 3");
    let stopped = crashed.stop().await?;

    poll_until("remaining nodes notice validator 3 disconnect", || async {
        if nodes.iter().all(|node| node.inner.network.num_connected_peers() == 2) {
            return Ok(Some(()));
        }
        Ok(None)
    })
    .await?;

    // Advance remaining 3 nodes across epoch 0 boundary (4) into epoch 1 (block 7).
    wait_for_finalized_number(&nodes, 7, "remaining 3 nodes finalize epoch 1 block 7").await?;

    // Simulate power loss where validator 3's WAL flushed ahead to epoch 1 while its MDBX DB
    // remained stuck in epoch 0 (<= block 3) without block 4..=7 or epoch_certs.json.
    let node0_wal_dir = nodes[0].inner.data_dir.data_dir().join("hotstuff");
    let ahead_wal =
        HotStuffStore::open(&node0_wal_dir)?.load_state()?.expect("node 0 epoch 1 WAL state");
    assert!(ahead_wal.epoch >= 1, "expected node 0 WAL in epoch >= 1");
    assert!(ahead_wal.committed_exec_number >= 7, "expected node 0 WAL committed >= 7");

    let node3_wal_dir = stopped.data_dir().data_dir().join("hotstuff");
    HotStuffStore::open(&node3_wal_dir)?.save_state(&ahead_wal)?;

    // Restart validator 3, backfill missing epoch 0 boundary and epoch 1 blocks, and rejoin.
    let mut restarted = stopped.start().await?;
    let restarted_hs = latest_nodes.lock()[3].take().expect("restarted HotStuffNode handle");
    restarted_hs.spawn_driver(&restarted.inner)?;
    for peer in &mut nodes {
        restarted.connect(peer).await;
    }
    nodes.push(restarted);

    let final_hash = wait_for_finalized_number(
        &nodes,
        9,
        "validator 3 backfills execution DB from epoch 0 to WAL tip and finalizes block 9",
    )
    .await?;

    for (idx, node) in nodes.iter().enumerate() {
        assert_eq!(node.block_hash(4), nodes[0].block_hash(4), "node {idx} diverged at block 4");
        assert_eq!(node.block_hash(7), nodes[0].block_hash(7), "node {idx} diverged at block 7");
        assert_eq!(node.block_hash(9), final_hash, "node {idx} diverged at block 9");
    }
    assert!(
        restarted_hs.context().epoch_manager().validator_set(1).is_some(),
        "restarted node must retain epoch 1 validator set"
    );
    let recovered_wal =
        HotStuffStore::open(&node3_wal_dir)?.load_state()?.expect("node 3 WAL after recovery");
    assert!(
        recovered_wal.epoch > ahead_wal.epoch ||
            (recovered_wal.epoch == ahead_wal.epoch &&
                recovered_wal.last_voted_view >= ahead_wal.last_voted_view),
        "WAL safety monotonic guards must not regress across DB backfill"
    );

    Ok(())
}

fn finalized_block_number(node: &NodeHelperType<HotStuffNode>) -> eyre::Result<u64> {
    let fcu = node.current_forkchoice_state()?;
    if fcu.finalized_block_hash.is_zero() {
        return Ok(0);
    }
    Ok(node
        .inner
        .provider
        .sealed_header_by_hash(fcu.finalized_block_hash)?
        .map_or(0, |h| h.number()))
}

async fn partition_groups(
    nodes: &[NodeHelperType<HotStuffNode>],
    group_a: &[usize],
    group_b: &[usize],
) -> eyre::Result<()> {
    for &a in group_a {
        for &b in group_b {
            let rec_a = nodes[a].network.record();
            let rec_b = nodes[b].network.record();
            nodes[a].inner.network.ban_peer(rec_b.id);
            nodes[a].inner.network.remove_peer(rec_b.id, PeerKind::Basic);
            nodes[a].inner.network.remove_peer(rec_b.id, PeerKind::Static);
            nodes[a].inner.network.disconnect_peer(rec_b.id);

            nodes[b].inner.network.ban_peer(rec_a.id);
            nodes[b].inner.network.remove_peer(rec_a.id, PeerKind::Basic);
            nodes[b].inner.network.remove_peer(rec_a.id, PeerKind::Static);
            nodes[b].inner.network.disconnect_peer(rec_a.id);
        }
    }

    let expected_a = group_a.len().saturating_sub(1);
    let expected_b = group_b.len().saturating_sub(1);
    poll_until("partition groups disconnect across boundary", || async {
        let ok_a =
            group_a.iter().all(|&i| nodes[i].inner.network.num_connected_peers() == expected_a);
        let ok_b =
            group_b.iter().all(|&i| nodes[i].inner.network.num_connected_peers() == expected_b);
        if ok_a && ok_b {
            return Ok(Some(()));
        }
        Ok(None)
    })
    .await
}

async fn heal_partition(
    nodes: &[NodeHelperType<HotStuffNode>],
    group_a: &[usize],
    group_b: &[usize],
) -> eyre::Result<()> {
    for &a in group_a {
        for &b in group_b {
            let rec_a = nodes[a].network.record();
            let rec_b = nodes[b].network.record();
            nodes[a].inner.network.unban_peer(rec_b.id);
            nodes[b].inner.network.unban_peer(rec_a.id);
            nodes[a].inner.network.connect_peer(rec_b.id, rec_b.tcp_addr());
        }
    }

    let expected = nodes.len().saturating_sub(1);
    poll_until("healed partition reconnects full mesh", || async {
        if nodes.iter().all(|n| n.inner.network.num_connected_peers() == expected) {
            return Ok(Some(()));
        }
        Ok(None)
    })
    .await
}

#[tokio::test]
async fn network_partition_2_plus_2_halts_finality_and_heals_cleanly() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (signers, validators) = make_signers(4);
    let hotstuff_nodes: Vec<_> = signers
        .into_iter()
        .map(|signer| {
            let cfg = HotStuffConfig::new(validators.clone())
                .with_epoch_length(20)
                .with_view_timeout(Duration::from_millis(500))
                .with_block_time(Duration::from_millis(80))
                .with_payload_wait_time(Duration::from_millis(20))
                .with_signer(Some(signer));
            HotStuffNode::new(cfg).unwrap()
        })
        .collect();

    let factories = hotstuff_nodes.clone();
    let (mut nodes, _wallet) = HotStuffNode::test_setup_for(EthereumHardfork::Cancun)
        .with_num_nodes(4)
        .with_connect_nodes(false)
        .with_node(move |idx| factories[idx].clone())
        .build()
        .await?;

    connect_full_mesh(&mut nodes).await;
    spawn_hotstuff_nodes(&hotstuff_nodes, &nodes)?;

    wait_for_finalized_number(&nodes, 2, "all 4 nodes finalize block 2 before 2+2 partition")
        .await?;

    partition_groups(&nodes, &[0, 1], &[2, 3]).await?;

    let frozen: Vec<u64> =
        nodes.iter().map(finalized_block_number).collect::<eyre::Result<Vec<_>>>()?;

    // Neither 2-validator side has quorum (3), so finality must remain stalled.
    assert_holds_for(
        Duration::from_millis(1200),
        "2+2 partition stalls HotStuff finality",
        || async {
            for (idx, node) in nodes.iter().enumerate() {
                if finalized_block_number(node)? > frozen[idx] {
                    return Ok(false);
                }
            }
            Ok(true)
        },
    )
    .await?;

    heal_partition(&nodes, &[0, 1], &[2, 3]).await?;

    let target = frozen.iter().copied().max().unwrap_or(2) + 4;
    let target_hash =
        wait_for_finalized_number(&nodes, target, "cluster heals and resumes finalization").await?;
    for (idx, node) in nodes.iter().enumerate() {
        assert_eq!(node.block_hash(target), target_hash, "node {idx} diverged after heal");
    }

    Ok(())
}

#[tokio::test]
async fn network_partition_3_plus_1_advances_majority_and_syncs_minority_on_heal(
) -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (signers, validators) = make_signers(4);
    let hotstuff_nodes: Vec<_> = signers
        .into_iter()
        .map(|signer| {
            let cfg = HotStuffConfig::new(validators.clone())
                .with_epoch_length(4)
                .with_view_timeout(Duration::from_millis(500))
                .with_block_time(Duration::from_millis(80))
                .with_payload_wait_time(Duration::from_millis(20))
                .with_signer(Some(signer));
            HotStuffNode::new(cfg).unwrap()
        })
        .collect();

    let factories = hotstuff_nodes.clone();
    let (mut nodes, _wallet) = HotStuffNode::test_setup_for(EthereumHardfork::Cancun)
        .with_num_nodes(4)
        .with_connect_nodes(false)
        .with_node(move |idx| factories[idx].clone())
        .build()
        .await?;

    connect_full_mesh(&mut nodes).await;
    spawn_hotstuff_nodes(&hotstuff_nodes, &nodes)?;

    wait_for_finalized_number(&nodes, 2, "all 4 nodes finalize block 2 before 3+1 partition")
        .await?;

    partition_groups(&nodes, &[0, 1, 2], &[3]).await?;

    // Majority 3/4 crosses epoch 0 boundary (4) into epoch 1 (7).
    wait_for_finalized_number(
        &nodes[..3],
        7,
        "majority 3/4 advances across epoch boundary during 3+1 partition",
    )
    .await?;

    assert!(
        finalized_block_number(&nodes[3])? < 4,
        "isolated minority node must remain behind epoch boundary while partitioned"
    );

    heal_partition(&nodes, &[0, 1, 2], &[3]).await?;

    let final_hash = wait_for_finalized_number(
        &nodes,
        9,
        "minority syncs across epoch boundary and rejoins consensus to block 9",
    )
    .await?;

    for (idx, node) in nodes.iter().enumerate() {
        assert_eq!(node.block_hash(4), nodes[0].block_hash(4), "node {idx} diverged at block 4");
        assert_eq!(node.block_hash(7), nodes[0].block_hash(7), "node {idx} diverged at block 7");
        assert_eq!(node.block_hash(9), final_hash, "node {idx} diverged at block 9");
    }
    assert!(
        hotstuff_nodes[3].context().epoch_manager().validator_set(1).is_some(),
        "rejoined minority node must derive epoch 1 validator set"
    );

    Ok(())
}

#[tokio::test]
async fn byzantine_equivocating_leader_does_not_fork_honest_validators() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (signers, validators) = make_signers(4);
    let vs0 = Arc::new(ValidatorSet::new(0, validators.clone())?);
    let hotstuff_nodes: Vec<_> = signers
        .iter()
        .cloned()
        .map(|signer| {
            let cfg = HotStuffConfig::new(validators.clone())
                .with_epoch_length(20)
                .with_view_timeout(Duration::from_millis(600))
                .with_block_time(Duration::from_millis(80))
                .with_payload_wait_time(Duration::from_millis(20))
                .with_signer(Some(signer));
            HotStuffNode::new(cfg).unwrap()
        })
        .collect();

    let factories = hotstuff_nodes.clone();
    let (mut nodes, _wallet) = HotStuffNode::test_setup_for(EthereumHardfork::Cancun)
        .with_num_nodes(4)
        .with_connect_nodes(false)
        .with_node(move |idx| factories[idx].clone())
        .build()
        .await?;

    // Run real honest HotStuffDrivers on validators 0..3 and a live Byzantine equivocator on node
    // 3.
    let byz_signer = signers[3].clone();
    let mut byz_events = hotstuff_nodes[3].context().take_peer_events().expect("node 3 events");
    let byz_peer_id = *nodes[3].inner.network.peer_id();
    let byz_engine = nodes[3].inner.add_ons_handle.beacon_engine_handle.clone();
    let byz_payload = nodes[3].inner.payload_builder_handle.clone();
    let byz_provider = nodes[3].inner.provider.clone();
    let byz_seal_store = hotstuff_nodes[3].context().seal_store().clone();
    let byz_qc_store = hotstuff_nodes[3].context().qc_store().clone();
    let equivocation_rounds = Arc::new(AtomicUsize::new(0));
    let eq_counter = Arc::clone(&equivocation_rounds);
    let vs0_for_byz = Arc::clone(&vs0);

    let byz_task = tokio::spawn(async move {
        let genesis_hash =
            byz_provider.sealed_header(0).ok().flatten().map_or(B256::ZERO, |h| h.hash());
        let _ = byz_engine
            .fork_choice_updated(
                ForkchoiceState {
                    head_block_hash: genesis_hash,
                    safe_block_hash: genesis_hash,
                    finalized_block_hash: genesis_hash,
                },
                None,
            )
            .await;

        let mut peers: Vec<(PeerId, mpsc::Sender<BytesMut>)> = Vec::new();
        let mut vote_buckets: HashMap<(u64, B256), Vec<ValidatorSignature>> = HashMap::new();
        let mut equivocated_views: HashSet<u64> = HashSet::new();
        let mut buffered_blocks: BTreeMap<u64, (SealedBlock<EthBlock>, QuorumCertificate)> =
            BTreeMap::new();
        let mut imported_height = 0u64;
        let mut pending_qc: Option<QuorumCertificate> = None;

        while let Some(ev) = byz_events.recv().await {
            match ev {
                HotStuffPeerEvent::Connected { peer_id, outbound } => {
                    let hello = PeerHello {
                        validator: byz_signer.address(),
                        peer_id: byz_peer_id,
                        signature: byz_signer
                            .sign_digest(peer_hello_digest(byz_signer.address(), &byz_peer_id)),
                    };
                    if let Ok(frame) = HotStuffWireMessage::Hello(hello).encode() {
                        let _ = outbound.try_send(frame);
                    }
                    peers.push((peer_id, outbound));
                }
                HotStuffPeerEvent::Disconnected { peer_id } => {
                    peers.retain(|(pid, _)| *pid != peer_id);
                }
                HotStuffPeerEvent::Message { message, .. } => match message {
                    HotStuffWireMessage::Proposal(prop) => {
                        if !prop.header.is_nil &&
                            let Ok(block) = EthBlock::decode(&mut prop.block_rlp.as_ref())
                        {
                            let sealed = SealedBlock::seal_slow(block);
                            buffered_blocks
                                .entry(sealed.number())
                                .or_insert((sealed, prop.justify_qc));
                            while let Some((sealed, justify_qc)) =
                                buffered_blocks.remove(&(imported_height + 1))
                            {
                                if justify_qc.view > 0 {
                                    byz_qc_store.insert(justify_qc);
                                }
                                let block_hash = sealed.hash();
                                let block = sealed.into_block();
                                let (payload, _) =
                                    ExecutionPayload::from_block_unchecked_with_extras(
                                        block_hash, &block, None,
                                    );
                                let sidecar = ExecutionPayloadSidecar::v3(CancunPayloadFields {
                                    parent_beacon_block_root: block
                                        .header
                                        .parent_beacon_block_root
                                        .unwrap_or_default(),
                                    versioned_hashes: block
                                        .body
                                        .blob_versioned_hashes_iter()
                                        .copied()
                                        .collect(),
                                });
                                let _ = byz_engine
                                    .new_payload(ExecutionData::new(payload, sidecar))
                                    .await;
                                let _ = byz_engine
                                    .fork_choice_updated(
                                        ForkchoiceState {
                                            head_block_hash: block_hash,
                                            safe_block_hash: block_hash,
                                            finalized_block_hash: genesis_hash,
                                        },
                                        None,
                                    )
                                    .await;
                                imported_height += 1;
                            }
                        }
                    }
                    HotStuffWireMessage::Vote(vote) => {
                        if vote.data.epoch != 0 {
                            continue;
                        }
                        let key = (vote.data.view, vote.data.node_hash);
                        let entry = vote_buckets.entry(key).or_default();
                        if !entry.iter().any(|s| s.signer == vote.voter) {
                            entry.push(ValidatorSignature {
                                signer: vote.voter,
                                signature: vote.signature,
                            });
                        }
                        let target_view = vote.data.view + 1;
                        if entry.len() >= vs0_for_byz.quorum_size() &&
                            vs0_for_byz.leader_for_view(target_view) == byz_signer.address() &&
                            !equivocated_views.contains(&target_view)
                        {
                            pending_qc = Some(QuorumCertificate {
                                epoch: 0,
                                view: vote.data.view,
                                node_hash: vote.data.node_hash,
                                exec_block_hash: vote.data.exec_block_hash,
                                exec_block_number: vote.data.exec_block_number,
                                signatures: entry.clone(),
                            });
                        }
                    }
                    _ => {}
                },
            }

            // Whenever validator 3 is leader for pending_qc.view + 1 and has the parent block,
            // construct TWO conflicting valid Ethereum blocks and equivocate to split peers.
            if peers.len() >= 2 &&
                let Some(qc) = pending_qc.clone()
            {
                let target_view = qc.view + 1;
                if let Ok(Some(parent)) = byz_provider.sealed_header_by_hash(qc.exec_block_hash) {
                    pending_qc = None;
                    equivocated_views.insert(target_view);

                    let seal = HotStuffHeaderSeal {
                        epoch: 0,
                        view: target_view,
                        justify_view: qc.view,
                        validator_set_hash_prefix: vs0_for_byz.hash_prefix(),
                    };
                    let prev_randao = qc.hash();
                    byz_seal_store.insert(parent.hash(), prev_randao, seal.encode());
                    byz_qc_store.insert(qc.clone());

                    let base_ts = parent.timestamp().saturating_add(1);
                    let mut conflicting = Vec::with_capacity(2);
                    for ts_offset in [0u64, 1u64] {
                        let timestamp = base_ts.saturating_add(ts_offset);
                        let attrs = EthPayloadAttributes {
                            timestamp,
                            prev_randao,
                            suggested_fee_recipient: byz_signer.address(),
                            withdrawals: Some(Default::default()),
                            parent_beacon_block_root: Some(qc.node_hash),
                            ..Default::default()
                        };
                        let fcu_state = ForkchoiceState {
                            head_block_hash: parent.hash(),
                            safe_block_hash: parent.hash(),
                            finalized_block_hash: genesis_hash,
                        };
                        if let Ok(fcu_res) =
                            byz_engine.fork_choice_updated(fcu_state, Some(attrs)).await &&
                            let Some(pid) = fcu_res.payload_id
                        {
                            tokio::time::sleep(Duration::from_millis(25)).await;
                            if let Some(Ok(built)) =
                                byz_payload.resolve_kind(pid, PayloadKind::WaitForPending).await
                            {
                                let sealed = built.block();
                                let mut block_rlp = Vec::new();
                                sealed.clone_block().encode(&mut block_rlp);
                                let header = HotStuffNodeHeader {
                                    epoch: 0,
                                    view: target_view,
                                    parent_node_hash: qc.node_hash,
                                    justify_qc_hash: prev_randao,
                                    exec_block_hash: sealed.hash(),
                                    exec_block_number: sealed.number(),
                                    proposer: byz_signer.address(),
                                    is_nil: false,
                                };
                                let signature =
                                    byz_signer.sign_digest(proposal_digest(header.node_hash()));
                                conflicting.push(Proposal {
                                    header,
                                    justify_qc: qc.clone(),
                                    block_rlp: Bytes::from(block_rlp),
                                    requests: Vec::new(),
                                    signature,
                                    timeout_cert: None,
                                });
                            }
                        }
                    }

                    if conflicting.len() == 2 {
                        let prop_a = &conflicting[0];
                        let prop_b = &conflicting[1];
                        if let Ok(frame_a) =
                            HotStuffWireMessage::Proposal(Box::new(prop_a.clone())).encode()
                        {
                            let _ = peers[0].1.try_send(frame_a);
                        }
                        if let Ok(frame_b) =
                            HotStuffWireMessage::Proposal(Box::new(prop_b.clone())).encode()
                        {
                            for (_, outbound) in &peers[1..] {
                                let _ = outbound.try_send(frame_b.clone());
                            }
                        }

                        // Also broadcast conflicting signed votes from validator 3.
                        for prop in [&conflicting[0], &conflicting[1]] {
                            let data = VoteData {
                                epoch: prop.header.epoch,
                                view: prop.header.view,
                                node_hash: prop.header.node_hash(),
                                exec_block_hash: prop.header.exec_block_hash,
                                exec_block_number: prop.header.exec_block_number,
                            };
                            let vote = Vote {
                                signature: byz_signer.sign_digest(vote_digest(&data)),
                                voter: byz_signer.address(),
                                data,
                            };
                            if let Ok(frame) = HotStuffWireMessage::Vote(vote).encode() {
                                for (_, outbound) in &peers {
                                    let _ = outbound.try_send(frame.clone());
                                }
                            }
                        }

                        eq_counter.fetch_add(1, Ordering::Release);
                    }
                }
            }
        }
    });

    connect_full_mesh(&mut nodes).await;
    spawn_hotstuff_nodes(&hotstuff_nodes[..3], &nodes[..3])?;

    poll_until("Byzantine leader equivocates and honest nodes finalize block 8", || async {
        if equivocation_rounds.load(Ordering::Acquire) < 1 {
            return Ok(None);
        }
        for node in &nodes[..3] {
            if finalized_block_number(node)? < 8 {
                return Ok(None);
            }
        }
        Ok(Some(()))
    })
    .await?;

    // Every committed height 1..=8 across honest validators 0, 1, 2 must have zero forks.
    for h in 1..=8 {
        let h0 = nodes[0].block_hash(h);
        assert_eq!(nodes[1].block_hash(h), h0, "honest node 1 forked at height {h}");
        assert_eq!(nodes[2].block_hash(h), h0, "honest node 2 forked at height {h}");
    }

    byz_task.abort();
    Ok(())
}
