//! Chained `HotStuff` (3-chain) BFT consensus engine for Reth.
//!
//! Provides:
//! - [`HotStuffCore`] — deterministic Chained `HotStuff` state machine with 3-chain commit and
//!   Pacemaker exponential-backoff view change.
//! - [`HotStuffConsensus`] — Reth [`Consensus`](reth_consensus::Consensus) and
//!   [`HeaderValidator`](reth_consensus::HeaderValidator) validating 32-byte [`HotStuffHeaderSeal`]
//!   metadata, round-robin leaders, and epoch transitions.
//! - [`HotStuffPayloadBuilder`] — Reth
//!   [`PayloadBuilder`](reth_basic_payload_builder::PayloadBuilder) injecting per-block `HotStuff`
//!   seals into `header.extra_data`.
//! - [`HotStuffRlpxHandler`] — `RLPx` `hotstuff/1` subprotocol for real multi-node P2P consensus.
//! - [`HotStuffDriver`] and [`HotStuffNode`] — full Reth node integration with dynamic epoch
//!   validator reconfiguration from on-chain state.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod config;
pub mod consensus;
pub mod crypto;
pub mod driver;
pub mod error;
pub mod network;
pub mod node;
pub mod payload;
pub mod state_machine;
pub mod storage;
pub mod types;
pub mod validator;

pub use config::HotStuffConfig;
pub use consensus::{HotStuffConsensus, QcStore};
pub use crypto::ValidatorSigner;
pub use driver::HotStuffDriver;
pub use error::HotStuffError;
pub use network::{
    HotStuffNetworkBridge, HotStuffPeerEvent, HotStuffRlpxHandler, HotStuffWireMessage,
};
pub use node::{
    HotStuffConsensusBuilder, HotStuffNetworkBuilder, HotStuffNode, HotStuffNodeContext,
    HotStuffPayloadBuilderBuilder,
};
pub use payload::{HotStuffPayloadBuilder, HotStuffSealStore};
pub use state_machine::{HotStuffAction, HotStuffCore};
pub use storage::{BlockQcRecord, HotStuffPersistedState, HotStuffStore, HOTSTUFF_WAL_VERSION};
pub use types::{
    EpochChangeCert, HotStuffHeaderSeal, HotStuffNodeHeader, HotStuffSignature, NewView, PeerHello,
    Proposal, QuorumCertificate, SyncBlocksRequest, SyncBlocksResponse, SyncStatus, SyncedBlock,
    TimeoutCertificate, TimeoutData, TimeoutMsg, TimeoutSignature, ValidatorSignature, Vote,
    VoteData, HOTSTUFF_SEAL_LEN, HOTSTUFF_SEAL_MAGIC, MAX_HOTSTUFF_MESSAGE_SIZE, MAX_SYNC_BATCH,
    MAX_VALIDATORS,
};
pub use validator::{
    encode_set_validators_calldata, encode_validator_registry_storage,
    read_validator_set_from_state, set_validators_selector, validator_registry_bytecode,
    EpochManager, ValidatorSet, DEFAULT_VALIDATOR_REGISTRY_ADDRESS,
};
