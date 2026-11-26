//! Error types for the `HotStuff` BFT consensus crate.

use alloy_primitives::{Address, B256};

/// Errors produced during `HotStuff` validation, cryptography, networking, or execution driving.
#[derive(Debug, Clone, thiserror::Error)]
pub enum HotStuffError {
    /// Block header `extra_data` does not have the expected 32-byte `HotStuff` seal length.
    #[error("invalid HotStuff seal length: expected {expected}, got {got}")]
    InvalidSealLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },

    /// Block header `extra_data` does not start with the `HotStuff` magic bytes.
    #[error("invalid HotStuff seal magic: {0:?}")]
    InvalidSealMagic([u8; 4]),

    /// Signature verification failed or signature recovery failed.
    #[error("invalid secp256k1 signature: {0}")]
    InvalidSignature(String),

    /// Proposal proposer does not match the expected round-robin leader for the view.
    #[error("invalid proposer for epoch {epoch} view {view}: expected {expected}, got {got}")]
    InvalidProposer {
        /// Epoch number.
        epoch: u64,
        /// View number.
        view: u64,
        /// Expected leader address.
        expected: Address,
        /// Actual proposer address.
        got: Address,
    },

    /// Signer is not an active validator in the target epoch validator set.
    #[error("address {address} is not a validator in epoch {epoch}")]
    NonValidator {
        /// Epoch number.
        epoch: u64,
        /// Address that attempted to sign.
        address: Address,
    },

    /// A certificate contains multiple signatures from the same validator.
    #[error("duplicate signer {0} in certificate")]
    DuplicateSigner(Address),

    /// A certificate does not meet the `2f + 1` quorum threshold.
    #[error("insufficient quorum: need {required}, got {got}")]
    InsufficientQuorum {
        /// Required quorum size.
        required: usize,
        /// Actual distinct valid signature count.
        got: usize,
    },

    /// Message or block epoch does not match the expected epoch.
    #[error("epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch {
        /// Expected epoch.
        expected: u64,
        /// Actual epoch.
        got: u64,
    },

    /// View number violates `HotStuff` monotonicity or progression rules.
    #[error("invalid view {view}: {reason}")]
    InvalidView {
        /// View number involved.
        view: u64,
        /// Reason the view is invalid.
        reason: &'static str,
    },

    /// Proposal violates the Chained `HotStuff` `SafeNode` rule or NIL-suffix rule.
    #[error("HotStuff safety violation: {0}")]
    SafetyViolation(&'static str),

    /// Referenced parent `HotStuff` node is not yet known locally.
    #[error("missing parent HotStuff node {0}")]
    MissingParent(B256),

    /// View jump requires a valid `TimeoutCertificate` for `view - 1`.
    #[error("missing timeout certificate for view {0}")]
    MissingTimeoutCertificate(u64),

    /// Proposed execution block hash or number does not match the decoded payload.
    #[error("invalid execution block binding: {0}")]
    InvalidBlockHash(String),

    /// Validator set is empty, contains duplicates, exceeds limits, or has a mismatched prefix.
    #[error("invalid validator set: {0}")]
    InvalidValidatorSet(String),

    /// RLP decoding error.
    #[error("RLP decode error: {0}")]
    RlpDecode(String),

    /// Wire message exceeds the maximum allowed byte length.
    #[error("HotStuff wire message too large: {size} > {max}")]
    MessageTooLarge {
        /// Actual payload size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },

    /// State provider error when reading on-chain validator registry state.
    #[error("state provider error: {0}")]
    StateProvider(String),

    /// Consensus engine API error when submitting or finalizing payloads.
    #[error("engine error: {0}")]
    Engine(String),

    /// Payload builder error when constructing a proposed execution block.
    #[error("payload build error: {0}")]
    PayloadBuild(String),

    /// Consensus WAL or persisted QC storage error.
    #[error("HotStuff storage error: {0}")]
    Storage(String),

    /// Catch-all error for unexpected internal failures.
    #[error("{0}")]
    Other(String),
}
