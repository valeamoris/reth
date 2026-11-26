//! Configuration for a `HotStuff` consensus node.

use alloy_primitives::Address;
use std::{fmt, path::PathBuf, time::Duration};

use crate::{
    crypto::ValidatorSigner, error::HotStuffError, validator::DEFAULT_VALIDATOR_REGISTRY_ADDRESS,
};

/// Configuration parameters for a `HotStuff` consensus node.
#[derive(Clone)]
pub struct HotStuffConfig {
    /// Number of execution blocks per consensus epoch.
    pub epoch_length: u64,
    /// On-chain `ValidatorRegistry` contract address read at epoch boundaries.
    pub validator_registry: Address,
    /// Initial validator addresses for epoch `0`.
    pub genesis_validators: Vec<Address>,
    /// Base Pacemaker view timeout duration before initiating a view change.
    pub view_timeout: Duration,
    /// Maximum Pacemaker view timeout duration under exponential backoff.
    pub max_view_timeout: Duration,
    /// Target interval between consecutive block proposals when acting as leader.
    pub block_time: Duration,
    /// Optional delay between requesting a payload build and resolving it.
    pub payload_wait_time: Duration,
    /// Validator signing key (`None` runs the node as a non-voting observer).
    pub signer: Option<ValidatorSigner>,
    /// Optional directory for consensus WAL and QC storage (`None` uses `<datadir>/hotstuff`).
    pub storage_dir: Option<PathBuf>,
}

impl fmt::Debug for HotStuffConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HotStuffConfig")
            .field("epoch_length", &self.epoch_length)
            .field("validator_registry", &self.validator_registry)
            .field("genesis_validators", &self.genesis_validators)
            .field("view_timeout", &self.view_timeout)
            .field("max_view_timeout", &self.max_view_timeout)
            .field("block_time", &self.block_time)
            .field("payload_wait_time", &self.payload_wait_time)
            .field("validator_address", &self.signer.as_ref().map(ValidatorSigner::address))
            .field("storage_dir", &self.storage_dir)
            .finish()
    }
}

impl HotStuffConfig {
    /// Creates a new [`HotStuffConfig`] with sensible defaults for the given genesis validators.
    pub const fn new(genesis_validators: Vec<Address>) -> Self {
        Self {
            epoch_length: 100,
            validator_registry: DEFAULT_VALIDATOR_REGISTRY_ADDRESS,
            genesis_validators,
            view_timeout: Duration::from_secs(2),
            max_view_timeout: Duration::from_secs(30),
            block_time: Duration::from_millis(500),
            payload_wait_time: Duration::from_millis(50),
            signer: None,
            storage_dir: None,
        }
    }

    /// Sets the number of execution blocks per consensus epoch.
    pub const fn with_epoch_length(mut self, epoch_length: u64) -> Self {
        self.epoch_length = epoch_length;
        self
    }

    /// Sets the on-chain validator registry contract address.
    pub const fn with_validator_registry(mut self, validator_registry: Address) -> Self {
        self.validator_registry = validator_registry;
        self
    }

    /// Sets the base Pacemaker view timeout.
    pub const fn with_view_timeout(mut self, view_timeout: Duration) -> Self {
        self.view_timeout = view_timeout;
        self
    }

    /// Sets the maximum Pacemaker view timeout under exponential backoff.
    pub const fn with_max_view_timeout(mut self, max_view_timeout: Duration) -> Self {
        self.max_view_timeout = max_view_timeout;
        self
    }

    /// Sets the target interval between block proposals.
    pub const fn with_block_time(mut self, block_time: Duration) -> Self {
        self.block_time = block_time;
        self
    }

    /// Sets the payload build wait duration.
    pub const fn with_payload_wait_time(mut self, payload_wait_time: Duration) -> Self {
        self.payload_wait_time = payload_wait_time;
        self
    }

    /// Configures the local validator signer key.
    pub const fn with_signer(mut self, signer: Option<ValidatorSigner>) -> Self {
        self.signer = signer;
        self
    }

    /// Configures an explicit directory for consensus WAL and QC storage.
    pub fn with_storage_dir(mut self, storage_dir: impl Into<PathBuf>) -> Self {
        self.storage_dir = Some(storage_dir.into());
        self
    }

    /// Validates configuration invariants.
    pub fn validate(&self) -> Result<(), HotStuffError> {
        if self.epoch_length == 0 {
            return Err(HotStuffError::InvalidValidatorSet(
                "epoch_length must be at least 1".to_string(),
            ));
        }
        if self.genesis_validators.is_empty() {
            return Err(HotStuffError::InvalidValidatorSet(
                "genesis_validators must not be empty".to_string(),
            ));
        }
        if self.view_timeout.is_zero() || self.max_view_timeout < self.view_timeout {
            return Err(HotStuffError::Other(
                "view_timeout must be non-zero and <= max_view_timeout".to_string(),
            ));
        }
        Ok(())
    }
}
