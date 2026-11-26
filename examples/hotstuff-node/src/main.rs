//! Standalone Reth node running Chained `HotStuff` BFT consensus over the `hotstuff/1` `RLPx`
//! subprotocol.
//!
//! # Running a 4-node local `HotStuff` cluster
//!
//! Launch 4 nodes with the same `--chain <genesis.json>` and `--hotstuff.validators <v0,v1,v2,v3>`,
//! each with its own `--datadir`, `--port`, `--authrpc.port`, `--hotstuff.validator-key`, and
//! peer `--trusted-peers <enode://...>`:
//!
//! ```sh
//! cargo run -p example-hotstuff-node -- node \
//!     --chain genesis.json \
//!     --datadir /tmp/hotstuff-0 \
//!     --port 30303 \
//!     --authrpc.port 8551 \
//!     --hotstuff.validator-key <hex_secret_key_0> \
//!     --hotstuff.validators 0x...,0x...,0x...,0x... \
//!     --hotstuff.epoch-length 100
//! ```

#![warn(unused_crate_dependencies)]

use alloy_primitives::Address;
use clap::{Args, Parser};
use reth_consensus_hotstuff::{
    HotStuffConfig, HotStuffNode, ValidatorSigner, DEFAULT_VALIDATOR_REGISTRY_ADDRESS,
};
use reth_ethereum::{
    cli::{chainspec::EthereumChainSpecParser, interface::Cli},
    node::builder::NodeHandle,
};
use std::time::Duration;
use tracing::info;

/// `HotStuff` consensus CLI options appended to `reth node`.
#[derive(Debug, Clone, Args)]
pub struct HotStuffCliArgs {
    /// Hex-encoded 32-byte secp256k1 secret key for signing `HotStuff` proposals/votes.
    ///
    /// Omit to run the node as a non-voting observer.
    #[arg(long = "hotstuff.validator-key", value_name = "HEX")]
    pub validator_key: Option<String>,

    /// Comma-separated list of epoch-0 validator addresses in leader-rotation order.
    #[arg(
        long = "hotstuff.validators",
        value_delimiter = ',',
        required = true,
        value_name = "ADDRESSES"
    )]
    pub validators: Vec<Address>,

    /// Number of execution blocks per consensus epoch before reading the on-chain registry.
    #[arg(long = "hotstuff.epoch-length", default_value_t = 100)]
    pub epoch_length: u64,

    /// On-chain `ValidatorRegistry` contract address read at finalized epoch boundaries.
    #[arg(
        long = "hotstuff.validator-registry",
        default_value_t = DEFAULT_VALIDATOR_REGISTRY_ADDRESS
    )]
    pub validator_registry: Address,

    /// Base Pacemaker view timeout in milliseconds before initiating a view change.
    #[arg(long = "hotstuff.view-timeout-ms", default_value_t = 2000)]
    pub view_timeout_ms: u64,

    /// Target block interval in milliseconds when acting as round leader.
    #[arg(long = "hotstuff.block-time-ms", default_value_t = 1000)]
    pub block_time_ms: u64,
}

impl HotStuffCliArgs {
    fn to_config(&self) -> eyre::Result<HotStuffConfig> {
        let signer = self.validator_key.as_deref().map(ValidatorSigner::from_hex).transpose()?;
        let config = HotStuffConfig::new(self.validators.clone())
            .with_epoch_length(self.epoch_length)
            .with_validator_registry(self.validator_registry)
            .with_view_timeout(Duration::from_millis(self.view_timeout_ms))
            .with_block_time(Duration::from_millis(self.block_time_ms))
            .with_signer(signer);
        config.validate()?;
        Ok(config)
    }
}

fn main() -> eyre::Result<()> {
    Cli::<EthereumChainSpecParser, HotStuffCliArgs>::parse().run(async move |builder, args| {
        let config = args.to_config()?;
        let hotstuff_node = HotStuffNode::new(config.clone())?;

        info!(
            target: "consensus::hotstuff",
            epoch_length = config.epoch_length,
            registry = %config.validator_registry,
            validators = ?config.genesis_validators,
            "Launching Reth HotStuff node"
        );

        let NodeHandle { node, node_exit_future } =
            builder.node(hotstuff_node.clone()).launch().await?;

        hotstuff_node.spawn_driver(&node)?;
        node_exit_future.await
    })
}
