//! A node: the host that runs a kernel (spec 06). It owns the executor with
//! the kernel loaded under the privileged capability set, serves the
//! privileged host functions that need node state, turns driver effects
//! into host actions, holds the mempool, and answers queries.

#![forbid(unsafe_code)]

pub mod extension;
pub mod keystore;
pub mod mempool;
pub mod net;
pub mod node;
pub mod sim;
pub mod store;
pub mod telemetry;
pub mod upgrade;

pub use extension::{NodeExtension, NodeServices, Outbound, sign_recoverable, validator_id};
pub use mempool::{MAX_TX_BYTES, Mempool, PoolError, PoolLimits, PoolTx};
pub use net::Transport;
pub use node::{
    ARCHIVE, BLOCK_KERNEL_GAS, HISTORY_KEYS_PER_BLOCK, Node, NodeConfig, NodeError, STATE_HISTORY,
    SubmitError,
};
pub use sim::Sim;
pub use store::DriverStore;
pub use upgrade::{GatedExtension, Switch, Upgrades};
