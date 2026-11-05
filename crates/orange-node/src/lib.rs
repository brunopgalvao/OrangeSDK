//! A node: the host that runs a kernel (spec 06). It owns the executor with
//! the kernel loaded under the privileged capability set, serves the
//! privileged host functions that need node state, turns driver effects
//! into host actions, holds the mempool, and answers queries.

#![forbid(unsafe_code)]

pub mod catchup;
pub mod extension;
pub mod keystore;
pub mod mempool;
pub mod net;
pub mod node;
pub mod peers;
pub mod session;
pub mod sim;
pub mod state;
pub mod statesync;
pub mod store;
pub mod telemetry;
pub mod upgrade;
pub mod worker;

pub use extension::{NodeExtension, NodeServices, Outbound, sign_recoverable, validator_id};
pub use mempool::{MAX_TX_BYTES, Mempool, PoolError, PoolLimits, PoolTx};
pub use net::{Discovery, Transport};
pub use node::{
    ARCHIVE, BLOCK_KERNEL_GAS, DRIVER_RETENTION, HISTORY_KEYS_PER_BLOCK, KEPT_RECORDS, Node,
    NodeConfig, NodeError, PRUNE_EVERY, STATE_HISTORY, SubmitError, keep_latest,
};
pub use sim::Sim;
pub use state::{ChainState, StoreConfig};
pub use store::DriverStore;
pub use upgrade::{GatedExtension, Switch, Upgrades};
