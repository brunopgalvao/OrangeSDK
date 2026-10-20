//! A node: the host that runs a kernel (spec 06). It owns the executor with
//! the kernel loaded under the privileged capability set, serves the
//! privileged host functions that need node state, turns driver effects
//! into host actions, holds the mempool, and answers queries.

#![forbid(unsafe_code)]

pub mod extension;
pub mod net;
pub mod node;
pub mod sim;
pub mod telemetry;

pub use extension::{NodeExtension, NodeServices, Outbound, sign_recoverable, validator_id};
pub use net::Transport;
pub use node::{Node, NodeConfig, NodeError, PROOF_HISTORY, SubmitError};
pub use sim::Sim;
