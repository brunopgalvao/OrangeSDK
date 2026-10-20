//! A node: the host that runs a kernel (spec 06). It owns the executor with
//! the kernel loaded under the privileged capability set, serves the
//! privileged host functions that need node state, turns driver effects
//! into host actions, holds the mempool, and answers queries.

#![forbid(unsafe_code)]

pub mod extension;
pub mod node;

pub use extension::{NodeExtension, NodeServices};
pub use node::{Node, NodeError, SubmitError};
