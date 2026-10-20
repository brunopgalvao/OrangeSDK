//! Ethereum JSON-RPC served from a [`solo_node::Node`].
//!
//! The method set is what wallets, explorers and `cast` need to send and
//! inspect value transfers on the reference kernel. Quantities are `0x`
//! hex without leading zeros, data is `0x` hex, addresses are lowercase.

#![forbid(unsafe_code)]

pub mod http;
pub mod methods;

pub use methods::{Rpc, RpcError};

pub mod telemetry;
