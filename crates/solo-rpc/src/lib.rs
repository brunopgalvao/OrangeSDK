//! Ethereum JSON-RPC served from a [`solo_node::Node`].
//!
//! The method set is what wallets, `cast`, ethers, viem and explorers need
//! against the reference kernel's EVM: sending every transaction type,
//! receipts with logs, blocks, `eth_call` and gas estimation, code and
//! storage, log filters, fee history and the `txpool` namespace, the
//! bridge relayer's `solo_getFinalityProof`, `solo_getOutboxProof` and
//! `solo_getRotation`, and governance's `solo_getGovernance`,
//! `solo_getProposals` and `solo_getProposal`.
//! Responses take geth's shapes and error codes. Quantities are `0x` hex
//! without leading zeros, data is `0x` hex, addresses are lowercase.

#![forbid(unsafe_code)]

pub mod bridge;
pub mod call;
pub mod filter;
pub mod governance;
pub mod hex;
pub mod http;
pub mod methods;
pub mod proof;
pub mod txpool;
pub mod views;

pub use methods::{Rpc, RpcError};

pub mod telemetry;
