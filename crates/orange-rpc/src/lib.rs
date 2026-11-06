//! Ethereum JSON-RPC served from an [`orange_node::Node`].
//!
//! The method set is what wallets, `cast`, ethers, viem and explorers need
//! against the reference kernel's EVM: sending every transaction type,
//! receipts with logs, blocks, `eth_call` and gas estimation, code and
//! storage, log filters (`eth_getLogs` and the polled filters of
//! `eth_newFilter`), fee history and the `txpool` namespace, the
//! bridge relayer's `orange_getFinalityProof`, `orange_getOutboxProof` and
//! `orange_getRotation`, governance's `orange_getGovernance`,
//! `orange_getProposals` and `orange_getProposal`, the operator's
//! `orange_upgradeStatus`, and geth's tracing methods `debug_traceTransaction`,
//! `debug_traceBlockByNumber`, `debug_traceBlockByHash` and `debug_traceCall`
//! with `callTracer` and `prestateTracer`.
//! Responses take geth's shapes and error codes. Quantities are `0x` hex
//! without leading zeros, data is `0x` hex, addresses are lowercase.

#![forbid(unsafe_code)]

pub mod bridge;
pub mod call;
pub mod fees;
pub mod filter;
pub mod filters;
pub mod governance;
pub mod hex;
pub mod http;
pub mod indexed;
pub mod methods;
pub mod proof;
pub mod subscriptions;
pub mod txpool;
pub mod upgrades;
pub mod views;
pub mod ws;

pub use methods::{Rpc, RpcError};

pub mod telemetry;
pub mod trace;
