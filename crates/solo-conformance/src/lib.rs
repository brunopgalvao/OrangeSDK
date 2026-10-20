//! Ethereum execution-spec conformance of the Solo pipeline (spec 07 §4.2).
//!
//! The EVM as Solo runs it is revm compiled for `riscv64imac`, recompiled
//! into a Solo module, interpreted by `solo-vm` (or compiled by `solo-jit`),
//! with the precompiles the host accelerates routed to host functions, and
//! with state read and written through the kernel's storage layout. The
//! conformance guest (`guest/evm-conformance`) compiles the kernel's own
//! EVM, state and transaction modules and runs one state test case per
//! call; this crate parses the fixtures, runs each case on the VM, reads the
//! post-state back from storage and compares Ethereum's state root and logs
//! hash with the fixture's.

pub mod check;
pub mod cli;
pub mod fixture;
pub mod mpt;
pub mod run;
pub mod suite;

pub use fixture::{FORK, TestCase};
pub use run::{Executed, Runner};
pub use suite::{Expectation, Report};

/// The conformance guest, built by `tools/build-guest.sh`.
pub const GUEST: &[u8] = include_bytes!("../tests/fixtures/evm-conformance.elf");
