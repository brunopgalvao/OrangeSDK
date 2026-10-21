//! The host side of the Solo VM boundary (spec 05).
//!
//! `solo-vm` executes one instance and knows nothing about storage, code, or
//! nested calls. This crate supplies those: a [`cache::ModuleCache`] keyed by
//! code hash, [`storage`] with per-call overlays and namespaces, the host ABI
//! functions in [`abi`] and those behind feature gates in [`gated`] and
//! [`precompiles`], and the frame stack that makes `invoke` work in
//! [`executor`].

#![forbid(unsafe_code)]

pub mod abi;
pub mod cache;
pub mod code;
pub mod executor;
pub mod gated;
pub mod hash;
pub mod precompiles;
pub mod storage;

#[cfg(test)]
mod tests;

pub use cache::{LoadError, ModuleCache};
pub use executor::{
    Backend, CallResult, EXTENSION_HANDLE_BASE, Executor, Extension, Flags, NATIVE_CODE_BUDGET,
    NativeStats,
};
pub use storage::{MemStorage, Overlay, Storage, Writes};
