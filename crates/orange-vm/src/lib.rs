//! Reference implementation of the Orange VM.
//!
//! This crate is the normative companion to `spec/`. Where the two disagree,
//! the spec wins and this crate has a bug. The reference interpreter is
//! `no_std`-capable so it can be compiled to wasm for light clients and used
//! as the differential oracle for every JIT backend.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod builder;
pub mod gas;
pub mod host;
pub mod interp;
pub mod isa;
pub mod leb128;
pub mod memory;
pub mod module;
pub mod status;

/// Version of the VM specification this crate implements, as `(major, minor)`.
pub const SPEC_VERSION: (u8, u8) = (0, 1);

#[cfg(test)]
mod tests {
    use super::SPEC_VERSION;

    #[test]
    fn spec_version_is_v0_1() {
        assert_eq!(SPEC_VERSION, (0, 1));
    }
}
