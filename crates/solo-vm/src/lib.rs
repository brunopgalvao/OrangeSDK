//! Reference implementation of the Solo VM.
//!
//! This crate is the normative companion to `spec/`. Where the two disagree,
//! the spec wins and this crate has a bug. The reference interpreter is
//! `no_std`-capable so it can be compiled to wasm for light clients and used
//! as the differential oracle for every JIT backend.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

/// Version of the VM specification this crate implements.
pub const SPEC_VERSION: (u16, u16) = (0, 1);

#[cfg(test)]
mod tests {
    use super::SPEC_VERSION;

    #[test]
    fn spec_version_is_v0() {
        assert_eq!(SPEC_VERSION.0, 0);
    }
}
