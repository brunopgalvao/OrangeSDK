//! Governed kernel upgrades and host feature gates (spec 13).
//!
//! What every side of the boundary must agree on lives here: the upgrade
//! system address and the Solidity-ABI encoding of the actions sent to it
//! ([`action`]), the records the reference kernel keeps and serves
//! ([`records`]), and the feature-gate state machine ([`gates`]). `no_std`
//! with `alloc`, shared by the kernel guest, the node host and tooling.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

/// A struct with a canonical encoding: its fields in order (spec 06 §2).
macro_rules! record {
    ($(#[$meta:meta])* $name:ident { $($(#[$fmeta:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name {
            $($(#[$fmeta])* pub $field: $ty,)*
        }
        impl orange_abi::Encode for $name {
            fn encode(&self, e: &mut orange_abi::Encoder) {
                $(self.$field.encode(e);)*
            }
        }
        impl orange_abi::Decode for $name {
            fn decode(d: &mut orange_abi::Decoder<'_>) -> Result<Self, orange_abi::DecodeError> {
                Ok($name { $($field: d.get()?,)* })
            }
        }
    };
}

pub mod action;
pub mod gates;
pub mod records;

pub use action::Action;
pub use gates::{GateBook, GateRecord};
pub use records::{EnactedUpgrade, PendingUpgrade, Signal, UpgradeStatus, ValidatorSignal};

use orange_abi::types::Address;

/// The upgrade system address, `0x0000000000000000000000000000000000005010`.
/// A transaction to it carries an upgrade action or a feature-gate signal
/// in its calldata instead of a message call.
pub const UPGRADE_ADDRESS: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x10,
];

/// Largest chunk of kernel code one `stage` action carries: small enough that
/// the chunk, and the raw transaction carrying it, each fit one storage value
/// (spec 05 §4.2).
pub const CHUNK_SIZE: usize = 61_440;

/// Most chunks one kernel's code may span: 7.5 MiB of code.
pub const MAX_CHUNKS: u32 = 128;

/// Gas limit of the feature-gate signal transaction a host sends; above the
/// intrinsic cost of its 36 bytes of calldata.
pub const SIGNAL_GAS: u64 = 100_000;

/// Query methods the reference kernel serves for upgrades (spec 13 §6).
pub mod query {
    /// `() -> u32`: the running kernel's version.
    pub const KERNEL_VERSION: &str = "kernel_version";
    /// `() -> UpgradeStatus`.
    pub const STATUS: &str = "upgrade_status";
    /// `(Hash) -> bytes`: the staged code of a code hash, its chunks
    /// concatenated from index 0 up to the first missing one.
    pub const CODE: &str = "upgrade_code";
}

/// Storage keys of the reference kernel's upgrade records (spec 13 §5).
pub mod keys {
    use alloc::vec::Vec;

    use orange_abi::types::Hash;

    /// `gov/pending` → `PendingUpgrade`.
    pub const PENDING: &[u8] = b"gov/pending";
    /// `gov/enacted` → `EnactedUpgrade`, the latest switch.
    pub const ENACTED: &[u8] = b"gov/enacted";
    /// `gov/c/` + stager + code hash + index (big-endian u32) → chunk bytes
    /// of the stager's upload (spec 13 §3); a short prefix, so that the key
    /// fits 64 bytes.
    pub const CHUNK: &[u8] = b"gov/c/";
    /// `gov/kernel/` + code hash → `EnactedUpgrade`, for every kernel switched to.
    pub const KERNEL: &[u8] = b"gov/kernel/";
    /// `gov/source/` + code hash → `[20]`, the stager whose upload the
    /// latest `propose` of the code hash used (spec 13 §3).
    pub const SOURCE: &[u8] = b"gov/source/";
    /// `gate/book` → `GateBook`.
    pub const BOOK: &[u8] = b"gate/book";
    /// `gate/signal/` + validator id → `Signal`, the validator's latest.
    pub const SIGNAL: &[u8] = b"gate/signal/";

    /// The key of chunk `index` of `stager`'s upload of `code_hash`.
    #[must_use]
    pub fn chunk(stager: &[u8; 20], code_hash: &Hash, index: u32) -> Vec<u8> {
        let mut k = CHUNK.to_vec();
        k.extend_from_slice(stager);
        k.extend_from_slice(code_hash);
        k.extend_from_slice(&index.to_be_bytes());
        k
    }

    /// The key recording the switch to the kernel `code_hash`.
    #[must_use]
    pub fn kernel(code_hash: &Hash) -> Vec<u8> {
        let mut k = KERNEL.to_vec();
        k.extend_from_slice(code_hash);
        k
    }

    /// The key of the source of `code_hash`.
    #[must_use]
    pub fn source(code_hash: &Hash) -> Vec<u8> {
        let mut k = SOURCE.to_vec();
        k.extend_from_slice(code_hash);
        k
    }

    /// The key of a validator's latest signal.
    #[must_use]
    pub fn signal(id: &Hash) -> Vec<u8> {
        let mut k = SIGNAL.to_vec();
        k.extend_from_slice(id);
        k
    }
}

/// The feature gates host releases define (spec 13 §8.1), as bit indices of
/// a 64-bit feature set.
pub mod gate {
    /// The `secp256k1_verify` host function (spec 05 §4.3).
    pub const SECP256K1_VERIFY: u8 = 0;
    /// The `bls12381_fast_aggregate_verify` host function (spec 05 §4.3),
    /// which the Ethereum light client of spec 18 needs.
    pub const BLS12381_FAST_AGGREGATE_VERIFY: u8 = 1;
    /// The precompile host functions (spec 05 §4.8, spec 19): bn254, modexp,
    /// BLAKE2F, KZG point evaluation and the EIP-2537 BLS12-381 operations
    /// the kernel's EVM runs on the host once this gate is active.
    pub const PRECOMPILES: u8 = 2;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_and_keys() {
        assert_eq!(UPGRADE_ADDRESS[18..], [0x50, 0x10]);
        assert!(UPGRADE_ADDRESS[..18].iter().all(|b| *b == 0));
        // The governance address of spec 13 §9 is this address.
        assert_eq!(UPGRADE_ADDRESS, orange_abi::governance::GOVERNANCE_ADDRESS);
        // A chunk transaction still fits a 64 KiB storage value with room for its envelope.
        const { assert!(CHUNK_SIZE + 1024 < 65_536) };
        assert_eq!(MAX_CHUNKS as usize * CHUNK_SIZE, 15 << 19);
        let k = keys::chunk(&[8; 20], &[7; 32], 0x0102_0304);
        assert_eq!(k.len(), 62);
        assert!(k.len() <= 64);
        assert_eq!(&k[..6], keys::CHUNK);
        assert_eq!((&k[6..26], &k[26..58]), (&[8u8; 20][..], &[7u8; 32][..]));
        assert_eq!(&k[58..], &[1, 2, 3, 4]);
        let k = keys::signal(&[9; 32]);
        assert_eq!(k.len(), 44);
        assert_eq!(&k[..12], keys::SIGNAL);
        let k = keys::kernel(&[5; 32]);
        assert_eq!(
            (k.len(), &k[..11], &k[11..]),
            (43, keys::KERNEL, &[5u8; 32][..])
        );
        let k = keys::source(&[6; 32]);
        assert_eq!(
            (k.len(), &k[..11], &k[11..]),
            (43, keys::SOURCE, &[6u8; 32][..])
        );
        assert_eq!(
            (keys::PENDING, keys::ENACTED, keys::BOOK),
            (&b"gov/pending"[..], &b"gov/enacted"[..], &b"gate/book"[..])
        );
        assert_eq!(
            (query::KERNEL_VERSION, query::STATUS, query::CODE),
            ("kernel_version", "upgrade_status", "upgrade_code")
        );
        assert_eq!((gate::SECP256K1_VERIFY, SIGNAL_GAS), (0, 100_000));
        assert_eq!(
            (gate::BLS12381_FAST_AGGREGATE_VERIFY, gate::PRECOMPILES),
            (1, 2)
        );
    }
}
