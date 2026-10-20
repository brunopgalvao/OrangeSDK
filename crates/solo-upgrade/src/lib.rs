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
        impl solo_abi::Encode for $name {
            fn encode(&self, e: &mut solo_abi::Encoder) {
                $(self.$field.encode(e);)*
            }
        }
        impl solo_abi::Decode for $name {
            fn decode(d: &mut solo_abi::Decoder<'_>) -> Result<Self, solo_abi::DecodeError> {
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

use solo_abi::types::Address;

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

    use solo_abi::types::Hash;

    /// `gov/pending` → `PendingUpgrade`.
    pub const PENDING: &[u8] = b"gov/pending";
    /// `gov/enacted` → `EnactedUpgrade`, the latest switch.
    pub const ENACTED: &[u8] = b"gov/enacted";
    /// `gov/chunk/` + code hash + index (big-endian u32) → chunk bytes.
    pub const CHUNK: &[u8] = b"gov/chunk/";
    /// `gov/kernel/` + code hash → `EnactedUpgrade`, for every kernel switched to.
    pub const KERNEL: &[u8] = b"gov/kernel/";
    /// `gate/book` → `GateBook`.
    pub const BOOK: &[u8] = b"gate/book";
    /// `gate/signal/` + validator id → `Signal`, the validator's latest.
    pub const SIGNAL: &[u8] = b"gate/signal/";

    /// The key of chunk `index` of `code_hash`.
    #[must_use]
    pub fn chunk(code_hash: &Hash, index: u32) -> Vec<u8> {
        let mut k = CHUNK.to_vec();
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_and_keys() {
        assert_eq!(UPGRADE_ADDRESS[18..], [0x50, 0x10]);
        assert!(UPGRADE_ADDRESS[..18].iter().all(|b| *b == 0));
        // A chunk transaction still fits a 64 KiB storage value with room for its envelope.
        const { assert!(CHUNK_SIZE + 1024 < 65_536) };
        assert_eq!(MAX_CHUNKS as usize * CHUNK_SIZE, 15 << 19);
        let k = keys::chunk(&[7; 32], 0x0102_0304);
        assert_eq!(k.len(), 46);
        assert!(k.len() <= 64);
        assert_eq!(&k[..10], keys::CHUNK);
        assert_eq!(&k[42..], &[1, 2, 3, 4]);
        let k = keys::signal(&[9; 32]);
        assert_eq!(k.len(), 44);
        assert_eq!(&k[..12], keys::SIGNAL);
        let k = keys::kernel(&[5; 32]);
        assert_eq!(
            (k.len(), &k[..11], &k[11..]),
            (43, keys::KERNEL, &[5u8; 32][..])
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
    }
}
