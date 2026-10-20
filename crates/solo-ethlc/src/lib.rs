//! The Ethereum-to-Solo half of the Tier-2 bridge (spec 18; codex ADR 0013).
//!
//! - [`ssz`]: SSZ merkleization and Merkle branches, over SHA-256.
//! - [`beacon`]: the light-client containers at the Electra format (also
//!   Fulu's), their SSZ decoding and their hash tree roots.
//! - [`sync`]: the Altair light-client sync protocol, restricted to
//!   finalized updates: bootstrap, validation and application.
//! - [`mpt`]: Merkle-Patricia proofs of Ethereum accounts and storage slots
//!   (the `eth_getProof` format), verified and, for tests and relayers, built.
//! - [`inbox`]: the message an `EthereumOutbox` stores and its proof.
//! - [`abi`]: the Solidity ABI words of the light client's interface.
//! - [`client`]: the light-client module itself, over a key-value store:
//!   genesis, updates, governance, views, and the admission checks of the
//!   bridge's addresses.
//! - [`verifier`]: the message-verifier module: proofs of outbox messages,
//!   delivered-once records, the rate limit and the pause.
//!
//! Hashing and the one signature check go through [`Crypto`], so the same
//! code runs in the kernel and its module (through host functions) and on a
//! host. `no_std` with `alloc`; the `testing` feature adds native crypto and
//! the builders tests need.

#![cfg_attr(not(feature = "testing"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

/// A record in the canonical encoding (spec 06 §2): its fields in order.
macro_rules! record {
    ($(#[$meta:meta])* $name:ident { $($(#[$fmeta:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name {
            $($(#[$fmeta])* pub $field: $ty,)*
        }
        impl solo_abi::codec::Encode for $name {
            fn encode(&self, e: &mut solo_abi::codec::Encoder) {
                $(self.$field.encode(e);)*
            }
        }
        impl solo_abi::codec::Decode for $name {
            fn decode(d: &mut solo_abi::codec::Decoder<'_>) -> Result<Self, solo_abi::codec::DecodeError> {
                Ok($name { $($field: d.get()?,)* })
            }
        }
    };
}

pub mod abi;
pub mod beacon;
pub mod client;
pub mod inbox;
pub mod mpt;
pub mod ssz;
pub mod sync;
pub mod verifier;

#[cfg(feature = "testing")]
pub mod testing;

/// A 32-byte hash.
pub type Hash = [u8; 32];

/// The cryptography the bridge needs from its environment.
pub trait Crypto {
    /// SHA-256.
    fn sha256(&self, data: &[u8]) -> Hash;
    /// Keccak-256.
    fn keccak256(&self, data: &[u8]) -> Hash;
    /// Ethereum's `FastAggregateVerify` over compressed G1 keys of 48 bytes
    /// each, concatenated, and a compressed G2 signature (spec 05 §4.3,
    /// `bls12381_fast_aggregate_verify`).
    fn fast_aggregate_verify(&self, keys: &[u8], msg: &Hash, signature: &[u8; 96]) -> bool;
}
