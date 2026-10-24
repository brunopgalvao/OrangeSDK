//! Threshold BLS signatures over BLS12-381 for Solo finality certificates
//! (spec 12).
//!
//! - [`sig`]: the signature scheme. Signatures and message hashes live in G1
//!   (48 bytes), public keys in G2 (96 bytes), which makes verification on
//!   Ethereum cheapest (spec 12 §2).
//! - [`threshold`]: Shamir shares with Feldman commitments, partial
//!   signatures and their Lagrange combination into the group signature.
//! - [`dkg`]: the dealerless key generation and the resharing that keeps the
//!   group key across validator-set changes, as a pure state machine.
//! - [`batch`]: share checks and partial-signature checks batched into
//!   random linear combinations.
//! - [`certificate`]: the versioned finality certificate and the bytes it signs.
//! - [`evm`]: the inputs an Ethereum contract passes to the EIP-2537 precompiles.
//! - [`host`]: the byte-level semantics of the `bls12381_*` host functions.
//! - [`eth`]: Ethereum consensus-layer signatures (keys in G1, signatures in
//!   G2) and the fast aggregate verification sync committees need.
//!
//! `no_std` with `alloc`, so the kernel can link the same code.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod batch;
pub mod certificate;
pub mod dkg;
pub mod eth;
pub mod evm;
pub mod hash;
pub mod host;
mod par;
mod point;
mod poly;
pub mod sig;
pub mod threshold;

#[cfg(test)]
mod tests;

/// The curve implementation, for callers that need the point types.
pub use bls12_381 as curve;
pub use certificate::Certificate;
pub use sig::{PublicKey, SecretKey, Signature};
pub use threshold::{PartialSignature, PublicKeySet, SecretShare};

/// Why an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Bytes that are not the canonical compressed encoding of a point in the
    /// prime-order subgroup, or an identity point where one is not allowed.
    InvalidPoint,
    /// Bytes that are not a canonical scalar (below the group order), or a
    /// zero secret.
    InvalidScalar,
    /// Input of the wrong length.
    InvalidLength,
    /// Key material shorter than 32 bytes.
    ShortKeyMaterial,
    /// A share index of zero, or the same index twice.
    InvalidIndex,
    /// A threshold of zero or above the number of participants.
    InvalidThreshold,
    /// Fewer partial signatures than the threshold.
    NotEnoughShares,
    /// A combined signature that does not verify: a partial was invalid.
    InvalidSignature,
    /// A certificate version this code does not know.
    UnsupportedVersion,
}
