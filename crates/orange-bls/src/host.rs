//! The byte-level semantics of the host functions `bls12381_verify` and
//! `bls12381_pairing_check` (spec 05 §4.3), so that every host computes
//! exactly the same answers.

use alloc::vec::Vec;

use bls12_381::{G2Prepared, Gt};

use crate::{hash, point, sig};

/// Length of one `(G1, G2)` pair in a `bls12381_pairing_check` input: a
/// compressed G1 point followed by a compressed G2 point.
pub const PAIR_LENGTH: usize = 144;

/// Longest domain separation tag `bls12381_verify` accepts.
pub const MAX_DST_LENGTH: usize = 255;

/// `bls12381_verify`: whether `signature` (compressed G1) is a valid
/// signature over `msg` under `key` (compressed G2) with hash-to-curve
/// domain separation tag `dst`. False for a tag that is empty or longer
/// than [`MAX_DST_LENGTH`], a point that does not decode or lies outside
/// the prime-order subgroup, and an identity key.
#[must_use]
pub fn verify(msg: &[u8], dst: &[u8], signature: &[u8; 48], key: &[u8; 96]) -> bool {
    if dst.is_empty() || dst.len() > MAX_DST_LENGTH {
        return false;
    }
    let (Some(signature), Some(key)) = (point::g1(signature), point::g2(key)) else {
        return false;
    };
    !bool::from(key.is_identity()) && sig::verify_hashed(&hash::to_g1(msg, dst), &signature, &key)
}

/// `bls12381_pairing_check`: whether `Π e(P_i, Q_i)` is the identity of
/// the target group, for the pairs `P_i ‖ Q_i` of [`PAIR_LENGTH`] bytes
/// each. False for an empty input, a length that is not a multiple of
/// [`PAIR_LENGTH`], and any point that does not decode or lies outside the
/// prime-order subgroup. Identity points are allowed.
#[must_use]
pub fn pairing_check(pairs: &[u8]) -> bool {
    if pairs.is_empty() || !pairs.len().is_multiple_of(PAIR_LENGTH) {
        return false;
    }
    let mut g1 = Vec::with_capacity(pairs.len() / PAIR_LENGTH);
    let mut g2 = Vec::with_capacity(pairs.len() / PAIR_LENGTH);
    for pair in pairs.chunks_exact(PAIR_LENGTH) {
        let mut p = [0u8; 48];
        let mut q = [0u8; 96];
        p.copy_from_slice(&pair[..48]);
        q.copy_from_slice(&pair[48..]);
        let (Some(p), Some(q)) = (point::g1(&p), point::g2(&q)) else {
            return false;
        };
        g1.push(p);
        g2.push(G2Prepared::from(q));
    }
    let terms: Vec<_> = g1.iter().zip(&g2).collect();
    bls12_381::multi_miller_loop(&terms).final_exponentiation() == Gt::identity()
}
