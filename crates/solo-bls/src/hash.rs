//! Hashing to the curve and to the scalar field (RFC 9380), with the
//! domain separation tags of spec 12 §3.

use alloc::vec::Vec;

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve, HashToField};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use sha2::{Digest, Sha256};

/// `hash_to_curve` with suite `BLS12381G1_XMD:SHA-256_SSWU_RO_` (RFC 9380 §8.8.1).
#[must_use]
pub fn to_g1(msg: &[u8], dst: &[u8]) -> G1Affine {
    <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([msg], dst).into()
}

/// `hash_to_curve` with suite `BLS12381G2_XMD:SHA-256_SSWU_RO_` (RFC 9380 §8.8.2).
#[must_use]
pub fn to_g2(msg: &[u8], dst: &[u8]) -> G2Affine {
    <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([msg], dst).into()
}

/// `hash_to_field` (RFC 9380 §5.2) into the scalar field with
/// `expand_message_xmd(SHA-256)`, `L = 48` and one output element. The
/// message is the concatenation of `parts`.
#[must_use]
pub fn to_scalar(parts: &[&[u8]], dst: &[u8]) -> Scalar {
    let mut out = [Scalar::zero()];
    <Scalar as HashToField>::hash_to_field::<ExpandMsgXmd<Sha256>, _>(
        parts.iter().copied(),
        dst,
        &mut out,
    );
    out[0]
}

/// `expand_message_xmd` with SHA-256 (RFC 9380 §5.3.1). The curve library
/// carries its own copy; this one exists so that [`crate::evm`] can show,
/// byte for byte, what an Ethereum contract computes.
///
/// # Panics
/// If `len` is zero or above 8160, or `dst` is empty or longer than 255
/// bytes: the RFC leaves those undefined and every caller passes constants.
#[must_use]
pub fn expand_message_xmd(msg: &[u8], dst: &[u8], len: usize) -> Vec<u8> {
    assert!(len > 0 && len <= 255 * 32 && !dst.is_empty() && dst.len() <= 255);
    let ell = len.div_ceil(32);
    let dst_len = [u8::try_from(dst.len()).expect("checked above")];
    let len_bytes = u16::try_from(len).expect("checked above").to_be_bytes();
    let b0: [u8; 32] = Sha256::new()
        .chain_update([0u8; 64])
        .chain_update(msg)
        .chain_update(len_bytes)
        .chain_update([0u8])
        .chain_update(dst)
        .chain_update(dst_len)
        .finalize()
        .into();
    let mut out = Vec::with_capacity(ell * 32);
    let mut prev = [0u8; 32];
    for i in 1..=ell {
        let mut input = b0;
        for (x, p) in input.iter_mut().zip(prev) {
            *x ^= p;
        }
        prev = Sha256::new()
            .chain_update(input)
            .chain_update([u8::try_from(i).expect("ell <= 255")])
            .chain_update(dst)
            .chain_update(dst_len)
            .finalize()
            .into();
        out.extend_from_slice(&prev);
    }
    out.truncate(len);
    out
}
