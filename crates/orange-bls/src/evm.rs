//! What an Ethereum contract computes to verify a certificate with the
//! EIP-2537 precompiles (spec 12 §8): the precompile addresses and prices,
//! the EIP-2537 point encodings, and the exact input of each call.
//!
//! EIP-2537 encodes a base-field element as 64 big-endian bytes (16 zero
//! bytes, then the 48-byte value), a G1 point as `x ‖ y` (128 bytes), an
//! `Fp2` element `c0 + c1·u` as `c0 ‖ c1`, a G2 point as `x ‖ y` (256
//! bytes), and the identity as all zeros.

use bls12_381::{G1Affine, G2Affine};

use crate::hash;

/// Address of the SHA-256 precompile, used for `expand_message_xmd`.
pub const SHA256: u8 = 0x02;
/// Address of the MODEXP precompile, used to reduce 64-byte values modulo `p`.
pub const MODEXP: u8 = 0x05;
/// Address of `BLS12_G1ADD`.
pub const G1_ADD: u8 = 0x0b;
/// Address of `BLS12_PAIRING_CHECK`.
pub const PAIRING_CHECK: u8 = 0x0f;
/// Address of `BLS12_MAP_FP_TO_G1`.
pub const MAP_FP_TO_G1: u8 = 0x10;

/// Gas of `BLS12_G1ADD`.
pub const G1_ADD_GAS: u64 = 375;
/// Gas of `BLS12_MAP_FP_TO_G1`.
pub const MAP_FP_TO_G1_GAS: u64 = 5_500;
/// Gas of `BLS12_PAIRING_CHECK`: this base plus [`PAIRING_PAIR_GAS`] per pair.
pub const PAIRING_BASE_GAS: u64 = 37_700;
/// Gas of `BLS12_PAIRING_CHECK` per pair.
pub const PAIRING_PAIR_GAS: u64 = 32_600;

/// Gas of the BLS precompile calls in one certificate verification: two
/// maps to G1, one addition, a two-pair pairing check.
pub const VERIFY_BLS_GAS: u64 =
    2 * MAP_FP_TO_G1_GAS + G1_ADD_GAS + PAIRING_BASE_GAS + 2 * PAIRING_PAIR_GAS;

/// The base-field modulus `p`, big-endian.
pub const P: [u8; 48] = [
    0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7,
    0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24,
    0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
];

/// `p` as little-endian 64-bit limbs.
const P_LIMBS: [u64; 6] = [
    0xb9fe_ffff_ffff_aaab,
    0x1eab_fffe_b153_ffff,
    0x6730_d2a0_f6b0_f624,
    0x6477_4b84_f385_12bf,
    0x4b1b_a7b6_434b_acd7,
    0x1a01_11ea_397f_e69a,
];

/// The EIP-2537 encoding of a G1 point.
#[must_use]
pub fn encode_g1(point: &G1Affine) -> [u8; 128] {
    let mut raw = point.to_uncompressed();
    // Clearing the flag bits turns the identity's encoding into all zeros
    // and leaves every other point's untouched.
    raw[0] &= 0x1f;
    let mut out = [0u8; 128];
    out[16..64].copy_from_slice(&raw[..48]);
    out[80..].copy_from_slice(&raw[48..]);
    out
}

/// The EIP-2537 encoding of a G2 point. The compressed and uncompressed
/// encodings of spec 12 §2 put `c1` before `c0`; EIP-2537 puts `c0` first.
#[must_use]
pub fn encode_g2(point: &G2Affine) -> [u8; 256] {
    let mut raw = point.to_uncompressed();
    raw[0] &= 0x1f;
    let mut out = [0u8; 256];
    for (i, from) in [48usize, 0, 144, 96].into_iter().enumerate() {
        out[i * 64 + 16..(i + 1) * 64].copy_from_slice(&raw[from..from + 48]);
    }
    out
}

/// The two field elements `hash_to_field(msg, 2)` of the G1 suite (RFC 9380
/// §5.2) under tag `dst` ([`DST_SIGNATURE`] for certificates), each in the
/// 64-byte form `BLS12_MAP_FP_TO_G1` takes. A contract computes them with
/// the SHA-256 precompile (`expand_message_xmd`, 128 bytes) and two MODEXP
/// calls with exponent 1 (reducing each 64-byte half modulo `p`). Mapping
/// both and adding the results gives `hash_to_curve(msg)`, because the map
/// precompile clears the cofactor and cofactor clearing is linear.
///
/// [`DST_SIGNATURE`]: crate::sig::DST_SIGNATURE
#[must_use]
pub fn hash_to_field(msg: &[u8], dst: &[u8]) -> [[u8; 64]; 2] {
    let uniform = hash::expand_message_xmd(msg, dst, 128);
    [reduce(&uniform[..64]), reduce(&uniform[64..])]
}

/// The input of `BLS12_PAIRING_CHECK` that verifies `signature` over the
/// message whose hash is `message_point`: the pairs `(σ, −g2)` and
/// `(H(m), pk)`. The precompile returns 1 exactly when the signature is valid.
#[must_use]
pub fn pairing_input(signature: &G1Affine, message_point: &G1Affine, key: &G2Affine) -> [u8; 768] {
    let mut out = [0u8; 768];
    out[..128].copy_from_slice(&encode_g1(signature));
    out[128..384].copy_from_slice(&encode_g2(&-G2Affine::generator()));
    out[384..512].copy_from_slice(&encode_g1(message_point));
    out[512..].copy_from_slice(&encode_g2(key));
    out
}

/// A big-endian integer modulo `p`, in the 64-byte EIP-2537 form.
fn reduce(bytes: &[u8]) -> [u8; 64] {
    let mut r = [0u64; 6];
    for byte in bytes {
        for bit in (0..8).rev() {
            // r < p < 2^381, so 2r + 1 still fits in 384 bits.
            let mut carry = u64::from((byte >> bit) & 1);
            for limb in &mut r {
                let top = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = top;
            }
            let mut diff = [0u64; 6];
            let mut borrow = false;
            for ((d, a), b) in diff.iter_mut().zip(r).zip(P_LIMBS) {
                let (x, under1) = a.overflowing_sub(b);
                let (y, under2) = x.overflowing_sub(u64::from(borrow));
                *d = y;
                borrow = under1 || under2;
            }
            if !borrow {
                r = diff;
            }
        }
    }
    let mut out = [0u8; 64];
    for (i, limb) in r.iter().rev().enumerate() {
        out[16 + i * 8..24 + i * 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modulus_constants_agree() {
        let mut from_limbs = [0u8; 48];
        for (i, limb) in P_LIMBS.iter().rev().enumerate() {
            from_limbs[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
        }
        assert_eq!(from_limbs, P);
        assert_eq!(VERIFY_BLS_GAS, 114_275);
        // p reduces to 0, p − 1 to itself, 2^512 − 1 to a value below p.
        let mut p64 = [0u8; 64];
        p64[16..].copy_from_slice(&P);
        assert_eq!(reduce(&p64), [0u8; 64]);
        let mut below = p64;
        below[63] -= 1;
        assert_eq!(reduce(&below), below);
        let max = reduce(&[0xFF; 64]);
        assert!(max[..16].iter().all(|&b| b == 0) && max[16..] < p64[16..]);
    }

    #[test]
    fn identity_encodes_as_zeros() {
        assert_eq!(encode_g1(&G1Affine::identity()), [0u8; 128]);
        assert_eq!(encode_g2(&G2Affine::identity()), [0u8; 256]);
    }
}
