//! Encodings shared by every module (spec 12 §2): compressed points and
//! big-endian scalars.

use bls12_381::{G1Affine, G2Affine, G2Projective, Scalar};

/// Decodes a compressed G1 point, checking the encoding, the curve equation
/// and membership of the prime-order subgroup.
pub(crate) fn g1(bytes: &[u8; 48]) -> Option<G1Affine> {
    Option::from(G1Affine::from_compressed(bytes))
}

/// Decodes a compressed G2 point with the same checks as [`g1`].
pub(crate) fn g2(bytes: &[u8; 96]) -> Option<G2Affine> {
    Option::from(G2Affine::from_compressed(bytes))
}

/// Decodes a big-endian scalar, rejecting values at or above the group order.
pub(crate) fn scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    let mut le = *bytes;
    le.reverse();
    Option::from(Scalar::from_bytes(&le))
}

/// Encodes a scalar as 32 big-endian bytes.
pub(crate) fn scalar_bytes(s: &Scalar) -> [u8; 32] {
    let mut be = s.to_bytes();
    be.reverse();
    be
}

/// Interprets 48 big-endian bytes as an integer and reduces it modulo the
/// group order (`OS2IP(okm) mod r`).
pub(crate) fn scalar_wide(okm: &[u8; 48]) -> Scalar {
    let mut wide = [0u8; 64];
    wide[16..].copy_from_slice(okm);
    wide.reverse();
    Scalar::from_bytes_wide(&wide)
}

/// `k · p` for a public small integer `k`, by variable-time double-and-add.
/// Only for public data: Feldman evaluations at participant indices.
pub(crate) fn mul_small(p: &G2Projective, k: u64) -> G2Projective {
    let mut acc = G2Projective::identity();
    for bit in (0..64 - k.leading_zeros()).rev() {
        acc = acc.double();
        if (k >> bit) & 1 == 1 {
            acc += p;
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_round_trip_big_endian_and_reject_the_order() {
        let s = Scalar::from(0x0102_0304u64);
        let be = scalar_bytes(&s);
        assert_eq!(&be[28..], &[1, 2, 3, 4]);
        assert_eq!(scalar(&be), Some(s));
        // r itself is not canonical.
        let r = [
            0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1,
            0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x01,
        ];
        assert_eq!(scalar(&r), None);
        let mut below = r;
        below[31] = 0;
        assert_eq!(scalar(&below), Some(-Scalar::one()));
        // OS2IP mod r: r + 5 reduces to 5.
        let mut wide = [0u8; 48];
        wide[16..].copy_from_slice(&r);
        wide[47] += 5;
        assert_eq!(scalar_wide(&wide), Scalar::from(5u64));
    }

    #[test]
    fn small_multiples_match_scalar_multiplication() {
        let g = G2Projective::generator();
        for k in [0u64, 1, 2, 3, 7, 255, 1 << 31, u64::MAX] {
            assert_eq!(mul_small(&g, k), g * Scalar::from(k), "{k}");
        }
    }

    #[test]
    fn point_decoding_rejects_garbage() {
        assert_eq!(g1(&[0xFF; 48]), None);
        assert_eq!(g2(&[0xFF; 96]), None);
        let g = G1Affine::generator();
        assert_eq!(g1(&g.to_compressed()), Some(g));
        let h = G2Affine::generator();
        assert_eq!(g2(&h.to_compressed()), Some(h));
    }
}
