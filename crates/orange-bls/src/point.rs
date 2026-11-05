//! Encodings shared by every module (spec 12 §2): compressed points and
//! big-endian scalars.

use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

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

/// The `c`-bit digit of a little-endian scalar starting at bit `bit`.
fn digit(scalar: &[u8; 32], bit: usize, c: usize) -> usize {
    (0..c)
        .filter(|i| {
            let b = bit + i;
            b < 256 && (scalar[b / 8] >> (b % 8)) & 1 == 1
        })
        .fold(0, |d, i| d | 1 << i)
}

/// The bucket width for `n` points: about `log2(n) − 2` bits, at least 1.
pub(crate) fn window(n: usize) -> usize {
    usize::try_from(n.max(1).ilog2()).map_or(1, |l| l.saturating_sub(2).clamp(1, 16))
}

macro_rules! multi_scalar_mul {
    ($(#[$meta:meta])* $name:ident, $affine:ty, $projective:ty) => {
        $(#[$meta])*
        pub(crate) fn $name(points: &[$affine], scalars: &[[u8; 32]], bits: usize) -> $projective {
            let c = window(points.len());
            let mut buckets = alloc::vec![<$projective>::identity(); (1 << c) - 1];
            let mut acc = <$projective>::identity();
            for w in (0..bits.div_ceil(c)).rev() {
                for _ in 0..c {
                    acc = acc.double();
                }
                buckets.fill(<$projective>::identity());
                for (p, s) in points.iter().zip(scalars) {
                    if let Some(d) = digit(s, w * c, c).checked_sub(1) {
                        buckets[d] += p;
                    }
                }
                // Σ_d d · bucket_d, as a running sum from the top bucket down.
                let mut running = <$projective>::identity();
                let mut sum = <$projective>::identity();
                for b in buckets.iter().rev() {
                    running += b;
                    sum += running;
                }
                acc += sum;
            }
            acc
        }
    };
}

multi_scalar_mul!(
    /// `Σ k_i · P_i` in G2 by Pippenger's bucket method, for little-endian
    /// scalars `k_i` below `2^bits`. Variable time: only for values the
    /// verifier may reveal, the random coefficients of a batched check and
    /// what follows from public data.
    msm_g2,
    G2Affine,
    G2Projective
);

multi_scalar_mul!(
    /// [`msm_g2`] in G1.
    msm_g1,
    G1Affine,
    G1Projective
);

/// A `u64` as a little-endian scalar for [`msm_g1`] and [`msm_g2`].
pub(crate) fn u64_scalar(k: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&k.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_scalar_multiplication_matches_the_sum_of_products() {
        for n in [0usize, 1, 2, 5, 40, 130] {
            let g1: Vec<G1Affine> = (0..n)
                .map(|i| (G1Affine::generator() * Scalar::from(i as u64 * 31 + 7)).into())
                .collect();
            let g2: Vec<G2Affine> = (0..n)
                .map(|i| (G2Affine::generator() * Scalar::from(i as u64 * 17 + 3)).into())
                .collect();
            let small: Vec<u64> = (0..n as u64)
                .map(|i| i.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
                .collect();
            let wide: Vec<Scalar> = small
                .iter()
                .map(|k| -Scalar::from(*k) * Scalar::from(*k))
                .collect();
            let small_le: Vec<[u8; 32]> = small.iter().map(|k| u64_scalar(*k)).collect();
            let wide_le: Vec<[u8; 32]> = wide.iter().map(Scalar::to_bytes).collect();
            let expect1: G1Projective = g1
                .iter()
                .zip(&small)
                .map(|(p, k)| p * Scalar::from(*k))
                .sum();
            assert_eq!(msm_g1(&g1, &small_le, 64), expect1, "{n}");
            let expect2: G2Projective = g2
                .iter()
                .zip(&small)
                .map(|(p, k)| p * Scalar::from(*k))
                .sum();
            assert_eq!(msm_g2(&g2, &small_le, 64), expect2, "{n}");
            let expect2: G2Projective = g2.iter().zip(&wide).map(|(p, k)| p * k).sum();
            assert_eq!(msm_g2(&g2, &wide_le, 255), expect2, "{n}");
        }
        assert_eq!(window(0), 1);
        assert_eq!(window(1 << 20), 16);
        assert_eq!(window(1 << 30), 16);
    }

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
