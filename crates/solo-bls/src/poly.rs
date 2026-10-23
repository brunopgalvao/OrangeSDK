//! Secret polynomials, Feldman commitments and Lagrange coefficients
//! (spec 12 §4).

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use bls12_381::{G2Affine, G2Projective, Scalar};
use zeroize::Zeroize;

use crate::{Error, hash, point};

/// Domain separation tag of polynomial coefficients derived from a seed.
pub(crate) const DST_COEFFICIENT: &[u8] = b"SOLO-V01-COEFFICIENT_XMD:SHA-256";

/// A secret polynomial over the scalar field, lowest coefficient first.
/// Zeroed on drop.
pub(crate) struct Polynomial(Vec<Scalar>);

impl Drop for Polynomial {
    fn drop(&mut self) {
        for c in &mut self.0 {
            c.zeroize();
        }
    }
}

impl Polynomial {
    /// The polynomial of degree `threshold − 1` whose coefficient `k` is
    /// `hash_to_scalar(seed ‖ context ‖ k as u32 big-endian)` under
    /// [`DST_COEFFICIENT`], except that `constant`, when given, replaces
    /// coefficient 0.
    pub(crate) fn derive(
        seed: &[u8; 32],
        context: &[u8],
        threshold: u32,
        constant: Option<Scalar>,
    ) -> Polynomial {
        let mut coefficients: Vec<Scalar> = (0..threshold)
            .map(|k| hash::to_scalar(&[seed, context, &k.to_be_bytes()], DST_COEFFICIENT))
            .collect();
        if let Some(c) = constant {
            coefficients[0] = c;
        }
        Polynomial(coefficients)
    }

    /// The constant term.
    #[cfg(test)]
    pub(crate) fn constant(&self) -> Scalar {
        self.0[0]
    }

    /// The value at `x`, by Horner's rule.
    pub(crate) fn evaluate(&self, x: u32) -> Scalar {
        let x = Scalar::from(u64::from(x));
        self.0
            .iter()
            .rev()
            .fold(Scalar::zero(), |acc, c| acc * x + c)
    }

    /// The Feldman commitment: each coefficient times the G2 generator.
    pub(crate) fn commit(&self) -> Vec<G2Affine> {
        let points: Vec<G2Projective> = self
            .0
            .iter()
            .map(|c| G2Projective::generator() * c)
            .collect();
        normalize(&points)
    }
}

/// Affine forms of `points`, with one shared inversion.
pub(crate) fn normalize(points: &[G2Projective]) -> Vec<G2Affine> {
    let mut out = alloc::vec![G2Affine::identity(); points.len()];
    G2Projective::batch_normalize(points, &mut out);
    out
}

/// The committed polynomial evaluated "in the exponent" at `x`:
/// `Σ x^k · C_k`, which equals `f(x) · g2` for the polynomial `f` behind the
/// commitment.
pub(crate) fn evaluate_commitment(commitment: &[G2Affine], x: u32) -> G2Projective {
    commitment
        .iter()
        .rev()
        .fold(G2Projective::identity(), |acc, c| {
            point::mul_small(&acc, u64::from(x)) + c
        })
}

/// The committed polynomial evaluated in the exponent at `1, 2, …, count`,
/// by forward differences (spec 12 §4.2): the same points as
/// [`evaluate_commitment`] at each.
///
/// `P(x) = Σ_k x^k · C_k` is rewritten by Horner's rule in the
/// falling-factorial basis, `P(x) = Σ_j A_j · x(x − 1)…(x − j + 1)`, using
/// `x · x^(j) = x^(j+1) + j · x^(j)` for the falling factorial `x^(j)`: a
/// multiplication of each running coefficient by its small index per step.
/// The forward differences of `P` at zero are then `Δ^j P(0) = j! · A_j`, and
/// stepping the difference table from `x` to `x + 1` is `Δ^j P += Δ^(j+1) P`
/// for every `j`, one addition each.
pub(crate) fn evaluate_commitment_at_naturals(
    commitment: &[G2Affine],
    count: u32,
) -> Vec<G2Projective> {
    let t = commitment.len();
    // Falling-factorial coefficients of the running Horner value.
    let mut table = alloc::vec![G2Projective::identity(); t];
    for (k, c) in commitment.iter().enumerate().rev() {
        // Multiply by x: coefficient i becomes A_(i−1) + i · A_i, the
        // highest first so that each reads the old values. Coefficient i is
        // still the identity until step t − 1 − i, so the loop skips it.
        for i in (1..t - k).rev() {
            table[i] = point::mul_small(&table[i], i as u64) + table[i - 1];
        }
        table[0] = G2Projective::from(c);
    }
    // Δ^j P(0) = j! · A_j.
    let mut factorial = Scalar::one();
    for (j, entry) in table.iter_mut().enumerate().skip(2) {
        factorial *= Scalar::from(j as u64);
        *entry *= factorial;
    }
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        for j in 0..t - 1 {
            let next = table[j + 1];
            table[j] += next;
        }
        out.push(table[0]);
    }
    out
}

/// Whether `share` is the value at `x` of the polynomial behind `commitment`
/// (the Feldman check).
pub(crate) fn share_matches(commitment: &[G2Affine], x: u32, share: &Scalar) -> bool {
    G2Projective::generator() * share == evaluate_commitment(commitment, x)
}

/// The Lagrange coefficients at zero for the points `indices`:
/// `λ_i = Π_{j ≠ i} x_j / (x_j − x_i)`.
///
/// # Errors
/// [`Error::InvalidIndex`] if an index is zero or repeated.
pub(crate) fn lagrange_at_zero(indices: &[u32]) -> Result<Vec<Scalar>, Error> {
    let mut seen = BTreeSet::new();
    if indices.iter().any(|&i| i == 0 || !seen.insert(i)) {
        return Err(Error::InvalidIndex);
    }
    let xs: Vec<Scalar> = indices
        .iter()
        .map(|&i| Scalar::from(u64::from(i)))
        .collect();
    let mut out = Vec::with_capacity(xs.len());
    for (i, xi) in xs.iter().enumerate() {
        let mut num = Scalar::one();
        let mut den = Scalar::one();
        for (j, xj) in xs.iter().enumerate() {
            if i != j {
                num *= xj;
                den *= xj - xi;
            }
        }
        let inv: Option<Scalar> = den.invert().into();
        out.push(num * inv.expect("distinct indices below 2^32 differ modulo r"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluation_matches_the_commitment_and_interpolation_recovers_the_constant() {
        let p = Polynomial::derive(&[3; 32], b"ctx", 4, None);
        let c = p.commit();
        assert_eq!(c.len(), 4);
        for x in 1..=6 {
            assert!(share_matches(&c, x, &p.evaluate(x)));
            assert!(!share_matches(&c, x, &(p.evaluate(x) + Scalar::one())));
        }
        assert_eq!(evaluate_commitment(&c, 0), G2Projective::from(c[0]));
        let xs = [2u32, 5, 6, 9];
        let lambda = lagrange_at_zero(&xs).unwrap();
        let at_zero: Scalar = xs
            .iter()
            .zip(&lambda)
            .map(|(&x, l)| p.evaluate(x) * l)
            .sum();
        assert_eq!(at_zero, p.constant());
        // Three points of a degree-3 polynomial do not determine it.
        let lambda = lagrange_at_zero(&xs[..3]).unwrap();
        let wrong: Scalar = xs
            .iter()
            .zip(&lambda)
            .map(|(&x, l)| p.evaluate(x) * l)
            .sum();
        assert_ne!(wrong, p.constant());
    }

    #[test]
    fn derivation_is_deterministic_and_respects_the_constant() {
        let a = Polynomial::derive(&[1; 32], b"x", 3, None);
        let b = Polynomial::derive(&[1; 32], b"x", 3, None);
        let other = Polynomial::derive(&[1; 32], b"y", 3, None);
        assert_eq!(a.0, b.0);
        assert_ne!(a.0, other.0);
        let fixed = Polynomial::derive(&[1; 32], b"x", 3, Some(Scalar::from(42u64)));
        assert_eq!(fixed.constant(), Scalar::from(42u64));
        assert_eq!(fixed.0[1..], a.0[1..]);
    }

    #[test]
    fn lagrange_rejects_zero_and_repeated_indices() {
        assert_eq!(lagrange_at_zero(&[1, 0]), Err(Error::InvalidIndex));
        assert_eq!(lagrange_at_zero(&[3, 4, 3]), Err(Error::InvalidIndex));
        assert_eq!(lagrange_at_zero(&[7]).unwrap(), alloc::vec![Scalar::one()]);
    }
}
