//! `t`-of-`n` threshold signatures (spec 12 §4): secret shares of a group
//! key, the public key set that commits to them, partial signatures and
//! their combination into the one group signature.

use alloc::vec::Vec;
use core::fmt;

use bls12_381::{G2Affine, G2Projective, Scalar};
use zeroize::Zeroize;

use crate::poly::{self, Polynomial};
use crate::sig::{DST_SIGNATURE, PublicKey, SecretKey, Signature};
use crate::{Error, batch, hash, point};

/// One participant's share `f(i)` of the group secret `f(0)`. Zeroed on drop.
pub struct SecretShare {
    pub(crate) index: u32,
    pub(crate) secret: Scalar,
}

impl fmt::Debug for SecretShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretShare({}, ..)", self.index)
    }
}

impl Drop for SecretShare {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl SecretShare {
    /// A share from its index and 32 big-endian bytes, as persisted.
    ///
    /// # Errors
    /// [`Error::InvalidIndex`] for index zero, [`Error::InvalidScalar`] for a
    /// non-canonical scalar.
    pub fn from_bytes(index: u32, bytes: &[u8; 32]) -> Result<SecretShare, Error> {
        if index == 0 {
            return Err(Error::InvalidIndex);
        }
        let secret = point::scalar(bytes).ok_or(Error::InvalidScalar)?;
        Ok(SecretShare { index, secret })
    }

    /// The participant index, starting at 1.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The 32 big-endian bytes of the share.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        point::scalar_bytes(&self.secret)
    }

    /// The public key share `f(i) · g2`.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey((G2Affine::generator() * self.secret).into())
    }

    /// The partial signature `f(i) · H(msg)`.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> PartialSignature {
        let h = hash::to_g1(msg, DST_SIGNATURE);
        PartialSignature {
            index: self.index,
            signature: Signature((h * self.secret).into()),
        }
    }
}

/// A partial signature by the holder of share `index`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialSignature {
    /// The signer's share index.
    pub index: u32,
    /// `f(index) · H(msg)`.
    pub signature: Signature,
}

/// The public side of a threshold key: the Feldman commitment
/// `(a_0 · g2, …, a_{t−1} · g2)` to the group polynomial. Its first point is
/// the group public key; evaluating it at `i` gives participant `i`'s public
/// key share; its length is the threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeySet {
    pub(crate) commitment: Vec<G2Affine>,
}

impl PublicKeySet {
    /// A key set from its commitment points.
    ///
    /// # Errors
    /// [`Error::InvalidThreshold`] for no points, [`Error::InvalidPoint`] if
    /// the group key is the identity.
    pub fn new(commitment: Vec<G2Affine>) -> Result<PublicKeySet, Error> {
        let Some(first) = commitment.first() else {
            return Err(Error::InvalidThreshold);
        };
        if bool::from(first.is_identity()) {
            return Err(Error::InvalidPoint);
        }
        Ok(PublicKeySet { commitment })
    }

    /// Decodes the concatenated compressed commitment points.
    ///
    /// # Errors
    /// [`Error::InvalidLength`] unless the length is a multiple of 96,
    /// [`Error::InvalidPoint`] for a bad point, and the errors of [`Self::new`].
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKeySet, Error> {
        if !bytes.len().is_multiple_of(96) {
            return Err(Error::InvalidLength);
        }
        let mut points = Vec::with_capacity(bytes.len() / 96);
        for chunk in bytes.chunks_exact(96) {
            let mut raw = [0u8; 96];
            raw.copy_from_slice(chunk);
            points.push(point::g2(&raw).ok_or(Error::InvalidPoint)?);
        }
        PublicKeySet::new(points)
    }

    /// The concatenated compressed commitment points.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.commitment
            .iter()
            .flat_map(G2Affine::to_compressed)
            .collect()
    }

    /// The commitment points, lowest degree first.
    #[must_use]
    pub fn commitment(&self) -> &[G2Affine] {
        &self.commitment
    }

    /// The number of partial signatures that make a group signature.
    ///
    /// # Panics
    /// Never for a key set built by this crate, whose commitments are far
    /// shorter than `2^32` points.
    #[must_use]
    pub fn threshold(&self) -> u32 {
        u32::try_from(self.commitment.len()).expect("commitment length fits u32")
    }

    /// The group public key, which every certificate verifies against.
    #[must_use]
    pub fn group_key(&self) -> PublicKey {
        PublicKey(self.commitment[0])
    }

    /// Participant `index`'s public key share.
    #[must_use]
    pub fn public_share(&self, index: u32) -> PublicKey {
        PublicKey(poly::evaluate_commitment(&self.commitment, index).into())
    }

    /// The public key shares of indices `1..=count`, in order: exactly
    /// [`Self::public_share`] of each, computed together (spec 12 §4.2).
    ///
    /// One by one, each share is `t` Horner steps, each a multiplication by
    /// the index, so `count · t` of them. Together, once `count` is at least
    /// half the threshold, the commitment polynomial is first rewritten in
    /// the falling-factorial basis `x(x − 1)…(x − j + 1)` (about `t²/2`
    /// multiplications by `j < t`), which gives its forward differences at
    /// zero; from there each next share costs `t − 1` additions. Fewer
    /// shares are evaluated one by one, which is then cheaper.
    #[must_use]
    pub fn public_shares(&self, count: u32) -> Vec<PublicKey> {
        let t = self.commitment.len();
        let points: Vec<G2Projective> = if (count as usize) < t.div_ceil(2) {
            (1..=count)
                .map(|x| poly::evaluate_commitment(&self.commitment, x))
                .collect()
        } else {
            poly::evaluate_commitment_at_naturals(&self.commitment, count)
        };
        poly::normalize(&points)
            .into_iter()
            .map(PublicKey)
            .collect()
    }

    /// Whether `signature` is a valid group signature over `msg`.
    #[must_use]
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
        self.group_key().verify(msg, signature)
    }

    /// Whether `partial` is a valid partial signature over `msg` by the
    /// share it names.
    #[must_use]
    pub fn verify_partial(&self, msg: &[u8], partial: &PartialSignature) -> bool {
        partial.index != 0
            && self
                .public_share(partial.index)
                .verify(msg, &partial.signature)
    }

    /// Which of `partials` are valid partial signatures over `msg`, one flag
    /// each, in order: the same answer as [`Self::verify_partial`] on each,
    /// except with probability at most `2^−64` per invalid partial, found
    /// with one batched check of all of them and, when that fails, of halves
    /// until each invalid one stands alone (spec 12 §4.1). `key` must be
    /// fresh secret randomness: whoever chose the partials must not know it.
    #[must_use]
    pub fn verify_partials(
        &self,
        msg: &[u8],
        partials: &[PartialSignature],
        key: &[u8; 32],
    ) -> Vec<bool> {
        let h = hash::to_g1(msg, DST_SIGNATURE);
        let rho: Vec<u64> = (0u64..)
            .zip(partials)
            .map(|(j, _)| batch::coefficient(&[key, &j.to_be_bytes()], batch::DST_PARTIAL_BATCH))
            .collect();
        batch::valid_partials(&self.commitment, &h, partials, &rho)
    }

    /// Combines the first `threshold` partial signatures by Lagrange
    /// interpolation at zero. The result is the unique group signature over
    /// the message the partials sign when every one of them is valid, so a
    /// caller verifies either each partial or the result.
    ///
    /// # Errors
    /// [`Error::NotEnoughShares`] for fewer than `threshold` partials,
    /// [`Error::InvalidIndex`] if the ones used repeat an index or name zero.
    pub fn combine(&self, partials: &[PartialSignature]) -> Result<Signature, Error> {
        let t = self.commitment.len();
        if partials.len() < t {
            return Err(Error::NotEnoughShares);
        }
        interpolate(&partials[..t])
    }
}

/// Lagrange interpolation at zero of any number of partial signatures.
pub(crate) fn interpolate(partials: &[PartialSignature]) -> Result<Signature, Error> {
    let indices: Vec<u32> = partials.iter().map(|p| p.index).collect();
    let lambda = poly::lagrange_at_zero(&indices)?;
    let sum: bls12_381::G1Projective = partials
        .iter()
        .zip(&lambda)
        .map(|(p, l)| p.signature.0 * l)
        .sum();
    Ok(Signature(sum.into()))
}

/// Splits `secret` into `n` shares of which any `threshold` sign, as a
/// trusted dealer: for tests, and for a chain run by one operator who
/// holds every share anyway. Coefficients above the constant are derived
/// from `seed`, which must be fresh randomness. Validator sets use
/// [`crate::dkg`] instead.
///
/// # Errors
/// [`Error::InvalidThreshold`] unless `1 ≤ threshold ≤ n`.
pub fn deal(
    secret: &SecretKey,
    threshold: u32,
    n: u32,
    seed: &[u8; 32],
) -> Result<(PublicKeySet, Vec<SecretShare>), Error> {
    if threshold == 0 || threshold > n {
        return Err(Error::InvalidThreshold);
    }
    let f = Polynomial::derive(seed, b"deal", threshold, Some(secret.0));
    let shares = (1..=n)
        .map(|index| SecretShare {
            index,
            secret: f.evaluate(index),
        })
        .collect();
    Ok((
        PublicKeySet {
            commitment: f.commit(),
        },
        shares,
    ))
}

/// The group public key a set of key shares commits to, recomputed from
/// `threshold` public key shares by interpolation in G2. Lets a verifier
/// that only knows shares check a claimed group key.
///
/// # Errors
/// [`Error::InvalidIndex`] if an index is zero or repeated.
pub fn interpolate_public(shares: &[(u32, PublicKey)]) -> Result<PublicKey, Error> {
    let indices: Vec<u32> = shares.iter().map(|(i, _)| *i).collect();
    let lambda = poly::lagrange_at_zero(&indices)?;
    let sum: G2Projective = shares.iter().zip(&lambda).map(|((_, k), l)| k.0 * l).sum();
    Ok(PublicKey(sum.into()))
}
