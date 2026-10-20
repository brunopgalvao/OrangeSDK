//! The signature scheme of spec 12 §3: BLS over BLS12-381 in the
//! minimal-signature-size variant. Signatures and message hashes are G1
//! points (48 bytes compressed), public keys are G2 points (96 bytes).

use core::fmt;

use bls12_381::{G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar};
use hkdf::HkdfExtract;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{Error, hash, point};

/// Domain separation tag of every signature over a message (spec 12 §3).
pub const DST_SIGNATURE: &[u8] = b"SOLO-V01-CS01-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// Domain separation tag of proofs of possession (spec 12 §3).
pub const DST_POSSESSION: &[u8] = b"SOLO-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// A secret key: a nonzero scalar. Zeroed on drop.
pub struct SecretKey(pub(crate) Scalar);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl SecretKey {
    /// `KeyGen` of draft-irtf-cfrg-bls-signature-05 §2.3 (the same function
    /// as `HKDF_mod_r` of EIP-2333): HKDF-SHA-256 over `ikm`, retried with a
    /// rehashed salt until the result is nonzero.
    ///
    /// # Errors
    /// [`Error::ShortKeyMaterial`] if `ikm` is shorter than 32 bytes.
    pub fn generate(ikm: &[u8], key_info: &[u8]) -> Result<SecretKey, Error> {
        if ikm.len() < 32 {
            return Err(Error::ShortKeyMaterial);
        }
        Ok(SecretKey(keygen(ikm, key_info)))
    }

    /// Decodes 32 big-endian bytes.
    ///
    /// # Errors
    /// [`Error::InvalidScalar`] for zero or a value at or above the group order.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<SecretKey, Error> {
        match point::scalar(bytes) {
            Some(s) if s != Scalar::zero() => Ok(SecretKey(s)),
            _ => Err(Error::InvalidScalar),
        }
    }

    /// The 32 big-endian bytes of the key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        point::scalar_bytes(&self.0)
    }

    /// The public key `sk · g2`.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey((G2Affine::generator() * self.0).into())
    }

    /// Signs `msg`: `sk · H(msg)` with [`DST_SIGNATURE`].
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature((hash::to_g1(msg, DST_SIGNATURE) * self.0).into())
    }

    /// Proves possession of the key: `sk · H(pk)` with [`DST_POSSESSION`],
    /// where `pk` is the compressed public key. Required of every key that
    /// enters a same-message aggregate.
    #[must_use]
    pub fn prove_possession(&self) -> Signature {
        let pk = self.public_key().to_bytes();
        Signature((hash::to_g1(&pk, DST_POSSESSION) * self.0).into())
    }
}

/// `KeyGen` without the length check.
pub(crate) fn keygen(ikm: &[u8], key_info: &[u8]) -> Scalar {
    let mut salt: [u8; 32] = Sha256::digest(b"BLS-SIG-KEYGEN-SALT-").into();
    let mut sk = Scalar::zero();
    while sk == Scalar::zero() {
        let mut extract = HkdfExtract::<Sha256>::new(Some(&salt));
        extract.input_ikm(ikm);
        extract.input_ikm(&[0]);
        let (_, hk) = extract.finalize();
        let mut okm = [0u8; 48];
        hk.expand_multi_info(&[key_info, &[0, 48]], &mut okm)
            .expect("48 bytes is within HKDF-SHA-256's output limit");
        sk = point::scalar_wide(&okm);
        okm.zeroize();
        salt = Sha256::digest(salt).into();
    }
    sk
}

/// A public key: a G2 point other than the identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub(crate) G2Affine);

impl PublicKey {
    /// Decodes a compressed G2 point, rejecting the identity.
    ///
    /// # Errors
    /// [`Error::InvalidPoint`].
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<PublicKey, Error> {
        match point::g2(bytes) {
            Some(p) if !bool::from(p.is_identity()) => Ok(PublicKey(p)),
            _ => Err(Error::InvalidPoint),
        }
    }

    /// The compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_compressed()
    }

    /// The point.
    #[must_use]
    pub fn point(&self) -> &G2Affine {
        &self.0
    }

    /// Verifies a signature over `msg`.
    #[must_use]
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
        verify_hashed(&hash::to_g1(msg, DST_SIGNATURE), &signature.0, &self.0)
    }

    /// Verifies a proof of possession of this key.
    #[must_use]
    pub fn verify_possession(&self, proof: &Signature) -> bool {
        let h = hash::to_g1(&self.to_bytes(), DST_POSSESSION);
        verify_hashed(&h, &proof.0, &self.0)
    }

    /// The sum of `keys`, for verifying a same-message aggregate. Every key
    /// must have had its proof of possession verified, or a rogue key can
    /// cancel the others.
    ///
    /// # Errors
    /// [`Error::InvalidLength`] for no keys, [`Error::InvalidPoint`] if the
    /// sum is the identity.
    pub fn aggregate(keys: &[PublicKey]) -> Result<PublicKey, Error> {
        if keys.is_empty() {
            return Err(Error::InvalidLength);
        }
        let sum: G2Projective = keys.iter().map(|k| G2Projective::from(k.0)).sum();
        if bool::from(sum.is_identity()) {
            return Err(Error::InvalidPoint);
        }
        Ok(PublicKey(sum.into()))
    }
}

/// A signature: a G1 point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub(crate) G1Affine);

impl Signature {
    /// Decodes a compressed G1 point.
    ///
    /// # Errors
    /// [`Error::InvalidPoint`].
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Signature, Error> {
        point::g1(bytes).map(Signature).ok_or(Error::InvalidPoint)
    }

    /// The compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.to_compressed()
    }

    /// The point.
    #[must_use]
    pub fn point(&self) -> &G1Affine {
        &self.0
    }

    /// The sum of `signatures`: a same-message aggregate verifies against
    /// the sum of the signers' keys.
    #[must_use]
    pub fn aggregate(signatures: &[Signature]) -> Signature {
        let sum: G1Projective = signatures.iter().map(|s| G1Projective::from(s.0)).sum();
        Signature(sum.into())
    }
}

/// `FastAggregateVerify`: one signature over `msg` by every key in `keys`,
/// each of which must have a verified proof of possession.
#[must_use]
pub fn verify_aggregate(keys: &[PublicKey], msg: &[u8], signature: &Signature) -> bool {
    PublicKey::aggregate(keys).is_ok_and(|key| key.verify(msg, signature))
}

/// The pairing equation of every verification: `e(σ, −g2) · e(h, pk) = 1`,
/// computed as one multi-Miller loop and one final exponentiation.
pub(crate) fn verify_hashed(h: &G1Affine, signature: &G1Affine, key: &G2Affine) -> bool {
    let neg_g2 = G2Prepared::from(-G2Affine::generator());
    let key = G2Prepared::from(*key);
    bls12_381::multi_miller_loop(&[(signature, &neg_g2), (h, &key)]).final_exponentiation()
        == Gt::identity()
}
