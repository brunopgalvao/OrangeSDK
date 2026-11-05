//! Ethereum consensus-layer signatures: BLS over BLS12-381 in the
//! minimal-public-key-size variant, public keys in G1 (48 bytes) and
//! signatures in G2 (96 bytes), with the proof-of-possession ciphersuite
//! `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (draft-irtf-cfrg-bls-signature-05
//! §4.2.3). This is the scheme of the beacon chain's sync committees, which
//! the sync-committee light client of spec 18 verifies through the gated
//! host function `bls12381_fast_aggregate_verify` (spec 05 §4.3).
//!
//! OrangeSDK's own certificates use the other variant (spec 12, [`crate::sig`]).

use bls12_381::{G1Affine, G1Projective, G2Prepared, Gt};

use crate::{hash, point};

/// The ciphersuite's hash-to-curve tag: messages are hashed to G2 with
/// `BLS12381G2_XMD:SHA-256_SSWU_RO_` under it.
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Length of a compressed public key.
pub const PUBLIC_KEY_LENGTH: usize = 48;

/// Length of a compressed signature.
pub const SIGNATURE_LENGTH: usize = 96;

/// `FastAggregateVerify(PK_1..PK_n, message, signature)` of the proof-of-
/// possession ciphersuite: whether `signature` (a compressed G2 point) is a
/// valid signature over `msg` by the sum of the compressed G1 keys `keys`,
/// concatenated.
///
/// False when `keys` is empty or not a whole number of keys, when a key
/// fails `KeyValidate` (it does not decode, lies outside the prime-order
/// subgroup, or is the identity), when the keys sum to the identity, and
/// when the signature does not decode or lies outside its subgroup. Every
/// key must have had its proof of possession verified when it was
/// registered, as the beacon chain does at deposit, or a rogue key could
/// cancel the others.
///
/// # Panics
/// Never: the keys are read in whole chunks of 48 bytes.
#[must_use]
pub fn fast_aggregate_verify(keys: &[u8], msg: &[u8], signature: &[u8; SIGNATURE_LENGTH]) -> bool {
    if keys.is_empty() || !keys.len().is_multiple_of(PUBLIC_KEY_LENGTH) {
        return false;
    }
    let Some(signature) = point::g2(signature) else {
        return false;
    };
    let mut sum = G1Projective::identity();
    for key in keys.chunks_exact(PUBLIC_KEY_LENGTH) {
        let key: &[u8; PUBLIC_KEY_LENGTH] = key.try_into().expect("whole chunks");
        match point::g1(key) {
            Some(p) if !bool::from(p.is_identity()) => sum += p,
            _ => return false,
        }
    }
    if bool::from(sum.is_identity()) {
        return false;
    }
    let sum = G1Affine::from(sum);
    let h = G2Prepared::from(hash::to_g2(msg, DST));
    let signature = G2Prepared::from(signature);
    let neg_g1 = -G1Affine::generator();
    // e(Σ pk, H(m)) = e(g1, σ), as one multi-Miller loop.
    bls12_381::multi_miller_loop(&[(&sum, &h), (&neg_g1, &signature)]).final_exponentiation()
        == Gt::identity()
}

#[cfg(test)]
mod tests {
    use bls12_381::{G2Affine, G2Projective, Scalar};

    use super::*;

    fn secret(i: u64) -> Scalar {
        Scalar::from(i * 7919 + 13)
    }

    fn public(i: u64) -> [u8; 48] {
        (G1Affine::generator() * secret(i)).to_affine_bytes()
    }

    trait Bytes {
        fn to_affine_bytes(&self) -> [u8; 48];
    }

    impl Bytes for G1Projective {
        fn to_affine_bytes(&self) -> [u8; 48] {
            G1Affine::from(self).to_compressed()
        }
    }

    fn sign(signers: &[u64], msg: &[u8]) -> [u8; 96] {
        let h = G2Projective::from(hash::to_g2(msg, DST));
        let sum: G2Projective = signers.iter().map(|i| h * secret(*i)).sum();
        G2Affine::from(sum).to_compressed()
    }

    fn keys(signers: &[u64]) -> alloc::vec::Vec<u8> {
        signers.iter().flat_map(|i| public(*i)).collect()
    }

    #[test]
    fn verifies_an_aggregate_and_rejects_what_it_should() {
        let signers = [1, 2, 3, 4];
        let sig = sign(&signers, b"root");
        assert!(fast_aggregate_verify(&keys(&signers), b"root", &sig));
        assert!(!fast_aggregate_verify(&keys(&signers), b"rooT", &sig));
        assert!(!fast_aggregate_verify(&keys(&signers[..3]), b"root", &sig));
        assert!(!fast_aggregate_verify(&[], b"root", &sig));
        assert!(!fast_aggregate_verify(&keys(&signers)[..47], b"root", &sig));
        // One signer alone.
        assert!(fast_aggregate_verify(&keys(&[9]), b"m", &sign(&[9], b"m")));
        // A signature that does not decode.
        assert!(!fast_aggregate_verify(
            &keys(&signers),
            b"root",
            &[0xFF; 96]
        ));
        // A key that does not decode, and the identity key.
        let mut bad = keys(&signers);
        bad[..48].fill(0xFF);
        assert!(!fast_aggregate_verify(&bad, b"root", &sig));
        let mut infinity = keys(&signers);
        infinity[..48].copy_from_slice(&G1Affine::identity().to_compressed());
        assert!(!fast_aggregate_verify(&infinity, b"root", &sig));
        // Keys that cancel: KeyValidate passes for each, the sum is the identity,
        // and the identity signature would satisfy the pairing equation.
        let k = public(5);
        let neg = G1Affine::from(-(G1Affine::generator() * secret(5))).to_compressed();
        let cancel = [k, neg].concat();
        let identity_sig = G2Affine::identity().to_compressed();
        assert!(!fast_aggregate_verify(&cancel, b"root", &identity_sig));
    }
}
