//! The verification procedure of spec 12 §8 run against an independent
//! model of the EIP-2537 precompiles, and checked against this crate's
//! hash-to-curve and signatures. The model calls arkworks exactly as revm's
//! precompiles do when built without blst; the same procedure was also run
//! as a Solidity contract on a Prague EVM (spec 12 Appendix A).

use orange_bls::curve::{G1Affine, G2Affine};
use orange_bls::sig::DST_SIGNATURE;
use orange_bls::{Certificate, PublicKey, SecretKey, certificate, evm, hash, threshold};

/// The three precompiles a verifier calls, over their byte formats.
mod eip2537 {
    use ark_bls12_381::{Bls12_381, Fq, Fq2, G1Affine, G2Affine};
    use ark_ec::hashing::curve_maps::wb::WBMap;
    use ark_ec::hashing::map_to_curve_hasher::MapToCurve;
    use ark_ec::pairing::Pairing;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{One, Zero};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    /// A 64-byte padded field element; `None` unless the padding is zero
    /// and the value is below `p`.
    fn fp(bytes: &[u8]) -> Option<Fq> {
        if bytes[..16].iter().any(|&b| b != 0) {
            return None;
        }
        let mut le = bytes[16..64].to_vec();
        le.reverse();
        Fq::deserialize_uncompressed(&le[..]).ok()
    }

    fn encode_fp(f: &Fq, out: &mut [u8]) {
        let mut le = [0u8; 48];
        f.serialize_uncompressed(&mut le[..]).unwrap();
        le.reverse();
        out[16..64].copy_from_slice(&le);
    }

    fn g1(bytes: &[u8]) -> Option<G1Affine> {
        let (x, y) = (fp(&bytes[..64])?, fp(&bytes[64..128])?);
        if x.is_zero() && y.is_zero() {
            return Some(G1Affine::zero());
        }
        let p = G1Affine::new_unchecked(x, y);
        p.is_on_curve().then_some(p)
    }

    fn g2(bytes: &[u8]) -> Option<G2Affine> {
        let x = Fq2::new(fp(&bytes[..64])?, fp(&bytes[64..128])?);
        let y = Fq2::new(fp(&bytes[128..192])?, fp(&bytes[192..256])?);
        if x.is_zero() && y.is_zero() {
            return Some(G2Affine::zero());
        }
        let p = G2Affine::new_unchecked(x, y);
        p.is_on_curve().then_some(p)
    }

    fn encode_g1(p: &G1Affine) -> Vec<u8> {
        let mut out = vec![0u8; 128];
        if let Some((x, y)) = p.xy() {
            encode_fp(&x, &mut out[..64]);
            encode_fp(&y, &mut out[64..]);
        }
        out
    }

    /// `BLS12_MAP_FP_TO_G1` (0x10): map to the curve, clear the cofactor.
    pub fn map_fp_to_g1(input: &[u8]) -> Vec<u8> {
        assert_eq!(input.len(), 64);
        let point: G1Affine = WBMap::map_to_curve(fp(input).unwrap()).unwrap();
        encode_g1(&point.clear_cofactor())
    }

    /// `BLS12_G1ADD` (0x0b), which checks the curve but not the subgroup.
    pub fn g1_add(input: &[u8]) -> Vec<u8> {
        assert_eq!(input.len(), 256);
        let sum = g1(&input[..128]).unwrap() + g1(&input[128..]).unwrap();
        encode_g1(&sum.into_affine())
    }

    /// `BLS12_PAIRING_CHECK` (0x0f): `None` where the precompile fails
    /// (bad length, point off the curve or outside the subgroup).
    pub fn pairing(input: &[u8]) -> Option<bool> {
        if input.is_empty() || !input.len().is_multiple_of(384) {
            return None;
        }
        let mut ps = Vec::new();
        let mut qs = Vec::new();
        for pair in input.chunks(384) {
            let p = g1(&pair[..128])?;
            let q = g2(&pair[128..])?;
            if !p.is_in_correct_subgroup_assuming_on_curve()
                || !q.is_in_correct_subgroup_assuming_on_curve()
            {
                return None;
            }
            ps.push(p);
            qs.push(q);
        }
        Some(Bls12_381::multi_pairing(ps, qs).0.is_one())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .concat()
}

/// What a contract does: hash the message to G1 with two maps and an
/// addition, then run the pairing check.
fn contract_verify(
    chain_id: u64,
    height: u64,
    block_hash: &[u8; 32],
    signature: &[u8; 128],
    key: &[u8; 256],
) -> Option<bool> {
    let msg = certificate::message(chain_id, height, block_hash);
    let [u0, u1] = evm::hash_to_field(&msg, DST_SIGNATURE);
    let sum = eip2537::g1_add(&[eip2537::map_fp_to_g1(&u0), eip2537::map_fp_to_g1(&u1)].concat());
    let neg_g2 = evm::encode_g2(&-G2Affine::generator());
    eip2537::pairing(&[signature.as_slice(), &neg_g2, &sum, key].concat())
}

/// The intermediate values of spec 12 §9.1, step by step.
#[test]
fn the_worked_example_step_by_step() {
    let msg = certificate::message(1337, 1, &[0xab; 32]);
    assert_eq!(
        hex(&hash::expand_message_xmd(&msg, DST_SIGNATURE, 128)),
        "e30e1fabce37270e6233d8d182417bc724a8a1b4fec166544aca6ba5e8c3fa58350a909d9a01a5aa1489aa0ede743569ff9dfce521a9c1b65154a8ca2f849415aeed4fd380f605f147ce42d113f2535c6b61c1f10ffb3df15dd62f0880fccb9daa2c20b919e5ba76b6803bf023e3dfe769386a659411acce4ecd336874c5afb6"
    );
    let [u0, u1] = evm::hash_to_field(&msg, DST_SIGNATURE);
    let q0 = eip2537::map_fp_to_g1(&u0);
    let q1 = eip2537::map_fp_to_g1(&u1);
    assert_eq!(
        hex(&q0),
        "0000000000000000000000000000000005610b51dc93d448f487264f569d2112417a936e8bc241d922d32550d602c017ec2bb506c251f5725f7a168671afed64000000000000000000000000000000000a43f864c866319c1fe24cdbbc4ee1ea44554623e62e002047b33573f8e1fefe818d705d8fe94123e52b5a123cc13df6"
    );
    assert_eq!(
        hex(&q1),
        "00000000000000000000000000000000163a9b749c315db80c4785f8c69a0af93380a6cae95b582a7f48f33e51ceb63b770599853c12107401b358c70b8a4c2e0000000000000000000000000000000018e7678557110ab62c3523d2d770e2933ecef0359235a76ad596ed98aa9a6c71d14e4cdcc4fdd07e3e6aef6e60dfcaa4"
    );
    assert_eq!(
        eip2537::g1_add(&[q0, q1].concat()),
        evm::encode_g1(&hash::to_g1(&msg, DST_SIGNATURE))
    );
}

#[test]
fn map_and_add_reproduce_hash_to_curve() {
    for msg in [&b""[..], b"abc", &certificate::message(1, 2, &[3; 32])] {
        let [u0, u1] = evm::hash_to_field(msg, DST_SIGNATURE);
        let sum =
            eip2537::g1_add(&[eip2537::map_fp_to_g1(&u0), eip2537::map_fp_to_g1(&u1)].concat());
        assert_eq!(sum, evm::encode_g1(&hash::to_g1(msg, DST_SIGNATURE)));
    }
}

#[test]
fn a_certificate_verifies_on_the_precompiles_and_a_forgery_does_not() {
    let sk = SecretKey::generate(&[0x77; 32], b"").unwrap();
    let pk = evm::encode_g2(sk.public_key().point());
    let block = [0xcd; 32];
    let sig = sk.sign(&certificate::message(1337, 42, &block));
    let encoded = evm::encode_g1(sig.point());
    assert_eq!(contract_verify(1337, 42, &block, &encoded, &pk), Some(true));
    assert_eq!(
        contract_verify(1337, 43, &block, &encoded, &pk),
        Some(false)
    );
    assert_eq!(
        contract_verify(1338, 42, &block, &encoded, &pk),
        Some(false)
    );
    let other = evm::encode_g2(
        SecretKey::generate(&[0x78; 32], b"")
            .unwrap()
            .public_key()
            .point(),
    );
    assert_eq!(
        contract_verify(1337, 42, &block, &encoded, &other),
        Some(false)
    );
    // The identity signature fails too: e(O, −g2) · e(H, pk) ≠ 1.
    let identity = evm::encode_g1(&G1Affine::identity());
    assert_eq!(
        contract_verify(1337, 42, &block, &identity, &pk),
        Some(false)
    );
    // A signature off the curve makes the precompile fail.
    let mut off_curve = encoded;
    off_curve[127] ^= 1;
    assert_eq!(contract_verify(1337, 42, &block, &off_curve, &pk), None);
    // The precompile's own input is what `pairing_input` builds.
    let h = hash::to_g1(&certificate::message(1337, 42, &block), DST_SIGNATURE);
    let input = evm::pairing_input(sig.point(), &h, sk.public_key().point());
    assert_eq!(eip2537::pairing(&input), Some(true));
    assert_eq!(evm::VERIFY_BLS_GAS, 114_275);
}

#[test]
fn a_threshold_certificate_verifies_under_the_static_group_key() {
    let group = SecretKey::generate(&[0x10; 32], b"").unwrap();
    let (keys, shares) = threshold::deal(&group, 5, 7, &[0x20; 32]).unwrap();
    let block = [0x99; 32];
    let partials: Vec<_> = shares[2..]
        .iter()
        .map(|s| certificate::sign_partial(s, 7, 1_000_000, &block))
        .collect();
    let cert = Certificate::combine(&keys, 7, 1_000_000, &block, &partials).unwrap();
    // The relayer decodes the 89-byte certificate and submits the signature
    // in EIP-2537 form; the contract holds the group key as a constant.
    let decoded = Certificate::from_bytes(&cert.to_bytes()).unwrap();
    let key = PublicKey::from_bytes(&keys.group_key().to_bytes()).unwrap();
    let valid = contract_verify(
        7,
        decoded.height,
        &decoded.block_hash,
        &evm::encode_g1(decoded.signature.point()),
        &evm::encode_g2(key.point()),
    );
    assert_eq!(valid, Some(true));
}
