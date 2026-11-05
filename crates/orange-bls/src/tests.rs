//! Known-answer and property tests of the scheme, the threshold layer, the
//! certificate and the host-function semantics.

mod vectors;

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use bls12_381::{G1Affine, G2Affine, G2Projective, Scalar};
use proptest::prelude::*;

use crate::certificate::{self, Certificate};
use crate::sig::{self, DST_POSSESSION, DST_SIGNATURE, PublicKey, SecretKey, Signature};
use crate::threshold::{self, PartialSignature, PublicKeySet, SecretShare};
use crate::{Error, evm, hash, host, poly};

/// Decodes hex, ignoring whitespace.
pub(crate) fn unhex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    bytes.iter().fold(alloc::string::String::new(), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    })
}

fn rfc_message(m: &str) -> Vec<u8> {
    match m {
        "q128_" => [b"q128_".as_slice(), &[b'q'; 128]].concat(),
        "a512_" => [b"a512_".as_slice(), &[b'a'; 512]].concat(),
        other => other.as_bytes().to_vec(),
    }
}

/// 16 zero bytes followed by a 48-byte field element given in hex.
fn padded(fp: &str) -> Vec<u8> {
    [vec![0u8; 16], unhex(fp)].concat()
}

#[test]
fn rfc9380_hash_to_g1_and_hash_to_field() {
    for (msg, x, y, u0, u1) in vectors::G1_RO {
        let msg = rfc_message(msg);
        let p = hash::to_g1(&msg, vectors::G1_DST);
        assert_eq!(p.to_uncompressed().to_vec(), [unhex(x), unhex(y)].concat());
        assert_eq!(evm::encode_g1(&p).to_vec(), [padded(x), padded(y)].concat());
        let [f0, f1] = evm::hash_to_field(&msg, vectors::G1_DST);
        assert_eq!(f0.to_vec(), padded(u0));
        assert_eq!(f1.to_vec(), padded(u1));
    }
}

#[test]
fn rfc9380_hash_to_g2_in_eip2537_order() {
    for (msg, x0, x1, y0, y1) in vectors::G2_RO {
        let p = hash::to_g2(&rfc_message(msg), vectors::G2_DST);
        let expected = [padded(x0), padded(x1), padded(y0), padded(y1)].concat();
        assert_eq!(evm::encode_g2(&p).to_vec(), expected);
    }
}

#[test]
fn rfc9380_expand_message_xmd() {
    for (msg, len, uniform) in vectors::EXPAND_XMD {
        let out = hash::expand_message_xmd(&rfc_message(msg), vectors::EXPAND_DST, *len);
        assert_eq!(out, unhex(uniform), "{msg} {len}");
    }
}

#[test]
fn keygen_matches_eip2333_master_keys() {
    let cases = [
        (
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            "0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070",
        ),
        (
            "3141592653589793238462643383279502884197169399375105820974944592",
            "41c9e07822b092a93fd6797396338c3ada4170cc81829fdfce6b5d34bd5e7ec7",
        ),
        (
            "0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
            "3cfa341ab3910a7d00d933d8f7c4fe87c91798a0397421d6b19fd5b815132e80",
        ),
        (
            "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
            "2a0e28ffa5fbbe2f8e7aad4ed94f745d6bf755c51182e119bb1694fe61d3afca",
        ),
    ];
    for (seed, master) in cases {
        let sk = SecretKey::generate(&unhex(seed), b"").unwrap();
        assert_eq!(sk.to_bytes().to_vec(), unhex(master));
    }
    assert_eq!(
        SecretKey::generate(&[0; 31], b"").unwrap_err(),
        Error::ShortKeyMaterial
    );
}

#[test]
fn signatures_verify_and_reject_what_they_should() {
    let sk = SecretKey::generate(&[7; 32], b"").unwrap();
    let pk = sk.public_key();
    let sig = sk.sign(b"block");
    assert!(pk.verify(b"block", &sig));
    assert!(!pk.verify(b"blocc", &sig));
    let other = SecretKey::generate(&[8; 32], b"").unwrap().public_key();
    assert!(!other.verify(b"block", &sig));
    // A signature under another tag is a different point.
    let foreign = Signature((hash::to_g1(b"block", DST_POSSESSION) * sk.0).into());
    assert!(!pk.verify(b"block", &foreign));
    // Encodings round trip; garbage and the identity key are rejected.
    assert_eq!(Signature::from_bytes(&sig.to_bytes()), Ok(sig));
    assert_eq!(PublicKey::from_bytes(&pk.to_bytes()), Ok(pk));
    assert_eq!(
        SecretKey::from_bytes(&sk.to_bytes()).unwrap().public_key(),
        pk
    );
    assert_eq!(Signature::from_bytes(&[0xFF; 48]), Err(Error::InvalidPoint));
    assert_eq!(PublicKey::from_bytes(&[0xFF; 96]), Err(Error::InvalidPoint));
    let identity = G2Affine::identity().to_compressed();
    assert_eq!(PublicKey::from_bytes(&identity), Err(Error::InvalidPoint));
    assert_eq!(
        SecretKey::from_bytes(&[0; 32]).unwrap_err(),
        Error::InvalidScalar
    );
    assert_eq!(
        SecretKey::from_bytes(&[0xFF; 32]).unwrap_err(),
        Error::InvalidScalar
    );
    assert_eq!(pk.point(), &pk.0);
    assert_eq!(sig.point(), &sig.0);
    assert_eq!(format!("{sk:?}"), "SecretKey(..)");
}

#[test]
fn possession_proofs_and_same_message_aggregation() {
    let keys: Vec<SecretKey> = (1u8..=3)
        .map(|i| SecretKey::generate(&[i; 32], b"").unwrap())
        .collect();
    let pks: Vec<PublicKey> = keys.iter().map(SecretKey::public_key).collect();
    for (sk, pk) in keys.iter().zip(&pks) {
        assert!(pk.verify_possession(&sk.prove_possession()));
        // A proof is not a signature over the key bytes, nor the reverse.
        assert!(!pk.verify(&pk.to_bytes(), &sk.prove_possession()));
        assert!(!pk.verify_possession(&sk.sign(&pk.to_bytes())));
    }
    assert!(!pks[1].verify_possession(&keys[0].prove_possession()));
    let sigs: Vec<Signature> = keys.iter().map(|k| k.sign(b"m")).collect();
    let agg = Signature::aggregate(&sigs);
    assert!(sig::verify_aggregate(&pks, b"m", &agg));
    assert!(!sig::verify_aggregate(&pks[..2], b"m", &agg));
    assert!(!sig::verify_aggregate(&[], b"m", &agg));
    assert_eq!(PublicKey::aggregate(&[]), Err(Error::InvalidLength));
    let negated = PublicKey(-pks[0].0);
    assert_eq!(
        PublicKey::aggregate(&[pks[0], negated]),
        Err(Error::InvalidPoint)
    );
}

/// The worked example of spec 12 §9.
mod example {
    pub const IKM: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    pub const SECRET: &str = "23360db7e337b0a32b264e06bc11c1b474d16f55665373de1ce93cf15ddb3456";
    pub const PUBLIC: &str = "acfd749941a5bea56796745d1fc91668d63f9522374cb6e9c033433e3216dcad48b4fc1ab7000a365f2861565daa6b0819fd041ac58eed8c441c8b3478df6ceeaf89cc02c8119f63891a1368d7ec1d0c7e2abaaae2ac8579b7eece473478dac7";
    pub const POSSESSION: &str = "8a0d2f4b03fb570df9d343f8f19571426c64d78ac3a9120d712394bf933995204ca51596809cd6ec6b79c096df2955ec";
    pub const CHAIN_ID: u64 = 1337;
    pub const HEIGHT: u64 = 1;
    pub const BLOCK: [u8; 32] = [0xab; 32];
    pub const MESSAGE: &str = "4f52414e47452d46494e414c4954590100000000000005390000000000000001abababababababababababababababababababababababababababababababab";
    pub const HASH: &str = "912a7d1c60395e053ea92ba12ba033c8d263a64e4b61f227bbb0357ae2c836ca3037b8253ab0a814b81d8602830fcd36";
    pub const U0: &str = "000000000000000000000000000000000141b848c9222101167eda90edbec6c69a66429aed00a4842830a92a44d02600f0ec18dc241c874b9ad8f802feddc428";
    pub const U1: &str = "000000000000000000000000000000001232b42a1ac04c6ae1f8fc406a8beed6bf1fa7632d97362d536f7766b816f6499cf6acafa8123effb0d5a59b61e062d9";
    pub const SIGNATURE: &str = "8f931999d6a28f2af460ae920a9254c18d79742a3704955a479df804975aa2b1d89d5e1c9a8d56056b91e617a67bd7f2";
    pub const CERTIFICATE: &str = "010000000000000001abababababababababababababababababababababababababababababababab8f931999d6a28f2af460ae920a9254c18d79742a3704955a479df804975aa2b1d89d5e1c9a8d56056b91e617a67bd7f2";
    pub const SIGNATURE_EIP2537: &str = "000000000000000000000000000000000f931999d6a28f2af460ae920a9254c18d79742a3704955a479df804975aa2b1d89d5e1c9a8d56056b91e617a67bd7f20000000000000000000000000000000008b71a684a8467d7879122445ee60ad9165a7e08615b70550485262b455931bb30600192d2ab757b74b8b6c234df056a";
    pub const HASH_EIP2537: &str = "00000000000000000000000000000000112a7d1c60395e053ea92ba12ba033c8d263a64e4b61f227bbb0357ae2c836ca3037b8253ab0a814b81d8602830fcd360000000000000000000000000000000002ce316d5a9d20bdb19597653654a6923abaf67ccc4479a139c1d65d806588deb05fc08034ce84997a7db2c0c47d69c3";
    pub const PUBLIC_EIP2537: &str = "0000000000000000000000000000000019fd041ac58eed8c441c8b3478df6ceeaf89cc02c8119f63891a1368d7ec1d0c7e2abaaae2ac8579b7eece473478dac7000000000000000000000000000000000cfd749941a5bea56796745d1fc91668d63f9522374cb6e9c033433e3216dcad48b4fc1ab7000a365f2861565daa6b08000000000000000000000000000000000e7dbc1ef1502e48bb553bcc411d4c42bc70170821815c0a8f1431421a099a45a74efd2d70623f02011040ec965316eb000000000000000000000000000000000f170ab6ff2c30023a686560aea44adbe4d9938f9dd4e761311f23fc91f81b7c6e3037ece5d4428c88a494c65fbd9542";
    pub const NEG_G2_EIP2537: &str = "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";
    /// Trusted-dealer split of `SECRET`, 3 of 4, seed 32 bytes of 0x42.
    pub const SEED: [u8; 32] = [0x42; 32];
    pub const COMMITMENT: [&str; 3] = [
        "acfd749941a5bea56796745d1fc91668d63f9522374cb6e9c033433e3216dcad48b4fc1ab7000a365f2861565daa6b0819fd041ac58eed8c441c8b3478df6ceeaf89cc02c8119f63891a1368d7ec1d0c7e2abaaae2ac8579b7eece473478dac7",
        "a6be66577235802a3b2d2bf6cfaa73294b728c0d239e54b1a8ad39dbbb10f67e07b46f65a69db62f5ae3b00266f4856b11cbf2da6375f7494f7d7e4f2f74df3a4b2dd107399c2b368145ad40330851cf48d91becf8f9dd417a88884aed3c74d1",
        "ad37dbc60aec26b128cc149d4a8b050464f8de9b71b044e651c71129e89d5b18d1359c44f6b6bbc48d82d0eb6880d156008913ac569a8b511ccb018bf3d5dae22a5b68cec24898332737abd33454f0e536f28bd12e8c7c3946d7b4780239545b",
    ];
    pub const SHARES: [&str; 4] = [
        "4b9c2865a52f6138fd74f25f3f7780ca46ac8d0894b57fa8bc7b2f039a6d8698",
        "73352aa817677e00b49db4104dba9c463099af0452a1f1f6724daff3ae969eaa",
        "26136d2c104289b21d66bb11dd393c22dedb3145a01a6ec83e60bfc29a567c8b",
        "4c123e97e2fb7edd9e43b7740137106af8ec5bd27d1bae1c20b45e6e5dad203d",
    ];
    pub const PARTIALS: [&str; 4] = [
        "99c916bf2bb8583c304ab3b0730eb79d0c9527998009ecf3c31b9ff122fd06a4a73d002a04076ad604967c93d4c3143f",
        "a1417d93b02e27dfe72f1e5a4de4c4142ec5119a8b3dc3cd468f266bc535b2d3dab12ff918929b2c189b81127376ffbb",
        "aaf4e739b16f8137ff23ed1e8e0537d51b9144dc6f9a7a8239be9baa3e55f4f864322a9e442aff06bbe4279fcd3d2add",
        "acdbda4b87869b0015f3f35a0383f326c8c68fe067b93b0355d13b5434b83e28375bee2400da731dd5953655959326d6",
    ];
}

#[test]
fn worked_example_single_key() {
    use example::*;
    let sk = SecretKey::generate(&unhex(IKM), b"").unwrap();
    let pk = sk.public_key();
    assert_eq!(hex(&sk.to_bytes()), SECRET);
    assert_eq!(hex(&pk.to_bytes()), PUBLIC);
    assert_eq!(hex(&sk.prove_possession().to_bytes()), POSSESSION);
    let msg = certificate::message(CHAIN_ID, HEIGHT, &BLOCK);
    assert_eq!(hex(&msg), MESSAGE);
    let h = hash::to_g1(&msg, DST_SIGNATURE);
    assert_eq!(hex(&h.to_compressed()), HASH);
    let [u0, u1] = evm::hash_to_field(&msg, DST_SIGNATURE);
    assert_eq!((hex(&u0), hex(&u1)), (U0.into(), U1.into()));
    let sig = sk.sign(&msg);
    assert_eq!(hex(&sig.to_bytes()), SIGNATURE);
    let cert = Certificate {
        height: HEIGHT,
        block_hash: BLOCK,
        signature: sig,
    };
    assert_eq!(hex(&cert.to_bytes()), CERTIFICATE);
    assert_eq!(cert.message(CHAIN_ID), msg);
    assert!(cert.verify(CHAIN_ID, &pk));
    assert!(!cert.verify(CHAIN_ID + 1, &pk));
    assert_eq!(Certificate::from_bytes(&unhex(CERTIFICATE)), Ok(cert));
    assert_eq!(hex(&evm::encode_g1(sig.point())), SIGNATURE_EIP2537);
    assert_eq!(hex(&evm::encode_g1(&h)), HASH_EIP2537);
    assert_eq!(hex(&evm::encode_g2(pk.point())), PUBLIC_EIP2537);
    let input = evm::pairing_input(sig.point(), &h, pk.point());
    assert_eq!(
        hex(&input),
        [
            SIGNATURE_EIP2537,
            NEG_G2_EIP2537,
            HASH_EIP2537,
            PUBLIC_EIP2537
        ]
        .concat()
    );
}

#[test]
fn worked_example_threshold() {
    use example::*;
    let sk = SecretKey::generate(&unhex(IKM), b"").unwrap();
    let (keys, shares) = threshold::deal(&sk, 3, 4, &SEED).unwrap();
    let commitment: Vec<_> = keys
        .commitment()
        .iter()
        .map(|c| hex(&c.to_compressed()))
        .collect();
    assert_eq!(commitment, COMMITMENT);
    assert_eq!(keys.group_key(), sk.public_key());
    assert_eq!(keys.threshold(), 3);
    let partials: Vec<PartialSignature> = shares
        .iter()
        .map(|s| certificate::sign_partial(s, CHAIN_ID, HEIGHT, &BLOCK))
        .collect();
    for (i, (share, partial)) in shares.iter().zip(&partials).enumerate() {
        assert_eq!(hex(&share.to_bytes()), SHARES[i]);
        assert_eq!(hex(&partial.signature.to_bytes()), PARTIALS[i]);
        assert_eq!(share.public_key(), keys.public_share(share.index()));
        let msg = certificate::message(CHAIN_ID, HEIGHT, &BLOCK);
        assert!(keys.verify_partial(&msg, partial));
    }
    // Partials 1, 2, 4 and 4, 3, 2 both give the single-key signature.
    for pick in [[0usize, 1, 3], [3, 2, 1]] {
        let chosen: Vec<PartialSignature> = pick.iter().map(|&i| partials[i]).collect();
        let cert = Certificate::combine(&keys, CHAIN_ID, HEIGHT, &BLOCK, &chosen).unwrap();
        assert_eq!(hex(&cert.to_bytes()), CERTIFICATE);
    }
}

/// Spec 12 §9.5: a version-2 certificate and a rotation message, signed by
/// the key of §9.1 as key set 3, handing off to the §9.3 group key as key set 4.
mod rotation_example {
    pub const KEY_ID: u64 = 3;
    pub const NEXT_ID: u64 = 4;
    pub const NEXT_KEY: &str = "a1e907f8b3d3f525da3021ff8d62eaa7fa2f001625aad5ada2ca101c5407cc2b34217dadbfdb3a08a242ff3c2515ea95084f49c59dcdcaff6ce064f18bd217383e191d75e3b85e9e88d84dda61d1ca84f4ca998ca0cc5f3b63dfd217bb0a5799";
    pub const MESSAGE: &str = "4f52414e47452d46494e414c49545902000000000000053900000000000000030000000000000001abababababababababababababababababababababababababababababababab";
    pub const CERTIFICATE: &str = "0200000000000000030000000000000001ababababababababababababababababababababababababababababababababb6cf865e18c607da365e1a51018c3db8d4efcf437efb1fe1db23f40f09c219c85a9041f1d3506c58d5d701a32bcfc221";
    pub const ROTATION: &str = "4f52414e47452d524f544154450100000000000005390000000000000004a1e907f8b3d3f525da3021ff8d62eaa7fa2f001625aad5ada2ca101c5407cc2b34217dadbfdb3a08a242ff3c2515ea95084f49c59dcdcaff6ce064f18bd217383e191d75e3b85e9e88d84dda61d1ca84f4ca998ca0cc5f3b63dfd217bb0a5799";
    pub const ROTATION_SIGNATURE: &str = "88b60f250b5a4bb41acadf55b22cd9330032d5a5c5a4e43f670b4179b2e5450439df95c143d63e21a5da1933671c17ed";
}

#[test]
fn worked_example_rotation() {
    use example::{BLOCK, CHAIN_ID, HEIGHT, IKM};
    use rotation_example::*;
    let sk = SecretKey::generate(&unhex(IKM), b"").unwrap();
    let pk = sk.public_key();
    let msg = certificate::message_v2(CHAIN_ID, KEY_ID, HEIGHT, &BLOCK);
    let cert = certificate::CertificateV2 {
        key_id: KEY_ID,
        height: HEIGHT,
        block_hash: BLOCK,
        signature: sk.sign(&msg),
    };
    assert_eq!(cert.message(CHAIN_ID), msg);
    assert!(cert.verify(CHAIN_ID, &pk));
    assert!(!cert.verify(CHAIN_ID + 1, &pk));
    let next = PublicKey::from_bytes(&unhex(NEXT_KEY).try_into().unwrap()).unwrap();
    let rotation = certificate::rotation_message(CHAIN_ID, NEXT_ID, &next);
    let rotation_signature = sk.sign(&rotation);
    assert_eq!(hex(&msg), MESSAGE);
    assert_eq!(hex(&cert.to_bytes()), CERTIFICATE);
    assert_eq!(hex(&rotation), ROTATION);
    assert_eq!(hex(&rotation_signature.to_bytes()), ROTATION_SIGNATURE);
    assert_eq!(
        certificate::CertificateV2::from_bytes(&cert.to_bytes()),
        Ok(cert)
    );
    let bytes = cert.to_bytes();
    assert_eq!(
        certificate::CertificateV2::from_bytes(&bytes[..96]),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        certificate::CertificateV2::from_bytes(&unhex(example::CERTIFICATE)),
        Err(Error::UnsupportedVersion)
    );
    let mut bad = bytes;
    bad[49..].fill(0xFF);
    assert_eq!(
        certificate::CertificateV2::from_bytes(&bad),
        Err(Error::InvalidPoint)
    );
}

#[test]
fn certificate_decoding_and_combination_errors() {
    use example::*;
    let bytes = unhex(CERTIFICATE);
    assert_eq!(Certificate::from_bytes(&[]), Err(Error::UnsupportedVersion));
    let mut v2 = bytes.clone();
    v2[0] = 2;
    assert_eq!(Certificate::from_bytes(&v2), Err(Error::UnsupportedVersion));
    assert_eq!(
        Certificate::from_bytes(&bytes[..88]),
        Err(Error::InvalidLength)
    );
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(Certificate::from_bytes(&long), Err(Error::InvalidLength));
    let mut bad = bytes.clone();
    bad[41..].fill(0xFF);
    assert_eq!(Certificate::from_bytes(&bad), Err(Error::InvalidPoint));
    let sk = SecretKey::generate(&unhex(IKM), b"").unwrap();
    let (keys, shares) = threshold::deal(&sk, 3, 4, &SEED).unwrap();
    let mut partials: Vec<PartialSignature> = shares
        .iter()
        .map(|s| certificate::sign_partial(s, CHAIN_ID, HEIGHT, &BLOCK))
        .collect();
    assert_eq!(
        Certificate::combine(&keys, CHAIN_ID, HEIGHT, &BLOCK, &partials[..2]),
        Err(Error::NotEnoughShares)
    );
    // A partial over another height spoils the combination.
    partials[1] = certificate::sign_partial(&shares[1], CHAIN_ID, HEIGHT + 1, &BLOCK);
    assert_eq!(
        Certificate::combine(&keys, CHAIN_ID, HEIGHT, &BLOCK, &partials),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn threshold_edge_cases() {
    let sk = SecretKey::generate(&[9; 32], b"").unwrap();
    assert_eq!(
        threshold::deal(&sk, 0, 3, &[0; 32]).unwrap_err(),
        Error::InvalidThreshold
    );
    assert_eq!(
        threshold::deal(&sk, 4, 3, &[0; 32]).unwrap_err(),
        Error::InvalidThreshold
    );
    let (keys, shares) = threshold::deal(&sk, 2, 3, &[1; 32]).unwrap();
    let p1 = shares[0].sign(b"m");
    let p2 = shares[1].sign(b"m");
    assert_eq!(keys.combine(&[p1, p1]), Err(Error::InvalidIndex));
    let zero = PartialSignature {
        index: 0,
        signature: p2.signature,
    };
    assert!(!keys.verify_partial(b"m", &zero));
    assert_eq!(keys.combine(&[p1, zero]), Err(Error::InvalidIndex));
    assert!(keys.verify(b"m", &keys.combine(&[p2, p1]).unwrap()));
    // Key sets round trip and reject what is not one.
    assert_eq!(PublicKeySet::from_bytes(&keys.to_bytes()), Ok(keys.clone()));
    assert_eq!(PublicKeySet::from_bytes(&[]), Err(Error::InvalidThreshold));
    assert_eq!(
        PublicKeySet::from_bytes(&[0; 95]),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        PublicKeySet::from_bytes(&[0xFF; 96]),
        Err(Error::InvalidPoint)
    );
    let identity = G2Affine::identity().to_compressed();
    assert_eq!(
        PublicKeySet::from_bytes(&identity),
        Err(Error::InvalidPoint)
    );
    assert_eq!(
        PublicKeySet::new(vec![G2Affine::generator()])
            .unwrap()
            .threshold(),
        1
    );
    // Shares round trip through their persisted form.
    let back = SecretShare::from_bytes(2, &shares[1].to_bytes()).unwrap();
    assert_eq!(back.sign(b"m"), p2);
    assert_eq!(
        SecretShare::from_bytes(0, &[1; 32]).unwrap_err(),
        Error::InvalidIndex
    );
    assert_eq!(
        SecretShare::from_bytes(1, &[0xFF; 32]).unwrap_err(),
        Error::InvalidScalar
    );
    assert_eq!(format!("{back:?}"), "SecretShare(2, ..)");
    // The group key interpolates from any two public key shares.
    let pks: Vec<(u32, PublicKey)> = [3u32, 1]
        .iter()
        .map(|&i| (i, keys.public_share(i)))
        .collect();
    assert_eq!(threshold::interpolate_public(&pks), Ok(keys.group_key()));
    assert_eq!(
        threshold::interpolate_public(&[pks[0], pks[0]]),
        Err(Error::InvalidIndex)
    );
}

#[test]
fn public_shares_together_are_the_shares_one_by_one() {
    let sk = SecretKey::generate(&[4; 32], b"").unwrap();
    // Thresholds 1 and 2 have no difference above the first; 7 and 8 an
    // odd and an even degree. Counts below half the threshold go one by
    // one, from half up by differences; both past the threshold too.
    for (seed, t) in [(1u8, 1u32), (2, 2), (7, 7), (8, 8)] {
        let (keys, shares) = threshold::deal(&sk, t, 20, &[seed; 32]).unwrap();
        for count in [0, 1, t / 2, t.div_ceil(2), t, 20] {
            let together = keys.public_shares(count);
            // By differences on one thread, one by one on several: the same.
            assert_eq!(keys.public_shares_on(count, 1), together);
            assert_eq!(keys.public_shares_on(count, 5), together);
            assert_eq!(together.len(), count as usize);
            for (x, key) in (1..).zip(&together) {
                assert_eq!(*key, keys.public_share(x), "t {t}, count {count}, x {x}");
                assert_eq!(*key, shares[x as usize - 1].public_key());
            }
        }
    }
}

#[test]
fn batched_partial_checks_agree_with_single_ones() {
    let sk = SecretKey::generate(&[4; 32], b"batch").unwrap();
    let msg = b"batched partials";
    for (t, n) in [(3u32, 40u32), (40, 60)] {
        let (keys, shares) = threshold::deal(&sk, t, n, &[5; 32]).unwrap();
        let mut partials: Vec<PartialSignature> = shares.iter().map(|s| s.sign(msg)).collect();
        assert!(
            keys.verify_partials(msg, &partials, &[1; 32])
                .iter()
                .all(|v| *v)
        );
        // Another message, index zero, and a partial claiming another's index.
        partials[3] = shares[3].sign(b"other");
        partials[17].index = 0;
        partials[30].index = partials[31].index;
        let expect: Vec<bool> = partials
            .iter()
            .map(|p| keys.verify_partial(msg, p))
            .collect();
        assert_eq!(expect.iter().filter(|v| !**v).count(), 3);
        assert_eq!(keys.verify_partials(msg, &partials, &[2; 32]), expect);
        assert_eq!(
            keys.verify_partials(msg, &partials[3..4], &[2; 32]),
            [false]
        );
        assert!(keys.verify_partials(msg, &[], &[2; 32]).is_empty());
    }
}

fn threshold_case() -> impl Strategy<Value = (u32, u32, [u8; 32], Vec<u32>)> {
    (1u32..=7)
        .prop_flat_map(|n| (Just(n), 1..=n, any::<[u8; 32]>()))
        .prop_flat_map(|(n, t, seed)| {
            let subset = proptest::sample::subsequence((1..=n).collect::<Vec<u32>>(), t as usize)
                .prop_shuffle();
            (Just(n), Just(t), Just(seed), subset)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn any_t_partials_combine_to_the_group_signature(
        (n, t, seed, subset) in threshold_case(),
        msg in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let sk = SecretKey::generate(&seed, b"prop").unwrap();
        let (keys, shares) = threshold::deal(&sk, t, n, &seed).unwrap();
        let partials: Vec<PartialSignature> =
            subset.iter().map(|&i| shares[i as usize - 1].sign(&msg)).collect();
        for p in &partials {
            prop_assert!(keys.verify_partial(&msg, p));
        }
        let combined = keys.combine(&partials).unwrap();
        prop_assert_eq!(combined, sk.sign(&msg));
        prop_assert!(keys.verify(&msg, &combined));
    }

    #[test]
    fn fewer_than_t_partials_do_not_make_a_signature(
        (n, t, seed, subset) in threshold_case(),
    ) {
        prop_assume!(t >= 2);
        let sk = SecretKey::generate(&seed, b"prop").unwrap();
        let (keys, shares) = threshold::deal(&sk, t, n, &seed).unwrap();
        let partials: Vec<PartialSignature> =
            subset[..t as usize - 1].iter().map(|&i| shares[i as usize - 1].sign(b"m")).collect();
        prop_assert_eq!(keys.combine(&partials), Err(Error::NotEnoughShares));
        // Interpolating the t − 1 points anyway gives some other point.
        let forged = threshold::interpolate(&partials).unwrap();
        prop_assert!(!keys.verify(b"m", &forged));
    }

    #[test]
    fn tampered_shares_fail_the_feldman_check(
        (n, t, seed, subset) in threshold_case(),
        delta in 1u64..,
    ) {
        let sk = SecretKey::generate(&seed, b"prop").unwrap();
        let (keys, shares) = threshold::deal(&sk, t, n, &seed).unwrap();
        let share = &shares[subset[0] as usize - 1];
        prop_assert!(poly::share_matches(keys.commitment(), share.index, &share.secret));
        let tampered = share.secret + Scalar::from(delta);
        prop_assert!(!poly::share_matches(keys.commitment(), share.index, &tampered));
        let forged = SecretShare { index: share.index, secret: tampered };
        prop_assert!(!keys.verify_partial(b"m", &forged.sign(b"m")));
    }
}

#[test]
fn host_verify_semantics() {
    let sk = SecretKey::generate(&[5; 32], b"").unwrap();
    let pk = sk.public_key().to_bytes();
    let sig = sk.sign(b"payload").to_bytes();
    assert!(host::verify(b"payload", DST_SIGNATURE, &sig, &pk));
    assert!(!host::verify(b"payloaf", DST_SIGNATURE, &sig, &pk));
    assert!(!host::verify(b"payload", DST_POSSESSION, &sig, &pk));
    assert!(!host::verify(b"payload", b"", &sig, &pk));
    assert!(!host::verify(b"payload", &[b'x'; 256], &sig, &pk));
    assert!(!host::verify(b"payload", DST_SIGNATURE, &[0xFF; 48], &pk));
    assert!(!host::verify(b"payload", DST_SIGNATURE, &sig, &[0xFF; 96]));
    let identity = G2Affine::identity().to_compressed();
    assert!(!host::verify(b"payload", DST_SIGNATURE, &sig, &identity));
    // Any tag of 1 to 255 bytes works.
    let tag = [b't'; 255];
    let tagged = Signature((hash::to_g1(b"payload", &tag) * sk.0).into()).to_bytes();
    assert!(host::verify(b"payload", &tag, &tagged, &pk));
}

#[test]
fn host_pairing_check_semantics() {
    let sk = SecretKey::generate(&[6; 32], b"").unwrap();
    let pk = sk.public_key();
    let sig = sk.sign(b"x");
    let h = hash::to_g1(b"x", DST_SIGNATURE);
    let pair = |p: &G1Affine, q: &G2Affine| {
        [p.to_compressed().to_vec(), q.to_compressed().to_vec()].concat()
    };
    let valid = [pair(&sig.0, &(-G2Affine::generator())), pair(&h, &pk.0)].concat();
    assert_eq!(valid.len(), 2 * host::PAIR_LENGTH);
    assert!(host::pairing_check(&valid));
    let wrong = [pair(&sig.0, &G2Affine::generator()), pair(&h, &pk.0)].concat();
    assert!(!host::pairing_check(&wrong));
    assert!(!host::pairing_check(&[]));
    assert!(!host::pairing_check(&valid[..143]));
    let mut bad_g1 = valid.clone();
    bad_g1[..48].fill(0xFF);
    assert!(!host::pairing_check(&bad_g1));
    let mut bad_g2 = valid.clone();
    bad_g2[48..144].fill(0xFF);
    assert!(!host::pairing_check(&bad_g2));
    // Identity points are allowed: e(O, Q) = 1.
    assert!(host::pairing_check(&pair(
        &G1Affine::identity(),
        &G2Affine::generator()
    )));
    let projective = G2Projective::generator();
    assert!(!host::pairing_check(&pair(
        &G1Affine::generator(),
        &projective.into()
    )));
}
