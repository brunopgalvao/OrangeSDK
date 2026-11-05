//! Seeded fuzzing of the finality certificates and key sets of spec 12 as
//! they arrive from peers and relayers: mutated encodings never panic a
//! decoder, whatever one accepts re-encodes to exactly its input (a point
//! has one compressed form), and a certificate changed anywhere never
//! verifies. See `orange-fuzz` for the long mode.

use orange_bls::certificate::CertificateV2;
use orange_bls::{Certificate, PublicKeySet, SecretKey};
use orange_fuzz::evolve;

const CHAIN: u64 = 1337;

fn key(seed: u8) -> SecretKey {
    SecretKey::generate(&[seed; 32], b"fuzz").unwrap()
}

#[test]
fn certificates_decode_only_canonical_bytes_and_forgeries_fail() {
    let sk = key(1);
    let pk = sk.public_key();
    let mut v1 = Certificate {
        height: 7,
        block_hash: [9; 32],
        signature: sk.sign(&[0]),
    };
    v1.signature = sk.sign(&v1.message(CHAIN));
    let mut v2 = CertificateV2 {
        key_id: 3,
        height: 7,
        block_hash: [9; 32],
        signature: sk.sign(&[0]),
    };
    v2.signature = sk.sign(&v2.message(CHAIN));
    assert!(v1.verify(CHAIN, &pk) && v2.verify(CHAIN, &pk));
    let (good1, good2) = (v1.to_bytes().to_vec(), v2.to_bytes().to_vec());
    let accepted = evolve(
        "bls-certificates",
        300,
        vec![good1.clone(), good2.clone()],
        |bytes| {
            if let Ok(c) = Certificate::from_bytes(bytes) {
                assert_eq!(c.to_bytes().as_slice(), bytes);
                assert_eq!(c.verify(CHAIN, &pk), bytes == good1);
                true
            } else if let Ok(c) = CertificateV2::from_bytes(bytes) {
                assert_eq!(c.to_bytes().as_slice(), bytes);
                assert_eq!(c.verify(CHAIN, &pk), bytes == good2);
                true
            } else {
                false
            }
        },
    );
    assert!(accepted > 10, "{accepted}");
}

#[test]
fn key_sets_decode_only_canonical_bytes() {
    let keys: Vec<u8> = (1..4)
        .flat_map(|i| key(i).public_key().to_bytes())
        .collect();
    assert_eq!(PublicKeySet::from_bytes(&keys).unwrap().to_bytes(), keys);
    // A mutated point almost never decodes; the corpus mostly checks that
    // nothing panics and that what decodes is canonical.
    evolve(
        "bls-key-sets",
        200,
        vec![keys.clone(), keys[..96].to_vec()],
        |bytes| {
            let Ok(set) = PublicKeySet::from_bytes(bytes) else {
                return false;
            };
            assert_eq!(set.to_bytes(), bytes);
            true
        },
    );
}
