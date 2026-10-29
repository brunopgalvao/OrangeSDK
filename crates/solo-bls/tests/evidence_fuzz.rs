//! Seeded forgeries of threshold evidence (spec 12 §7, spec 15 §6.6): the
//! version-2 finality certificate a key set signs and the rotation with
//! which the active key set hands off to the next one. Every case takes key
//! sets from real runs of the DKG, signs genuine evidence with a random
//! quorum of shares, and checks that it is accepted; then it forges the
//! evidence every way a faulty relayer or a coalition below the threshold
//! could (another signer set, another key id or epoch, fewer than `t`
//! shares, a swapped or cross-domain message, the replaced key, the new key
//! signing its own handoff, damaged encodings) and checks that no forgery
//! is accepted. The verifier here is what every consumer of the evidence
//! runs: decode with `solo_abi::rotation` as the kernel, the snapshot check
//! and the relayer do, then verify under the key set the evidence names.
//! See `solo-fuzz` for the long mode.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use solo_abi::rotation::{Handoff, threshold_certificate};
use solo_abi::{Decode, Encode};
use solo_bls::certificate::{self, CertificateV2};
use solo_bls::dkg::{Config, Dealer, DecryptionKey, Dkg, Recipient, Step};
use solo_bls::{Certificate, Error, PartialSignature, PublicKey, PublicKeySet, SecretShare};
use solo_fuzz::{Rng, run};

const CHAIN: u64 = 1337;

/// A key set from an honest DKG run, with every share.
struct Committee {
    keys: PublicKeySet,
    shares: Vec<SecretShare>,
}

/// An honest fresh run among `counts.len()` participants, participant `j`
/// holding `counts[j - 1]` shares (spec 12 §4), with threshold `t`.
fn dkg(tag: u8, counts: &[u32], t: u32) -> Committee {
    let n = u32::try_from(counts.len()).unwrap();
    let ikm = |j: u32| [tag, u8::try_from(j).unwrap()].repeat(16);
    let config = Config {
        session: [tag; 32],
        threshold: t,
        dealers: n,
        recipients: (1..=n)
            .map(|j| DecryptionKey::generate(&ikm(j)).unwrap().encryption_key())
            .collect(),
        shares: counts.to_vec(),
        weights: Vec::new(),
        previous: None,
    };
    let mut nodes = Vec::new();
    let mut messages = Vec::new();
    for i in 1..=n {
        let dealer = Dealer {
            index: i,
            seed: [tag ^ 0x5A, u8::try_from(i).unwrap()]
                .repeat(16)
                .try_into()
                .unwrap(),
            share: None,
        };
        let recipient = Recipient {
            index: i,
            key: DecryptionKey::generate(&ikm(i)).unwrap(),
        };
        let (node, dealing) = Dkg::new(config.clone(), Some(dealer), Some(recipient)).unwrap();
        nodes.push(node);
        messages.extend(dealing);
    }
    let mut outputs = Vec::new();
    while outputs.is_empty() {
        for m in &messages {
            for node in &mut nodes {
                node.handle(m).unwrap();
            }
        }
        messages.clear();
        for node in &mut nodes {
            match node.advance().unwrap() {
                Step::Broadcast(m) => messages.push(m),
                Step::Idle => {}
                Step::Finished(o) => outputs.push(o),
            }
        }
    }
    let keys = outputs[0].key_set.clone();
    assert!(outputs.iter().all(|o| o.key_set == keys));
    let shares: Vec<SecretShare> = outputs.into_iter().flat_map(|o| o.shares).collect();
    assert_eq!(shares.len(), counts.iter().sum::<u32>() as usize);
    Committee { keys, shares }
}

/// Key set 3, the active one: four participants, the first holding two of
/// the five shares, threshold 3; key set 4, which it hands off to; and an
/// unrelated key set.
fn committees() -> &'static [Committee; 3] {
    static SETS: OnceLock<[Committee; 3]> = OnceLock::new();
    SETS.get_or_init(|| {
        [
            dkg(0xA1, &[2, 1, 1, 1], 3),
            dkg(0xB2, &[1, 1, 1, 1], 3),
            dkg(0xC3, &[1, 1, 1], 2),
        ]
    })
}

const ACTIVE: u64 = 3;
const NEXT: u64 = 4;
/// The height a handoff records, which nothing signs.
const HANDOFF_HEIGHT: u64 = 30;

impl Committee {
    fn key(&self) -> PublicKey {
        self.keys.group_key()
    }

    fn t(&self) -> usize {
        self.keys.threshold() as usize
    }

    /// Partials over `msg` by `count` distinct shares, chosen and ordered at random.
    fn partials(&self, r: &mut Rng, msg: &[u8], count: usize) -> Vec<PartialSignature> {
        let mut order: Vec<&SecretShare> = self.shares.iter().collect();
        for i in (1..order.len()).rev() {
            order.swap(i, r.index(i + 1));
        }
        order[..count].iter().map(|s| s.sign(msg)).collect()
    }

    /// The group signature over `msg` combined from a random quorum: `t`
    /// shares or more, of which `combine` uses the first `t`.
    fn sign(&self, r: &mut Rng, msg: &[u8]) -> solo_bls::Signature {
        let count = self.t() + r.index(self.shares.len() - self.t() + 1);
        let partials = self.partials(r, msg, count);
        let signature = self.keys.combine(&partials).unwrap();
        assert!(self.keys.verify(msg, &signature));
        signature
    }

    /// What a coalition of `t − 1` shares can make of `msg`, each of which
    /// must fail: the combination refuses too few partials or a repeated
    /// index, and every way of filling the gap (interpolating the minority
    /// alone, a partial of another key set or over another message at an
    /// unused index) yields a signature that does not verify.
    fn minority(&self, r: &mut Rng, msg: &[u8], other: &Committee) -> Vec<solo_bls::Signature> {
        let t = self.t();
        let few = self.partials(r, msg, t - 1);
        assert_eq!(self.keys.combine(&few), Err(Error::NotEnoughShares));
        let mut repeated = few.clone();
        repeated.push(few[r.index(few.len())]);
        assert_eq!(self.keys.combine(&repeated), Err(Error::InvalidIndex));
        let used: Vec<u32> = few.iter().map(|p| p.index).collect();
        let spare = self
            .shares
            .iter()
            .map(SecretShare::index)
            .find(|i| !used.contains(i))
            .unwrap();
        let mut out = Vec::new();
        if t > 1 {
            let lower = PublicKeySet::new(self.keys.commitment()[..t - 1].to_vec()).unwrap();
            out.push(lower.combine(&few).unwrap());
        }
        let foreign = other.shares[r.index(other.shares.len())].sign(msg);
        let mut stolen = few.clone();
        stolen.push(PartialSignature {
            index: spare,
            signature: foreign.signature,
        });
        out.push(self.keys.combine(&stolen).unwrap());
        let mut elsewhere = few;
        let honest = self.shares.iter().find(|s| s.index() == spare).unwrap();
        let mut other_msg = msg.to_vec();
        other_msg[r.index(msg.len())] ^= 1 << r.below(8);
        elsewhere.push(honest.sign(&other_msg));
        out.push(self.keys.combine(&elsewhere).unwrap());
        // A lone partial is no group signature either.
        out.push(self.partials(r, msg, 1)[0].signature);
        out
    }
}

/// The key sets a verifier knows, by id.
fn known() -> BTreeMap<u64, PublicKey> {
    let [a, b, _] = committees();
    BTreeMap::from([(ACTIVE, a.key()), (NEXT, b.key())])
}

/// What a verifier accepts as a certificate: the key set, height and block
/// a version-2 certificate names, if it verifies under that key set.
fn accepts_certificate(
    bytes: &[u8],
    chain_id: u64,
    sets: &BTreeMap<u64, PublicKey>,
) -> Option<(u64, u64, [u8; 32])> {
    let c = threshold_certificate(bytes).filter(|c| c.version == 2)?;
    let key = sets.get(&c.key_id)?;
    let decoded = CertificateV2::from_bytes(bytes).ok()?;
    assert_eq!(
        (decoded.key_id, decoded.height, decoded.block_hash),
        (c.key_id, c.height, c.block_hash)
    );
    assert_eq!(&decoded.signature.to_bytes()[..], c.signature);
    let message = c.message(chain_id);
    assert_eq!(message, decoded.message(chain_id).to_vec());
    decoded
        .verify(chain_id, key)
        .then_some((c.key_id, c.height, c.block_hash))
}

/// What a verifier accepts as a handoff: one to a newer key set, with a
/// valid group key, signed by the key set it hands off from.
fn accepts_handoff(h: &Handoff, chain_id: u64, sets: &BTreeMap<u64, PublicKey>) -> bool {
    let Some(from) = sets.get(&h.from) else {
        return false;
    };
    let Ok(key) = <[u8; 96]>::try_from(h.key.as_slice()) else {
        return false;
    };
    let Ok(signature) = <[u8; 48]>::try_from(h.signature.as_slice()) else {
        return false;
    };
    let (Ok(next), Ok(signature)) = (
        PublicKey::from_bytes(&key),
        solo_bls::Signature::from_bytes(&signature),
    ) else {
        return false;
    };
    assert_eq!(
        h.message(chain_id),
        certificate::rotation_message(chain_id, h.to, &next).to_vec()
    );
    h.to > h.from && from.verify(&h.message(chain_id), &signature)
}

fn certificate_bytes(
    key_id: u64,
    height: u64,
    hash: &[u8; 32],
    s: &solo_bls::Signature,
) -> Vec<u8> {
    CertificateV2 {
        key_id,
        height,
        block_hash: *hash,
        signature: *s,
    }
    .to_bytes()
    .to_vec()
}

/// The identity of G1 as a signature.
fn identity() -> solo_bls::Signature {
    let mut bytes = [0u8; 48];
    bytes[0] = 0xC0;
    solo_bls::Signature::from_bytes(&bytes).unwrap()
}

/// A number other than `n`, near it or far.
fn other_than(r: &mut Rng, n: u64) -> u64 {
    let step = 1 + r.below(3);
    let m = match r.below(3) {
        0 => n.wrapping_add(step),
        1 => n.wrapping_sub(step),
        _ => r.edgy(),
    };
    if m == n { n ^ 1 } else { m }
}

#[test]
fn forged_certificates_are_refused() {
    let [a, b, c] = committees();
    let sets = known();
    run("bls-forged-certificates", 16, |r| {
        let height = 1 + r.below(1 << 40);
        let hash = r.array32();
        let msg = certificate::message_v2(CHAIN, ACTIVE, height, &hash);
        let genuine = certificate_bytes(ACTIVE, height, &hash, &a.sign(r, &msg));
        assert_eq!(
            accepts_certificate(&genuine, CHAIN, &sets),
            Some((ACTIVE, height, hash))
        );
        let refused = |bytes: &[u8], class: &str| {
            assert_eq!(accepts_certificate(bytes, CHAIN, &sets), None, "{class}");
        };
        // Another signer set: the next key set, an unrelated one, under the active id.
        refused(
            &certificate_bytes(ACTIVE, height, &hash, &b.sign(r, &msg)),
            "next signs",
        );
        refused(
            &certificate_bytes(ACTIVE, height, &hash, &c.sign(r, &msg)),
            "foreign",
        );
        // Another key id or epoch: the active key's signature relabelled, or the
        // active key signing for the next id (a stale key posing as the new one).
        let sig = a.sign(r, &msg);
        refused(&certificate_bytes(NEXT, height, &hash, &sig), "relabelled");
        refused(
            &certificate_bytes(other_than(r, ACTIVE), height, &hash, &sig),
            "other id",
        );
        let as_next = certificate::message_v2(CHAIN, NEXT, height, &hash);
        refused(
            &certificate_bytes(NEXT, height, &hash, &a.sign(r, &as_next)),
            "stale key",
        );
        // Below the threshold.
        for s in a.minority(r, &msg, c) {
            refused(&certificate_bytes(ACTIVE, height, &hash, &s), "minority");
        }
        // The identity, which no key signs with.
        refused(
            &certificate_bytes(ACTIVE, height, &hash, &identity()),
            "identity",
        );
        // A swapped message: another height, block or chain, the version-1 message,
        // or the rotation domain.
        refused(
            &certificate_bytes(ACTIVE, other_than(r, height), &hash, &sig),
            "height",
        );
        let mut other_hash = hash;
        other_hash[r.index(32)] ^= 1 << r.below(8);
        refused(
            &certificate_bytes(ACTIVE, height, &other_hash, &sig),
            "block",
        );
        assert_eq!(
            accepts_certificate(&genuine, other_than(r, CHAIN), &sets),
            None
        );
        let v1 = a.sign(r, &certificate::message(CHAIN, height, &hash));
        refused(&certificate_bytes(ACTIVE, height, &hash, &v1), "version 1");
        let rotation = a.sign(r, &certificate::rotation_message(CHAIN, NEXT, &b.key()));
        refused(
            &certificate_bytes(ACTIVE, height, &hash, &rotation),
            "rotation",
        );
        // The version-1 encoding of the same signature names no key set.
        let v1_bytes = Certificate {
            height,
            block_hash: hash,
            signature: v1,
        }
        .to_bytes();
        refused(&v1_bytes, "version-1 encoding");
        // Damaged encodings: whatever still decodes and verifies is the genuine one.
        for _ in 0..8 {
            let m = r.mutate(&genuine);
            if accepts_certificate(&m, CHAIN, &sets).is_some() {
                assert_eq!(m, genuine, "a damaged certificate verified");
            }
        }
        let cut = r.index(genuine.len());
        refused(&genuine[..cut], "truncated");
        let mut long = genuine.clone();
        let extra = 1 + r.index(8);
        long.extend(r.bytes(extra));
        refused(&long, "extended");
    });
}

#[test]
fn forged_handoffs_are_refused() {
    let [a, b, c] = committees();
    let sets = known();
    run("bls-forged-handoffs", 16, |r| {
        let next = b.key();
        let msg = certificate::rotation_message(CHAIN, NEXT, &next);
        let handoff = |signature: &solo_bls::Signature| Handoff {
            from: ACTIVE,
            to: NEXT,
            key: next.to_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
            height: HANDOFF_HEIGHT,
        };
        let genuine = handoff(&a.sign(r, &msg));
        assert!(accepts_handoff(&genuine, CHAIN, &sets));
        let refused = |forged: &Handoff, class: &str| {
            assert!(!accepts_handoff(forged, CHAIN, &sets), "{class}");
        };
        // Signed by the new key instead of the old, or by a stranger.
        refused(&handoff(&b.sign(r, &msg)), "new key signs");
        refused(&handoff(&c.sign(r, &msg)), "foreign");
        // Below the threshold of the old key.
        for s in a.minority(r, &msg, c) {
            refused(&handoff(&s), "minority");
        }
        // Another target id, another key, a key set handing off to itself or
        // backwards, a handoff claimed from the new key set, another chain.
        let mut forged = genuine.clone();
        forged.to = other_than(r, NEXT);
        refused(&forged, "target id");
        for key in [c.key(), a.key()] {
            let mut forged = genuine.clone();
            forged.key = key.to_bytes().to_vec();
            refused(&forged, "target key");
        }
        let back = a.sign(r, &certificate::rotation_message(CHAIN, ACTIVE, &a.key()));
        refused(
            &Handoff {
                to: ACTIVE,
                key: a.key().to_bytes().to_vec(),
                ..handoff(&back)
            },
            "not newer",
        );
        // The identity as the new key, with the identity as the signature,
        // which would verify anything under it.
        let mut forged = handoff(&identity());
        forged.key = [0xC0].into_iter().chain([0; 95]).collect();
        refused(&forged, "identity key");
        refused(&handoff(&identity()), "identity signature");
        let mut forged = genuine.clone();
        forged.from = NEXT;
        refused(&forged, "from the new key set");
        assert!(!accepts_handoff(&genuine, other_than(r, CHAIN), &sets));
        // The certificate domain: the old key's certificate signature over
        // bytes that only look like a handoff's.
        let cert = a.sign(r, &certificate::message_v2(CHAIN, NEXT, 1, &[0; 32]));
        refused(&handoff(&cert), "certificate domain");
        // Damaged encodings: whatever decodes and verifies hands off the same
        // way; only the recorded height is not signed.
        let bytes = genuine.to_bytes();
        for _ in 0..8 {
            let m = r.mutate(&bytes);
            if let Ok(decoded) = Handoff::from_bytes(&m)
                && accepts_handoff(&decoded, CHAIN, &sets)
            {
                assert_eq!(
                    (decoded.from, decoded.to, &decoded.key, &decoded.signature),
                    (genuine.from, genuine.to, &genuine.key, &genuine.signature),
                    "a damaged handoff verified"
                );
            }
        }
        let mut short = genuine.clone();
        short.signature.truncate(r.index(48));
        refused(&short, "truncated signature");
        let mut long = genuine.clone();
        long.key.push(r.byte());
        refused(&long, "extended key");
    });
}
