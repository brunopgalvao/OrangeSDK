//! Seeded forgeries of the threshold evidence a relayer carries to Ethereum
//! (spec 17 §5.3, spec 12 §7–§8): light-client submissions built from
//! finality proofs and key rotations built from recorded handoffs, through
//! the relayer's builders into `SoloLightClientV2` and
//! `SoloFinalityVerifierV2` on revm. Key sets come from real DKG runs. In
//! every case the genuine submission and rotation are accepted; every
//! forgery (another signer set, another key id, fewer than `t` shares, a
//! swapped or cross-domain message, a version-1 certificate, the replaced
//! key after a handoff, a handoff signed by the new key, an anchor that
//! does not chain below its proposal or past the key's age, damaged
//! encodings) is refused, by the builder or by the contracts. See
//! `solo-fuzz` for the long mode.

mod support;

use std::sync::OnceLock;

use solo_abi::Encode;
use solo_abi::bridge::FinalityProof;
use solo_abi::chain::Proposal;
use solo_abi::rotation::Handoff;
use solo_bls::certificate::{self, CertificateV2};
use solo_bls::dkg::{Config, Dealer, DecryptionKey, Dkg, Recipient, Step};
use solo_bls::{PartialSignature, PublicKey, PublicKeySet, SecretShare, Signature};
use solo_bridge::abi::{self, Value};
use solo_bridge::{Rotation, Submission, group_key, light_client_v2_args, verifier_v2_args};
use solo_fuzz::{Rng, run};
use solo_trie::keccak256;
use support::eth::{Eth, init_code, word_u64};

const SOLO_CHAIN_ID: u64 = 1337;
const DEPLOYER: [u8; 20] = [0xD0; 20];
const RELAYER: [u8; 20] = [0xEE; 20];
const EPOCH_BLOCKS: u64 = 16;
const MAX_KEY_AGE: u64 = 2;
/// The key set the light client starts from, and the one it hands off to.
const ACTIVE: u64 = 3;
const NEXT: u64 = 4;

/// A key set from an honest DKG run, with every share.
struct Committee {
    keys: PublicKeySet,
    shares: Vec<SecretShare>,
}

/// An honest fresh run among `counts.len()` participants, participant `j`
/// holding `counts[j - 1]` shares, with threshold `t`.
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
    let shares = outputs.into_iter().flat_map(|o| o.shares).collect();
    Committee { keys, shares }
}

/// The active key set (one participant holds two of five shares, threshold
/// 3), the next one, and an unrelated one.
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

impl Committee {
    fn key(&self) -> PublicKey {
        self.keys.group_key()
    }

    fn t(&self) -> usize {
        self.keys.threshold() as usize
    }

    fn partials(&self, r: &mut Rng, msg: &[u8], count: usize) -> Vec<PartialSignature> {
        let mut order: Vec<&SecretShare> = self.shares.iter().collect();
        for i in (1..order.len()).rev() {
            order.swap(i, r.index(i + 1));
        }
        order[..count].iter().map(|s| s.sign(msg)).collect()
    }

    /// The group signature over `msg` from a random quorum.
    fn sign(&self, r: &mut Rng, msg: &[u8]) -> Signature {
        let count = self.t() + r.index(self.shares.len() - self.t() + 1);
        self.keys.combine(&self.partials(r, msg, count)).unwrap()
    }

    /// Signatures a coalition of `t − 1` shares can make over `msg`: the
    /// minority interpolated alone, filled with another key set's partial,
    /// and a lone partial.
    fn minority(&self, r: &mut Rng, msg: &[u8], other: &Committee) -> Vec<Signature> {
        let t = self.t();
        let few = self.partials(r, msg, t - 1);
        let used: Vec<u32> = few.iter().map(|p| p.index).collect();
        let spare = self
            .shares
            .iter()
            .map(SecretShare::index)
            .find(|i| !used.contains(i))
            .unwrap();
        let lower = PublicKeySet::new(self.keys.commitment()[..t - 1].to_vec()).unwrap();
        let mut stolen = few.clone();
        stolen.push(PartialSignature {
            index: spare,
            signature: other.shares[r.index(other.shares.len())]
                .sign(msg)
                .signature,
        });
        vec![
            lower.combine(&few).unwrap(),
            self.keys.combine(&stolen).unwrap(),
            few[0].signature,
        ]
    }
}

fn eip(key: &PublicKey) -> [u8; 256] {
    group_key(&key.to_bytes()).unwrap()
}

/// A proposal at `height` anchoring `anchor` with `root`.
fn proposal(height: u64, anchor: u64, root: [u8; 32]) -> Vec<u8> {
    Proposal {
        view: height + 7,
        height,
        parent: [3; 32],
        timestamp_ms: 1_700_000_000_000,
        anchor_height: anchor,
        anchor_root: root,
        txs: solo_abi::codec::Seq(vec![vec![0xC0; 3]]),
        ..Proposal::default()
    }
    .to_bytes()
}

/// The finality proof of `proposal`: a version-2 certificate naming
/// `key_id` with `signature`.
fn proof(key_id: u64, proposal: &[u8], signature: Signature) -> FinalityProof {
    let height = u64::from_le_bytes(proposal[8..16].try_into().unwrap());
    FinalityProof {
        certificate: CertificateV2 {
            key_id,
            height,
            block_hash: keccak256(proposal),
            signature,
        }
        .to_bytes()
        .to_vec(),
        proposal: proposal.to_vec(),
    }
}

/// The version-2 message of `proposal` under `key_id`.
fn message(key_id: u64, proposal: &[u8]) -> Vec<u8> {
    let height = u64::from_le_bytes(proposal[8..16].try_into().unwrap());
    certificate::message_v2(SOLO_CHAIN_ID, key_id, height, &keccak256(proposal)).to_vec()
}

fn submit_call(proposal: &[u8], signature: &[u8]) -> Vec<u8> {
    abi::call(
        "submit(bytes,bytes)",
        &[
            Value::Bytes(proposal.to_vec()),
            Value::Bytes(signature.to_vec()),
        ],
    )
}

fn rotate_call(to: u64, key: &[u8], signature: &[u8]) -> Vec<u8> {
    abi::call(
        "rotate(uint64,bytes,bytes)",
        &[
            Value::uint(u128::from(to)),
            Value::Bytes(key.to_vec()),
            Value::Bytes(signature.to_vec()),
        ],
    )
}

/// A light client holding the active key set.
struct Client {
    eth: Eth,
    client: [u8; 20],
}

impl Client {
    fn new(key: &PublicKey) -> Client {
        let mut eth = Eth::new();
        let verifier = eth.deploy(
            DEPLOYER,
            &init_code("SoloFinalityVerifierV2"),
            &verifier_v2_args(SOLO_CHAIN_ID),
        );
        let client = eth.deploy(
            DEPLOYER,
            &init_code("SoloLightClientV2"),
            &light_client_v2_args(&verifier, ACTIVE, &eip(key), EPOCH_BLOCKS, MAX_KEY_AGE),
        );
        Client { eth, client }
    }

    /// Whether the light client takes `data`, without keeping its effects.
    fn takes(&mut self, data: &[u8]) -> bool {
        self.eth.view(RELAYER, self.client, data).success
    }

    /// Whether a relayer gets `proof` accepted: the builder takes it and
    /// the light client takes the call.
    fn takes_proof(&mut self, proof: &FinalityProof) -> bool {
        Submission::new(proof).is_ok_and(|s| self.takes(&s.calldata()))
    }

    /// Whether a relayer gets `handoff` accepted.
    fn takes_handoff(&mut self, handoff: &Handoff) -> bool {
        Rotation::new(handoff).is_ok_and(|r| self.takes(&r.calldata()))
    }

    fn commit(&mut self, data: &[u8]) {
        let outcome = self.eth.call(RELAYER, self.client, data);
        assert!(outcome.success, "{outcome:?}");
    }

    fn root(&mut self, height: u64) -> [u8; 32] {
        let data = abi::call("stateRoots(uint64)", &[Value::uint(u128::from(height))]);
        self.eth
            .view(RELAYER, self.client, &data)
            .output
            .try_into()
            .unwrap()
    }

    fn key_id(&mut self) -> u64 {
        word_u64(
            &self
                .eth
                .view(RELAYER, self.client, &abi::call("keyId()", &[]))
                .output,
        )
    }
}

/// Highest anchor a key set `id` is trusted for: the last block of epoch
/// `id + MAX_KEY_AGE`.
fn last_trusted(id: u64) -> u64 {
    (id + MAX_KEY_AGE + 1) * EPOCH_BLOCKS
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
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
fn forged_submissions_and_rotations_are_refused() {
    let [a, b, c] = committees();
    run("bridge-forged-evidence", 8, |r| {
        let mut lc = Client::new(&a.key());
        // A genuine submission of the active key set, anchored in its trust.
        let anchor = 1 + r.below(last_trusted(ACTIVE) - 8);
        let height = anchor + 1 + r.below(4);
        let root = r.array32();
        let p = proposal(height, anchor, root);
        let genuine = proof(ACTIVE, &p, a.sign(r, &message(ACTIVE, &p)));
        let calldata = Submission::new(&genuine).unwrap().calldata();
        assert!(lc.takes(&calldata));
        let refused = |lc: &mut Client, proof: &FinalityProof, class: &str| {
            assert!(!lc.takes_proof(proof), "submission: {class}");
        };
        // Another signer set under the active id.
        refused(
            &mut lc,
            &proof(ACTIVE, &p, b.sign(r, &message(ACTIVE, &p))),
            "next signs",
        );
        refused(
            &mut lc,
            &proof(ACTIVE, &p, c.sign(r, &message(ACTIVE, &p))),
            "foreign",
        );
        // Another key id. The call does not carry the certificate's id: the
        // light client signs with its own, so a relabelled certificate is
        // either the genuine call again or refused.
        let sig = a.sign(r, &message(ACTIVE, &p));
        for id in [NEXT, other_than(r, ACTIVE)] {
            let relabelled = proof(id, &p, sig);
            if lc.takes_proof(&relabelled) {
                assert_eq!(Submission::new(&relabelled).unwrap().calldata(), calldata);
            }
        }
        refused(
            &mut lc,
            &proof(NEXT, &p, a.sign(r, &message(NEXT, &p))),
            "as next",
        );
        // Below the threshold.
        for s in a.minority(r, &message(ACTIVE, &p), c) {
            refused(&mut lc, &proof(ACTIVE, &p, s), "minority");
        }
        // Swapped messages: the version-1 message in either encoding, the
        // rotation domain, another proposal's certificate.
        let v1 = a.sign(
            r,
            &certificate::message(SOLO_CHAIN_ID, height, &keccak256(&p)),
        );
        refused(&mut lc, &proof(ACTIVE, &p, v1), "version-1 message");
        let v1_proof = FinalityProof {
            certificate: solo_bls::Certificate {
                height,
                block_hash: keccak256(&p),
                signature: v1,
            }
            .to_bytes()
            .to_vec(),
            proposal: p.clone(),
        };
        refused(&mut lc, &v1_proof, "version-1 certificate");
        let rotation = a.sign(
            r,
            &certificate::rotation_message(SOLO_CHAIN_ID, NEXT, &b.key()),
        );
        refused(&mut lc, &proof(ACTIVE, &p, rotation), "rotation domain");
        let other = proposal(height, anchor, r.array32());
        let mut swapped = genuine.clone();
        swapped.proposal.clone_from(&other);
        refused(&mut lc, &swapped, "swapped proposal");
        let eip_sig = solo_bls::evm::encode_g1(sig.point());
        assert!(!lc.takes(&submit_call(&other, &eip_sig)), "unbuilt swap");
        // The identity (all zeros in EIP-2537 encoding) as the signature.
        assert!(!lc.takes(&submit_call(&p, &[0; 128])), "identity");
        // Anchors that do not chain: none, at or above the proposal, past
        // the key's age; all signed by the active key set.
        for (top, anc) in [
            (height, 0),
            (anchor, anchor),
            (anchor, anchor + r.below(4)),
            (last_trusted(ACTIVE) + 2, last_trusted(ACTIVE) + 1),
        ] {
            let q = proposal(top, anc, root);
            let signed = proof(ACTIVE, &q, a.sign(r, &message(ACTIVE, &q)));
            refused(&mut lc, &signed, "anchor");
            let s = solo_bls::evm::encode_g1(a.sign(r, &message(ACTIVE, &q)).point());
            assert!(
                !lc.takes(&submit_call(&q, &s)),
                "unbuilt anchor {top} {anc}"
            );
        }
        // Damaged encodings: certificate, proposal and signature.
        for _ in 0..4 {
            let mut m = genuine.clone();
            m.certificate = r.mutate(&genuine.certificate);
            if lc.takes_proof(&m) {
                assert_eq!(Submission::new(&m).unwrap().calldata(), calldata);
            }
            let q = r.mutate(&p);
            if lc.takes(&submit_call(&q, &eip_sig)) {
                assert_eq!(q, p, "a damaged proposal was taken");
            }
            let s = r.mutate(&eip_sig);
            if lc.takes(&submit_call(&p, &s)) {
                assert_eq!(s, eip_sig, "a damaged signature was taken");
            }
        }
        lc.commit(&calldata);
        assert_eq!(lc.root(anchor), root);
        // The same anchor again, or a lower one, is no news.
        assert!(!lc.takes(&calldata), "replay");

        // A genuine handoff from the active key set to the next.
        let next = b.key();
        let msg = certificate::rotation_message(SOLO_CHAIN_ID, NEXT, &next);
        let handoff = |signature: &Signature| Handoff {
            from: ACTIVE,
            to: NEXT,
            key: next.to_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
            height: 30,
        };
        let real = handoff(&a.sign(r, &msg));
        let rotate = Rotation::new(&real).unwrap().calldata();
        assert!(lc.takes(&rotate));
        let refused = |lc: &mut Client, forged: &Handoff, class: &str| {
            assert!(!lc.takes_handoff(forged), "handoff: {class}");
        };
        refused(&mut lc, &handoff(&b.sign(r, &msg)), "new key signs");
        refused(&mut lc, &handoff(&c.sign(r, &msg)), "foreign");
        for s in a.minority(r, &msg, c) {
            refused(&mut lc, &handoff(&s), "minority");
        }
        let mut forged = real.clone();
        forged.to = other_than(r, NEXT);
        refused(&mut lc, &forged, "target id");
        let mut forged = real.clone();
        forged.key = c.key().to_bytes().to_vec();
        refused(&mut lc, &forged, "target key");
        let other_chain = certificate::rotation_message(other_than(r, SOLO_CHAIN_ID), NEXT, &next);
        refused(&mut lc, &handoff(&a.sign(r, &other_chain)), "other chain");
        let cert = a.sign(r, &message(NEXT, &p));
        refused(&mut lc, &handoff(&cert), "certificate domain");
        // The identity as the new key and as the signature, which would
        // verify anything under it.
        assert!(
            !lc.takes(&rotate_call(NEXT, &[0; 256], &[0; 128])),
            "identity key"
        );
        let mut forged = real.clone();
        forged.key = [0xC0].into_iter().chain([0; 95]).collect();
        refused(&mut lc, &forged, "identity key");
        // Well signed, but not newer or past the key's age.
        for to in [ACTIVE, ACTIVE + MAX_KEY_AGE + 1 + r.below(3)] {
            let m = certificate::rotation_message(SOLO_CHAIN_ID, to, &next);
            let forged = Handoff {
                to,
                ..handoff(&a.sign(r, &m))
            };
            refused(&mut lc, &forged, "out of range");
        }
        // Damaged encodings of the record and of the call.
        let bytes = real.to_bytes();
        for _ in 0..4 {
            let m = r.mutate(&bytes);
            if let Ok(decoded) = <Handoff as solo_abi::Decode>::from_bytes(&m)
                && lc.takes_handoff(&decoded)
            {
                assert_eq!(Rotation::new(&decoded).unwrap().calldata(), rotate);
            }
            let built = Rotation::new(&real).unwrap();
            let key = r.mutate(&built.key_eip2537);
            if lc.takes(&rotate_call(NEXT, &key, &built.signature)) {
                assert_eq!(key, built.key_eip2537.to_vec(), "a damaged key was taken");
            }
            let s = r.mutate(&built.signature);
            if lc.takes(&rotate_call(NEXT, &built.key_eip2537, &s)) {
                assert_eq!(s, built.signature.to_vec(), "a damaged signature was taken");
            }
        }
        lc.commit(&rotate);
        assert_eq!(lc.key_id(), NEXT);
        assert!(!lc.takes(&rotate), "rotation replay");

        // The replaced key set certifies nothing, under either id; the next
        // one certifies anchors up to its own age.
        let anchor2 = anchor + 1 + r.below(last_trusted(NEXT) - anchor - 1);
        let q = proposal(anchor2 + 1, anchor2, r.array32());
        for (id, signer) in [(ACTIVE, a), (NEXT, a), (ACTIVE, b)] {
            let stale = proof(id, &q, signer.sign(r, &message(id, &q)));
            assert!(!lc.takes_proof(&stale), "stale key {id}");
        }
        let fresh = proof(NEXT, &q, b.sign(r, &message(NEXT, &q)));
        assert!(lc.takes_proof(&fresh));
    });
}
