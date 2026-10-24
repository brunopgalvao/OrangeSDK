//! The threshold keystore behind key role 2 of `sign` (spec 05 §4.3): the
//! node's DKG decryption key and dealer randomness, both derived from its
//! consensus key, and the threshold shares the DKG gives it. The kernel
//! drives the DKG and reads its public messages from chain state; whatever
//! needs a secret runs here, natively, and no secret leaves the host.
//!
//! A DKG answer can take seconds at the largest runs (spec 15 §6.4): the
//! share checks at the end of dealing and the public key shares of the
//! outcome. A node that runs its heavy work in the background computes
//! them on threads of their own and hands the answer over when the kernel
//! asks again, so that the loop that steps the driver goes on voting.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use k256::ecdsa::SigningKey;
use solo_abi::codec::Seq;
use solo_abi::staking::{DkgReply, DkgRequest, KeySetVote, KeystoreRequest, PartialShare};
use solo_abi::{Decode, Encode};
use solo_bls::dkg::{
    Complaints, Config, Dealer, DecryptionKey, Dkg, EncryptionKey, Message, Recipient, Step,
};
use solo_bls::{PartialSignature, PublicKeySet, SecretShare, Signature};

/// Domain separation tag of a dealer's per-run seed.
pub const DST_DEALER_SEED: &[u8] = b"SOLO-V01-DKG-SEED_XMD:SHA-256";

/// How long a DKG request waits for its computation in the call that asks
/// for it, in a keystore that computes in the background: one that ends
/// within it is answered at once, as without the background.
pub const QUICK_MS: u64 = 50;

/// Most finished DKG answers a background keystore keeps for the kernel to
/// ask again.
pub const KEPT_ANSWERS: usize = 64;

/// The node's DKG decryption key: `KeyGen(consensus secret, "SOLO-DKG-ENCRYPTION")`.
///
/// # Panics
/// Never: a secp256k1 secret is 32 bytes, enough key material.
#[must_use]
pub fn decryption_key(key: &SigningKey) -> DecryptionKey {
    DecryptionKey::generate(&key.to_bytes()).expect("a secp256k1 secret is 32 bytes")
}

/// The DKG encryption key a validator registers (48 bytes, compressed G1).
#[must_use]
pub fn encryption_key(key: &SigningKey) -> [u8; 48] {
    decryption_key(key).encryption_key().to_bytes()
}

/// The dealer seed of one run: `expand_message_xmd(secret ‖ session)`, so a
/// dealer deals the same polynomial however often it is asked.
fn dealer_seed(key: &SigningKey, session: &[u8; 32]) -> [u8; 32] {
    let mut input = key.to_bytes().to_vec();
    input.extend_from_slice(session);
    let out = solo_bls::hash::expand_message_xmd(&input, DST_DEALER_SEED, 32);
    out.try_into().expect("32 bytes asked for")
}

/// Threshold shares by key set id, ascending by index within a key set.
#[derive(Debug, Default)]
pub struct Keystore {
    shares: BTreeMap<u64, Vec<SecretShare>>,
    background: Option<Background>,
}

/// DKG computations running off the node loop and their answers, by the
/// hash of the request.
#[derive(Debug)]
struct Background {
    /// Answers of computations that ended, `None` for a run that failed.
    answers: BTreeMap<[u8; 32], Option<Vec<u8>>>,
    /// The latest of them, oldest first, at most [`KEPT_ANSWERS`].
    finished: VecDeque<[u8; 32]>,
    /// Where each running computation will send what it produced.
    computing: BTreeMap<[u8; 32], Receiver<Done>>,
    hold: Arc<AtomicBool>,
}

/// The shares a finished run gave this node, with their key set's id.
type Made = Option<(u64, Vec<SecretShare>)>;

/// What a computation produced: the answer and the shares it made.
type Done = (Option<Vec<u8>>, Made);

impl Keystore {
    /// Whether the keystore holds a share of key set `key_set`.
    #[must_use]
    pub fn has_share(&self, key_set: u64) -> bool {
        self.shares.contains_key(&key_set)
    }

    /// Computes DKG answers on threads of their own from now on (`on`), or
    /// inside the call that asks (spec 15 §6.4). In the background, a
    /// request whose computation does not end within [`QUICK_MS`] is
    /// answered `None`, as one that cannot be served yet; the kernel asks
    /// again after its next block and gets the answer once it is ready,
    /// the same bytes it would have got at once.
    pub fn set_background(&mut self, on: bool) {
        self.background = on.then(|| Background {
            answers: BTreeMap::new(),
            finished: VecDeque::new(),
            computing: BTreeMap::new(),
            hold: Arc::default(),
        });
    }

    /// How many DKG computations are running in the background.
    #[must_use]
    pub fn busy(&self) -> usize {
        self.background.as_ref().map_or(0, |b| b.computing.len())
    }

    /// Holds background computations before they start while `hold` is
    /// set (tests that need one to keep running); only in builds with the
    /// `fault-injection` feature.
    #[cfg(feature = "fault-injection")]
    pub fn hold(&self, hold: bool) {
        if let Some(b) = &self.background {
            b.hold.store(hold, Ordering::Relaxed);
        }
    }

    /// Takes up the computations that ended: their answers, and the shares
    /// they made, which later requests sign with. The node calls this
    /// between steps; every request does it first.
    pub fn drain(&mut self) {
        let Some(b) = &mut self.background else {
            return;
        };
        let mut ended = Vec::new();
        b.computing.retain(|id, done| match done.try_recv() {
            Ok(done) => {
                ended.push((*id, done));
                false
            }
            Err(_) => true,
        });
        for (id, done) in ended {
            self.finish(id, done);
        }
    }

    /// Keeps what the computation for request `id` produced: its shares,
    /// and its answer among the latest [`KEPT_ANSWERS`].
    fn finish(&mut self, id: [u8; 32], (answer, made): Done) {
        if let Some((key_set, shares)) = made {
            self.shares.insert(key_set, shares);
        }
        let b = self
            .background
            .as_mut()
            .expect("computed in the background");
        b.answers.insert(id, answer);
        b.finished.push_back(id);
        while b.finished.len() > KEPT_ANSWERS {
            let old = b.finished.pop_front().expect("over the cap");
            b.answers.remove(&old);
        }
    }

    /// Answers an encoded [`KeystoreRequest`]; `None` when the request does
    /// not decode or cannot be served (no key, no share, a failed run, or,
    /// in the background, a computation that has not ended yet).
    pub fn handle(&mut self, key: Option<&SigningKey>, request: &[u8]) -> Option<Vec<u8>> {
        self.drain();
        match KeystoreRequest::from_bytes(request).ok()? {
            KeystoreRequest::EncryptionKey => Some(encryption_key(key?).to_vec()),
            KeystoreRequest::Dkg(r) => self.dkg(key?, &r, &[], request),
            KeystoreRequest::WeightedDkg { request: r, shares } => {
                self.dkg(key?, &r, &shares.0, request)
            }
            KeystoreRequest::Sign { key_set, message } => {
                key?;
                let share = self.shares.get(&key_set)?.first()?;
                Some(share.sign(&message).signature.to_bytes().to_vec())
            }
            KeystoreRequest::SignAll { key_set, message } => {
                key?;
                let partials = self
                    .shares
                    .get(&key_set)?
                    .iter()
                    .map(|share| PartialShare {
                        key_set,
                        index: share.index(),
                        signature: share.sign(&message).signature.to_bytes().to_vec(),
                    })
                    .collect();
                Some(Seq(partials).to_bytes())
            }
            KeystoreRequest::Combine {
                key_set,
                message,
                partials,
            } => combine(&key_set, &message, &partials.0),
        }
    }

    /// Replays the run for this node up to the requested boundary (see
    /// [`run`]), here or in the background; `raw` is the encoded request,
    /// whose hash names its answer.
    fn dkg(
        &mut self,
        key: &SigningKey,
        r: &DkgRequest,
        shares: &[u32],
        raw: &[u8],
    ) -> Option<Vec<u8>> {
        let current = self.dealing_share(r).ok()?;
        let Some(b) = &mut self.background else {
            let (reply, made) = run(key, r, shares, current)?;
            if let Some((key_set, shares)) = made {
                self.shares.insert(key_set, shares);
            }
            return Some(reply.to_bytes());
        };
        let id = solo_host::hash::keccak256(raw);
        if let Some(answer) = b.answers.get(&id) {
            return answer.clone();
        }
        if b.computing.contains_key(&id) {
            return None;
        }
        let (key, r, shares) = (key.clone(), r.clone(), shares.to_vec());
        let hold = Arc::clone(&b.hold);
        let (done_tx, done_rx) = channel();
        std::thread::spawn(move || {
            while hold.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(1));
            }
            let done = match run(&key, &r, &shares, current) {
                Some((reply, made)) => (Some(reply.to_bytes()), made),
                None => (None, None),
            };
            // A keystore that is gone wants no answer.
            let _ = done_tx.send(done);
        });
        // A computation that ends quickly is answered now.
        let Ok(done) = done_rx.recv_timeout(Duration::from_millis(QUICK_MS)) else {
            b.computing.insert(id, done_rx);
            return None;
        };
        let answer = done.0.clone();
        self.finish(id, done);
        answer
    }

    /// The share a resharing dealer deals, copied: `Ok(None)` when the
    /// request deals none, `Err` when the keystore lacks it.
    fn dealing_share(&self, r: &DkgRequest) -> Result<Option<SecretShare>, ()> {
        if r.dealer == 0 || r.previous.is_empty() {
            return Ok(None);
        }
        let current = self.shares.get(&r.previous_id).ok_or(())?;
        let current = current.iter().find(|s| s.index() == r.dealer).ok_or(())?;
        SecretShare::from_bytes(r.dealer, &current.to_bytes())
            .map(Some)
            .map_err(drop)
    }
}

/// Replays the run for this node up to the requested boundary, with
/// recipient `j` holding `shares[j − 1]` shares (one each when empty)
/// and, for a fresh key, dealer `j` weighing as much; a resharing dealer
/// deals `current`. The reply, and the shares the run gave this node if
/// it finished.
fn run(
    key: &SigningKey,
    r: &DkgRequest,
    shares: &[u32],
    current: Option<SecretShare>,
) -> Option<(DkgReply, Made)> {
    let recipients = r
        .recipients
        .0
        .iter()
        .map(|k| EncryptionKey::from_bytes(k.as_slice().try_into().ok()?).ok())
        .collect::<Option<Vec<_>>>()?;
    let previous = if r.previous.is_empty() {
        None
    } else {
        Some(PublicKeySet::from_bytes(&r.previous).ok()?)
    };
    let dealer = (r.dealer != 0).then(|| Dealer {
        index: r.dealer,
        seed: dealer_seed(key, &r.session),
        share: current,
    });
    let recipient = (r.recipient != 0).then(|| Recipient {
        index: r.recipient,
        key: decryption_key(key),
    });
    let weights = if previous.is_none() {
        shares.to_vec()
    } else {
        Vec::new()
    };
    let config = Config {
        session: r.session,
        threshold: r.threshold,
        dealers: r.dealers,
        recipients,
        shares: shares.to_vec(),
        weights,
        previous,
    };
    let (mut dkg, dealing) = Dkg::new(config, dealer, recipient).ok()?;
    if r.upto == 0 {
        let reply = dealing.map_or(DkgReply::Idle, |m| DkgReply::Message(m.to_bytes()));
        return Some((reply, None));
    }
    for phase in 0..r.upto.min(3) {
        for raw in r.transcript.0.iter().filter(|m| m.first() == Some(&phase)) {
            if let Ok(message) = Message::from_bytes(raw) {
                let _ = dkg.handle(&message);
            }
        }
        match dkg.advance().ok()? {
            Step::Broadcast(m) if phase + 1 == r.upto => {
                return Some((DkgReply::Message(m.to_bytes()), None));
            }
            // A recipient none of whose shares failed says so, with an empty
            // complaint, so that the phase can end as soon as every recipient
            // has spoken (spec 15 §6.1).
            Step::Idle if phase == 0 && r.upto == 1 && r.recipient != 0 => {
                let none = Message::Complaints(Complaints {
                    session: r.session,
                    accuser: r.recipient,
                    dealers: Vec::new(),
                });
                return Some((DkgReply::Message(none.to_bytes()), None));
            }
            Step::Finished(out) => {
                let total = if shares.is_empty() {
                    u32::try_from(r.recipients.0.len()).expect("checked by the run")
                } else {
                    shares.iter().sum()
                };
                let public_shares = out
                    .key_set
                    .public_shares(total)
                    .iter()
                    .map(|k| k.to_bytes().to_vec())
                    .collect();
                let vote = KeySetVote {
                    key_set: out.key_set.to_bytes(),
                    public_shares: Seq(public_shares),
                };
                let made = (!out.shares.is_empty()).then_some((r.key_set, out.shares));
                return Some((DkgReply::Finished(vote), made));
            }
            _ => {}
        }
    }
    Some((DkgReply::Idle, None))
}

/// Combines partial signatures and verifies the result under the group key;
/// when it fails, finds the invalid partials with one batched check and its
/// halves (spec 12 §4.1), drops them and combines again (spec 12 §7). The
/// batch's coefficients come from fresh randomness of this host, which no
/// signer can know.
fn combine(key_set: &[u8], message: &[u8], partials: &[PartialShare]) -> Option<Vec<u8>> {
    let set = PublicKeySet::from_bytes(key_set).ok()?;
    let mut parsed: Vec<PartialSignature> = Vec::new();
    for p in partials {
        let Some(signature) = <&[u8; 48]>::try_from(p.signature.as_slice())
            .ok()
            .and_then(|b| Signature::from_bytes(b).ok())
        else {
            continue;
        };
        if !parsed.iter().any(|q| q.index == p.index) {
            parsed.push(PartialSignature {
                index: p.index,
                signature,
            });
        }
    }
    if let Ok(signature) = set.combine(&parsed)
        && set.verify(message, &signature)
    {
        return Some(signature.to_bytes().to_vec());
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).ok()?;
    let valid = set.verify_partials(message, &parsed, &seed);
    let mut flags = valid.into_iter();
    parsed.retain(|_| flags.next().unwrap_or(false));
    let signature = set.combine(&parsed).ok()?;
    Some(signature.to_bytes().to_vec())
}
