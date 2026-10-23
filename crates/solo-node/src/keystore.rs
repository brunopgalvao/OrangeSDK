//! The threshold keystore behind key role 2 of `sign` (spec 05 §4.3): the
//! node's DKG decryption key and dealer randomness, both derived from its
//! consensus key, and the threshold shares the DKG gives it. The kernel
//! drives the DKG and reads its public messages from chain state; whatever
//! needs a secret runs here, natively, and no secret leaves the host.

use std::collections::BTreeMap;

use k256::ecdsa::SigningKey;
use solo_abi::codec::Seq;
use solo_abi::staking::{DkgReply, DkgRequest, KeySetVote, KeystoreRequest, PartialShare};
use solo_abi::{Decode, Encode};
use solo_bls::dkg::{Config, Dealer, DecryptionKey, Dkg, EncryptionKey, Message, Recipient, Step};
use solo_bls::{PartialSignature, PublicKeySet, SecretShare, Signature};

/// Domain separation tag of a dealer's per-run seed.
pub const DST_DEALER_SEED: &[u8] = b"SOLO-V01-DKG-SEED_XMD:SHA-256";

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
}

impl Keystore {
    /// Whether the keystore holds a share of key set `key_set`.
    #[must_use]
    pub fn has_share(&self, key_set: u64) -> bool {
        self.shares.contains_key(&key_set)
    }

    /// Answers an encoded [`KeystoreRequest`]; `None` when the request does
    /// not decode or cannot be served (no key, no share, a failed run).
    pub fn handle(&mut self, key: Option<&SigningKey>, request: &[u8]) -> Option<Vec<u8>> {
        match KeystoreRequest::from_bytes(request).ok()? {
            KeystoreRequest::EncryptionKey => Some(encryption_key(key?).to_vec()),
            KeystoreRequest::Dkg(request) => self.dkg(key?, &request, &[]).map(|r| r.to_bytes()),
            KeystoreRequest::WeightedDkg { request, shares } => {
                self.dkg(key?, &request, &shares.0).map(|r| r.to_bytes())
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

    /// Replays the run for this node up to the requested boundary, with
    /// recipient `j` holding `shares[j − 1]` shares (one each when empty)
    /// and, for a fresh key, dealer `j` weighing as much.
    fn dkg(&mut self, key: &SigningKey, r: &DkgRequest, shares: &[u32]) -> Option<DkgReply> {
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
        let dealer = if r.dealer == 0 {
            None
        } else {
            let share = if previous.is_some() {
                let current = self.shares.get(&r.previous_id)?;
                let current = current.iter().find(|s| s.index() == r.dealer)?;
                Some(SecretShare::from_bytes(r.dealer, &current.to_bytes()).ok()?)
            } else {
                None
            };
            Some(Dealer {
                index: r.dealer,
                seed: dealer_seed(key, &r.session),
                share,
            })
        };
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
            return Some(dealing.map_or(DkgReply::Idle, |m| DkgReply::Message(m.to_bytes())));
        }
        for phase in 0..r.upto.min(3) {
            for raw in r.transcript.0.iter().filter(|m| m.first() == Some(&phase)) {
                if let Ok(message) = Message::from_bytes(raw) {
                    let _ = dkg.handle(&message);
                }
            }
            match dkg.advance().ok()? {
                Step::Broadcast(m) if phase + 1 == r.upto => {
                    return Some(DkgReply::Message(m.to_bytes()));
                }
                Step::Finished(out) => {
                    let total = if shares.is_empty() {
                        u32::try_from(r.recipients.0.len()).expect("checked by the run")
                    } else {
                        shares.iter().sum()
                    };
                    let public_shares = (1..=total)
                        .map(|x| out.key_set.public_share(x).to_bytes().to_vec())
                        .collect();
                    if !out.shares.is_empty() {
                        self.shares.insert(r.key_set, out.shares);
                    }
                    return Some(DkgReply::Finished(KeySetVote {
                        key_set: out.key_set.to_bytes(),
                        public_shares: solo_abi::codec::Seq(public_shares),
                    }));
                }
                _ => {}
            }
        }
        Some(DkgReply::Idle)
    }
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
