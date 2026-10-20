//! The threshold keystore behind key role 2 of `sign` (spec 05 §4.3): the
//! node's DKG decryption key and dealer randomness, both derived from its
//! consensus key, and the threshold shares the DKG gives it. The kernel
//! drives the DKG and reads its public messages from chain state; whatever
//! needs a secret runs here, natively, and no secret leaves the host.

use std::collections::BTreeMap;

use k256::ecdsa::SigningKey;
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

/// Threshold shares by key set id.
#[derive(Debug, Default)]
pub struct Keystore {
    shares: BTreeMap<u64, SecretShare>,
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
            KeystoreRequest::Dkg(request) => self.dkg(key?, &request).map(|r| r.to_bytes()),
            KeystoreRequest::Sign { key_set, message } => {
                key?;
                let share = self.shares.get(&key_set)?;
                Some(share.sign(&message).signature.to_bytes().to_vec())
            }
            KeystoreRequest::Combine {
                key_set,
                message,
                partials,
            } => combine(&key_set, &message, &partials.0),
        }
    }

    /// Replays the run for this node up to the requested boundary.
    fn dkg(&mut self, key: &SigningKey, r: &DkgRequest) -> Option<DkgReply> {
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
        let config = Config {
            session: r.session,
            threshold: r.threshold,
            dealers: r.dealers,
            recipients,
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
                    let n = u32::try_from(r.recipients.0.len()).expect("checked by the run");
                    let public_shares = (1..=n)
                        .map(|j| out.key_set.public_share(j).to_bytes().to_vec())
                        .collect();
                    if let Some(share) = out.share {
                        self.shares.insert(r.key_set, share);
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
/// when it fails, verifies each partial, drops the invalid ones and combines
/// again (spec 12 §7).
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
    parsed.retain(|p| set.verify_partial(message, p));
    let signature = set.combine(&parsed).ok()?;
    Some(signature.to_bytes().to_vec())
}
