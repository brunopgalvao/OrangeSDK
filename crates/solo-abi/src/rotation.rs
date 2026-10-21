//! Rotating threshold keys (spec 12 §7, spec 15 §6.5–§6.7): the version-2
//! certificate that names the key it is signed with, the rotation message
//! with which the active key hands off to the next one, the records the
//! kernel keeps of handoffs, and the evidence of threshold misbehaviour
//! that it records and slashes.

use alloc::vec::Vec;

use crate::codec::{Decode, DecodeError, Decoder, Encode, Encoder};
use crate::staking::{G1_LENGTH, G2_LENGTH, PartialShare};
use crate::types::Hash;

macro_rules! record {
    ($(#[$meta:meta])* $name:ident { $($(#[$fmeta:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name {
            $($(#[$fmeta])* pub $field: $ty,)*
        }
        impl Encode for $name {
            fn encode(&self, e: &mut Encoder) {
                $(self.$field.encode(e);)*
            }
        }
        impl Decode for $name {
            fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                Ok($name { $($field: d.get()?,)* })
            }
        }
    };
}

/// The ASCII tag that opens every certificate message.
pub const FINALITY_TAG: &[u8; 13] = b"SOLO-FINALITY";

/// The ASCII tag that opens every rotation message.
pub const ROTATION_TAG: &[u8; 11] = b"SOLO-ROTATE";

/// Length of a version-1 certificate (spec 12 §7).
pub const CERTIFICATE_V1_LENGTH: usize = 89;

/// Length of a version-2 certificate (spec 12 §7).
pub const CERTIFICATE_V2_LENGTH: usize = 97;

/// Length of the message a version-2 certificate signs.
pub const MESSAGE_V2_LENGTH: usize = 70;

/// Length of a rotation message.
pub const ROTATION_MESSAGE_LENGTH: usize = 124;

/// Epochs a handoff may take, from the key's own epoch, before light
/// clients see it (spec 15 §6.6): part of the margin between the key age and
/// the unbonding period.
pub const HANDOFF_EPOCHS: u64 = 1;

/// Extra EVM gas a `report` action pays on top of its intrinsic gas
/// (spec 15 §5.2): one partial-signature check and a few records.
pub const REPORT_GAS: u64 = 150_000;

/// Most bytes of evidence a `report` action carries.
pub const MAX_REPORT: usize = 1 << 17;

/// Most threshold evidence records one query answer holds.
pub const MAX_EVIDENCE_QUERY: usize = 64;

/// Kinds of threshold misbehaviour (spec 15 §5.1).
pub mod offence {
    /// A partial signature over a proposal whose anchor root is not the
    /// state root the chain executed at the anchored height.
    pub const ANCHOR: u8 = 0;
    /// A partial signature over a rotation message to a key other than the
    /// one the chain adopted with that id.
    pub const ROTATION: u8 = 1;
    /// A partial signature by a key set over a proposal anchored at or
    /// after the block that handed its key off.
    pub const STALE_KEY: u8 = 2;
}

/// Storage keys of key rotation and threshold evidence (spec 15 §7).
pub mod keys {
    /// `dkg/adopted` → u64, the id of the newest adopted key set.
    pub const ADOPTED: &[u8] = b"dkg/adopted";
    /// `dkg/activated/` + id (big-endian u64) → u64, the height of the
    /// block that made the key set active.
    pub const ACTIVATED: &[u8] = b"dkg/activated/";
    /// `dkg/replaced/` + id → u64, the height of the block whose handoff
    /// replaced the key set.
    pub const REPLACED: &[u8] = b"dkg/replaced/";
    /// `dkg/handoff/` + id of the key handed off → `Handoff`.
    pub const HANDOFF: &[u8] = b"dkg/handoff/";
    /// `tevidence/` + index (big-endian u64) → `ThresholdEvidence`.
    pub const EVIDENCE: &[u8] = b"tevidence/";
    /// `meta/tevidence_count` → u64, the number of threshold evidence records.
    pub const EVIDENCE_COUNT: &[u8] = b"meta/tevidence_count";
    /// `tevseen/` + kind ‖ key set (big-endian u64) ‖ index (big-endian
    /// u32) → u64 index of the record for that offence.
    pub const EVIDENCE_SEEN: &[u8] = b"tevseen/";
}

/// Query method names.
pub mod query {
    /// `(u64 from) -> Handoff`: the handoff out of key set `from`; status 1 if none.
    pub const HANDOFF: &str = "handoff";
    /// `(u64 first) -> vec<ThresholdEvidence>`: the records from `first`, at most 64.
    pub const THRESHOLD_EVIDENCE: &str = "threshold_evidence";
}

/// The 70 bytes a version-2 certificate signs: `"SOLO-FINALITY" ‖ 2 ‖
/// chain_id ‖ key_id ‖ height ‖ block_hash`, integers big-endian.
#[must_use]
pub fn certificate_message(chain_id: u64, key_id: u64, height: u64, block_hash: &Hash) -> Vec<u8> {
    let mut out = FINALITY_TAG.to_vec();
    out.push(2);
    out.extend_from_slice(&chain_id.to_be_bytes());
    out.extend_from_slice(&key_id.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(block_hash);
    out
}

/// A version-2 certificate: `2 ‖ key_id ‖ height ‖ block_hash ‖ signature`.
#[must_use]
pub fn certificate_bytes(key_id: u64, height: u64, block_hash: &Hash, signature: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![2u8];
    out.extend_from_slice(&key_id.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(block_hash);
    out.extend_from_slice(signature);
    out
}

/// The 124 bytes the active key signs to hand off to key set `key_id` with
/// group key `key` (96 bytes, compressed): `"SOLO-ROTATE" ‖ 1 ‖ chain_id ‖
/// key_id ‖ key`, integers big-endian.
#[must_use]
pub fn rotation_message(chain_id: u64, key_id: u64, key: &[u8]) -> Vec<u8> {
    let mut out = ROTATION_TAG.to_vec();
    out.push(1);
    out.extend_from_slice(&chain_id.to_be_bytes());
    out.extend_from_slice(&key_id.to_be_bytes());
    out.extend_from_slice(key);
    out
}

/// A decoded threshold certificate of either version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThresholdCertificate<'a> {
    /// 1 or 2.
    pub version: u8,
    /// The key set that signed it; zero for version 1, which does not say.
    pub key_id: u64,
    /// Height of the certified proposal.
    pub height: u64,
    /// Hash of the certified proposal.
    pub block_hash: Hash,
    /// The compressed group signature (48 bytes).
    pub signature: &'a [u8],
}

impl ThresholdCertificate<'_> {
    /// The message this certificate signs on chain `chain_id`.
    #[must_use]
    pub fn message(&self, chain_id: u64) -> Vec<u8> {
        if self.version == 1 {
            crate::staking::certificate_message(chain_id, self.height, &self.block_hash)
        } else {
            certificate_message(chain_id, self.key_id, self.height, &self.block_hash)
        }
    }
}

fn be64(bytes: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&bytes[at..at + 8]);
    u64::from_be_bytes(b)
}

fn hash_at(bytes: &[u8], at: usize) -> Hash {
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes[at..at + 32]);
    h
}

/// Decodes a threshold certificate: 89 bytes opening with 1, or 97 bytes
/// opening with 2. A spec 08 vote certificate also opens with 2 but is never
/// 97 bytes long (`42 + 69·n` bytes, plus a longer length prefix from 128 votes).
#[must_use]
pub fn threshold_certificate(bytes: &[u8]) -> Option<ThresholdCertificate<'_>> {
    match (bytes.first(), bytes.len()) {
        (Some(1), CERTIFICATE_V1_LENGTH) => Some(ThresholdCertificate {
            version: 1,
            key_id: 0,
            height: be64(bytes, 1),
            block_hash: hash_at(bytes, 9),
            signature: &bytes[41..],
        }),
        (Some(2), CERTIFICATE_V2_LENGTH) => Some(ThresholdCertificate {
            version: 2,
            key_id: be64(bytes, 1),
            height: be64(bytes, 9),
            block_hash: hash_at(bytes, 17),
            signature: &bytes[49..],
        }),
        _ => None,
    }
}

record! {
    /// The body of a rotation-share envelope (spec 15 §6.6): a shareholder's
    /// partial signature, with the active key set, over the rotation
    /// message to key set `to`.
    RotationShare {
        /// The key set handed off to.
        to: u64,
        /// Its group key, compressed (96 bytes), as the signer read it.
        key: Vec<u8>,
        /// The partial signature, with the signing key set and index.
        partial: PartialShare,
    }
}

record! {
    /// The body of a handoff envelope: the active key set's group signature
    /// over the rotation message to `to`.
    RotationCertificate {
        /// The key set handed off from: the active one.
        from: u64,
        /// The key set handed off to.
        to: u64,
        /// The compressed group signature (48 bytes).
        signature: Vec<u8>,
    }
}

record! {
    /// A recorded handoff: what a relayer submits to a light client to move
    /// it from key set `from` to key set `to`.
    Handoff {
        /// The key set handed off from.
        from: u64,
        /// The key set handed off to.
        to: u64,
        /// The group key of `to`, compressed (96 bytes).
        key: Vec<u8>,
        /// The group signature of `from` over the rotation message (48 bytes).
        signature: Vec<u8>,
        /// The height of the block that recorded it.
        height: u64,
    }
}

impl Handoff {
    /// The rotation message this handoff signs on chain `chain_id`.
    #[must_use]
    pub fn message(&self, chain_id: u64) -> Vec<u8> {
        rotation_message(chain_id, self.to, &self.key)
    }
}

record! {
    /// Evidence of threshold misbehaviour (spec 15 §5.1): a shareholder's
    /// partial signature over a message an honest shareholder never signs.
    ThresholdEvidence {
        /// An [`offence`] kind.
        kind: u8,
        /// The key set the partial was signed with.
        key_set: u64,
        /// The shareholder's index in it, from 1.
        index: u32,
        /// The compressed partial signature (48 bytes).
        signature: Vec<u8>,
        /// For a proposal (`ANCHOR`, `STALE_KEY`) the encoded proposal; for
        /// `ROTATION` the target key set (big-endian u64) and its claimed
        /// group key (96 bytes).
        subject: Vec<u8>,
    }
}

/// The fields of an encoded proposal that threshold evidence reads, at their
/// fixed offsets (spec 08 §4): height, anchor height, anchor root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchored {
    /// The proposal's height.
    pub height: u64,
    /// The anchored height.
    pub anchor_height: u64,
    /// The anchored state root.
    pub anchor_root: Hash,
}

fn le64(bytes: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(b)
}

impl ThresholdEvidence {
    /// Names the offence: kind ‖ key set (big-endian u64) ‖ index
    /// (big-endian u32). One record per offence.
    #[must_use]
    pub fn id(&self) -> [u8; 13] {
        let mut out = [0u8; 13];
        out[0] = self.kind;
        out[1..9].copy_from_slice(&self.key_set.to_be_bytes());
        out[9..].copy_from_slice(&self.index.to_be_bytes());
        out
    }

    /// The anchor fields of a proposal subject; `None` for a rotation or a
    /// subject shorter than a proposal's fixed prefix.
    #[must_use]
    pub fn anchored(&self) -> Option<Anchored> {
        if self.kind == offence::ROTATION || self.subject.len() < 96 {
            return None;
        }
        Some(Anchored {
            height: le64(&self.subject, 8),
            anchor_height: le64(&self.subject, 56),
            anchor_root: hash_at(&self.subject, 64),
        })
    }

    /// The target key set and claimed group key of a rotation subject.
    #[must_use]
    pub fn rotation(&self) -> Option<(u64, &[u8])> {
        (self.kind == offence::ROTATION && self.subject.len() == 8 + G2_LENGTH)
            .then(|| (be64(&self.subject, 0), &self.subject[8..]))
    }

    /// The message the partial signs on chain `chain_id`, with `keccak`
    /// hashing a proposal subject; `None` for an unknown kind, a malformed
    /// subject or a signature that is not 48 bytes.
    #[must_use]
    pub fn message(&self, chain_id: u64, keccak: &dyn Fn(&[u8]) -> Hash) -> Option<Vec<u8>> {
        if self.signature.len() != G1_LENGTH || self.kind > offence::STALE_KEY {
            return None;
        }
        if let Some((to, key)) = self.rotation() {
            return Some(rotation_message(chain_id, to, key));
        }
        let a = self.anchored()?;
        Some(certificate_message(
            chain_id,
            self.key_set,
            a.height,
            &keccak(&self.subject),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn roundtrip<T: Encode + Decode + PartialEq + core::fmt::Debug>(v: &T) {
        assert_eq!(&T::from_bytes(&v.to_bytes()).unwrap(), v);
        assert!(!alloc::format!("{v:?}").is_empty());
    }

    fn fake_keccak(data: &[u8]) -> Hash {
        [u8::try_from(data.len() % 256).unwrap(); 32]
    }

    #[test]
    fn messages_and_certificates() {
        let m = certificate_message(1337, 4, 9, &[0xab; 32]);
        assert_eq!(m.len(), MESSAGE_V2_LENGTH);
        assert_eq!(&m[..14], b"SOLO-FINALITY\x02");
        assert_eq!(&m[14..22], &1337u64.to_be_bytes());
        assert_eq!(&m[22..30], &4u64.to_be_bytes());
        assert_eq!(&m[30..38], &9u64.to_be_bytes());
        let r = rotation_message(1337, 5, &[7; 96]);
        assert_eq!(r.len(), ROTATION_MESSAGE_LENGTH);
        assert_eq!(&r[..12], b"SOLO-ROTATE\x01");
        assert_eq!(&r[20..28], &5u64.to_be_bytes());
        let v2 = certificate_bytes(4, 9, &[2; 32], &[3; 48]);
        assert_eq!(v2.len(), CERTIFICATE_V2_LENGTH);
        let c = threshold_certificate(&v2).unwrap();
        assert_eq!(
            (c.version, c.key_id, c.height, c.block_hash, c.signature),
            (2, 4, 9, [2; 32], &[3u8; 48][..])
        );
        assert_eq!(c.message(1337), certificate_message(1337, 4, 9, &[2; 32]));
        let v1 = crate::staking::certificate_bytes(9, &[2; 32], &[3; 48]);
        let c = threshold_certificate(&v1).unwrap();
        assert_eq!((c.version, c.key_id, c.height), (1, 0, 9));
        assert_eq!(
            c.message(1337),
            crate::staking::certificate_message(1337, 9, &[2; 32])
        );
        assert_eq!(threshold_certificate(&v2[..96]), None);
        assert_eq!(threshold_certificate(&v1[..88]), None);
        assert_eq!(threshold_certificate(&[]), None);
        let mut other = v2.clone();
        other[0] = 1;
        assert_eq!(threshold_certificate(&other), None);
        assert_eq!(
            (HANDOFF_EPOCHS, REPORT_GAS, MAX_REPORT, MAX_EVIDENCE_QUERY),
            (1, 150_000, 131_072, 64)
        );
        for key in [
            keys::ADOPTED,
            keys::ACTIVATED,
            keys::REPLACED,
            keys::HANDOFF,
            keys::EVIDENCE,
            keys::EVIDENCE_COUNT,
            keys::EVIDENCE_SEEN,
        ] {
            assert!(!key.is_empty());
        }
        assert_eq!(
            (query::HANDOFF, query::THRESHOLD_EVIDENCE),
            ("handoff", "threshold_evidence")
        );
    }

    #[test]
    fn records_roundtrip() {
        roundtrip(&RotationShare {
            to: 3,
            key: vec![3; 96],
            partial: PartialShare {
                key_set: 2,
                index: 1,
                signature: vec![4; 48],
            },
        });
        roundtrip(&RotationCertificate {
            from: 2,
            to: 3,
            signature: vec![5; 48],
        });
        let handoff = Handoff {
            from: 2,
            to: 3,
            key: vec![6; 96],
            signature: vec![7; 48],
            height: 40,
        };
        roundtrip(&handoff);
        assert_eq!(handoff.message(9), rotation_message(9, 3, &[6; 96]));
        roundtrip(&ThresholdEvidence {
            kind: 1,
            key_set: 2,
            index: 3,
            signature: vec![1; 48],
            subject: vec![2; 104],
        });
    }

    #[test]
    fn evidence_subjects() {
        let mut proposal = vec![0u8; 120];
        proposal[8..16].copy_from_slice(&9u64.to_le_bytes());
        proposal[56..64].copy_from_slice(&7u64.to_le_bytes());
        proposal[64..96].copy_from_slice(&[5; 32]);
        let anchor = ThresholdEvidence {
            kind: offence::ANCHOR,
            key_set: 2,
            index: 3,
            signature: vec![1; 48],
            subject: proposal.clone(),
        };
        assert_eq!(anchor.id(), [0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3]);
        assert_eq!(
            anchor.anchored(),
            Some(Anchored {
                height: 9,
                anchor_height: 7,
                anchor_root: [5; 32]
            })
        );
        assert_eq!(anchor.rotation(), None);
        assert_eq!(
            anchor.message(1337, &fake_keccak),
            Some(certificate_message(1337, 2, 9, &[120; 32]))
        );
        let stale = ThresholdEvidence {
            kind: offence::STALE_KEY,
            ..anchor.clone()
        };
        assert!(stale.message(1, &fake_keccak).is_some());
        let short = ThresholdEvidence {
            subject: vec![0; 95],
            ..anchor.clone()
        };
        assert_eq!(short.anchored(), None);
        assert_eq!(short.message(1, &fake_keccak), None);
        let bad_signature = ThresholdEvidence {
            signature: vec![1; 47],
            ..anchor.clone()
        };
        assert_eq!(bad_signature.message(1, &fake_keccak), None);
        let unknown = ThresholdEvidence {
            kind: 3,
            ..anchor.clone()
        };
        assert_eq!(unknown.message(1, &fake_keccak), None);
        let mut subject = 4u64.to_be_bytes().to_vec();
        subject.extend_from_slice(&[8; 96]);
        let rotation = ThresholdEvidence {
            kind: offence::ROTATION,
            subject,
            ..anchor.clone()
        };
        assert_eq!(rotation.anchored(), None);
        assert_eq!(rotation.rotation(), Some((4, &[8u8; 96][..])));
        assert_eq!(
            rotation.message(1337, &fake_keccak),
            Some(rotation_message(1337, 4, &[8; 96]))
        );
        let truncated = ThresholdEvidence {
            subject: vec![0; 100],
            ..rotation
        };
        assert_eq!(truncated.rotation(), None);
        assert_eq!(truncated.message(1, &fake_keccak), None);
    }
}
