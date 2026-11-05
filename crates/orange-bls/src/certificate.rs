//! The finality certificate of spec 12 §7: a group signature over a
//! domain-separated message naming the chain, the height and the block.

use crate::sig::{PublicKey, Signature};
use crate::threshold::{PartialSignature, PublicKeySet, SecretShare};
use crate::{Error, point};

/// The certificate version this module produces and accepts.
pub const VERSION: u8 = 1;

/// Length of an encoded version-1 certificate.
pub const LENGTH: usize = 89;

/// Length of the message a version-1 certificate signs.
pub const MESSAGE_LENGTH: usize = 64;

/// The ASCII tag that opens every certificate message.
pub const TAG: &[u8; 15] = b"ORANGE-FINALITY";

/// The message signed for block `block_hash` at `height` on chain
/// `chain_id`: `TAG ‖ VERSION ‖ chain_id ‖ height ‖ block_hash`, integers
/// big-endian.
#[must_use]
pub fn message(chain_id: u64, height: u64, block_hash: &[u8; 32]) -> [u8; MESSAGE_LENGTH] {
    let mut m = [0u8; MESSAGE_LENGTH];
    m[..15].copy_from_slice(TAG);
    m[15] = VERSION;
    m[16..24].copy_from_slice(&chain_id.to_be_bytes());
    m[24..32].copy_from_slice(&height.to_be_bytes());
    m[32..].copy_from_slice(block_hash);
    m
}

/// A validator's partial signature over the certificate message.
#[must_use]
pub fn sign_partial(
    share: &SecretShare,
    chain_id: u64,
    height: u64,
    block_hash: &[u8; 32],
) -> PartialSignature {
    share.sign(&message(chain_id, height, block_hash))
}

/// A version-1 finality certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Certificate {
    /// Height of the finalized block.
    pub height: u64,
    /// Hash of the finalized block.
    pub block_hash: [u8; 32],
    /// The group signature over [`message`].
    pub signature: Signature,
}

impl Certificate {
    /// Combines partial signatures over the certificate message into a
    /// certificate, and checks the result against the group key so that an
    /// invalid partial never yields an invalid certificate.
    ///
    /// # Errors
    /// The errors of [`PublicKeySet::combine`], and
    /// [`Error::InvalidSignature`] if the combined signature does not verify.
    pub fn combine(
        keys: &PublicKeySet,
        chain_id: u64,
        height: u64,
        block_hash: &[u8; 32],
        partials: &[PartialSignature],
    ) -> Result<Certificate, Error> {
        let certificate = Certificate {
            height,
            block_hash: *block_hash,
            signature: keys.combine(partials)?,
        };
        if certificate.verify(chain_id, &keys.group_key()) {
            Ok(certificate)
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// The message this certificate signs on chain `chain_id`.
    #[must_use]
    pub fn message(&self, chain_id: u64) -> [u8; MESSAGE_LENGTH] {
        message(chain_id, self.height, &self.block_hash)
    }

    /// Whether the signature is valid for chain `chain_id` under `group_key`.
    #[must_use]
    pub fn verify(&self, chain_id: u64, group_key: &PublicKey) -> bool {
        group_key.verify(&self.message(chain_id), &self.signature)
    }

    /// `VERSION ‖ height ‖ block_hash ‖ signature`, height big-endian.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; LENGTH] {
        let mut out = [0u8; LENGTH];
        out[0] = VERSION;
        out[1..9].copy_from_slice(&self.height.to_be_bytes());
        out[9..41].copy_from_slice(&self.block_hash);
        out[41..].copy_from_slice(&self.signature.to_bytes());
        out
    }

    /// Decodes a certificate.
    ///
    /// # Errors
    /// [`Error::UnsupportedVersion`] for a first byte other than
    /// [`VERSION`], [`Error::InvalidLength`] for a length other than
    /// [`LENGTH`], [`Error::InvalidPoint`] for a bad signature point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Certificate, Error> {
        if bytes.first() != Some(&VERSION) {
            return Err(Error::UnsupportedVersion);
        }
        if bytes.len() != LENGTH {
            return Err(Error::InvalidLength);
        }
        let mut height = [0u8; 8];
        let mut block_hash = [0u8; 32];
        let mut signature = [0u8; 48];
        height.copy_from_slice(&bytes[1..9]);
        block_hash.copy_from_slice(&bytes[9..41]);
        signature.copy_from_slice(&bytes[41..]);
        Ok(Certificate {
            height: u64::from_be_bytes(height),
            block_hash,
            signature: Signature(point::g1(&signature).ok_or(Error::InvalidPoint)?),
        })
    }
}

/// Length of an encoded version-2 certificate.
pub const LENGTH_V2: usize = 97;

/// Length of the message a version-2 certificate signs.
pub const MESSAGE_V2_LENGTH: usize = 72;

/// The ASCII tag that opens every rotation message.
pub const ROTATION_TAG: &[u8; 13] = b"ORANGE-ROTATE";

/// Length of a rotation message.
pub const ROTATION_MESSAGE_LENGTH: usize = 126;

/// The message a version-2 certificate signs for block `block_hash` at
/// `height` on chain `chain_id` with key set `key_id`: `TAG ‖ 2 ‖ chain_id ‖
/// key_id ‖ height ‖ block_hash`, integers big-endian.
#[must_use]
pub fn message_v2(
    chain_id: u64,
    key_id: u64,
    height: u64,
    block_hash: &[u8; 32],
) -> [u8; MESSAGE_V2_LENGTH] {
    let mut m = [0u8; MESSAGE_V2_LENGTH];
    m[..15].copy_from_slice(TAG);
    m[15] = 2;
    m[16..24].copy_from_slice(&chain_id.to_be_bytes());
    m[24..32].copy_from_slice(&key_id.to_be_bytes());
    m[32..40].copy_from_slice(&height.to_be_bytes());
    m[40..].copy_from_slice(block_hash);
    m
}

/// The message with which the active key hands off to key set `key_id`
/// with group key `key`: `ROTATION_TAG ‖ 1 ‖ chain_id ‖ key_id ‖ key`, the key
/// compressed, integers big-endian.
#[must_use]
pub fn rotation_message(
    chain_id: u64,
    key_id: u64,
    key: &PublicKey,
) -> [u8; ROTATION_MESSAGE_LENGTH] {
    let mut m = [0u8; ROTATION_MESSAGE_LENGTH];
    m[..13].copy_from_slice(ROTATION_TAG);
    m[13] = 1;
    m[14..22].copy_from_slice(&chain_id.to_be_bytes());
    m[22..30].copy_from_slice(&key_id.to_be_bytes());
    m[30..].copy_from_slice(&key.to_bytes());
    m
}

/// A version-2 finality certificate: it names the key set that signed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateV2 {
    /// The signing key set's id.
    pub key_id: u64,
    /// Height of the finalized block.
    pub height: u64,
    /// Hash of the finalized block.
    pub block_hash: [u8; 32],
    /// The group signature over [`message_v2`].
    pub signature: Signature,
}

impl CertificateV2 {
    /// The message this certificate signs on chain `chain_id`.
    #[must_use]
    pub fn message(&self, chain_id: u64) -> [u8; MESSAGE_V2_LENGTH] {
        message_v2(chain_id, self.key_id, self.height, &self.block_hash)
    }

    /// Whether the signature is valid for chain `chain_id` under `group_key`,
    /// the key of key set `key_id`.
    #[must_use]
    pub fn verify(&self, chain_id: u64, group_key: &PublicKey) -> bool {
        group_key.verify(&self.message(chain_id), &self.signature)
    }

    /// `2 ‖ key_id ‖ height ‖ block_hash ‖ signature`, integers big-endian.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; LENGTH_V2] {
        let mut out = [0u8; LENGTH_V2];
        out[0] = 2;
        out[1..9].copy_from_slice(&self.key_id.to_be_bytes());
        out[9..17].copy_from_slice(&self.height.to_be_bytes());
        out[17..49].copy_from_slice(&self.block_hash);
        out[49..].copy_from_slice(&self.signature.to_bytes());
        out
    }

    /// Decodes a version-2 certificate.
    ///
    /// # Errors
    /// [`Error::UnsupportedVersion`] for a first byte other than 2,
    /// [`Error::InvalidLength`] for a length other than [`LENGTH_V2`],
    /// [`Error::InvalidPoint`] for a bad signature point.
    pub fn from_bytes(bytes: &[u8]) -> Result<CertificateV2, Error> {
        if bytes.first() != Some(&2) {
            return Err(Error::UnsupportedVersion);
        }
        if bytes.len() != LENGTH_V2 {
            return Err(Error::InvalidLength);
        }
        let mut key_id = [0u8; 8];
        let mut height = [0u8; 8];
        let mut block_hash = [0u8; 32];
        let mut signature = [0u8; 48];
        key_id.copy_from_slice(&bytes[1..9]);
        height.copy_from_slice(&bytes[9..17]);
        block_hash.copy_from_slice(&bytes[17..49]);
        signature.copy_from_slice(&bytes[49..]);
        Ok(CertificateV2 {
            key_id: u64::from_be_bytes(key_id),
            height: u64::from_be_bytes(height),
            block_hash,
            signature: Signature(point::g1(&signature).ok_or(Error::InvalidPoint)?),
        })
    }
}
