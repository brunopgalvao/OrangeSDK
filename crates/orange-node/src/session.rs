//! The sealed channel a connection runs once both `Hello`s are known (spec
//! 09 §3a): each end's `Hello` carries a fresh secp256k1 key, the two ends
//! agree a secret over them (ECDH), HKDF-SHA256 turns it into one key per
//! direction, and every frame after the `Hello`s is sealed with
//! ChaCha20-Poly1305 under a nonce that counts the frames sent that way.
//! A frame that is altered, replayed, reordered, dropped from the middle or
//! sent in the clear fails to open, and the connection closes. The fresh
//! keys are forgotten once the session keys are derived, so a node key
//! taken later opens no recorded session.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use hkdf::Hkdf;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use orange_abi::codec::{Decode, Encode};
use sha2::Sha256;

use crate::net::Frame;

/// The transport's protocol version, which every `Hello` names (spec 09 §3).
pub const VERSION: u16 = 1;

/// Bytes a sealed frame adds to the frame it carries: the Poly1305 tag.
pub const TAG: usize = 16;

/// Domain of the key schedule's salt.
const KEY_DOMAIN: &[u8] = b"ORANGE-P2P";

/// What one end's `Hello` commits it to for one connection: its nonce and
/// its fresh public key, SEC1-compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Side {
    /// The `Hello`'s nonce.
    pub nonce: [u8; 32],
    /// The `Hello`'s ephemeral public key.
    pub ephemeral: [u8; 33],
}

/// A fresh secp256k1 key for one connection's key agreement.
pub struct Ephemeral(SecretKey);

impl Ephemeral {
    /// The key whose scalar is `seed`, 32 unpredictable bytes.
    ///
    /// # Panics
    /// Only if `seed` is zero or at or above the group order, odds about
    /// 2^-128 for a hash.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Ephemeral {
        Ephemeral(SecretKey::from_bytes(seed.into()).expect("a hash is a scalar"))
    }

    /// The public key, SEC1-compressed, as a `Hello` carries it.
    #[must_use]
    pub fn public(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out.copy_from_slice(self.0.public_key().to_encoded_point(true).as_bytes());
        out
    }
}

/// One direction of a session: its key and the number of frames sealed or
/// opened so far, which is the next frame's nonce.
struct Half {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl Half {
    /// The next frame's nonce, `counter` little-endian then four zero
    /// bytes; `None` once the counter is spent.
    fn next(&mut self) -> Option<Nonce> {
        let n = self.counter;
        self.counter = n.checked_add(1)?;
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&n.to_le_bytes());
        Some(nonce.into())
    }
}

/// The keys of one connection, one per direction.
pub struct Session {
    send: Half,
    recv: Half,
}

impl Session {
    /// Agrees the session of a connection on `chain_id` and `genesis` whose
    /// own `Hello` committed to `mine`, with `ephemeral` its secret, and the
    /// peer's to `theirs`. `None` when the peer's key is not a point of the
    /// curve. `ephemeral` is consumed: once this returns, nothing that is
    /// kept can derive the keys again.
    ///
    /// # Panics
    /// Never: 32 bytes is within what HKDF-SHA256 expands to.
    #[must_use]
    pub fn new(
        ephemeral: Ephemeral,
        chain_id: u64,
        genesis: &[u8; 32],
        mine: &Side,
        theirs: &Side,
    ) -> Option<Session> {
        let public = PublicKey::from_sec1_bytes(&theirs.ephemeral).ok()?;
        let shared =
            k256::ecdh::diffie_hellman(ephemeral.0.to_nonzero_scalar(), public.as_affine());
        // Forgotten (and zeroed) now: only the session keys remain.
        drop(ephemeral);
        let mut salt = KEY_DOMAIN.to_vec();
        salt.extend_from_slice(&VERSION.to_le_bytes());
        salt.extend_from_slice(&chain_id.to_le_bytes());
        salt.extend_from_slice(genesis);
        let kdf = Hkdf::<Sha256>::new(Some(&salt), shared.raw_secret_bytes());
        let half = |from: &Side, to: &Side| {
            let mut info = from.ephemeral.to_vec();
            info.extend_from_slice(&to.ephemeral);
            info.extend_from_slice(&from.nonce);
            info.extend_from_slice(&to.nonce);
            let mut key = [0u8; 32];
            kdf.expand(&info, &mut key)
                .expect("32 bytes is a valid length");
            Half {
                cipher: ChaCha20Poly1305::new(&key.into()),
                counter: 0,
            }
        };
        Some(Session {
            send: half(mine, theirs),
            recv: half(theirs, mine),
        })
    }

    /// `frame` sealed for the wire: a `u32` little-endian length (of what
    /// follows), the encrypted frame and its tag, with the length as the
    /// associated data. `None` once this direction's counter is spent.
    pub fn seal(&mut self, frame: &Frame) -> Option<Vec<u8>> {
        self.seal_encoded(&frame.to_bytes())
    }

    /// [`Session::seal`] of a frame already encoded as `body`.
    pub fn seal_encoded(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        let header = u32::try_from(body.len() + TAG).ok()?.to_le_bytes();
        let nonce = self.send.next()?;
        let mut out = Vec::with_capacity(4 + body.len() + TAG);
        out.extend_from_slice(&header);
        out.extend_from_slice(body);
        let cipher = &self.send.cipher;
        let tag = cipher.encrypt_in_place_detached(&nonce, &header, &mut out[4..]);
        out.extend_from_slice(&tag.ok()?);
        Some(out)
    }

    /// Opens the sealed frame at the front of `buf`, if it is all there,
    /// carrying a frame of at most `max` bytes: the frame and the bytes of
    /// `buf` it took, which the caller drops. `buf` is decrypted in place.
    /// `Err` means the stream is unusable (a length out of bounds, a frame
    /// that does not open or does not decode) and the connection must close.
    ///
    /// # Errors
    /// A message naming the problem.
    pub fn open(&mut self, buf: &mut [u8], max: usize) -> Result<Option<(Frame, usize)>, String> {
        let Some(&[b0, b1, b2, b3]) = buf.get(..4) else {
            return Ok(None);
        };
        let header = [b0, b1, b2, b3];
        let len = u32::from_le_bytes(header) as usize;
        if !(TAG..=max + TAG).contains(&len) {
            return Err(format!("sealed frame of {len} bytes"));
        }
        if buf.len() < 4 + len {
            return Ok(None);
        }
        let nonce = self.recv.next().ok_or("counter spent")?;
        let (body, sent_tag) = buf[4..4 + len].split_at_mut(len - TAG);
        let mut tag = Tag::default();
        tag.copy_from_slice(sent_tag);
        self.recv
            .cipher
            .decrypt_in_place_detached(&nonce, &header, body, &tag)
            .map_err(|_| "a frame that does not open")?;
        let frame = Frame::from_bytes(body).map_err(|_| "undecodable frame")?;
        Ok(Some((frame, 4 + len)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::MAX_FRAME;

    fn pair() -> (Session, Session) {
        let (a, b) = (
            Ephemeral::from_seed(&[1; 32]),
            Ephemeral::from_seed(&[2; 32]),
        );
        let sa = Side {
            nonce: [3; 32],
            ephemeral: a.public(),
        };
        let sb = Side {
            nonce: [4; 32],
            ephemeral: b.public(),
        };
        assert_ne!(sa, sb);
        assert!(format!("{sa:?}").contains("ephemeral"));
        let one = Session::new(a, 7, &[9; 32], &sa, &sb).unwrap();
        let two = Session::new(b, 7, &[9; 32], &sb, &sa).unwrap();
        (one, two)
    }

    /// Opens what `buf` holds of a frame of at most `MAX_FRAME` bytes.
    fn open(s: &mut Session, buf: &mut [u8]) -> Result<Option<(Frame, usize)>, String> {
        s.open(buf, MAX_FRAME)
    }

    #[test]
    fn a_frame_opens_once_whole_and_only_the_other_way() {
        let (mut a, mut b) = pair();
        let frame = Frame::Tx { raw: vec![7; 100] };
        let sealed = a.seal(&frame).unwrap();
        assert_eq!(sealed.len(), 4 + frame.to_bytes().len() + TAG);
        let mut buf = sealed[..3].to_vec();
        assert_eq!(open(&mut b, &mut buf), Ok(None));
        buf.extend_from_slice(&sealed[3..50]);
        assert_eq!(open(&mut b, &mut buf), Ok(None));
        buf.extend_from_slice(&sealed[50..]);
        // What follows the frame is left for the next.
        buf.push(0);
        assert_eq!(open(&mut b, &mut buf), Ok(Some((frame, sealed.len()))));
        // Each direction has its own key: a frame sent back to its sealer does not open.
        let mut back = b.seal(&Frame::GetPeers).unwrap();
        let mut own = back.clone();
        assert_eq!(
            open(&mut b, &mut own).unwrap_err(),
            "a frame that does not open"
        );
        assert_eq!(
            open(&mut a, &mut back),
            Ok(Some((Frame::GetPeers, back.len())))
        );
    }

    #[test]
    fn a_length_no_sealed_frame_has_closes() {
        let (_, mut b) = pair();
        for len in [0, TAG - 1, MAX_FRAME + TAG + 1] {
            let mut buf = u32::try_from(len).unwrap().to_le_bytes().to_vec();
            assert!(
                open(&mut b, &mut buf)
                    .unwrap_err()
                    .starts_with("sealed frame of")
            );
        }
        // Nor one longer than the caller takes, however little of it came.
        let mut buf = u32::try_from(11 + TAG).unwrap().to_le_bytes().to_vec();
        assert!(
            b.open(&mut buf, 10)
                .unwrap_err()
                .starts_with("sealed frame of")
        );
        assert_eq!(b.open(&mut buf, 11), Ok(None));
    }

    #[test]
    fn a_spent_counter_seals_and_opens_nothing() {
        let (mut a, mut b) = pair();
        let mut sealed = a.seal(&Frame::GetPeers).unwrap();
        a.send.counter = u64::MAX;
        assert!(a.seal(&Frame::GetPeers).is_none());
        b.recv.counter = u64::MAX;
        assert_eq!(open(&mut b, &mut sealed).unwrap_err(), "counter spent");
    }

    #[test]
    fn a_sealed_frame_that_does_not_decode_closes() {
        let (mut a, mut b) = pair();
        // A frame of an unknown tag, sealed by hand.
        let header = u32::try_from(1 + TAG).unwrap().to_le_bytes();
        let nonce = a.send.next().unwrap();
        let mut body = vec![0xEE];
        let tag = a
            .send
            .cipher
            .encrypt_in_place_detached(&nonce, &header, &mut body)
            .unwrap();
        let mut wire = header.to_vec();
        wire.extend_from_slice(&body);
        wire.extend_from_slice(&tag);
        assert_eq!(open(&mut b, &mut wire).unwrap_err(), "undecodable frame");
    }
}
