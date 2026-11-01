//! Peer exchange (spec 09 §5a): signed address records and the bounded
//! peer table a node learns them into, scores and dials from. The table is
//! plain data driven by the transport ([`crate::net`]); everything here is
//! deterministic and independent of sockets and clocks.
//!
//! A record binds a node id (the hash of a secp256k1 public key, the
//! validator id of spec 08 §2) to the address its holder listens on,
//! signed with that key, so no peer can point others at its own address
//! under somebody else's id. The table holds at most [`TABLE_CAP`]
//! entries, limits what one source and one address prefix can put in it
//! before any of it has answered, and lets a new entry displace only an
//! entry whose dials failed, so a flood of junk never pushes out peers that
//! work.
//!
//! A node with a data directory keeps the entries that answered in
//! [`PEER_FILE`] and takes them up again at start ([`PeerTable::saved`],
//! [`PeerTable::restore`]), checking every record once more.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use solo_abi::codec::{Decode, DecodeError, Decoder, Encode, Encoder, Seq};

/// Most records one `Peers` frame may carry.
pub const MAX_RECORDS: usize = 32;
/// Longest address a record may carry, in bytes.
pub const MAX_ADDR: usize = 64;
/// Most entries in the peer table.
pub const TABLE_CAP: usize = 256;
/// Most unverified entries one source may account for.
pub const PER_SOURCE: usize = 16;
/// Most unverified entries, and accepted connections, per address prefix.
pub const PER_PREFIX: usize = 8;
/// Failures running after which an entry outside the validator set is forgotten.
pub const MAX_FAILURES: u32 = 8;
/// How often a node asks each peer for its records.
pub const EXCHANGE_MS: u64 = 10_000;
/// Least time between two `GetPeers`, or two `Peers`, a connection's
/// sender has handled.
pub const PEER_GAP_MS: u64 = 1_000;
/// The first wait after a failed dial or a lost connection.
pub const BACKOFF_MS: u64 = 500;
/// The longest wait between dials of one entry.
pub const MAX_BACKOFF_MS: u64 = 60_000;
/// Most dials in flight at once.
pub const MAX_DIALING: usize = 8;
/// How often the transport reads the current validator set again.
pub const VALIDATOR_REFRESH_MS: u64 = 10_000;
/// Default of `--max-peers`: connections in all, configured peers aside.
pub const DEFAULT_MAX_PEERS: usize = 32;
/// Default of `--outbound-peers`: connections this node dials itself.
pub const DEFAULT_OUTBOUND: usize = 8;
/// The file in the data directory that keeps the table across restarts.
pub const PEER_FILE: &str = "peers.records";
/// Least time between two writes of [`PEER_FILE`].
pub const SAVE_MS: u64 = 10_000;
/// How long after its last handshake a saved entry is still taken up.
pub const SAVED_TTL_MS: u64 = 7 * 24 * 3_600_000;

const MAX_SCORE: i32 = 100;
const MIN_SCORE: i32 = -100;
const HANDSHAKE_REWARD: i32 = 10;
const DIAL_PENALTY: i32 = 5;
const MISMATCH_PENALTY: i32 = 50;
/// Domain of a record's signature.
const DOMAIN: &[u8] = b"SOLO-PEER";

/// A node's signed advertisement of where it listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    /// The node id: `keccak256` of the uncompressed public key.
    pub id: [u8; 32],
    /// The address to dial, `ip:port` in ASCII.
    pub addr: Vec<u8>,
    /// The signer's clock when it signed, in milliseconds; a higher one replaces a lower.
    pub seq: u64,
    /// Recoverable secp256k1 signature over [`PeerRecord::digest`].
    pub signature: [u8; 65],
}

impl Encode for PeerRecord {
    fn encode(&self, e: &mut Encoder) {
        e.put(&self.id)
            .put(&self.addr)
            .put(&self.seq)
            .put(&self.signature);
    }
}

impl Decode for PeerRecord {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(PeerRecord {
            id: d.get()?,
            addr: d.get()?,
            seq: d.get()?,
            signature: d.get()?,
        })
    }
}

impl PeerRecord {
    /// What a record's key signs: `keccak256("SOLO-PEER" ‖ chain_id ‖ seq ‖ addr)`.
    #[must_use]
    pub fn digest(chain_id: u64, seq: u64, addr: &[u8]) -> [u8; 32] {
        let mut preimage = DOMAIN.to_vec();
        preimage.extend_from_slice(&chain_id.to_le_bytes());
        preimage.extend_from_slice(&seq.to_le_bytes());
        preimage.extend_from_slice(addr);
        solo_host::hash::keccak256(&preimage)
    }

    /// The record of `key` for `addr`, signed at `seq`; none if the key
    /// cannot sign.
    #[must_use]
    pub fn sign(
        key: &k256::ecdsa::SigningKey,
        chain_id: u64,
        addr: SocketAddr,
        seq: u64,
    ) -> Option<PeerRecord> {
        let addr = addr.to_string().into_bytes();
        let digest = Self::digest(chain_id, seq, &addr);
        Some(PeerRecord {
            id: crate::validator_id(key),
            signature: crate::sign_recoverable(key, &digest)?,
            addr,
            seq,
        })
    }

    /// The address this record lets a node dial: when its signature recovers
    /// to the key whose hash is `id` and its address is one a node can dial.
    #[must_use]
    pub fn verify(&self, chain_id: u64) -> Option<SocketAddr> {
        if self.addr.len() > MAX_ADDR {
            return None;
        }
        let addr: SocketAddr = std::str::from_utf8(&self.addr).ok()?.parse().ok()?;
        if !dialable(&addr) {
            return None;
        }
        let digest = Self::digest(chain_id, self.seq, &self.addr);
        (recover_id(&digest, &self.signature)? == self.id).then_some(addr)
    }
}

/// The node id whose key made `signature` over `digest`: `keccak256` of
/// the recovered uncompressed public key; none if nothing recovers.
#[must_use]
pub fn recover_id(digest: &[u8; 32], signature: &[u8; 65]) -> Option<[u8; 32]> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    let recovery = RecoveryId::from_byte(signature[64])?;
    let parsed = Signature::from_slice(&signature[..64]).ok()?;
    let key = VerifyingKey::recover_from_prehash(digest, &parsed, recovery).ok()?;
    let point = key.to_encoded_point(false);
    Some(solo_host::hash::keccak256(&point.as_bytes()[1..]))
}

/// An entry as [`PEER_FILE`] keeps it: its record and the time of its
/// last handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedPeer {
    /// The entry's record, checked again when taken up.
    pub record: PeerRecord,
    /// When a dial of it last completed a handshake, in this node's clock.
    pub seen_ms: u64,
}

impl Encode for SavedPeer {
    fn encode(&self, e: &mut Encoder) {
        e.put(&self.record).put(&self.seen_ms);
    }
}

impl Decode for SavedPeer {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(SavedPeer {
            record: d.get()?,
            seen_ms: d.get()?,
        })
    }
}

/// What the file at `path` keeps; nothing when it is missing, unreadable
/// or does not decode, which a node takes as an empty table.
#[must_use]
pub fn load_saved(path: &Path) -> Vec<SavedPeer> {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| Seq::<SavedPeer>::from_bytes(&bytes).ok())
        .map_or_else(Vec::new, |saved| saved.0)
}

/// Writes `bytes` to `path` through a temporary file renamed into place,
/// so that a crash leaves the old file or the new one.
///
/// # Errors
/// If the temporary file cannot be written or renamed.
pub fn write_saved(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// Whether a node can dial `addr`: not unspecified, not multicast, port not 0.
#[must_use]
pub fn dialable(addr: &SocketAddr) -> bool {
    let ip = addr.ip();
    addr.port() != 0 && !ip.is_unspecified() && !ip.is_multicast()
}

/// The prefix whose entries and connections are limited together: the
/// first 24 bits of an IPv4 address, the first 48 of an IPv6 one, none for
/// a loopback address.
#[must_use]
pub fn prefix(addr: &SocketAddr) -> Option<Vec<u8>> {
    match addr.ip() {
        ip if ip.is_loopback() => None,
        IpAddr::V4(v4) => Some(v4.octets()[..3].to_vec()),
        IpAddr::V6(v6) => Some(v6.octets()[..6].to_vec()),
    }
}

/// The wait before the next dial after `failures` failures running.
#[must_use]
pub fn backoff_ms(failures: u32) -> u64 {
    let doublings = failures.saturating_sub(1).min(16);
    (BACKOFF_MS << doublings).min(MAX_BACKOFF_MS)
}

/// One peer the table knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its latest record.
    pub record: PeerRecord,
    /// The record's address.
    pub addr: SocketAddr,
    /// The peer that sent the record first; `None` for one learned from the peer itself.
    pub source: Option<[u8; 32]>,
    /// Whether a dial of `addr` completed a handshake that named `record.id`.
    pub verified: bool,
    /// Rises with handshakes, falls with failures (spec 09 §5a).
    pub score: i32,
    /// Failures running.
    pub failures: u32,
    /// When it may be dialled next.
    pub next_dial_ms: u64,
    /// When a dial of it last completed a handshake; 0 if none has.
    pub seen_ms: u64,
}

/// Why a `Peers` frame was refused: its sender's connection is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// More than [`MAX_RECORDS`] records.
    TooMany,
    /// A record that does not verify.
    Unverified,
}

/// The bounded peer table of spec 09 §5a.
#[derive(Debug, Clone)]
pub struct PeerTable {
    chain_id: u64,
    own: [u8; 32],
    entries: BTreeMap<[u8; 32], Entry>,
    validators: Vec<[u8; 32]>,
}

impl PeerTable {
    /// An empty table for a node with id `own` on `chain_id`.
    #[must_use]
    pub fn new(chain_id: u64, own: [u8; 32]) -> PeerTable {
        PeerTable {
            chain_id,
            own,
            entries: BTreeMap::new(),
            validators: Vec::new(),
        }
    }

    /// The entries, by id.
    #[must_use]
    pub fn entries(&self) -> &BTreeMap<[u8; 32], Entry> {
        &self.entries
    }

    /// The ids of the current validator set, which the table prefers and protects.
    pub fn set_validators(&mut self, ids: Vec<[u8; 32]>) {
        self.validators = ids;
    }

    /// The ids the table takes for the current validator set.
    #[must_use]
    pub fn validators(&self) -> &[[u8; 32]] {
        &self.validators
    }

    fn is_validator(&self, id: &[u8; 32]) -> bool {
        self.validators.contains(id)
    }

    /// Takes the records of a `Peers` frame from `source`. Every record must
    /// verify, or none is taken and the frame is refused. Returns how many
    /// entries were added or moved.
    ///
    /// # Errors
    /// [`Refused`] when the frame breaks the rules; its sender's connection closes.
    pub fn learn(
        &mut self,
        source: [u8; 32],
        records: &[PeerRecord],
        connected: &[[u8; 32]],
    ) -> Result<usize, Refused> {
        if records.len() > MAX_RECORDS {
            return Err(Refused::TooMany);
        }
        let mut verified = Vec::with_capacity(records.len());
        for record in records {
            verified.push(record.verify(self.chain_id).ok_or(Refused::Unverified)?);
        }
        let mut taken = 0;
        for (record, addr) in records.iter().zip(verified) {
            taken += usize::from(self.insert(source, record, addr, connected));
        }
        Ok(taken)
    }

    /// Enters one verified record from `source`.
    fn insert(
        &mut self,
        source: [u8; 32],
        record: &PeerRecord,
        addr: SocketAddr,
        connected: &[[u8; 32]],
    ) -> bool {
        if record.id == self.own {
            return false;
        }
        if let Some(entry) = self.entries.get_mut(&record.id) {
            if record.seq <= entry.record.seq {
                return false;
            }
            if entry.addr != addr {
                entry.verified = false;
                entry.failures = 0;
                entry.next_dial_ms = 0;
            }
            entry.addr = addr;
            entry.record = record.clone();
            return true;
        }
        let unverified = |e: &&Entry| !e.verified;
        let from_source = self
            .entries
            .values()
            .filter(unverified)
            .filter(|e| e.source == Some(source))
            .count();
        let in_prefix = prefix(&addr).map_or(0, |p| {
            self.entries
                .values()
                .filter(unverified)
                .filter(|e| prefix(&e.addr).as_ref() == Some(&p))
                .count()
        });
        if (record.id != source && from_source >= PER_SOURCE) || in_prefix >= PER_PREFIX {
            return false;
        }
        if self.entries.len() >= TABLE_CAP {
            let worst = self
                .entries
                .iter()
                .filter(|(id, e)| e.score < 0 && !self.is_validator(id) && !connected.contains(id))
                .min_by_key(|(id, e)| (e.score, **id))
                .map(|(id, _)| *id);
            let Some(worst) = worst else {
                return false;
            };
            self.entries.remove(&worst);
        }
        self.entries.insert(
            record.id,
            Entry {
                record: record.clone(),
                addr,
                source: (record.id != source).then_some(source),
                verified: false,
                score: 0,
                failures: 0,
                next_dial_ms: 0,
                seen_ms: 0,
            },
        );
        true
    }

    /// The entries to keep across a restart (spec 09 §5a.7): those seen,
    /// current validators first, then by score, then by id; at most `limit`.
    #[must_use]
    pub fn saved(&self, limit: usize) -> Vec<SavedPeer> {
        let mut seen: Vec<(&[u8; 32], &Entry)> =
            self.entries.iter().filter(|(_, e)| e.seen_ms > 0).collect();
        seen.sort_by_key(|(id, e)| (!self.is_validator(id), -e.score, **id));
        seen.into_iter()
            .take(limit)
            .map(|(_, e)| SavedPeer {
                record: e.record.clone(),
                seen_ms: e.seen_ms,
            })
            .collect()
    }

    /// Takes up the first `limit` of `saved` at `now_ms`, each as its
    /// holder's own record (spec 09 §5a.7). Records that do not verify,
    /// this node's own, and entries last seen more than [`SAVED_TTL_MS`]
    /// ago are skipped. Returns how many entries were entered.
    pub fn restore(&mut self, saved: &[SavedPeer], now_ms: u64, limit: usize) -> usize {
        let mut taken = 0;
        for s in saved.iter().take(limit) {
            let fresh = now_ms.saturating_sub(s.seen_ms) <= SAVED_TTL_MS;
            let Some(addr) = s.record.verify(self.chain_id).filter(|_| fresh) else {
                continue;
            };
            if self.insert(s.record.id, &s.record, addr, &[]) {
                if let Some(entry) = self.entries.get_mut(&s.record.id) {
                    entry.seen_ms = s.seen_ms;
                }
                taken += 1;
            }
        }
        taken
    }

    /// A dial of `id`'s address completed a handshake naming `hello`.
    /// Returns whether that was the id expected; another id is penalized and
    /// its connection closes.
    pub fn handshake(&mut self, id: &[u8; 32], hello: &[u8; 32], now_ms: u64) -> bool {
        let matched = id == hello;
        if let Some(entry) = self.entries.get_mut(id) {
            if matched {
                entry.verified = true;
                entry.failures = 0;
                entry.seen_ms = now_ms.max(1);
                entry.score = (entry.score + HANDSHAKE_REWARD).min(MAX_SCORE);
            } else {
                entry.score = (entry.score - MISMATCH_PENALTY).max(MIN_SCORE);
                self.failed(id, now_ms);
            }
        }
        matched
    }

    /// A dial of `id` failed: it waits longer for the next, scores lower,
    /// and is forgotten after [`MAX_FAILURES`] running unless it validates.
    pub fn dial_failed(&mut self, id: &[u8; 32], now_ms: u64) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.score = (entry.score - DIAL_PENALTY).max(MIN_SCORE);
        }
        self.failed(id, now_ms);
    }

    fn failed(&mut self, id: &[u8; 32], now_ms: u64) {
        let validator = self.is_validator(id);
        let Some(entry) = self.entries.get_mut(id) else {
            return;
        };
        entry.failures += 1;
        entry.next_dial_ms = now_ms + backoff_ms(entry.failures);
        if entry.failures >= MAX_FAILURES && !validator {
            self.entries.remove(id);
        }
    }

    /// The connection to `id` that this node dialled was lost: the next dial
    /// waits [`BACKOFF_MS`].
    pub fn lost(&mut self, id: &[u8; 32], now_ms: u64) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.next_dial_ms = now_ms + backoff_ms(1);
        }
    }

    /// Up to `n` entries to dial now: not connected, not being dialled, due;
    /// current validators first, then by score, fewest failures and id.
    #[must_use]
    pub fn candidates(
        &self,
        now_ms: u64,
        busy: &[[u8; 32]],
        n: usize,
    ) -> Vec<([u8; 32], SocketAddr)> {
        let mut due: Vec<(&[u8; 32], &Entry)> = self
            .entries
            .iter()
            .filter(|(id, e)| e.next_dial_ms <= now_ms && !busy.contains(id))
            .collect();
        due.sort_by_key(|(id, e)| (!self.is_validator(id), -e.score, e.failures, **id));
        due.into_iter()
            .take(n)
            .map(|(id, e)| (*id, e.addr))
            .collect()
    }

    /// The records to answer `asker`'s `GetPeers` with: `own` first, then
    /// the validators', then by score, never the asker's own or one with a
    /// negative score; at most [`MAX_RECORDS`].
    #[must_use]
    pub fn answer(&self, asker: &[u8; 32], own: Option<&PeerRecord>) -> Vec<PeerRecord> {
        let mut known: Vec<(&[u8; 32], &Entry)> = self
            .entries
            .iter()
            .filter(|(id, e)| *id != asker && e.score >= 0)
            .collect();
        known.sort_by_key(|(id, e)| (!self.is_validator(id), -e.score, **id));
        own.into_iter()
            .chain(known.into_iter().map(|(_, e)| &e.record))
            .take(MAX_RECORDS)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    const CHAIN: u64 = 7;

    fn key(i: u32) -> SigningKey {
        let mut bytes = [0x11; 32];
        bytes[28..].copy_from_slice(&i.to_be_bytes());
        SigningKey::from_slice(&bytes).unwrap()
    }

    fn record(i: u32, addr: &str, seq: u64) -> PeerRecord {
        PeerRecord::sign(&key(i), CHAIN, addr.parse().unwrap(), seq).unwrap()
    }

    fn id(i: u32) -> [u8; 32] {
        crate::validator_id(&key(i))
    }

    #[test]
    fn records_verify_only_as_signed() {
        let r = record(1, "10.0.0.1:30333", 5);
        assert_eq!(r.verify(CHAIN), Some("10.0.0.1:30333".parse().unwrap()));
        assert_eq!(PeerRecord::from_bytes(&r.to_bytes()).unwrap(), r);
        // Another chain, another id, a moved address, a replayed sequence: none verifies.
        assert_eq!(r.verify(CHAIN + 1), None);
        let mut forged = r.clone();
        forged.id = id(2);
        assert_eq!(forged.verify(CHAIN), None);
        let mut moved = r.clone();
        moved.addr = b"10.6.6.6:30333".to_vec();
        assert_eq!(moved.verify(CHAIN), None);
        let mut replayed = r.clone();
        replayed.seq = 6;
        assert_eq!(replayed.verify(CHAIN), None);
        // Garbage in the signature, the address or its length.
        let mut bad = r.clone();
        bad.signature[64] = 9;
        assert_eq!(bad.verify(CHAIN), None);
        let mut bad = r.clone();
        bad.signature[..64].fill(0);
        assert_eq!(bad.verify(CHAIN), None);
        let mut bad = r.clone();
        bad.signature[..32].fill(0xFF);
        assert_eq!(bad.verify(CHAIN), None);
        let mut bad = r.clone();
        bad.addr = vec![0xFF];
        assert_eq!(bad.verify(CHAIN), None);
        let mut bad = r;
        bad.addr = vec![b'1'; MAX_ADDR + 1];
        assert_eq!(bad.verify(CHAIN), None);
        // A key's record for an address nobody can dial does not verify either.
        for addr in ["0.0.0.0:1", "10.0.0.1:0", "224.0.0.1:5", "[::]:5"] {
            assert_eq!(record(1, addr, 1).verify(CHAIN), None, "{addr}");
        }
    }

    #[test]
    fn prefixes_and_backoff() {
        let p = |s: &str| prefix(&s.parse().unwrap());
        assert_eq!(p("10.1.2.3:1"), Some(vec![10, 1, 2]));
        assert_eq!(p("127.0.0.1:1"), None);
        assert_eq!(p("[::1]:1"), None);
        assert_eq!(
            p("[2001:db8:1:2::5]:1"),
            Some(vec![0x20, 0x01, 0x0d, 0xb8, 0, 1])
        );
        assert_eq!(backoff_ms(0), 500);
        assert_eq!(backoff_ms(1), 500);
        assert_eq!(backoff_ms(2), 1_000);
        assert_eq!(backoff_ms(8), 60_000);
        assert_eq!(backoff_ms(u32::MAX), 60_000);
    }

    #[test]
    fn learning_replaces_only_newer_records_and_never_itself() {
        let mut t = PeerTable::new(CHAIN, id(0));
        let src = id(9);
        let own = record(0, "10.0.0.9:1", 1);
        let r1 = record(1, "10.0.0.1:1", 1);
        assert_eq!(t.learn(src, &[own, r1.clone()], &[]), Ok(1));
        assert_eq!(t.entries().len(), 1);
        assert_eq!(t.entries()[&id(1)].source, Some(src));
        // The same record again, or an older one, changes nothing.
        assert_eq!(t.learn(src, &[r1], &[]), Ok(0));
        assert_eq!(t.learn(src, &[record(1, "10.0.0.2:1", 0)], &[]), Ok(0));
        // A verified entry that moves must be verified again, and is dialled at once.
        assert!(t.handshake(&id(1), &id(1), 0));
        t.dial_failed(&id(1), 100);
        assert!(t.entries()[&id(1)].next_dial_ms > 100);
        assert_eq!(t.learn(src, &[record(1, "10.0.0.2:1", 2)], &[]), Ok(1));
        let e = &t.entries()[&id(1)];
        assert_eq!((e.verified, e.failures, e.next_dial_ms), (false, 0, 0));
        // A newer record at the same address keeps what the entry earned.
        assert!(t.handshake(&id(1), &id(1), 0));
        assert_eq!(t.learn(src, &[record(1, "10.0.0.2:1", 3)], &[]), Ok(1));
        assert!(t.entries()[&id(1)].verified);
        // A node's own record, from itself, has no source.
        assert_eq!(t.learn(id(2), &[record(2, "10.0.1.2:1", 1)], &[]), Ok(1));
        assert_eq!(t.entries()[&id(2)].source, None);
    }

    #[test]
    fn frames_that_break_the_rules_are_refused_whole() {
        let mut t = PeerTable::new(CHAIN, id(0));
        let many: Vec<PeerRecord> = (1..=33).map(|i| record(i, "127.0.0.1:1", 1)).collect();
        assert_eq!(t.learn(id(9), &many, &[]), Err(Refused::TooMany));
        let mut forged = record(2, "127.0.0.1:2", 1);
        forged.id = id(3);
        assert_eq!(
            t.learn(id(9), &[record(1, "127.0.0.1:1", 1), forged], &[]),
            Err(Refused::Unverified)
        );
        assert!(t.entries().is_empty());
    }

    #[test]
    fn sources_and_prefixes_are_limited_until_entries_answer() {
        let mut t = PeerTable::new(CHAIN, id(0));
        let src = id(1000);
        // One source puts at most PER_SOURCE unverified entries in, across prefixes.
        for i in 0..20u32 {
            let addr = format!("10.{i}.0.1:1");
            t.learn(src, &[record(i + 1, &addr, 1)], &[]).unwrap();
        }
        assert_eq!(t.entries().len(), PER_SOURCE);
        // Once some answer, the source may name more.
        for i in 1..=4 {
            assert!(t.handshake(&id(i), &id(i), 0));
        }
        t.learn(src, &[record(50, "10.50.0.1:1", 1)], &[]).unwrap();
        assert!(t.entries().contains_key(&id(50)));
        // One prefix holds at most PER_PREFIX unverified entries, whatever the source.
        let mut t = PeerTable::new(CHAIN, id(0));
        for i in 0..12u32 {
            t.learn(
                id(2000 + i),
                &[record(i + 1, &format!("10.9.9.{i}:1"), 1)],
                &[],
            )
            .unwrap();
        }
        assert_eq!(t.entries().len(), PER_PREFIX);
        // Loopback addresses have no prefix limit.
        for i in 0..12u32 {
            t.learn(
                id(3000 + i),
                &[record(100 + i, &format!("127.0.0.1:{}", i + 1), 1)],
                &[],
            )
            .unwrap();
        }
        assert_eq!(t.entries().len(), PER_PREFIX + 12);
    }

    #[test]
    fn a_full_table_gives_way_only_to_failed_entries() {
        let mut t = PeerTable::new(CHAIN, id(0));
        // Fill the table from many sources over loopback.
        for i in 0..u32::try_from(TABLE_CAP).unwrap() {
            let r = record(i + 1, &format!("127.0.0.1:{}", i + 1), 1);
            t.learn(id(10_000 + i), &[r], &[]).unwrap();
        }
        assert_eq!(t.entries().len(), TABLE_CAP);
        let junk = record(5_000, "127.0.0.2:9", 1);
        // Nothing has failed: junk is refused.
        assert_eq!(t.learn(id(20_000), std::slice::from_ref(&junk), &[]), Ok(0));
        // Entry 1 fails twice, entry 2 once; a validator and a connected peer fail too,
        // but are protected.
        t.dial_failed(&id(1), 0);
        t.dial_failed(&id(1), 0);
        t.dial_failed(&id(2), 0);
        t.set_validators(vec![id(3)]);
        t.dial_failed(&id(3), 0);
        t.dial_failed(&id(3), 0);
        t.dial_failed(&id(3), 0);
        t.dial_failed(&id(4), 0);
        t.dial_failed(&id(4), 0);
        t.dial_failed(&id(4), 0);
        assert_eq!(t.learn(id(20_000), &[junk], &[id(4)]), Ok(1));
        assert!(t.entries().contains_key(&id(3)));
        assert!(t.entries().contains_key(&id(4)));
        assert!(
            !t.entries().contains_key(&id(1)),
            "the lowest score goes first"
        );
        assert!(t.entries().contains_key(&id(2)));
        assert_eq!(t.entries().len(), TABLE_CAP);
    }

    #[test]
    fn scores_backoff_and_forgetting() {
        let mut t = PeerTable::new(CHAIN, id(0));
        t.learn(
            id(9),
            &[record(1, "127.0.0.1:1", 1), record(2, "127.0.0.1:2", 1)],
            &[],
        )
        .unwrap();
        t.set_validators(vec![id(2)]);
        // A handshake naming another id is penalized and counts as a failure.
        assert!(!t.handshake(&id(1), &id(7), 10));
        let e = &t.entries()[&id(1)];
        assert_eq!((e.score, e.failures, e.next_dial_ms), (-50, 1, 510));
        // Unknown ids are ignored.
        assert!(t.handshake(&id(8), &id(8), 0));
        t.dial_failed(&id(8), 0);
        t.lost(&id(8), 0);
        // A lost connection waits one backoff.
        t.lost(&id(2), 1_000);
        assert_eq!(t.entries()[&id(2)].next_dial_ms, 1_500);
        // Failures running forget an entry, unless it validates.
        for _ in 0..MAX_FAILURES {
            t.dial_failed(&id(1), 0);
            t.dial_failed(&id(2), 0);
        }
        assert!(!t.entries().contains_key(&id(1)));
        assert_eq!(t.entries()[&id(2)].score, -40);
        // Scores stay within their bounds.
        for _ in 0..30 {
            t.dial_failed(&id(2), 0);
        }
        assert_eq!(t.entries()[&id(2)].score, MIN_SCORE);
        for _ in 0..30 {
            t.handshake(&id(2), &id(2), 0);
        }
        assert_eq!(t.entries()[&id(2)].score, MAX_SCORE);
        assert_eq!(t.entries()[&id(2)].failures, 0);
    }

    #[test]
    fn candidates_and_answers_are_ordered() {
        let mut t = PeerTable::new(CHAIN, id(0));
        let records: Vec<PeerRecord> = (1..=5)
            .map(|i| record(i, &format!("127.0.0.1:{i}"), 1))
            .collect();
        t.learn(id(9), &records, &[]).unwrap();
        t.set_validators(vec![id(5)]);
        assert!(t.handshake(&id(3), &id(3), 0));
        t.dial_failed(&id(4), 1_000);
        // Validators first, then score, then failures, then id; busy and waiting ones not.
        let ids = |v: Vec<([u8; 32], SocketAddr)>| v.into_iter().map(|c| c.0).collect::<Vec<_>>();
        assert_eq!(
            ids(t.candidates(1_000, &[id(2)], 10)),
            vec![id(5), id(3), id(1)]
        );
        assert_eq!(ids(t.candidates(2_000, &[], 2)), vec![id(5), id(3)]);
        assert_eq!(t.candidates(2_000, &[], 10).len(), 5);
        // Answers: our own record first, never the asker's or a failed one.
        let own = record(0, "127.0.0.1:9", 1);
        let answer = t.answer(&id(1), Some(&own));
        let got: Vec<[u8; 32]> = answer.iter().map(|r| r.id).collect();
        assert_eq!(got, vec![id(0), id(5), id(3), id(2)]);
        assert_eq!(t.answer(&id(1), None).len(), 3);
        // At most MAX_RECORDS.
        let mut big = PeerTable::new(CHAIN, id(0));
        for i in 1..=40u32 {
            big.learn(id(100 + i), &[record(i, &format!("127.0.0.1:{i}"), 1)], &[])
                .unwrap();
        }
        assert_eq!(big.answer(&id(0), Some(&own)).len(), MAX_RECORDS);
        assert!(format!("{big:?}").contains("PeerTable"));
        assert_eq!(format!("{:?}", Refused::TooMany), "TooMany");
    }

    #[test]
    fn only_seen_entries_are_saved_best_first() {
        let mut t = PeerTable::new(CHAIN, id(0));
        let records: Vec<PeerRecord> = (1..=4)
            .map(|i| record(i, &format!("127.0.0.1:{i}"), 1))
            .collect();
        t.learn(id(9), &records, &[]).unwrap();
        assert!(t.saved(10).is_empty(), "nothing has answered");
        // Entries 1, 2 and 3 answer; 3 twice, and 1 is a validator. A handshake at time
        // 0 still counts as seen.
        assert!(t.handshake(&id(1), &id(1), 0));
        assert!(t.handshake(&id(2), &id(2), 500));
        assert!(t.handshake(&id(3), &id(3), 600));
        assert!(t.handshake(&id(3), &id(3), 700));
        t.set_validators(vec![id(1)]);
        let saved = t.saved(10);
        let ids: Vec<[u8; 32]> = saved.iter().map(|s| s.record.id).collect();
        assert_eq!(ids, vec![id(1), id(3), id(2)]);
        assert_eq!(
            saved.iter().map(|s| s.seen_ms).collect::<Vec<_>>(),
            vec![1, 700, 500]
        );
        assert_eq!(t.saved(2).len(), 2);
        assert_eq!(
            SavedPeer::from_bytes(&saved[1].to_bytes()).unwrap(),
            saved[1]
        );
    }

    #[test]
    fn restored_entries_are_checked_again() {
        let now = SAVED_TTL_MS + 10_000;
        let saved = |i: u32, seen_ms: u64| SavedPeer {
            record: record(i, &format!("127.0.0.1:{i}"), 1),
            seen_ms,
        };
        let mut forged = saved(2, now);
        forged.record.id = id(3);
        let file = vec![
            saved(1, now - 5),
            forged,
            // Last seen just inside, and just outside, the time a saved entry is kept.
            saved(4, now - SAVED_TTL_MS),
            saved(5, now - SAVED_TTL_MS - 1),
            // This node's own record.
            saved(0, now),
            saved(6, now),
            saved(7, now),
        ];
        let mut t = PeerTable::new(CHAIN, id(0));
        assert_eq!(t.restore(&file, now, 6), 3);
        let ids: Vec<[u8; 32]> = t.entries().keys().copied().collect();
        let mut want = vec![id(1), id(4), id(6)];
        want.sort_unstable();
        assert_eq!(ids, want, "entry 7 is past the limit");
        let e = &t.entries()[&id(1)];
        assert_eq!(
            (e.source, e.verified, e.score, e.failures, e.seen_ms),
            (None, false, 0, 0, now - 5)
        );
        // Taken up again, nothing changes: the records are no newer.
        assert_eq!(t.restore(&file, now, 6), 0);
        // A record from another chain does not verify.
        let mut other = PeerTable::new(CHAIN + 1, id(0));
        assert_eq!(other.restore(&file, now, 10), 0);
    }

    #[test]
    fn the_peer_file_survives_only_whole() {
        let dir = solo_scratch::Scratch::dir("peers", "file");
        let path = dir.join(PEER_FILE);
        // Missing, then written and read back.
        assert!(load_saved(&path).is_empty());
        let saved = vec![SavedPeer {
            record: record(1, "127.0.0.1:1", 1),
            seen_ms: 9,
        }];
        write_saved(&path, &Seq(saved.clone()).to_bytes()).unwrap();
        assert_eq!(load_saved(&path), saved);
        assert!(!path.with_extension("tmp").exists());
        // Cut short, or with bytes after it, it reads as empty.
        let bytes = Seq(saved).to_bytes();
        std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
        assert!(load_saved(&path).is_empty());
        std::fs::write(&path, [bytes.as_slice(), &[0]].concat()).unwrap();
        assert!(load_saved(&path).is_empty());
        // A directory that is not there cannot be written to.
        assert!(write_saved(&dir.join("gone").join(PEER_FILE), &bytes).is_err());
    }
}
