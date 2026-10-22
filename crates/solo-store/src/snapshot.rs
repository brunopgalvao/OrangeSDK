//! Committee-signed state snapshots (spec 22 §6–§7).
//!
//! A snapshot is the whole committed state as it was after the last block
//! of an epoch, identified by the record the kernel wrote for that epoch
//! (`snap/` + epoch: the height and the state commitment), and vouched for
//! by a finality certificate: a certificate for a later proposal whose
//! anchor root (spec 17 §4) a spec 10 proof of the record verifies against.
//! A new node verifies the certificate under a key it trusts, the proof
//! against the anchor, and the entries against the record's root, before
//! it loads the state and syncs forward from there.
//!
//! The file is `SOLOSNAP`, the format, the header's length and the encoded
//! [`SnapshotHeader`], then the entries, each as `key length ‖ key ‖ value
//! length ‖ value` with `u32` little-endian lengths, in key order.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use solo_abi::chain::consensus::{KIND_FINALIZE, signing_preimage};
use solo_abi::chain::{Certificate, Proposal, SnapshotRecord, ValidatorSet, keys};
use solo_abi::codec::{Decoder, Encoder};
use solo_abi::rotation::threshold_certificate;
use solo_abi::{Decode, DecodeError, Encode};
use solo_bls::PublicKey;
use solo_bls::certificate::CertificateV2;
use solo_host::Storage;
use solo_trie::{Proof, Trie, keccak256};

use crate::disk::{DiskStore, Entries, StoreError};

/// The first eight bytes of a snapshot file.
pub const MAGIC: &[u8; 8] = b"SOLOSNAP";

/// The file format this release writes and reads.
pub const FORMAT: u32 = 1;

/// Node-local keys the kernel's block log uses (spec 22 §5), which an
/// imported snapshot sets for the height it loads so that the driver finds
/// its finalized head.
pub const LOG_PROPOSAL: &[u8] = b"local/log/prop/";
/// The finalize certificate of a logged height.
pub const LOG_CERTIFICATE: &[u8] = b"local/log/cert/";
/// The threshold certificate of a logged height.
pub const LOG_THRESHOLD: &[u8] = b"local/log/bcert/";

/// Everything in a snapshot but the entries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SnapshotHeader {
    /// The chain.
    pub chain_id: u64,
    /// The epoch whose end the snapshot is.
    pub epoch: u64,
    /// The epoch's last block, whose state the entries are.
    pub height: u64,
    /// The state commitment of the entries: the record's root.
    pub state_root: [u8; 32],
    /// How many entries follow the header.
    pub entries: u64,
    /// The encoded proposal whose anchor covers the record.
    pub anchor_proposal: Vec<u8>,
    /// The certificate for that proposal: a version-2 threshold certificate
    /// (spec 12 §7) or an encoded finalize vote certificate (spec 08 §6).
    pub certificate: Vec<u8>,
    /// The spec 10 proof of the record's key against the anchor root.
    pub record_proof: Vec<u8>,
    /// The encoded proposal of block `height`, for the driver's tables.
    pub head_proposal: Vec<u8>,
    /// The encoded finalize vote certificate of block `height`.
    pub head_certificate: Vec<u8>,
    /// The threshold certificate of block `height`, or empty.
    pub head_threshold: Vec<u8>,
}

impl Encode for SnapshotHeader {
    fn encode(&self, e: &mut Encoder) {
        self.chain_id.encode(e);
        self.epoch.encode(e);
        self.height.encode(e);
        self.state_root.encode(e);
        self.entries.encode(e);
        self.anchor_proposal.encode(e);
        self.certificate.encode(e);
        self.record_proof.encode(e);
        self.head_proposal.encode(e);
        self.head_certificate.encode(e);
        self.head_threshold.encode(e);
    }
}

impl Decode for SnapshotHeader {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(SnapshotHeader {
            chain_id: d.get()?,
            epoch: d.get()?,
            height: d.get()?,
            state_root: d.get()?,
            entries: d.get()?,
            anchor_proposal: d.get()?,
            certificate: d.get()?,
            record_proof: d.get()?,
            head_proposal: d.get()?,
            head_certificate: d.get()?,
            head_threshold: d.get()?,
        })
    }
}

/// What a verifier trusts (spec 22 §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// A group key of the chain's threshold key (spec 15 §6): the snapshot's
    /// certificate must be a threshold certificate that verifies under it.
    Key([u8; 96]),
    /// The genesis validator set, for a chain without staking, whose set
    /// never changes: the certificate must be a finalize vote certificate
    /// of that set.
    Genesis(ValidatorSet),
}

/// Why a snapshot was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// The file could not be read or written.
    Io(String),
    /// The file is not a snapshot of this format.
    Format(&'static str),
    /// The snapshot does not verify.
    Verify(&'static str),
    /// The store could not export or load it.
    Store(String),
    /// The node's store or tables lack what an export needs.
    Export(String),
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::Io(why) => write!(f, "snapshot file: {why}"),
            SnapshotError::Format(what) => write!(f, "snapshot: not a snapshot file: {what}"),
            SnapshotError::Verify(why) => write!(f, "snapshot does not verify: {why}"),
            SnapshotError::Store(why) => write!(f, "snapshot: {why}"),
            SnapshotError::Export(why) => write!(f, "snapshot: cannot export: {why}"),
        }
    }
}

impl std::error::Error for SnapshotError {}

#[allow(clippy::needless_pass_by_value)]
fn io_error(e: io::Error) -> SnapshotError {
    SnapshotError::Io(e.to_string())
}

#[allow(clippy::needless_pass_by_value)]
fn store_error(e: StoreError) -> SnapshotError {
    SnapshotError::Store(e.to_string())
}

/// The driver's node-local tables, as [`crate::disk::DiskStore`]'s
/// neighbour on disk holds them: `prop/`, `final/`, `cert/`, `bcert/`.
pub type Tables = BTreeMap<Vec<u8>, Vec<u8>>;

/// What vouches for a record: the anchoring proposal, its certificate and
/// the proof of the record against the anchor root, all encoded.
type Finality = (Vec<u8>, Vec<u8>, Vec<u8>);

/// A snapshot: its header and the entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Everything but the entries.
    pub header: SnapshotHeader,
    /// The committed state at `header.height`, in key order.
    pub entries: Entries,
}

/// One length-prefixed part of an entry.
fn read_part(file: &mut BufReader<File>, word: &mut [u8; 4]) -> Result<Vec<u8>, SnapshotError> {
    file.read_exact(word).map_err(io_error)?;
    let mut part = vec![0u8; u32::from_le_bytes(*word) as usize];
    file.read_exact(&mut part).map_err(io_error)?;
    Ok(part)
}

/// The key of the snapshot record of `epoch`.
#[must_use]
pub fn record_key(epoch: u64) -> Vec<u8> {
    [keys::SNAPSHOT, &epoch.to_be_bytes()[..]].concat()
}

fn height_key(prefix: &[u8], height: u64) -> Vec<u8> {
    [prefix, &height.to_le_bytes()[..]].concat()
}

/// Recovers the validator id (spec 08 §2) that signed `digest` with a
/// recoverable signature.
fn signer(digest: &[u8; 32], signature: &[u8; 65]) -> Option<[u8; 32]> {
    let sig = Signature::from_slice(&signature[..64]).ok()?;
    let id = RecoveryId::from_byte(signature[64])?;
    let key = VerifyingKey::recover_from_prehash(digest, &sig, id).ok()?;
    Some(keccak256(&key.to_encoded_point(false).as_bytes()[1..]))
}

/// Whether `certificate` is a finalize vote certificate for `hash` by a
/// quorum of `set` (spec 08 §6).
fn votes_certify(
    certificate: &Certificate,
    hash: &[u8; 32],
    chain_id: u64,
    set: &ValidatorSet,
) -> bool {
    let validators = &set.validators.0;
    if certificate.kind != KIND_FINALIZE || certificate.hash != *hash {
        return false;
    }
    let mut named = vec![false; validators.len()];
    let mut weight = 0u128;
    let total: u128 = validators.iter().map(|v| u128::from(v.weight)).sum();
    let digest = keccak256(&signing_preimage(
        KIND_FINALIZE,
        chain_id,
        certificate.view,
        hash,
    ));
    for vote in &certificate.votes.0 {
        let Some(validator) = validators.get(vote.validator as usize) else {
            return false;
        };
        if std::mem::replace(&mut named[vote.validator as usize], true) {
            return false;
        }
        if signer(&digest, &vote.signature.0) != Some(validator.id) {
            return false;
        }
        weight += u128::from(validator.weight);
    }
    weight * 3 > total * 2
}

impl Snapshot {
    /// Exports the snapshot of `epoch` (the latest recorded, for `None`)
    /// from a node's store and driver tables: the state at the record's
    /// height, a certificate whose proposal anchors a later height the store
    /// still keeps the trie of, with the proof of the record against it,
    /// and the head block's proposal and certificates.
    ///
    /// # Errors
    /// [`SnapshotError::Export`] when the chain has no such record, the
    /// store no longer keeps the height, or no certified proposal anchors a
    /// kept height above it.
    pub fn export(
        store: &DiskStore,
        tables: &Tables,
        epoch: Option<u64>,
    ) -> Result<Snapshot, SnapshotError> {
        let chain_id = store
            .get(keys::CHAIN_ID)
            .and_then(|b| u64::from_bytes(&b).ok())
            .ok_or_else(|| SnapshotError::Export("the store holds no chain".to_owned()))?;
        let epoch = match epoch {
            Some(epoch) => epoch,
            None => store
                .get(keys::SNAPSHOT_LATEST)
                .and_then(|b| u64::from_bytes(&b).ok())
                .ok_or_else(|| {
                    SnapshotError::Export("the chain has recorded no snapshot yet".to_owned())
                })?,
        };
        let record = store
            .get(&record_key(epoch))
            .and_then(|b| SnapshotRecord::from_bytes(&b).ok())
            .ok_or_else(|| {
                SnapshotError::Export(format!(
                    "the chain has no snapshot record for epoch {epoch}"
                ))
            })?;
        let entries = store.entries_at(record.height).map_err(|kept| {
            SnapshotError::Export(format!(
                "the store no longer keeps the state of block {} (it keeps {:?})",
                record.height, kept
            ))
        })?;
        let (anchor_proposal, certificate, record_proof) =
            Self::finality(store, tables, &record, epoch)?;
        let head = |prefix: &[u8]| tables.get(&height_key(prefix, record.height)).cloned();
        let head_hash = head(b"final/").ok_or_else(|| {
            SnapshotError::Export(format!(
                "the driver tables do not hold block {}",
                record.height
            ))
        })?;
        let head_proposal = tables
            .get(&[b"prop/".as_slice(), &head_hash].concat())
            .cloned()
            .ok_or_else(|| {
                SnapshotError::Export(format!(
                    "the driver tables do not hold the proposal of block {}",
                    record.height
                ))
            })?;
        let head_certificate = head(b"cert/").ok_or_else(|| {
            SnapshotError::Export(format!(
                "the driver tables do not hold the certificate of block {}",
                record.height
            ))
        })?;
        Ok(Snapshot {
            header: SnapshotHeader {
                chain_id,
                epoch,
                height: record.height,
                state_root: record.state_root,
                entries: entries.len() as u64,
                anchor_proposal,
                certificate,
                record_proof,
                head_proposal,
                head_certificate,
                head_threshold: head(b"bcert/").unwrap_or_default(),
            },
            entries,
        })
    }

    /// The latest certified proposal whose anchor names a height above the
    /// record's that the store keeps the trie of, its certificate (the
    /// threshold certificate when the tables hold one, else the votes) and
    /// the proof of the record against the anchor root.
    fn finality(
        store: &DiskStore,
        tables: &Tables,
        record: &SnapshotRecord,
        epoch: u64,
    ) -> Result<Finality, SnapshotError> {
        let key = record_key(epoch);
        let finalized = tables
            .range(b"final/".to_vec()..b"final0".to_vec())
            .filter_map(|(k, hash)| {
                let height = u64::from_le_bytes(k.get(6..14)?.try_into().ok()?);
                Some((height, hash.clone()))
            });
        for (height, hash) in finalized.rev() {
            if height <= record.height {
                break;
            }
            let Some(bytes) = tables.get(&[b"prop/".as_slice(), &hash].concat()) else {
                continue;
            };
            let Ok(proposal) = Proposal::from_bytes(bytes) else {
                continue;
            };
            if proposal.anchor_height <= record.height {
                continue;
            }
            let Some(trie) = store.trie_at(proposal.anchor_height) else {
                continue;
            };
            if trie.root() != proposal.anchor_root {
                continue;
            }
            let certificate = tables
                .get(&height_key(b"bcert/", height))
                .or_else(|| tables.get(&height_key(b"cert/", height)));
            let Some(certificate) = certificate else {
                continue;
            };
            return Ok((
                bytes.clone(),
                certificate.clone(),
                trie.prove(&key).encode(),
            ));
        }
        Err(SnapshotError::Export(format!(
            "no certified proposal anchors a kept height above block {}",
            record.height
        )))
    }

    /// Writes the snapshot to `path`.
    ///
    /// # Errors
    /// What the file system reports.
    pub fn write(&self, path: &Path) -> Result<(), SnapshotError> {
        let mut out = BufWriter::new(File::create(path).map_err(io_error)?);
        let header = self.header.to_bytes();
        out.write_all(MAGIC).map_err(io_error)?;
        out.write_all(&FORMAT.to_le_bytes()).map_err(io_error)?;
        let len = u32::try_from(header.len())
            .map_err(|_| SnapshotError::Io("the header does not fit the format".to_owned()))?;
        out.write_all(&len.to_le_bytes()).map_err(io_error)?;
        out.write_all(&header).map_err(io_error)?;
        for (key, value) in &self.entries {
            for part in [key, value] {
                let len = u32::try_from(part.len()).map_err(|_| {
                    SnapshotError::Io("an entry does not fit the format".to_owned())
                })?;
                out.write_all(&len.to_le_bytes()).map_err(io_error)?;
                out.write_all(part).map_err(io_error)?;
            }
        }
        out.flush().map_err(io_error)
    }

    /// Reads a snapshot from `path`.
    ///
    /// # Errors
    /// [`SnapshotError::Io`] when the file cannot be read,
    /// [`SnapshotError::Format`] when it is not a snapshot file.
    pub fn read(path: &Path) -> Result<Snapshot, SnapshotError> {
        let mut file = BufReader::new(File::open(path).map_err(io_error)?);
        let mut magic = [0u8; 8];
        let mut word = [0u8; 4];
        file.read_exact(&mut magic).map_err(io_error)?;
        if magic != *MAGIC {
            return Err(SnapshotError::Format("wrong magic"));
        }
        file.read_exact(&mut word).map_err(io_error)?;
        if u32::from_le_bytes(word) != FORMAT {
            return Err(SnapshotError::Format("another format"));
        }
        file.read_exact(&mut word).map_err(io_error)?;
        let mut header = vec![0u8; u32::from_le_bytes(word) as usize];
        file.read_exact(&mut header).map_err(io_error)?;
        let header = SnapshotHeader::from_bytes(&header)
            .ok()
            .ok_or(SnapshotError::Format("the header does not decode"))?;
        let count = usize::try_from(header.entries)
            .ok()
            .ok_or(SnapshotError::Format("too many entries"))?;
        let mut entries = Vec::with_capacity(count.min(1 << 20));
        for _ in 0..count {
            let key = read_part(&mut file, &mut word)?;
            let value = read_part(&mut file, &mut word)?;
            entries.push((key, value));
        }
        let mut rest = [0u8; 1];
        if file.read(&mut rest).map_err(io_error)? != 0 {
            return Err(SnapshotError::Format("bytes after the entries"));
        }
        Ok(Snapshot { header, entries })
    }

    /// Verifies the snapshot for `chain_id` under `trust` (spec 22 §7): the
    /// certificate for the anchoring proposal, the proof of the record
    /// against its anchor root, and the entries against the record's root.
    ///
    /// # Errors
    /// [`SnapshotError::Verify`] naming the first check that fails.
    pub fn verify(&self, chain_id: u64, trust: &Trust) -> Result<(), SnapshotError> {
        let h = &self.header;
        if h.chain_id != chain_id {
            return Err(SnapshotError::Verify("another chain"));
        }
        let proposal =
            Proposal::from_bytes(&h.anchor_proposal)
                .ok()
                .ok_or(SnapshotError::Verify(
                    "the anchoring proposal does not decode",
                ))?;
        if proposal.anchor_height <= h.height {
            return Err(SnapshotError::Verify(
                "the anchoring proposal anchors no height above the snapshot",
            ));
        }
        let hash = keccak256(&h.anchor_proposal);
        self.verify_certificate(&proposal, &hash, chain_id, trust)?;
        let record = SnapshotRecord {
            height: h.height,
            state_root: h.state_root,
        };
        let proof = Proof::decode(&h.record_proof)
            .ok()
            .ok_or(SnapshotError::Verify("the record's proof does not decode"))?;
        let proven = proof.verify(keccak256, &proposal.anchor_root, &record_key(h.epoch));
        if proven != Ok(Some(keccak256(&record.to_bytes()))) {
            return Err(SnapshotError::Verify(
                "the record's proof does not verify against the anchor root",
            ));
        }
        if self.entries.len() as u64 != h.entries {
            return Err(SnapshotError::Verify("the entry count is wrong"));
        }
        let mut trie = Trie::new();
        for (i, (key, value)) in self.entries.iter().enumerate() {
            if !solo_host::storage::committed(key) {
                return Err(SnapshotError::Verify("an entry is node-local"));
            }
            if i > 0 && self.entries[i - 1].0 >= *key {
                return Err(SnapshotError::Verify("the entries are not in key order"));
            }
            trie.insert(key, value);
        }
        if trie.root() != h.state_root {
            return Err(SnapshotError::Verify(
                "the entries do not hash to the record's root",
            ));
        }
        let head = Proposal::from_bytes(&h.head_proposal)
            .ok()
            .filter(|p| p.height == h.height)
            .ok_or(SnapshotError::Verify("the head proposal is not block's"))?;
        let head_hash = keccak256(&h.head_proposal);
        let head_certificate = Certificate::from_bytes(&h.head_certificate)
            .ok()
            .filter(|c| c.kind == KIND_FINALIZE && c.hash == head_hash)
            .ok_or(SnapshotError::Verify(
                "the head certificate is not the head proposal's",
            ))?;
        drop((head, head_certificate));
        Ok(())
    }

    /// Checks the anchoring proposal's certificate under `trust`.
    fn verify_certificate(
        &self,
        proposal: &Proposal,
        hash: &[u8; 32],
        chain_id: u64,
        trust: &Trust,
    ) -> Result<(), SnapshotError> {
        let bytes = &self.header.certificate;
        if let Some(threshold) = threshold_certificate(bytes) {
            if threshold.height != proposal.height || threshold.block_hash != *hash {
                return Err(SnapshotError::Verify(
                    "the threshold certificate is not the anchoring proposal's",
                ));
            }
            let Trust::Key(key) = trust else {
                return Err(SnapshotError::Verify(
                    "a threshold certificate needs a trusted group key",
                ));
            };
            let group_key = PublicKey::from_bytes(key)
                .ok()
                .ok_or(SnapshotError::Verify("the trusted key is not a group key"))?;
            let certificate =
                CertificateV2::from_bytes(bytes)
                    .ok()
                    .ok_or(SnapshotError::Verify(
                        "the threshold certificate does not decode",
                    ))?;
            if !certificate.verify(chain_id, &group_key) {
                return Err(SnapshotError::Verify(
                    "the threshold certificate does not verify under the trusted key",
                ));
            }
            return Ok(());
        }
        let Trust::Genesis(set) = trust else {
            return Err(SnapshotError::Verify(
                "a vote certificate needs the genesis validator set, and only a chain without staking keeps it",
            ));
        };
        let certificate = Certificate::from_bytes(bytes)
            .ok()
            .ok_or(SnapshotError::Verify("the certificate does not decode"))?;
        if !votes_certify(&certificate, hash, chain_id, set) {
            return Err(SnapshotError::Verify(
                "the vote certificate is not a quorum of the genesis set for the anchoring proposal",
            ));
        }
        Ok(())
    }

    /// The node-local keys an import sets beside the entries: the finalized
    /// height and the block log entry of the head (spec 22 §5), which the
    /// driver takes into its tables when it starts.
    #[must_use]
    pub fn local_keys(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let h = &self.header;
        let mut local = vec![
            (keys::FINALIZED.to_vec(), h.height.to_bytes()),
            (height_key(LOG_PROPOSAL, h.height), h.head_proposal.clone()),
            (
                height_key(LOG_CERTIFICATE, h.height),
                h.head_certificate.clone(),
            ),
        ];
        if !h.head_threshold.is_empty() {
            local.push((
                height_key(LOG_THRESHOLD, h.height),
                h.head_threshold.clone(),
            ));
        }
        local
    }

    /// Loads the snapshot into `store`, which holds the genesis alone, after
    /// [`Snapshot::verify`] passed.
    ///
    /// # Errors
    /// What the store reports.
    pub fn import(&self, store: &mut DiskStore) -> Result<(), SnapshotError> {
        store
            .load(
                self.header.height,
                &self.header.state_root,
                &self.entries,
                &self.local_keys(),
            )
            .map_err(store_error)
    }
}
