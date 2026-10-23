//! Committee-signed state snapshots (spec 22 §6–§7).
//!
//! A snapshot is the whole committed state as it was after the last block
//! of an epoch, identified by the record the kernel wrote for that epoch
//! (`snap/` + epoch: the height and the state commitment), and vouched for
//! by a finality certificate: a certificate for a later proposal whose
//! anchor root (spec 17 §4) a spec 10 proof of the record verifies against.
//! The head block's proposal is linked to that proposal by the parent
//! hashes of the proposals between them, which the file carries, so the
//! same certificate vouches for it. A new node verifies the certificate
//! under a key it trusts, the proof against the anchor, the links, and the
//! entries against the record's root, before it loads the state and syncs
//! forward from there.
//!
//! The file is `SOLOSNAP`, the format, the header's length and the encoded
//! [`SnapshotHeader`], then the entries, each as `key length ‖ key ‖ value
//! length ‖ value` with `u32` little-endian lengths, in ascending order of
//! their paths (`keccak256` of the key, spec 10 §3). Path order lets every
//! reader hash the entries into the trie as they stream past
//! ([`solo_trie::SortedRoot`]): exporting, verifying and importing keep a
//! bounded part of the state in memory whatever its size (spec 22 §7).

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use solo_abi::chain::consensus::{KIND_FINALIZE, signing_preimage};
use solo_abi::chain::{Certificate, Proposal, SnapshotRecord, ValidatorSet, keys};
use solo_abi::codec::{Decoder, Encoder, Seq};
use solo_abi::rotation::threshold_certificate;
use solo_abi::{Decode, DecodeError, Encode};
use solo_bls::PublicKey;
use solo_bls::certificate::CertificateV2;
use solo_host::Storage;
use solo_trie::{Hash, NODE_LEN, Proof, SortedRoot, keccak256};

use crate::disk::{DiskStore, NotKept, StoreError};

/// The first eight bytes of a snapshot file.
pub const MAGIC: &[u8; 8] = b"SOLOSNAP";

/// The file format this release writes and reads: 2, entries in path order
/// and the links from the head to the anchoring proposal in the header.
pub const FORMAT: u32 = 2;

/// Node-local keys the kernel's block log uses (spec 22 §5), which an
/// imported snapshot sets for the height it loads so that the driver finds
/// its finalized head.
pub const LOG_PROPOSAL: &[u8] = b"local/log/prop/";
/// The finalize certificate of a logged height.
pub const LOG_CERTIFICATE: &[u8] = b"local/log/cert/";
/// The threshold certificate of a logged height.
pub const LOG_THRESHOLD: &[u8] = b"local/log/bcert/";

/// How an export sorts the entries into path order: in runs of at most
/// `chunk_bytes` of entries in memory, each sorted and written to a
/// temporary file beside the output, then merged `fan_in` runs at a time
/// (spec 22 §7.1). Memory stays within `chunk_bytes` plus a read buffer per
/// merged run, whatever the size of the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportLimits {
    /// The most bytes of entries (key, value and path) a run holds.
    pub chunk_bytes: usize,
    /// The most runs one merge reads at once; at least 2.
    pub fan_in: usize,
}

impl Default for ExportLimits {
    /// Runs of 64 MiB, merged 64 at a time: a 4 GiB state sorts in one
    /// merge, a larger one in more.
    fn default() -> ExportLimits {
        ExportLimits {
            chunk_bytes: 64 << 20,
            fan_in: 64,
        }
    }
}

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
    /// The encoded finalized proposals of the heights between the head and
    /// the anchoring proposal, lowest first: each names the one before as
    /// its parent, the first the head, and the anchoring proposal the last.
    pub links: Seq<Vec<u8>>,
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
        self.links.encode(e);
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
            links: d.get()?,
        })
    }
}

impl SnapshotHeader {
    /// Verifies everything the header vouches for (spec 22 §7.2, checks 1
    /// to 4 and 6): the chain, the certificate for the anchoring proposal
    /// under `trust`, the proof of the record against its anchor root, and
    /// the head linked to the anchoring proposal. The entries, check 5, are
    /// checked as they are read ([`Snapshot::verify`]), or slice by slice as
    /// they are fetched from peers (spec 22 §7.4).
    ///
    /// # Errors
    /// [`SnapshotError::Verify`] naming the first check that fails.
    pub fn verify(&self, chain_id: u64, trust: &Trust) -> Result<(), SnapshotError> {
        if self.chain_id != chain_id {
            return Err(SnapshotError::Verify("another chain"));
        }
        let proposal =
            Proposal::from_bytes(&self.anchor_proposal)
                .ok()
                .ok_or(SnapshotError::Verify(
                    "the anchoring proposal does not decode",
                ))?;
        if proposal.anchor_height <= self.height {
            return Err(SnapshotError::Verify(
                "the anchoring proposal anchors no height above the snapshot",
            ));
        }
        let hash = keccak256(&self.anchor_proposal);
        self.verify_certificate(&proposal, &hash, chain_id, trust)?;
        let record = SnapshotRecord {
            height: self.height,
            state_root: self.state_root,
        };
        let proof = Proof::decode(&self.record_proof)
            .ok()
            .ok_or(SnapshotError::Verify("the record's proof does not decode"))?;
        let proven = proof.verify(keccak256, &proposal.anchor_root, &record_key(self.epoch));
        if proven != Ok(Some(keccak256(&record.to_bytes()))) {
            return Err(SnapshotError::Verify(
                "the record's proof does not verify against the anchor root",
            ));
        }
        self.verify_head(&proposal, chain_id, trust)
    }

    /// Checks the head block's proposal and certificate (spec 22 §7.2, 6),
    /// which seed the importing driver: its tip, entry certificate and
    /// view. The head proposal is the trust's through the links: each link
    /// names the one before it as its parent, the first the head, and the
    /// anchoring proposal, which the certificate vouches for, the last. The
    /// head certificate's view is bounded by the anchoring proposal's: a
    /// forged one cannot move a node past the views the chain has had. It
    /// may name a descendant that finalized the head, such as a suffix
    /// proposal (spec 08 §3a); under the genesis set its votes must verify.
    fn verify_head(
        &self,
        anchoring: &Proposal,
        chain_id: u64,
        trust: &Trust,
    ) -> Result<(), SnapshotError> {
        let head = Proposal::from_bytes(&self.head_proposal)
            .ok()
            .filter(|p| p.height == self.height)
            .ok_or(SnapshotError::Verify("the head proposal is not block's"))?;
        let mut parent = (head.height, keccak256(&self.head_proposal));
        for link in &self.links.0 {
            let p = Proposal::from_bytes(link)
                .ok()
                .ok_or(SnapshotError::Verify("a link does not decode"))?;
            if (p.height, p.parent) != (parent.0 + 1, parent.1) {
                return Err(SnapshotError::Verify(
                    "the links do not join the head to the anchoring proposal",
                ));
            }
            parent = (p.height, keccak256(link));
        }
        if (anchoring.height, anchoring.parent) != (parent.0 + 1, parent.1) {
            return Err(SnapshotError::Verify(
                "the links do not join the head to the anchoring proposal",
            ));
        }
        let certificate = Certificate::from_bytes(&self.head_certificate)
            .ok()
            .filter(|c| c.kind == KIND_FINALIZE && c.view <= anchoring.view)
            .ok_or(SnapshotError::Verify(
                "the head certificate is not a finalize certificate at or below the anchoring proposal's view",
            ))?;
        if let Trust::Genesis(set) = trust
            && !votes_certify(&certificate, &certificate.hash, chain_id, set)
        {
            return Err(SnapshotError::Verify(
                "the head certificate is not a quorum of the genesis set",
            ));
        }
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
        let bytes = &self.certificate;
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
    /// The export was called off before it finished (spec 22 §7.4).
    Cancelled,
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::Io(why) => write!(f, "snapshot file: {why}"),
            SnapshotError::Format(what) => write!(f, "snapshot: not a snapshot file: {what}"),
            SnapshotError::Verify(why) => write!(f, "snapshot does not verify: {why}"),
            SnapshotError::Store(why) => write!(f, "snapshot: {why}"),
            SnapshotError::Export(why) => write!(f, "snapshot: cannot export: {why}"),
            SnapshotError::Cancelled => write!(f, "snapshot: export cancelled"),
        }
    }
}

impl std::error::Error for SnapshotError {}

impl From<StoreError> for SnapshotError {
    fn from(e: StoreError) -> SnapshotError {
        SnapshotError::Store(e.to_string())
    }
}

impl From<NotKept> for SnapshotError {
    fn from(NotKept(kept): NotKept) -> SnapshotError {
        SnapshotError::Export(format!(
            "the store no longer keeps the state of the record's block (it keeps {kept:?})"
        ))
    }
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(e: io::Error) -> SnapshotError {
    SnapshotError::Io(e.to_string())
}

/// A header or an entry longer than a `u32` length can say: not one a
/// chain holds.
#[allow(clippy::needless_pass_by_value)]
fn too_long(_: std::num::TryFromIntError) -> SnapshotError {
    SnapshotError::Io("a length does not fit the format's u32".to_owned())
}

/// The driver's node-local tables, as [`crate::disk::DiskStore`]'s
/// neighbour on disk holds them: `prop/`, `final/`, `cert/`, `bcert/`.
pub type Tables = BTreeMap<Vec<u8>, Vec<u8>>;

/// What vouches for a record: the anchoring proposal, its certificate, the
/// proof of the record against the anchor root, all encoded, and the
/// proposals linking the head to it.
type Finality = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<Vec<u8>>);

/// A snapshot file: its header, read when it was opened, and its entries,
/// which stay on disk and stream from it as they are read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Everything but the entries.
    pub header: SnapshotHeader,
    path: PathBuf,
    /// Where the entries start in the file.
    body: u64,
}

/// One length-prefixed part of an entry or a run record.
fn read_part(file: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut word = [0u8; 4];
    file.read_exact(&mut word)?;
    let mut part = vec![0u8; u32::from_le_bytes(word) as usize];
    file.read_exact(&mut part)?;
    Ok(part)
}

/// Writes `part` behind its `u32` length.
fn write_part(out: &mut impl Write, part: &[u8]) -> Result<(), SnapshotError> {
    let len = u32::try_from(part.len()).map_err(too_long)?;
    out.write_all(&len.to_le_bytes()).map_err(io_error)?;
    out.write_all(part).map_err(io_error)
}

/// The entries of a snapshot file, read one at a time: exactly as many as
/// the header says, after which nothing may follow.
#[derive(Debug)]
pub struct EntryReader {
    file: BufReader<File>,
    left: u64,
    done: bool,
}

impl Iterator for EntryReader {
    type Item = Result<(Vec<u8>, Vec<u8>), SnapshotError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if self.left == 0 {
            self.done = true;
            let mut rest = [0u8; 1];
            let after = self.file.read(&mut rest).map_err(io_error);
            return after
                .and_then(|n| {
                    if n == 0 {
                        Ok(None)
                    } else {
                        Err(SnapshotError::Verify(
                            "the entry count is wrong: bytes follow the last entry",
                        ))
                    }
                })
                .transpose();
        }
        self.left -= 1;
        let entry = (|| {
            let mut word = [0u8; 4];
            if self.file.read(&mut word[..1]).map_err(io_error)? == 0 {
                return Err(SnapshotError::Verify(
                    "the entry count is wrong: the file ends early",
                ));
            }
            self.file.read_exact(&mut word[1..]).map_err(io_error)?;
            let mut key = vec![0u8; u32::from_le_bytes(word) as usize];
            self.file.read_exact(&mut key).map_err(io_error)?;
            let value = read_part(&mut self.file).map_err(io_error)?;
            Ok((key, value))
        })();
        self.done = entry.is_err();
        Some(entry)
    }
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

/// Which trust a certificate needs: the key set a threshold certificate
/// names, or none for a vote certificate. An export links the head to the
/// lowest proposal whose certificate needs the same trust as the latest's.
fn trust_class(certificate: &[u8]) -> Option<u64> {
    threshold_certificate(certificate).map(|c| c.key_id)
}

/// A temporary directory that goes when it is dropped, with whatever an
/// export left in it.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A sorted run being merged: its reader and its next record.
struct Run {
    file: BufReader<File>,
    next: Option<(Hash, Vec<u8>, Vec<u8>)>,
}

impl Run {
    fn open(path: &Path) -> Result<Run, SnapshotError> {
        let mut run = Run {
            file: BufReader::new(File::open(path).map_err(io_error)?),
            next: None,
        };
        run.advance()?;
        Ok(run)
    }

    /// Reads the next record: `path ‖ key ‖ value`, the two parts length
    /// prefixed; `None` at the end of the run.
    fn advance(&mut self) -> Result<(), SnapshotError> {
        let mut path = [0u8; 32];
        self.next = if self.file.read(&mut path[..1]).map_err(io_error)? == 0 {
            None
        } else {
            self.file.read_exact(&mut path[1..]).map_err(io_error)?;
            let key = read_part(&mut self.file).map_err(io_error)?;
            let value = read_part(&mut self.file).map_err(io_error)?;
            Some((path, key, value))
        };
        Ok(())
    }
}

/// Merges the sorted runs at `paths` in path order, handing each record to
/// `sink`.
fn merge_runs(
    paths: &[PathBuf],
    sink: &mut dyn FnMut(Hash, Vec<u8>, Vec<u8>) -> Result<(), SnapshotError>,
) -> Result<(), SnapshotError> {
    let mut runs = paths
        .iter()
        .map(|p| Run::open(p))
        .collect::<Result<Vec<Run>, SnapshotError>>()?;
    let mut heap = BinaryHeap::new();
    for (i, run) in runs.iter().enumerate() {
        if let Some((path, _, _)) = &run.next {
            heap.push(Reverse((*path, i)));
        }
    }
    while let Some(Reverse((_, i))) = heap.pop() {
        let (path, key, value) = runs[i].next.take().expect("a record");
        runs[i].advance()?;
        if let Some((next, _, _)) = &runs[i].next {
            heap.push(Reverse((*next, i)));
        }
        sink(path, key, value)?;
    }
    Ok(())
}

/// [`SnapshotError::Cancelled`] once `cancel` is set.
fn cancelled(cancel: &AtomicBool) -> Result<(), SnapshotError> {
    if cancel.load(Ordering::Relaxed) {
        return Err(SnapshotError::Cancelled);
    }
    Ok(())
}

/// Writes one sorted run of `records` to `path`.
fn write_run(
    path: &Path,
    records: &mut Vec<(Hash, Vec<u8>, Vec<u8>)>,
) -> Result<(), SnapshotError> {
    records.sort_unstable_by_key(|r| r.0);
    let mut out = BufWriter::new(File::create(path).map_err(io_error)?);
    for (p, key, value) in records.drain(..) {
        out.write_all(&p).map_err(io_error)?;
        write_part(&mut out, &key)?;
        write_part(&mut out, &value)?;
    }
    out.flush().map_err(io_error)
}

/// Writes the entries of `version` from `store` to `out` in path order,
/// sorting them through runs in `dir` within `limits`: the entry count and
/// the root they hash to.
fn sorted_entries(
    store: &crate::disk::Frozen,
    version: u64,
    dir: &Path,
    out: &Path,
    limits: ExportLimits,
    cancel: &AtomicBool,
) -> Result<(u64, Hash), SnapshotError> {
    let fan_in = limits.fan_in.max(2);
    let mut runs: Vec<PathBuf> = Vec::new();
    let mut records = Vec::new();
    let mut held = 0usize;
    store.each_entry_at(version, |key, value| {
        cancelled(cancel)?;
        held += 32 + key.len() + value.len();
        records.push((keccak256(key), key.to_vec(), value.to_vec()));
        if held >= limits.chunk_bytes {
            let path = dir.join(format!("run-0-{}", runs.len()));
            write_run(&path, &mut records)?;
            runs.push(path);
            held = 0;
        }
        Ok::<(), SnapshotError>(())
    })?;
    if !records.is_empty() || runs.is_empty() {
        let path = dir.join(format!("run-0-{}", runs.len()));
        write_run(&path, &mut records)?;
        runs.push(path);
    }
    // Merge passes until one merge can read every run.
    let mut pass = 0;
    while runs.len() > fan_in {
        pass += 1;
        let mut merged = Vec::new();
        for (i, group) in runs.chunks(fan_in).enumerate() {
            let path = dir.join(format!("run-{pass}-{i}"));
            let mut w = BufWriter::new(File::create(&path).map_err(io_error)?);
            let written = merge_runs(group, &mut |p, key, value| {
                cancelled(cancel)?;
                w.write_all(&p).map_err(io_error)?;
                write_part(&mut w, &key)?;
                write_part(&mut w, &value)
            });
            written.and_then(|()| w.flush().map_err(io_error))?;
            for done in group {
                std::fs::remove_file(done).map_err(io_error)?;
            }
            merged.push(path);
        }
        runs = merged;
    }
    let mut w = BufWriter::new(File::create(out).map_err(io_error)?);
    let mut root = SortedRoot::new(keccak256);
    let mut none = |_: &Hash, _: &[u8; NODE_LEN]| {};
    let written = merge_runs(&runs, &mut |path, key, value| {
        cancelled(cancel)?;
        // Two keys on one path would take a Keccak collision; the push
        // would refuse the second, and the root would not be the record's.
        let _ = root.push(path, keccak256(&value), &mut none);
        write_part(&mut w, &key)?;
        write_part(&mut w, &value)
    });
    written.and_then(|()| w.flush().map_err(io_error))?;
    Ok((root.len(), root.finish(&mut none)))
}

/// A snapshot export whose record and certificate are found, waiting for
/// its entries: [`Snapshot::prepare_export`] makes it on the node's
/// thread, and [`Export::run`] finishes it on any other.
pub struct Export {
    frozen: crate::disk::Frozen,
    header: SnapshotHeader,
    out: PathBuf,
}

impl Export {
    /// The epoch of the snapshot being exported.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.header.epoch
    }

    /// Walks the frozen store's entries at the record's height into path
    /// order within `limits` and writes the file. Setting `cancel` stops
    /// it at the next entry, leaving no file and no scratch behind.
    ///
    /// # Errors
    /// [`SnapshotError::Cancelled`] once `cancel` is set; as
    /// [`Snapshot::export`] otherwise.
    pub fn run(self, limits: ExportLimits, cancel: &AtomicBool) -> Result<Snapshot, SnapshotError> {
        let Export {
            frozen,
            mut header,
            out,
        } = self;
        let scratch = Scratch(out.with_extension("runs"));
        let _ = std::fs::remove_dir_all(&scratch.0);
        std::fs::create_dir_all(&scratch.0).map_err(io_error)?;
        let body = scratch.0.join("entries");
        let (count, root) =
            sorted_entries(&frozen, header.height, &scratch.0, &body, limits, cancel)?;
        // The record is the root as the next block began; a kernel switch
        // between the two blocks wrote into it after the version was sealed
        // (spec 22 §7.1), and a file of these entries would not verify.
        if root != header.state_root {
            return Err(SnapshotError::Export(format!(
                "the state sealed at block {} does not hash to epoch {}'s record: a kernel switch after that block wrote into it; export another epoch",
                header.height, header.epoch
            )));
        }
        header.entries = count;
        let partial = scratch.0.join("snapshot");
        let mut w = BufWriter::new(File::create(&partial).map_err(io_error)?);
        let body_at = Snapshot::write_header(&mut w, &header)?;
        io::copy(&mut File::open(&body).map_err(io_error)?, &mut w).map_err(io_error)?;
        w.flush().map_err(io_error)?;
        drop(w);
        std::fs::rename(&partial, &out).map_err(io_error)?;
        Ok(Snapshot {
            header,
            path: out,
            body: body_at,
        })
    }
}

impl Snapshot {
    /// The file the snapshot is in.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Where the entries start in the file: what a server that reads one
    /// slice of them (spec 22 §7.4) seeks from.
    #[must_use]
    pub fn body_offset(&self) -> u64 {
        self.body
    }

    /// Writes a snapshot file at `path` from `header` and the files `parts`,
    /// whose bytes are entries in the file's encoding and follow one another
    /// in path order: how a node that fetched a snapshot slice by slice
    /// (spec 22 §7.4) puts it together. Nothing is checked; the import
    /// checks the order and the root.
    ///
    /// # Errors
    /// What the file system reports.
    pub fn assemble(
        path: &Path,
        header: &SnapshotHeader,
        parts: &[PathBuf],
    ) -> Result<Snapshot, SnapshotError> {
        let mut out = BufWriter::new(File::create(path).map_err(io_error)?);
        let body = Self::write_header(&mut out, header)?;
        for part in parts {
            io::copy(&mut File::open(part).map_err(io_error)?, &mut out).map_err(io_error)?;
        }
        out.flush().map_err(io_error)?;
        Ok(Snapshot {
            header: header.clone(),
            path: path.to_path_buf(),
            body,
        })
    }

    /// Exports the snapshot of `epoch` (the latest recorded, for `None`)
    /// from a node's store and driver tables to the file `out`, within the
    /// default [`ExportLimits`]: the state at the record's height, a
    /// certificate whose proposal anchors a later height the store still
    /// keeps the trie of, with the proof of the record against it, the
    /// head block's proposal and certificates, and the proposals between.
    ///
    /// # Errors
    /// [`SnapshotError::Export`] when the chain has no such record, the
    /// store no longer keeps the height, no certified proposal anchors a
    /// kept height above it, or the tables lack a proposal between;
    /// [`SnapshotError::Io`] when the file cannot be written.
    pub fn export(
        store: &DiskStore,
        tables: &Tables,
        epoch: Option<u64>,
        out: &Path,
    ) -> Result<Snapshot, SnapshotError> {
        Self::export_within(store, tables, epoch, out, ExportLimits::default())
    }

    /// [`Snapshot::export`] within `limits`.
    ///
    /// # Errors
    /// As [`Snapshot::export`].
    pub fn export_within(
        store: &DiskStore,
        tables: &Tables,
        epoch: Option<u64>,
        out: &Path,
        limits: ExportLimits,
    ) -> Result<Snapshot, SnapshotError> {
        Self::prepare_export(store, tables, epoch, out)?.run(limits, &AtomicBool::new(false))
    }

    /// The cheap half of [`Snapshot::export`]: finds the record, the head
    /// and what vouches for them, and freezes the store (see
    /// [`DiskStore::frozen`]), leaving the entries, the expensive half, to
    /// [`Export::run`] on any thread while the store goes on.
    ///
    /// # Errors
    /// As [`Snapshot::export`], but for the entries and the file.
    pub fn prepare_export(
        store: &DiskStore,
        tables: &Tables,
        epoch: Option<u64>,
        out: &Path,
    ) -> Result<Export, SnapshotError> {
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
        // A verifier bounds the head certificate's view by the anchoring
        // proposal's (spec 22 §7.2).
        let head_view = Certificate::from_bytes(&head_certificate).map_or(u64::MAX, |c| c.view);
        let (anchor_proposal, certificate, record_proof, links) =
            Self::finality(store, tables, &record, epoch, head_view)?;
        // What vouches for the record is found before the entries are
        // sorted, the expensive part: a serving node tries again after every
        // block until a certificate covers the record (spec 22 §7.4).
        let header = SnapshotHeader {
            chain_id,
            epoch,
            height: record.height,
            state_root: record.state_root,
            entries: 0,
            anchor_proposal,
            certificate,
            record_proof,
            head_proposal,
            head_certificate,
            head_threshold: head(b"bcert/").unwrap_or_default(),
            links: Seq(links),
        };
        Ok(Export {
            frozen: store.frozen()?,
            header,
            out: out.to_path_buf(),
        })
    }

    /// The certified proposal whose anchor names a height above the
    /// record's that the store keeps the trie of, in a view at or above
    /// `head_view`, its certificate (the threshold certificate when the
    /// tables hold one, else the votes), the proof of the record against
    /// the anchor root, and the finalized proposals between the head and
    /// it. Of the candidates whose certificate needs the trust the latest
    /// one's needs, the lowest is taken, so that the links are few.
    fn finality(
        store: &DiskStore,
        tables: &Tables,
        record: &SnapshotRecord,
        epoch: u64,
        head_view: u64,
    ) -> Result<Finality, SnapshotError> {
        let key = record_key(epoch);
        let finalized = |height: u64| tables.get(&height_key(b"final/", height));
        let mut candidates = Vec::new();
        // Heights are little-endian in the keys: their byte order is not
        // their order.
        let mut heights: Vec<u64> = tables
            .range(b"final/".to_vec()..b"final0".to_vec())
            .filter_map(|(k, _)| Some(u64::from_le_bytes(k.get(6..14)?.try_into().ok()?)))
            .filter(|h| *h > record.height)
            .collect();
        heights.sort_unstable();
        for height in heights {
            let Some(bytes) = finalized(height)
                .and_then(|hash| tables.get(&[b"prop/".as_slice(), hash].concat()))
            else {
                continue;
            };
            let Ok(proposal) = Proposal::from_bytes(bytes) else {
                continue;
            };
            if proposal.anchor_height <= record.height || proposal.view < head_view {
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
            candidates.push((height, bytes, certificate, trie, proposal));
        }
        let class = candidates
            .last()
            .map(|(_, _, certificate, _, _)| trust_class(certificate))
            .ok_or_else(|| {
                SnapshotError::Export(format!(
                    "no certified proposal anchors a kept height above block {}",
                    record.height
                ))
            })?;
        let (height, bytes, certificate, trie, _) = candidates
            .into_iter()
            .find(|(_, _, certificate, _, _)| trust_class(certificate) == class)
            .expect("the latest candidate is one");
        let mut links = Vec::new();
        for h in record.height + 1..height {
            let link = finalized(h)
                .and_then(|hash| tables.get(&[b"prop/".as_slice(), hash].concat()))
                .ok_or_else(|| {
                    SnapshotError::Export(format!(
                        "the driver tables do not hold the proposal of block {h}"
                    ))
                })?;
            links.push(link.clone());
        }
        Ok((
            bytes.clone(),
            certificate.clone(),
            trie.prove(&key).encode(),
            links,
        ))
    }

    /// Writes the magic, the format and `header` to `out`; the offset at
    /// which the entries follow.
    fn write_header(out: &mut impl Write, header: &SnapshotHeader) -> Result<u64, SnapshotError> {
        let header = header.to_bytes();
        out.write_all(MAGIC).map_err(io_error)?;
        out.write_all(&FORMAT.to_le_bytes()).map_err(io_error)?;
        let len = u32::try_from(header.len()).map_err(too_long)?;
        out.write_all(&len.to_le_bytes()).map_err(io_error)?;
        out.write_all(&header).map_err(io_error)?;
        Ok(16 + header.len() as u64)
    }

    /// Writes a snapshot file at `path` from its parts, the entries in the
    /// order given: what tools and tests that build or alter a snapshot
    /// use. Nothing is checked; [`Snapshot::verify`] checks.
    ///
    /// # Errors
    /// What the file system reports.
    pub fn write(
        path: &Path,
        header: &SnapshotHeader,
        entries: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
    ) -> Result<Snapshot, SnapshotError> {
        let mut out = BufWriter::new(File::create(path).map_err(io_error)?);
        let body = Self::write_header(&mut out, header)?;
        for (key, value) in entries {
            write_part(&mut out, &key)?;
            write_part(&mut out, &value)?;
        }
        out.flush().map_err(io_error)?;
        Ok(Snapshot {
            header: header.clone(),
            path: path.to_path_buf(),
            body,
        })
    }

    /// Opens the snapshot at `path`, reading its header; the entries are
    /// read when [`Snapshot::entries`] streams them.
    ///
    /// # Errors
    /// [`SnapshotError::Io`] when the file cannot be read,
    /// [`SnapshotError::Format`] when it is not a snapshot file.
    pub fn open(path: &Path) -> Result<Snapshot, SnapshotError> {
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
        let header = read_part(&mut file).map_err(io_error)?;
        let body = 16 + header.len() as u64;
        let header = SnapshotHeader::from_bytes(&header)
            .ok()
            .ok_or(SnapshotError::Format("the header does not decode"))?;
        Ok(Snapshot {
            header,
            path: path.to_path_buf(),
            body,
        })
    }

    /// The entries, streamed from the file: as many as the header says,
    /// each read when it is asked for.
    ///
    /// # Errors
    /// [`SnapshotError::Io`] when the file cannot be opened.
    pub fn entries(&self) -> Result<EntryReader, SnapshotError> {
        let mut file = BufReader::new(File::open(&self.path).map_err(io_error)?);
        io::copy(&mut (&mut file).take(self.body), &mut io::sink()).map_err(io_error)?;
        Ok(EntryReader {
            file,
            left: self.header.entries,
            done: false,
        })
    }

    /// Verifies the snapshot for `chain_id` under `trust` (spec 22 §7.2):
    /// the certificate for the anchoring proposal, the proof of the record
    /// against its anchor root, the entries against the record's root as
    /// they stream from the file, and the head linked to the anchoring
    /// proposal.
    ///
    /// # Errors
    /// [`SnapshotError::Verify`] naming the first check that fails, or what
    /// reading the file reports.
    pub fn verify(&self, chain_id: u64, trust: &Trust) -> Result<(), SnapshotError> {
        let h = &self.header;
        h.verify(chain_id, trust)?;
        let mut root = SortedRoot::new(keccak256);
        let mut none = |_: &Hash, _: &[u8; NODE_LEN]| {};
        for entry in self.entries()? {
            let (key, value) = entry?;
            if !solo_host::storage::committed(&key) {
                return Err(SnapshotError::Verify("an entry is node-local"));
            }
            root.push(keccak256(&key), keccak256(&value), &mut none)
                .map_err(|_| SnapshotError::Verify("the entries are not in path order"))?;
        }
        if root.finish(&mut none) != h.state_root {
            return Err(SnapshotError::Verify(
                "the entries do not hash to the record's root",
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
    /// [`Snapshot::verify`] passed: the entries stream from the file into
    /// the store's one transaction ([`DiskStore::load`]), which checks
    /// their order and root again before it commits. The snapshot must be
    /// of the chain whose genesis the store holds: its state names the
    /// genesis block's hash at `bnum/` ‖ 0, and that must be the hash of the
    /// genesis block the store's own `kernel_init` stored (spec 22 §7.3,
    /// spec 20 §3.1), whatever its chain id and certificates say.
    ///
    /// # Errors
    /// [`SnapshotError::Verify`] for the state of another genesis; what
    /// reading the file or the store reports.
    pub fn import(&self, store: &mut DiskStore) -> Result<(), SnapshotError> {
        let key = [keys::BLOCK_NUMBER, &0u64.to_be_bytes()[..]].concat();
        let expected = store.get(&key);
        let entries = GenesisCheck {
            entries: self.entries()?,
            seen: expected.is_none(),
            key,
            expected,
        };
        store.load(
            self.header.height,
            &self.header.state_root,
            entries,
            &self.local_keys(),
        )
    }
}

/// The entries of a snapshot, refused unless they name the genesis hash
/// `expected` at `key` (`bnum/` ‖ 0), or name none when there is none to
/// expect.
struct GenesisCheck {
    entries: EntryReader,
    key: Vec<u8>,
    expected: Option<Vec<u8>>,
    seen: bool,
}

impl Iterator for GenesisCheck {
    type Item = Result<(Vec<u8>, Vec<u8>), SnapshotError>;

    fn next(&mut self) -> Option<Self::Item> {
        const OTHER: SnapshotError =
            SnapshotError::Verify("the snapshot is of a chain with another genesis block");
        match self.entries.next() {
            Some(Ok((key, value))) if key == self.key => {
                if self.expected.as_ref() != Some(&value) {
                    return Some(Err(OTHER));
                }
                self.seen = true;
                Some(Ok((key, value)))
            }
            None if !self.seen => {
                self.seen = true;
                Some(Err(OTHER))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use solo_abi::chain::{Certificate, Signature, SignedVote};
    use solo_abi::codec::Seq;

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        solo_scratch::Scratch::new("snapshot-unit", name).keep()
    }

    /// A proposal at `height` anchoring `anchor` with `root`.
    fn proposal(height: u64, anchor: u64, root: [u8; 32]) -> Proposal {
        Proposal {
            view: height,
            height,
            anchor_height: anchor,
            anchor_root: root,
            ..Proposal::default()
        }
    }

    fn certificate(hash: [u8; 32]) -> Certificate {
        Certificate {
            kind: KIND_FINALIZE,
            view: 1,
            hash,
            votes: Seq(vec![SignedVote {
                validator: 0,
                signature: Signature([0; 65]),
            }]),
        }
    }

    /// Enters `p` as finalized at its height in `tables`, with a vote
    /// certificate unless `certified` is false.
    fn finalize(tables: &mut Tables, p: &Proposal, certified: bool) {
        let bytes = p.to_bytes();
        let hash = keccak256(&bytes);
        tables.insert(height_key(b"final/", p.height), hash.to_vec());
        tables.insert([b"prop/".as_slice(), &hash].concat(), bytes);
        if certified {
            tables.insert(height_key(b"cert/", p.height), certificate(hash).to_bytes());
        }
    }

    /// A store with a chain id, three versions and the snapshot record of
    /// epoch 0 at version 1; returns it with the header roots of versions
    /// 2 and 3.
    fn store(name: &str) -> (DiskStore, [u8; 32], [u8; 32]) {
        let mut s = DiskStore::open(&scratch(name)).unwrap();
        s.set(keys::CHAIN_ID, &7u64.to_bytes());
        s.seal(0, None).unwrap();
        s.set(b"acct/a", b"1");
        s.seal(1, None).unwrap();
        let record = SnapshotRecord {
            height: 1,
            state_root: s.state_trie().root(),
        };
        s.set(&record_key(0), &record.to_bytes());
        s.set(keys::SNAPSHOT_LATEST, &0u64.to_bytes());
        let committed = s.state_trie();
        s.set(b"meta/height", b"2");
        s.seal(2, Some(&committed)).unwrap();
        let root2 = committed.root();
        s.set(b"acct/b", b"2");
        let committed = s.state_trie();
        s.set(b"meta/height", b"3");
        s.seal(3, Some(&committed)).unwrap();
        (s, root2, committed.root())
    }

    /// Exports from `s` to a file named after `name`.
    fn export(
        s: &DiskStore,
        tables: &Tables,
        epoch: Option<u64>,
        name: &str,
    ) -> Result<Snapshot, SnapshotError> {
        let dir = scratch(&format!("out-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        Snapshot::export(s, tables, epoch, &dir.join("x.snap"))
    }

    fn entries(snapshot: &Snapshot) -> Vec<(Vec<u8>, Vec<u8>)> {
        snapshot.entries().unwrap().map(Result::unwrap).collect()
    }

    /// Tables that certify the record of [`store`]: the head at 1, the
    /// proposals between and a certified one at 4 anchoring version 3.
    fn certifying(root3: [u8; 32]) -> Tables {
        let mut tables = Tables::new();
        finalize(&mut tables, &proposal(1, 0, [0; 32]), true);
        finalize(&mut tables, &proposal(2, 0, [0; 32]), false);
        finalize(&mut tables, &proposal(3, 0, [0; 32]), false);
        finalize(&mut tables, &proposal(4, 3, root3), true);
        tables
    }

    /// The expensive half of an export runs on another thread over the
    /// store as it was frozen, while the store seals and prunes on; a
    /// cancelled one stops and leaves nothing behind.
    #[test]
    fn an_export_runs_apart_from_a_store_that_goes_on() {
        let (mut s, _, root3) = store("apart");
        let tables = certifying(root3);
        let dir = scratch("apart-out");
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("x.snap");
        let mut before = s.entries_at(1).unwrap();
        let export = Snapshot::prepare_export(&s, &tables, None, &out).unwrap();
        assert_eq!(export.epoch(), 0);
        // The store changes the record's block's keys and prunes its
        // version after the freeze.
        s.set(b"acct/a", b"changed");
        s.seal(4, None).unwrap();
        s.prune(4).unwrap();
        assert!(s.entries_at(1).is_err());
        let ran = std::thread::spawn(move || {
            export.run(ExportLimits::default(), &AtomicBool::new(false))
        });
        let snapshot = ran.join().unwrap().unwrap();
        let mut exported = entries(&snapshot);
        exported.sort();
        before.sort();
        assert_eq!(exported, before);
        assert!(before.contains(&(b"acct/a".to_vec(), b"1".to_vec())));
        // Cancelled before it starts, cancelled during the merge of runs and
        // during the final merge: no file, no scratch.
        let (s, _, root3) = store("cancelled");
        let tables = certifying(root3);
        let out = dir.join("y.snap");
        let cancel = AtomicBool::new(true);
        let export = Snapshot::prepare_export(&s, &tables, None, &out).unwrap();
        let err = export.run(ExportLimits::default(), &cancel).unwrap_err();
        assert_eq!(err.to_string(), "snapshot: export cancelled");
        assert!(!out.exists() && !out.with_extension("runs").exists());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn export_names_what_the_store_or_the_tables_lack() {
        let (s, root2, root3) = store("export");
        let why = |r: Result<Snapshot, SnapshotError>| r.unwrap_err().to_string();
        // No chain, no record, no epoch: each named.
        let empty = DiskStore::open(&scratch("empty")).unwrap();
        assert!(why(export(&empty, &Tables::new(), None, "a")).contains("no chain"));
        let mut fresh = DiskStore::open(&scratch("fresh")).unwrap();
        fresh.set(keys::CHAIN_ID, &7u64.to_bytes());
        fresh.seal(0, None).unwrap();
        assert!(why(export(&fresh, &Tables::new(), None, "b")).contains("recorded no snapshot"));
        assert!(
            why(export(&s, &Tables::new(), Some(5), "c"))
                .contains("no snapshot record for epoch 5")
        );
        // A record whose root is not the sealed state's: what a kernel
        // switch right after the epoch's last block leaves.
        let mut switched = DiskStore::open(&scratch("switched")).unwrap();
        switched.set(keys::CHAIN_ID, &7u64.to_bytes());
        switched.seal(0, None).unwrap();
        switched.set(b"acct/a", b"1");
        switched.seal(1, None).unwrap();
        let stale = SnapshotRecord {
            height: 1,
            state_root: [3; 32],
        };
        switched.set(&record_key(0), &stale.to_bytes());
        switched.set(keys::SNAPSHOT_LATEST, &0u64.to_bytes());
        let committed = switched.state_trie();
        switched.seal(2, Some(&committed)).unwrap();
        // The certificate is found first; the entries, sorted after it,
        // do not hash to the record.
        let mut certified = Tables::new();
        finalize(&mut certified, &proposal(1, 0, [0; 32]), true);
        finalize(&mut certified, &proposal(2, 2, committed.root()), true);
        assert!(
            why(export(&switched, &certified, None, "d"))
                .contains("a kernel switch after that block wrote into it")
        );
        // The head block's entries, missing one by one.
        let mut tables = Tables::new();
        assert!(why(export(&s, &tables, None, "e")).contains("do not hold block 1"));
        let head = proposal(1, 0, [0; 32]);
        finalize(&mut tables, &head, true);
        let hash = keccak256(&head.to_bytes());
        tables.remove(&[b"prop/".as_slice(), &hash].concat());
        assert!(why(export(&s, &tables, None, "f")).contains("the proposal of block 1"));
        finalize(&mut tables, &head, false);
        tables.remove(&height_key(b"cert/", 1));
        assert!(why(export(&s, &tables, None, "g")).contains("the certificate of block 1"));
        finalize(&mut tables, &head, true);
        // Nothing certified above the record.
        assert!(why(export(&s, &tables, None, "h")).contains("no certified proposal"));
        // Candidates that do not do: one that anchors the record's height,
        // one anchoring a version with no trie, one with another root, one
        // without a certificate; above them heights whose proposal is
        // missing or does not decode, and a key too short for a height.
        finalize(&mut tables, &proposal(2, 1, root2), true);
        finalize(&mut tables, &proposal(3, 9, root3), true);
        finalize(&mut tables, &proposal(4, 2, [9; 32]), true);
        finalize(&mut tables, &proposal(5, 2, root2), false);
        tables.insert(height_key(b"final/", 20), vec![1; 32]);
        tables.insert(height_key(b"final/", 21), vec![2; 32]);
        tables.insert([b"prop/".as_slice(), &[2; 32]].concat(), vec![0xFF]);
        tables.insert(b"final/short".to_vec(), vec![3; 32]);
        assert!(why(export(&s, &tables, None, "i")).contains("no certified proposal"));
        // A good candidate at 8, but the tables lack the proposals of 6 and 7
        // between it and the head.
        finalize(&mut tables, &proposal(8, 3, root3), true);
        tables.insert(height_key(b"bcert/", 1), vec![2; 97]);
        assert!(why(export(&s, &tables, None, "j")).contains("the proposal of block 6"));
        finalize(&mut tables, &proposal(6, 0, [0; 32]), false);
        finalize(&mut tables, &proposal(7, 0, [0; 32]), false);
        let snapshot = export(&s, &tables, None, "k").unwrap();
        assert_eq!(
            (
                snapshot.header.chain_id,
                snapshot.header.epoch,
                snapshot.header.height
            ),
            (7, 0, 1)
        );
        assert_eq!(snapshot.header.head_threshold, vec![2; 97]);
        assert_eq!(snapshot.header.links.0.len(), 6);
        assert_eq!(snapshot.header.links.0[0], proposal(2, 1, root2).to_bytes());
        assert_eq!(
            snapshot.header.links.0[5],
            proposal(7, 0, [0; 32]).to_bytes()
        );
        // A later candidate in a view below the head certificate's is
        // passed over: a verifier bounds that view by the candidate's. One
        // past 255, whose key sorts before the others', still counts as
        // later; with the same trust as 8, 8 is taken, the links fewer.
        let mut low = proposal(9, 3, root3);
        low.view = 0;
        finalize(&mut tables, &low, true);
        finalize(&mut tables, &proposal(300, 3, root3), true);
        let snapshot = export(&s, &tables, None, "l").unwrap();
        assert_eq!(
            snapshot.header.anchor_proposal,
            proposal(8, 3, root3).to_bytes()
        );
        let mut expected = vec![
            (b"acct/a".to_vec(), b"1".to_vec()),
            (keys::CHAIN_ID.to_vec(), 7u64.to_bytes()),
        ];
        expected.sort_by_key(|(k, _)| keccak256(k));
        assert_eq!(entries(&snapshot), expected);
        assert_eq!(snapshot.header.entries, 2);
        // When the latest candidate has a threshold certificate, the lowest
        // with one of the same key set is taken over a lower one with votes.
        tables.insert(height_key(b"bcert/", 300), vec![2; 97]);
        finalize(&mut tables, &proposal(10, 3, root3), true);
        tables.insert(height_key(b"bcert/", 10), vec![2; 97]);
        let snapshot = export(&s, &tables, Some(0), "m").unwrap();
        assert_eq!(snapshot.header.certificate, vec![2; 97]);
        assert_eq!(
            snapshot.header.anchor_proposal,
            proposal(10, 3, root3).to_bytes()
        );
        assert_eq!(snapshot.local_keys().len(), 4);
        // The state of the record's height must still be kept.
        let (mut pruned, _, _) = store("pruned");
        pruned.prune(3).unwrap();
        assert!(why(export(&pruned, &tables, None, "n")).contains("no longer keeps"));
        // Errors read as sentences.
        for e in [
            SnapshotError::Io("x".into()),
            SnapshotError::Format("y"),
            SnapshotError::Verify("v"),
            SnapshotError::Store("z".into()),
            SnapshotError::Export("w".into()),
        ] {
            assert!(e.to_string().starts_with("snapshot"), "{e}");
        }
        assert_eq!(
            SnapshotError::from(StoreError::Injected).to_string(),
            "snapshot: chain store: injected fault"
        );
    }

    #[test]
    fn an_export_sorts_through_many_runs_to_the_same_file() {
        // A state of 306 entries, exported in one run and in runs of one
        // entry merged two at a time (nine merge passes): the files are the
        // same byte for byte, and the scratch runs are gone.
        let (mut s, _, _) = store("runs");
        for i in 0..300u32 {
            s.set(
                &[b"acct/x".as_slice(), &i.to_be_bytes()].concat(),
                &i.to_le_bytes(),
            );
        }
        s.seal(4, None).unwrap();
        let record = SnapshotRecord {
            height: 4,
            state_root: s.state_trie().root(),
        };
        s.set(&record_key(1), &record.to_bytes());
        let committed = s.state_trie();
        s.seal(5, Some(&committed)).unwrap();
        let mut tables = Tables::new();
        let head = proposal(4, 0, [0; 32]);
        finalize(&mut tables, &head, true);
        let mut anchoring = proposal(6, 5, committed.root());
        anchoring.parent = keccak256(&head.to_bytes());
        // Heights 5 has no proposal of its own here; one links them.
        let mut five = proposal(5, 0, [0; 32]);
        five.parent = keccak256(&head.to_bytes());
        finalize(&mut tables, &five, false);
        anchoring.parent = keccak256(&five.to_bytes());
        finalize(&mut tables, &anchoring, true);
        let dir = scratch("runs-out");
        std::fs::create_dir_all(&dir).unwrap();
        let one = Snapshot::export(&s, &tables, Some(1), &dir.join("one.snap")).unwrap();
        let limits = ExportLimits {
            chunk_bytes: 1,
            fan_in: 2,
        };
        let many =
            Snapshot::export_within(&s, &tables, Some(1), &dir.join("many.snap"), limits).unwrap();
        assert_eq!(one.header, many.header);
        assert_eq!(one.header.entries, 306);
        assert_eq!(
            std::fs::read(one.path()).unwrap(),
            std::fs::read(many.path()).unwrap()
        );
        let left = || std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(left(), 2, "only the two files remain");
        assert_eq!(ExportLimits::default().chunk_bytes, 64 << 20);
        // The entries stream in path order and hash to the record's root.
        let mut root = SortedRoot::new(keccak256);
        for (k, v) in entries(&many) {
            root.push(keccak256(&k), keccak256(&v), &mut |_, _| {})
                .unwrap();
        }
        assert_eq!(root.finish(&mut |_, _| {}), record.state_root);
        // An export under a path that is a file fails at the file system.
        let missing = one.path().join("x.snap");
        assert!(matches!(
            Snapshot::export(&s, &tables, Some(1), &missing),
            Err(SnapshotError::Io(_))
        ));
        assert_eq!(left(), 2);
    }

    #[test]
    fn an_import_needs_the_genesis_block_the_store_holds() {
        let key = [keys::BLOCK_NUMBER, &0u64.to_be_bytes()[..]].concat();
        // A snapshot of version 1 holding `entries`, in path order.
        let file = |name: &str, mut entries: Vec<(Vec<u8>, Vec<u8>)>| {
            entries.sort_by_key(|(k, _)| keccak256(k));
            let mut root = SortedRoot::new(keccak256);
            for (k, v) in &entries {
                root.push(keccak256(k), keccak256(v), &mut |_, _| {})
                    .unwrap();
            }
            let header = SnapshotHeader {
                height: 1,
                state_root: root.finish(&mut |_, _| {}),
                entries: entries.len() as u64,
                ..SnapshotHeader::default()
            };
            let dir = scratch(&format!("genesis-out-{name}"));
            std::fs::create_dir_all(&dir).unwrap();
            Snapshot::write(&dir.join("x.snap"), &header, entries).unwrap()
        };
        // A store holding a genesis whose block hash is `hash`, if any.
        let genesis = |name: &str, hash: Option<&[u8]>| {
            let mut s = DiskStore::open(&scratch(&format!("genesis-{name}"))).unwrap();
            s.set(keys::CHAIN_ID, &7u64.to_bytes());
            if let Some(hash) = hash {
                s.set(&key, hash);
            }
            s.seal(0, None).unwrap();
            s
        };
        let other = |r: Result<(), SnapshotError>| {
            r.unwrap_err().to_string().contains("another genesis block")
        };
        let acct = (b"acct/a".to_vec(), b"1".to_vec());
        let ours = (key.clone(), [1u8; 32].to_vec());
        let theirs = (key.clone(), [2u8; 32].to_vec());
        // Another genesis hash, or none, is another chain, and the store
        // keeps its genesis.
        let mut s = genesis("other", Some(&[1; 32]));
        assert!(other(
            file("other", vec![acct.clone(), theirs.clone()]).import(&mut s)
        ));
        assert!(other(file("none", vec![acct.clone()]).import(&mut s)));
        assert_eq!(s.get(&key), Some([1u8; 32].to_vec()));
        // A store whose kernel stored no genesis block takes only a chain
        // without one.
        let mut bare = genesis("bare", None);
        assert!(other(
            file("bare-other", vec![acct.clone(), theirs]).import(&mut bare)
        ));
        file("bare", vec![acct.clone()]).import(&mut bare).unwrap();
        assert_eq!(bare.get(b"acct/a"), Some(b"1".to_vec()));
        // The same genesis loads.
        file("same", vec![acct, ours]).import(&mut s).unwrap();
        assert_eq!(s.get(b"acct/a"), Some(b"1".to_vec()));
        assert_eq!(s.head(), 1);
    }

    #[test]
    fn a_file_too_large_for_the_format_is_refused() {
        let header = SnapshotHeader::default();
        // The header always fits; an entry longer than u32 cannot be built
        // in a test, so the error paths of `write` end at the file system.
        let path = scratch("write").join("missing-dir").join("x.snap");
        assert!(matches!(
            Snapshot::write(&path, &header, Vec::new()),
            Err(SnapshotError::Io(_))
        ));
        assert_eq!(
            too_long(u32::try_from(u64::MAX).unwrap_err()).to_string(),
            "snapshot file: a length does not fit the format's u32"
        );
        let dir = scratch("write-ok");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.snap");
        let written = Snapshot::write(&path, &header, Vec::new()).unwrap();
        assert_eq!(Snapshot::open(&path).unwrap(), written);
        assert!(entries(&written).is_empty());
        // A reader that is done stays done.
        let mut reader = written.entries().unwrap();
        assert!(reader.next().is_none());
        assert!(reader.next().is_none());
        // A vote certificate's checks, one by one.
        let hash = [5; 32];
        let set = ValidatorSet {
            validators: Seq(vec![solo_abi::chain::Validator {
                id: [1; 32],
                weight: 1,
            }]),
        };
        let mut c = certificate(hash);
        assert!(!votes_certify(&c, &hash, 7, &set));
        c.kind = 1;
        assert!(!votes_certify(&c, &hash, 7, &set));
        c.kind = KIND_FINALIZE;
        c.votes.0[0].validator = 3;
        assert!(!votes_certify(&c, &hash, 7, &set));
        c.votes.0[0].validator = 0;
        c.votes.0.push(c.votes.0[0].clone());
        assert!(!votes_certify(&c, &hash, 7, &set));
        assert!(signer(&[0; 32], &[0; 65]).is_none());
        // Signed votes: two of three equal weights are no quorum, three are;
        // a validator named twice or a vote signed by another key is refused.
        let keys: Vec<k256::ecdsa::SigningKey> = (1..=3u8)
            .map(|i| k256::ecdsa::SigningKey::from_slice(&[i; 32]).unwrap())
            .collect();
        let id = |k: &k256::ecdsa::SigningKey| {
            keccak256(&k.verifying_key().to_encoded_point(false).as_bytes()[1..])
        };
        let set = ValidatorSet {
            validators: Seq(keys
                .iter()
                .map(|k| solo_abi::chain::Validator {
                    id: id(k),
                    weight: 1,
                })
                .collect()),
        };
        let digest = keccak256(&signing_preimage(KIND_FINALIZE, 7, 1, &hash));
        let vote = |i: u32, k: &k256::ecdsa::SigningKey| {
            let (sig, rid) = k.sign_prehash_recoverable(&digest).unwrap();
            let mut bytes = [0u8; 65];
            bytes[..64].copy_from_slice(&sig.to_bytes());
            bytes[64] = rid.to_byte();
            SignedVote {
                validator: i,
                signature: Signature(bytes),
            }
        };
        let mut c = certificate(hash);
        c.votes = Seq(vec![vote(0, &keys[0]), vote(1, &keys[1])]);
        assert!(!votes_certify(&c, &hash, 7, &set));
        c.votes.0.push(vote(2, &keys[2]));
        assert!(votes_certify(&c, &hash, 7, &set));
        c.votes.0[2] = vote(1, &keys[1]);
        assert!(!votes_certify(&c, &hash, 7, &set));
        c.votes.0[2] = vote(2, &keys[0]);
        assert!(!votes_certify(&c, &hash, 7, &set));
    }
}
