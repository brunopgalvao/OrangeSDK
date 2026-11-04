//! State sync (spec 22 §7.4, spec 09 §6): a node serves the snapshots it
//! exported to its peers, and a node that joins fetches one from them,
//! verifying it as it arrives, before its driver starts.
//!
//! A served snapshot is split by the first `depth` bits of the entries'
//! paths into `2^depth` *slices*. Its *manifest* is the header of the file
//! (spec 22 §7.1) and one summary per slice: empty, the one leaf, or the
//! hash of the slice's subtree. The joining node verifies the header under
//! its trust, checks that the summaries combine to the record's root, and
//! then fetches every slice in pages of at most [`CHUNK_BYTES`], each slice
//! from one peer, hashing it as it arrives and comparing it with its
//! summary. A leaf's summary names its path, so an accepted manifest binds
//! every slice: a slice that fails is the fault of the peer that sent it,
//! which is not asked again. Verified slices go to part files, which
//! outlive a restart; once all are in they are put together into a
//! snapshot file, which the node imports as it would any other.
//!
//! [`StateSync`] is the fetching side without any I/O but its files: the
//! transport (or the simulator) hands it the connected peers and the
//! answers, and sends the requests it returns. [`SnapshotServer`] is the
//! serving side.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use solo_abi::chain::keys;
use solo_abi::codec::{Decode, DecodeError, Decoder, Encode, Encoder, Seq};
use solo_store::{Snapshot, SnapshotError, SnapshotHeader, Trust};
use solo_trie::{EMPTY, Hash, NODE_LEN, SortedRoot, branch_hash, keccak256, leaf_hash};

/// Most bytes of keys and values in one page of a slice.
pub const CHUNK_BYTES: usize = 1 << 20;
/// A served snapshot is split into slices of about this many entries.
pub const SLICE_ENTRIES: u64 = 4_096;
/// Most path bits a manifest splits by: at most `2^16` slices.
pub const MAX_DEPTH: u8 = 16;
/// Most slices a joining node fetches at once.
pub const MAX_ACTIVE: usize = 8;
/// Most requests a joining node has outstanding with one peer.
pub const PER_PEER: usize = 2;
/// A request unanswered for this long is abandoned.
pub const REQUEST_TIMEOUT_MS: u64 = 10_000;
/// How long discovery waits for more offers after the first.
pub const OFFER_WAIT_MS: u64 = 1_000;
/// Requests in a row a peer may let time out before it is not asked again.
pub const MAX_STRIKES: u32 = 3;
/// How many epochs' snapshots a serving node keeps.
pub const SERVED: usize = 2;

/// How a server splits and pages what it serves; a joining node accepts
/// any depth up to [`MAX_DEPTH`] and any page of at least one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeLimits {
    /// Entries per slice on average: [`SLICE_ENTRIES`].
    pub slice_entries: u64,
    /// Bytes of keys and values per page: [`CHUNK_BYTES`].
    pub chunk_bytes: usize,
}

impl Default for ServeLimits {
    fn default() -> ServeLimits {
        ServeLimits {
            slice_entries: SLICE_ENTRIES,
            chunk_bytes: CHUNK_BYTES,
        }
    }
}

/// A request of the state sync.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum SyncRequest {
    /// The snapshots the peer serves.
    Offers,
    /// The header and manifest of one.
    Manifest { epoch: u64 },
    /// A page of one slice: its entries above `after`.
    Slice {
        epoch: u64,
        slice: u32,
        after: Option<Hash>,
    },
}

/// A snapshot a peer serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Offer {
    pub epoch: u64,
    pub height: u64,
    pub state_root: Hash,
    pub entries: u64,
}

/// What a slice of a manifest holds: nothing, one entry, or a subtree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Summary {
    Empty,
    Leaf { path: Hash, value_hash: Hash },
    Branch { hash: Hash },
}

/// A served snapshot's header and the summaries of its slices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The encoded [`SnapshotHeader`].
    pub header: Vec<u8>,
    /// How many path bits split the slices.
    pub depth: u8,
    /// One summary per slice, in slice order.
    pub slices: Vec<Summary>,
}

/// One entry of a page.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Entry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// An answer of the state sync.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum SyncResponse {
    /// The snapshots served, newest first.
    Offers(Vec<Offer>),
    Manifest(Manifest),
    /// A page of a slice, and whether more of it follows.
    Slice {
        entries: Vec<Entry>,
        more: bool,
    },
    /// The epoch asked for is not served.
    Unavailable,
}

impl Encode for SyncRequest {
    fn encode(&self, e: &mut Encoder) {
        match self {
            SyncRequest::Offers => e.raw(&[0]),
            SyncRequest::Manifest { epoch } => {
                e.raw(&[1]);
                e.put(epoch);
            }
            SyncRequest::Slice {
                epoch,
                slice,
                after,
            } => {
                e.raw(&[2]);
                e.put(epoch).put(slice).put(after);
            }
        }
    }
}

impl Decode for SyncRequest {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(match d.raw(1)?[0] {
            0 => SyncRequest::Offers,
            1 => SyncRequest::Manifest { epoch: d.get()? },
            2 => SyncRequest::Slice {
                epoch: d.get()?,
                slice: d.get()?,
                after: d.get()?,
            },
            tag => return Err(DecodeError::BadTag(tag)),
        })
    }
}

impl Encode for Offer {
    fn encode(&self, e: &mut Encoder) {
        e.put(&self.epoch)
            .put(&self.height)
            .put(&self.state_root)
            .put(&self.entries);
    }
}

impl Decode for Offer {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Offer {
            epoch: d.get()?,
            height: d.get()?,
            state_root: d.get()?,
            entries: d.get()?,
        })
    }
}

impl Encode for Summary {
    fn encode(&self, e: &mut Encoder) {
        match self {
            Summary::Empty => e.raw(&[0]),
            Summary::Leaf { path, value_hash } => {
                e.raw(&[1]);
                e.put(path).put(value_hash);
            }
            Summary::Branch { hash } => {
                e.raw(&[2]);
                e.put(hash);
            }
        }
    }
}

impl Decode for Summary {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(match d.raw(1)?[0] {
            0 => Summary::Empty,
            1 => Summary::Leaf {
                path: d.get()?,
                value_hash: d.get()?,
            },
            2 => Summary::Branch { hash: d.get()? },
            tag => return Err(DecodeError::BadTag(tag)),
        })
    }
}

impl Encode for Manifest {
    fn encode(&self, e: &mut Encoder) {
        e.put(&self.header)
            .put(&self.depth)
            .put(&Seq(self.slices.clone()));
    }
}

impl Decode for Manifest {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Manifest {
            header: d.get()?,
            depth: d.get()?,
            slices: d.get::<Seq<Summary>>()?.0,
        })
    }
}

impl Encode for Entry {
    fn encode(&self, e: &mut Encoder) {
        e.put(&self.key).put(&self.value);
    }
}

impl Decode for Entry {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Entry {
            key: d.get()?,
            value: d.get()?,
        })
    }
}

impl Encode for SyncResponse {
    fn encode(&self, e: &mut Encoder) {
        match self {
            SyncResponse::Offers(offers) => {
                e.raw(&[0]);
                e.put(&Seq(offers.clone()));
            }
            SyncResponse::Manifest(manifest) => {
                e.raw(&[1]);
                e.put(manifest);
            }
            SyncResponse::Slice { entries, more } => {
                e.raw(&[2]);
                e.put(&Seq(entries.clone())).put(more);
            }
            SyncResponse::Unavailable => e.raw(&[3]),
        }
    }
}

impl Decode for SyncResponse {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(match d.raw(1)?[0] {
            0 => SyncResponse::Offers(d.get::<Seq<Offer>>()?.0),
            1 => SyncResponse::Manifest(d.get()?),
            2 => SyncResponse::Slice {
                entries: d.get::<Seq<Entry>>()?.0,
                more: d.get()?,
            },
            3 => SyncResponse::Unavailable,
            tag => return Err(DecodeError::BadTag(tag)),
        })
    }
}

/// The smallest depth at which the slices of `entries` entries hold at most
/// `per_slice` each on average, at most [`MAX_DEPTH`].
#[must_use]
pub fn depth_for(entries: u64, per_slice: u64) -> u8 {
    let mut depth = 0;
    while depth < MAX_DEPTH && entries > per_slice << depth {
        depth += 1;
    }
    depth
}

/// The slice of `path` at `depth`: its first `depth` bits.
#[must_use]
pub fn slice_of(path: &Hash, depth: u8) -> u32 {
    let top = u32::from_be_bytes([path[0], path[1], path[2], path[3]]);
    top.checked_shr(32 - u32::from(depth)).unwrap_or(0)
}

/// The node hash a summary stands for.
fn summary_hash(summary: &Summary) -> Hash {
    match summary {
        Summary::Empty => EMPTY,
        Summary::Leaf { path, value_hash } => leaf_hash(keccak256, path, value_hash),
        Summary::Branch { hash } => *hash,
    }
}

/// The summary of the two halves of a subtree (spec 22 §7.4): a leaf beside
/// an empty half moves up, as spec 10 §4 places it as high as possible.
fn join(left: &Summary, right: &Summary) -> Summary {
    match (left, right) {
        (Summary::Empty, other @ (Summary::Empty | Summary::Leaf { .. }))
        | (other @ Summary::Leaf { .. }, Summary::Empty) => *other,
        _ => Summary::Branch {
            hash: branch_hash(keccak256, &summary_hash(left), &summary_hash(right)),
        },
    }
}

/// The root the summaries of `2^depth` slices combine to.
#[must_use]
pub fn combine(slices: &[Summary]) -> Hash {
    let mut level = slices.to_vec();
    while level.len() > 1 {
        level = level.chunks(2).map(|p| join(&p[0], &p[1])).collect();
    }
    level.first().map_or(EMPTY, summary_hash)
}

/// Reads one entry in the snapshot file's encoding.
fn read_entry(file: &mut BufReader<File>) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut part = || -> io::Result<Vec<u8>> {
        let mut word = [0u8; 4];
        file.read_exact(&mut word)?;
        let mut bytes = vec![0u8; u32::from_le_bytes(word) as usize];
        file.read_exact(&mut bytes)?;
        Ok(bytes)
    };
    Ok((part()?, part()?))
}

/// Writes one entry in the snapshot file's encoding.
fn write_entry(out: &mut BufWriter<Box<dyn Write>>, key: &[u8], value: &[u8]) -> io::Result<()> {
    for part in [key, value] {
        let len = u32::try_from(part.len()).map_err(io::Error::other)?;
        out.write_all(&len.to_le_bytes())?;
        out.write_all(part)?;
    }
    Ok(())
}

/// A snapshot a node serves: the file, its manifest, and where each slice
/// starts in the file with how many entries it holds.
#[derive(Debug)]
struct Served {
    snapshot: Snapshot,
    manifest: Manifest,
    starts: Vec<(u64, u64)>,
    chunk_bytes: usize,
}

impl Served {
    /// Computes the manifest of `snapshot` in one pass over its entries.
    fn index(snapshot: Snapshot, limits: ServeLimits) -> Result<Served, SnapshotError> {
        let depth = depth_for(snapshot.header.entries, limits.slice_entries);
        let mut starts = vec![(0, 0); 1 << depth];
        let mut slices = vec![Summary::Empty; 1 << depth];
        let mut offset = snapshot.body_offset();
        let mut last: Option<Hash> = None;
        // The slice being read: its index, first entry and running root.
        let mut open: Option<(u32, Summary, SortedRoot)> = None;
        let mut close = |open: Option<(u32, Summary, SortedRoot)>, starts: &[(u64, u64)]| {
            if let Some((slice, first, root)) = open {
                slices[slice as usize] = if starts[slice as usize].1 == 1 {
                    first
                } else {
                    Summary::Branch {
                        hash: root.finish_at(usize::from(depth), &mut |_, _| {}),
                    }
                };
            }
        };
        for entry in snapshot.entries()? {
            let (key, value) = entry?;
            let (path, value_hash) = (keccak256(&key), keccak256(&value));
            if last.is_some_and(|l| path <= l) {
                return Err(SnapshotError::Verify("the entries are not in path order"));
            }
            last = Some(path);
            let slice = slice_of(&path, depth);
            if open.as_ref().is_none_or(|(s, _, _)| *s != slice) {
                close(open.take(), &starts);
                starts[slice as usize].0 = offset;
                let first = Summary::Leaf { path, value_hash };
                open = Some((slice, first, SortedRoot::new(keccak256)));
            }
            let (_, _, root) = open.as_mut().expect("opened above");
            root.push(path, value_hash, &mut |_, _| {})
                .expect("paths ascend, checked above");
            starts[slice as usize].1 += 1;
            offset += 8 + key.len() as u64 + value.len() as u64;
        }
        close(open, &starts);
        Ok(Served {
            manifest: Manifest {
                header: snapshot.header.to_bytes(),
                depth,
                slices,
            },
            snapshot,
            starts,
            chunk_bytes: limits.chunk_bytes,
        })
    }

    fn offer(&self) -> Offer {
        let h = &self.snapshot.header;
        Offer {
            epoch: h.epoch,
            height: h.height,
            state_root: h.state_root,
            entries: h.entries,
        }
    }

    /// A page of `slice`: its entries above `after`, as many as fit in
    /// the limits' bytes, at least one.
    fn page(&self, slice: u32, after: Option<Hash>) -> io::Result<SyncResponse> {
        let (start, count) = *self
            .starts
            .get(slice as usize)
            .ok_or_else(|| io::Error::other("no such slice"))?;
        let mut file = BufReader::new(File::open(self.snapshot.path())?);
        file.seek(SeekFrom::Start(start))?;
        let mut entries = Vec::new();
        let mut bytes = 0;
        for left in (0..count).rev() {
            let (key, value) = read_entry(&mut file)?;
            if after.is_some_and(|a| keccak256(&key) <= a) {
                continue;
            }
            bytes += key.len() + value.len();
            entries.push(Entry { key, value });
            if bytes >= self.chunk_bytes && left > 0 {
                return Ok(SyncResponse::Slice {
                    entries,
                    more: true,
                });
            }
        }
        Ok(SyncResponse::Slice {
            entries,
            more: false,
        })
    }
}

/// The answer to the request `payload` from the snapshots `served`, newest
/// first: `Unavailable` for an epoch not served, a slice not in it or a
/// file that can no longer be read, and for a request that does not decode.
fn answer(served: &[Served], payload: &[u8]) -> Vec<u8> {
    let find = |epoch: u64| served.iter().find(|s| s.snapshot.header.epoch == epoch);
    let response = match SyncRequest::from_bytes(payload) {
        Ok(SyncRequest::Offers) => SyncResponse::Offers(served.iter().map(Served::offer).collect()),
        Ok(SyncRequest::Manifest { epoch }) => find(epoch).map_or(SyncResponse::Unavailable, |s| {
            SyncResponse::Manifest(s.manifest.clone())
        }),
        Ok(SyncRequest::Slice {
            epoch,
            slice,
            after,
        }) => find(epoch)
            .and_then(|s| s.page(slice, after).ok())
            .unwrap_or(SyncResponse::Unavailable),
        Err(_) => SyncResponse::Unavailable,
    };
    response.to_bytes()
}

/// The answer of a node that serves no snapshot: no offers, and
/// `Unavailable` to anything else.
#[must_use]
pub fn answer_unserved(payload: &[u8]) -> Vec<u8> {
    answer(&[], payload)
}

/// The snapshots a node serves from its directory (spec 22 §7.4).
#[derive(Debug)]
pub struct SnapshotServer {
    dir: PathBuf,
    limits: ServeLimits,
    /// Newest first, at most [`SERVED`].
    served: Vec<Served>,
    /// How many finalized heights the node had when it last looked for a
    /// newer record; none yet at first.
    pub(crate) checked: u64,
}

impl SnapshotServer {
    /// Serves the snapshot files in `dir`, creating it if need be: the
    /// [`SERVED`] newest epochs whose files open and read, deleting the
    /// rest, split and paged within `limits`.
    ///
    /// # Errors
    /// [`SnapshotError::Io`] when the directory cannot be made or read.
    pub fn open(dir: &Path, limits: ServeLimits) -> Result<SnapshotServer, SnapshotError> {
        let io = |e: io::Error| SnapshotError::Io(e.to_string());
        fs::create_dir_all(dir).map_err(io)?;
        let mut server = SnapshotServer {
            dir: dir.to_path_buf(),
            limits,
            served: Vec::new(),
            checked: u64::MAX,
        };
        for entry in fs::read_dir(dir).map_err(io)? {
            let path = entry.map_err(io)?.path();
            // Anything else in the directory is left alone; a snapshot that
            // does not read, such as an export cut short, goes.
            let added = Snapshot::open(&path).and_then(|s| server.add(s));
            if added.is_err() && path.extension().is_some_and(|x| x == "snap") {
                let _ = fs::remove_file(&path);
            }
        }
        Ok(server)
    }

    /// Where the snapshot of `epoch` is written.
    #[must_use]
    pub fn path_for(&self, epoch: u64) -> PathBuf {
        self.dir.join(format!("epoch-{epoch}.snap"))
    }

    /// Serves `snapshot` too, dropping (and deleting) the oldest beyond
    /// [`SERVED`].
    ///
    /// # Errors
    /// What reading its entries reports.
    pub fn add(&mut self, snapshot: Snapshot) -> Result<(), SnapshotError> {
        let served = Served::index(snapshot, self.limits)?;
        self.served.push(served);
        self.served
            .sort_by_key(|s| std::cmp::Reverse(s.snapshot.header.epoch));
        for old in self.served.split_off(SERVED.min(self.served.len())) {
            let _ = fs::remove_file(old.snapshot.path());
        }
        Ok(())
    }

    /// The newest epoch served.
    #[must_use]
    pub fn newest(&self) -> Option<u64> {
        self.served.first().map(|s| s.snapshot.header.epoch)
    }

    /// What this server offers, newest first.
    #[must_use]
    pub fn offers(&self) -> Vec<Offer> {
        self.served.iter().map(Served::offer).collect()
    }

    /// The answer to the request `payload`.
    #[must_use]
    pub fn answer(&self, payload: &[u8]) -> Vec<u8> {
        answer(&self.served, payload)
    }
}

/// What the joining node trusts and where it works.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// The chain's id, from its genesis.
    pub chain_id: u64,
    /// The trust a snapshot's header must verify under (spec 22 §7.2).
    pub trust: Trust,
    /// What the local `kernel_init` stored at `bnum/` ‖ 0, which the
    /// snapshot's state must hold too (spec 22 §7.3).
    pub genesis_hash: Option<Vec<u8>>,
    /// The working directory: the accepted manifest, the verified slices
    /// and, at the end, the snapshot file.
    pub dir: PathBuf,
}

/// Something the state sync did that its operator may want to hear about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncEvent {
    /// The snapshot it fetches.
    Target(Offer),
    /// Verified slices it found on disk from an earlier run.
    Resumed {
        /// How many.
        slices: usize,
    },
    /// An offer whose certificate the trusted key does not verify, set
    /// aside for the rest of the sync: it may predate the key set the node
    /// trusts (spec 22 §7.4).
    SetAside {
        /// The peer that sent its manifest.
        peer: [u8; 32],
        /// Its epoch.
        epoch: u64,
    },
    /// A peer it no longer asks, and why.
    Banned {
        /// The peer.
        peer: [u8; 32],
        /// What it did.
        why: &'static str,
    },
}

/// Why [`SnapshotHeader::verify`] refuses a threshold certificate that is
/// well formed and the anchoring proposal's but signed by another key set
/// than the trusted one.
const UNTRUSTED_CERTIFICATE: &str =
    "the threshold certificate does not verify under the trusted key";

/// A manifest whose certificate the trusted key does not verify.
const UNTRUSTED: &str = "a snapshot whose certificate the trusted key does not verify";

/// What a joining node knows of a peer.
#[derive(Debug, Default)]
struct Peer {
    offers: Option<Vec<Offer>>,
    /// When its offers came.
    answered_ms: u64,
    asked: bool,
    strikes: u32,
    banned: bool,
    busy: usize,
    /// Manifests of its that the trusted key did not verify.
    untrusted: u32,
    /// Its last offers were all set aside: it keeps the sync going no
    /// more than a banned peer, until it offers something else.
    stale: bool,
}

/// What a request asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    Offers,
    Manifest,
    Slice(u32),
}

#[derive(Debug)]
struct Pending {
    peer: [u8; 32],
    sent_ms: u64,
    asked: Asked,
}

/// A slice being fetched.
struct Active {
    peer: [u8; 32],
    root: Option<SortedRoot>,
    last: Option<Hash>,
    count: u64,
    file: BufWriter<Box<dyn Write>>,
    /// Whether a page is asked for and not yet in.
    waiting: bool,
    /// The genesis hash, when the slice holds its key.
    genesis: Option<Vec<u8>>,
}

/// The snapshot being fetched, once its manifest is accepted.
struct Fetch {
    offer: Offer,
    header: SnapshotHeader,
    depth: u8,
    slices: Vec<Summary>,
    todo: VecDeque<u32>,
    active: BTreeMap<u32, Active>,
    /// Verified slices and their entry counts.
    done: BTreeMap<u32, u64>,
    genesis_slice: u32,
}

enum Phase {
    Discover,
    Manifest(Offer),
    Fetch(Box<Fetch>),
    Done(Box<Snapshot>),
    Failed(String),
}

/// Bad data from a peer, or a local failure that ends the sync.
enum Fault {
    Peer(&'static str),
    Local(String),
}

impl From<io::Error> for Fault {
    fn from(e: io::Error) -> Fault {
        Fault::Local(e.to_string())
    }
}

/// The key the genesis hash is stored under.
fn genesis_key() -> Vec<u8> {
    [keys::BLOCK_NUMBER, &0u64.to_be_bytes()[..]].concat()
}

/// A joining node's state sync (spec 22 §7.4).
pub struct StateSync {
    config: SyncConfig,
    peers: BTreeMap<[u8; 32], Peer>,
    pending: BTreeMap<u64, Pending>,
    next_id: u64,
    first_answer: Option<u64>,
    phase: Phase,
    /// The manifest an earlier run accepted, read from the directory.
    saved: Option<Manifest>,
    /// Whether the manifest of the target is asked for, in that phase.
    manifest_asked: bool,
    /// Offers whose certificate the trusted key did not verify.
    set_aside: BTreeSet<(u64, u64, Hash)>,
    events: Vec<SyncEvent>,
}

impl StateSync {
    /// A state sync working in `config.dir`, which keeps what an earlier
    /// sync there verified.
    ///
    /// # Errors
    /// When the directory cannot be made.
    pub fn new(config: SyncConfig) -> io::Result<StateSync> {
        fs::create_dir_all(config.dir.join("parts"))?;
        let saved = fs::read(config.dir.join("manifest"))
            .ok()
            .and_then(|b| Manifest::from_bytes(&b).ok());
        Ok(StateSync {
            config,
            peers: BTreeMap::new(),
            pending: BTreeMap::new(),
            next_id: 0,
            first_answer: None,
            phase: Phase::Discover,
            saved,
            manifest_asked: false,
            set_aside: BTreeSet::new(),
            events: Vec::new(),
        })
    }

    /// The snapshot file, once every slice is in.
    #[must_use]
    pub fn done(&self) -> Option<&Snapshot> {
        match &self.phase {
            Phase::Done(snapshot) => Some(snapshot),
            _ => None,
        }
    }

    /// Why the sync stopped, if it did.
    #[must_use]
    pub fn failed(&self) -> Option<&str> {
        match &self.phase {
            Phase::Failed(why) => Some(why),
            _ => None,
        }
    }

    /// Whether `peer` is no longer asked during this sync (spec 09 §6).
    #[must_use]
    pub fn drops(&self, peer: &[u8; 32]) -> bool {
        self.peers.get(peer).is_some_and(|p| p.banned || p.stale)
    }

    /// Whether every one of `offers` is set aside, and there is one.
    fn all_set_aside(set_aside: &BTreeSet<(u64, u64, Hash)>, offers: &[Offer]) -> bool {
        !offers.is_empty()
            && offers
                .iter()
                .all(|o| set_aside.contains(&(o.epoch, o.height, o.state_root)))
    }

    /// Slices verified and slices in all, once a manifest is accepted.
    #[must_use]
    pub fn progress(&self) -> Option<(usize, usize)> {
        match &self.phase {
            Phase::Fetch(f) => Some((
                f.done.len(),
                f.slices.iter().filter(|s| **s != Summary::Empty).count(),
            )),
            _ => None,
        }
    }

    /// What happened since the last call.
    pub fn take_events(&mut self) -> Vec<SyncEvent> {
        std::mem::take(&mut self.events)
    }

    /// Moves the sync on at `now_ms` with `connected` the peers it can
    /// reach: abandons the requests of peers gone or too slow, and returns
    /// the requests to send, as `(peer, request id, payload)`.
    pub fn poll(&mut self, now_ms: u64, connected: &[[u8; 32]]) -> Vec<([u8; 32], u64, Vec<u8>)> {
        if matches!(self.phase, Phase::Done(_) | Phase::Failed(_)) {
            return Vec::new();
        }
        let gone: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| !connected.contains(&p.peer))
            .map(|(id, _)| *id)
            .collect();
        for id in gone {
            self.cancel(id, false);
        }
        let late: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| now_ms >= p.sent_ms + REQUEST_TIMEOUT_MS)
            .map(|(id, _)| *id)
            .collect();
        for id in late {
            self.cancel(id, true);
        }
        let mut out = Vec::new();
        for peer in connected {
            let p = self.peers.entry(*peer).or_default();
            if !p.banned && p.offers.is_none() && !p.asked {
                p.asked = true;
                out.push(self.send(*peer, now_ms, Asked::Offers, &SyncRequest::Offers));
            }
        }
        if matches!(self.phase, Phase::Discover) {
            self.choose(now_ms, connected);
        }
        let sources = self.sources(connected);
        let manifest = match &self.phase {
            Phase::Manifest(offer) if !self.manifest_asked && !sources.is_empty() => {
                self.manifest_asked = true;
                Some(SyncRequest::Manifest { epoch: offer.epoch })
            }
            _ => None,
        };
        if let Some(request) = manifest {
            out.push(self.send(sources[0], now_ms, Asked::Manifest, &request));
        }
        self.schedule(now_ms, &sources, &mut out);
        // Nobody offers the target any more: choose again.
        let stranded = self.target().is_some_and(|t| {
            !self
                .peers
                .values()
                .any(|p| !p.banned && p.offers.as_ref().is_some_and(|o| o.contains(&t)))
        });
        if stranded {
            self.rediscover();
        }
        out
    }

    /// Hands the sync `payload`, the answer `peer` gave to request `id`.
    ///
    /// # Panics
    /// Never: a pending request's peer is known.
    pub fn on_response(&mut self, peer: [u8; 32], id: u64, payload: &[u8], now_ms: u64) {
        // An answer to a request abandoned, or another peer's, is dropped.
        if self.pending.get(&id).is_none_or(|p| p.peer != peer) {
            return;
        }
        let pending = self.pending.remove(&id).expect("checked above");
        let target = self.target();
        let p = self.peers.get_mut(&peer).expect("asked peers are known");
        p.busy -= 1;
        p.strikes = 0;
        match (pending.asked, SyncResponse::from_bytes(payload)) {
            (Asked::Offers, Ok(SyncResponse::Offers(offers))) => {
                p.stale = Self::all_set_aside(&self.set_aside, &offers);
                p.offers = Some(offers);
                p.answered_ms = now_ms;
                self.first_answer.get_or_insert(now_ms);
            }
            (Asked::Manifest, Ok(SyncResponse::Manifest(manifest))) => {
                self.on_manifest(peer, &manifest);
            }
            (Asked::Slice(slice), Ok(SyncResponse::Slice { entries, more })) => {
                self.on_slice(peer, slice, &entries, more);
            }
            (asked, Ok(SyncResponse::Unavailable)) => {
                let offers = p.offers.get_or_insert_with(Vec::new);
                offers.retain(|o| Some(*o) != target);
                self.requeue(peer, asked);
            }
            (asked, Ok(_)) => self.ban(peer, asked, "an answer of another kind than asked"),
            (asked, Err(_)) => self.ban(peer, asked, "an answer that does not decode"),
        }
    }

    fn send(
        &mut self,
        peer: [u8; 32],
        now_ms: u64,
        asked: Asked,
        request: &SyncRequest,
    ) -> ([u8; 32], u64, Vec<u8>) {
        self.next_id += 1;
        self.peers.get_mut(&peer).expect("known").busy += 1;
        self.pending.insert(
            self.next_id,
            Pending {
                peer,
                sent_ms: now_ms,
                asked,
            },
        );
        (peer, self.next_id, request.to_bytes())
    }

    /// The offer being fetched, past discovery.
    fn target(&self) -> Option<Offer> {
        match &self.phase {
            Phase::Manifest(offer) => Some(*offer),
            Phase::Fetch(f) => Some(f.offer),
            _ => None,
        }
    }

    /// The connected peers, not banned, that offer the target, least busy
    /// first.
    fn sources(&self, connected: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let Some(target) = self.target() else {
            return Vec::new();
        };
        let mut sources: Vec<[u8; 32]> = connected
            .iter()
            .filter(|id| {
                self.peers[*id]
                    .offers
                    .as_ref()
                    .is_some_and(|o| o.contains(&target))
                    && !self.peers[*id].banned
            })
            .copied()
            .collect();
        sources.sort_by_key(|id| self.peers[id].busy);
        sources
    }

    /// Picks the target once every connected peer answered, or a while
    /// after the first did: the newest epoch offered, and of its offers the
    /// one the most peers name.
    fn choose(&mut self, now_ms: u64, connected: &[[u8; 32]]) {
        let peers: Vec<&Peer> = connected
            .iter()
            .map(|id| &self.peers[id])
            .filter(|p| !p.banned)
            .collect();
        let answered = peers.iter().all(|p| p.offers.is_some());
        let waited = self
            .first_answer
            .is_some_and(|t| now_ms >= t + OFFER_WAIT_MS);
        if !(answered || waited) {
            return;
        }
        let mut tally: BTreeMap<(u64, u64, Hash), (usize, Offer)> = BTreeMap::new();
        for offer in peers.iter().filter_map(|p| p.offers.as_ref()).flatten() {
            let key = (offer.epoch, offer.height, offer.state_root);
            if !self.set_aside.contains(&key) {
                tally.entry(key).or_insert((0, *offer)).0 += 1;
            }
        }
        let Some((_, offer)) = tally
            .into_iter()
            .max_by_key(|((epoch, _, _), (count, _))| (*epoch, *count))
            .map(|(_, v)| v)
        else {
            // Nobody serves anything yet: ask again a while after each
            // answer.
            for p in self.peers.values_mut() {
                if p.offers.is_some() && now_ms >= p.answered_ms + OFFER_WAIT_MS {
                    p.offers = None;
                    p.asked = false;
                }
            }
            return;
        };
        self.events.push(SyncEvent::Target(offer));
        let resumed = self.saved.take().and_then(|m| {
            let header = self.verify_manifest(&offer, &m).ok()?;
            Some((header, m))
        });
        if let Some((header, manifest)) = resumed {
            let done = self.parts_on_disk();
            self.events.push(SyncEvent::Resumed { slices: done.len() });
            self.enter_fetch(offer, header, manifest, done);
        } else {
            self.manifest_asked = false;
            self.phase = Phase::Manifest(offer);
        }
    }

    /// The verified slices an earlier run left, by their file names
    /// (`slice-count`); anything else there goes.
    fn parts_on_disk(&self) -> BTreeMap<u32, u64> {
        let mut done = BTreeMap::new();
        for entry in fs::read_dir(self.config.dir.join("parts"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            let parsed = name
                .split_once('-')
                .and_then(|(s, c)| Some((s.parse().ok()?, c.parse().ok()?)));
            match parsed {
                Some((slice, count)) => {
                    done.insert(slice, count);
                }
                None => {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        done
    }

    /// Checks `manifest` for `offer` (spec 22 §7.4, step 2).
    fn verify_manifest(
        &self,
        offer: &Offer,
        manifest: &Manifest,
    ) -> Result<SnapshotHeader, &'static str> {
        let header = SnapshotHeader::from_bytes(&manifest.header)
            .map_err(|_| "a manifest whose header does not decode")?;
        if (header.epoch, header.height, header.state_root)
            != (offer.epoch, offer.height, offer.state_root)
        {
            return Err("a manifest of another snapshot than offered");
        }
        header
            .verify(self.config.chain_id, &self.config.trust)
            .map_err(|e| match e {
                SnapshotError::Verify(UNTRUSTED_CERTIFICATE) => UNTRUSTED,
                _ => "a snapshot header that does not verify under the node's trust",
            })?;
        if manifest.depth > MAX_DEPTH || manifest.slices.len() != 1 << manifest.depth {
            return Err("a manifest of the wrong shape");
        }
        let misplaced = (0..).zip(&manifest.slices).any(
            |(i, s)| matches!(s, Summary::Leaf { path, .. } if slice_of(path, manifest.depth) != i),
        );
        if misplaced {
            return Err("a manifest with a leaf outside its slice");
        }
        if combine(&manifest.slices) != header.state_root {
            return Err("a manifest that does not combine to the snapshot's root");
        }
        Ok(header)
    }

    fn on_manifest(&mut self, peer: [u8; 32], manifest: &Manifest) {
        let Some(offer) = self.target() else { return };
        match self.verify_manifest(&offer, manifest) {
            Ok(header) => {
                // A new target: what an earlier run fetched is of another.
                let dir = &self.config.dir;
                let _ = fs::remove_dir_all(dir.join("parts"));
                let written = fs::create_dir_all(dir.join("parts"))
                    .and_then(|()| fs::write(dir.join("manifest"), manifest.to_bytes()));
                match written {
                    Ok(()) => self.enter_fetch(offer, header, manifest.clone(), BTreeMap::new()),
                    Err(e) => self.phase = Phase::Failed(e.to_string()),
                }
            }
            // The key the node trusts may be newer than the snapshot's
            // certificate: the snapshot is set aside, and the next epoch's
            // may verify. A peer whose second manifest fails so is banned.
            Err(UNTRUSTED) => {
                self.set_aside
                    .insert((offer.epoch, offer.height, offer.state_root));
                for p in self.peers.values_mut() {
                    if let Some(offers) = &p.offers {
                        p.stale = Self::all_set_aside(&self.set_aside, offers);
                    }
                }
                let p = self.peers.get_mut(&peer).expect("asked peers are known");
                p.untrusted += 1;
                if p.untrusted > 1 {
                    self.ban(peer, Asked::Manifest, UNTRUSTED);
                } else {
                    self.events.push(SyncEvent::SetAside {
                        peer,
                        epoch: offer.epoch,
                    });
                }
                self.rediscover();
            }
            Err(why) => {
                self.ban(peer, Asked::Manifest, why);
                self.rediscover();
            }
        }
    }

    fn enter_fetch(
        &mut self,
        offer: Offer,
        header: SnapshotHeader,
        manifest: Manifest,
        done: BTreeMap<u32, u64>,
    ) {
        let genesis_slice = slice_of(&keccak256(&genesis_key()), manifest.depth);
        let mut todo: VecDeque<u32> = (0..)
            .zip(&manifest.slices)
            .filter(|(i, s)| **s != Summary::Empty && !done.contains_key(i))
            .map(|(i, _)| i)
            .collect();
        if let Some(at) = todo.iter().position(|s| *s == genesis_slice) {
            todo.remove(at);
            todo.push_front(genesis_slice);
        }
        let empty_genesis = manifest.slices[genesis_slice as usize] == Summary::Empty;
        self.phase = Phase::Fetch(Box::new(Fetch {
            offer,
            header,
            depth: manifest.depth,
            slices: manifest.slices,
            todo,
            active: BTreeMap::new(),
            done,
            genesis_slice,
        }));
        if empty_genesis {
            self.check_genesis(None);
        }
        self.assemble_if_done();
    }

    /// Fails the sync unless `found` is the genesis hash the local
    /// `kernel_init` stored.
    fn check_genesis(&mut self, found: Option<&Vec<u8>>) {
        if found != self.config.genesis_hash.as_ref() {
            self.phase =
                Phase::Failed("the snapshot is of a chain with another genesis block".to_owned());
        }
    }

    /// Asks for the next page of every slice whose last page is in, then
    /// starts slices while there is room, the genesis slice alone until it
    /// is verified.
    fn schedule(
        &mut self,
        now_ms: u64,
        sources: &[[u8; 32]],
        out: &mut Vec<([u8; 32], u64, Vec<u8>)>,
    ) {
        let Phase::Fetch(f) = &mut self.phase else {
            return;
        };
        let mut requests = Vec::new();
        for (slice, active) in &mut f.active {
            if !active.waiting {
                active.waiting = true;
                requests.push((active.peer, *slice, active.last));
            }
        }
        let parts = self.config.dir.join("parts");
        let gated = !f.done.contains_key(&f.genesis_slice)
            && f.slices[f.genesis_slice as usize] != Summary::Empty;
        let mut sources = sources.to_vec();
        let mut failed = None;
        while f.active.len() < MAX_ACTIVE
            && !(gated && f.active.contains_key(&f.genesis_slice))
            && let Some(&slice) = f.todo.front()
        {
            let busy = |id: &[u8; 32]| {
                self.peers[id].busy + requests.iter().filter(|(p, _, _)| p == id).count()
            };
            sources.sort_by_key(busy);
            let Some(peer) = sources.first().copied().filter(|p| busy(p) < PER_PEER) else {
                break;
            };
            let file = match File::create(parts.join(format!("{slice}.tmp"))) {
                Ok(file) => BufWriter::new(Box::new(file) as Box<dyn Write>),
                Err(e) => {
                    failed = Some(e.to_string());
                    break;
                }
            };
            f.todo.pop_front();
            f.active.insert(
                slice,
                Active {
                    peer,
                    root: Some(SortedRoot::new(keccak256)),
                    last: None,
                    count: 0,
                    file,
                    waiting: true,
                    genesis: None,
                },
            );
            requests.push((peer, slice, None));
        }
        let epoch = f.offer.epoch;
        if let Some(why) = failed {
            self.phase = Phase::Failed(why);
            return;
        }
        for (peer, slice, after) in requests {
            let request = SyncRequest::Slice {
                epoch,
                slice,
                after,
            };
            out.push(self.send(peer, now_ms, Asked::Slice(slice), &request));
        }
    }

    fn on_slice(&mut self, peer: [u8; 32], slice: u32, entries: &[Entry], more: bool) {
        let parts = self.config.dir.join("parts");
        // Slices are asked for in the fetch phase, and leaving it drops
        // their requests.
        let f = self
            .fetch_mut()
            .expect("slices are answered while fetching");
        let summary = f.slices[slice as usize];
        let depth = f.depth;
        let active = f
            .active
            .get_mut(&slice)
            .expect("a slice asked for is active");
        match Self::ingest(active, &parts, slice, depth, &summary, entries, more) {
            Ok(None) => active.waiting = false,
            Ok(Some(count)) => {
                let active = f.active.remove(&slice).expect("active");
                f.done.insert(slice, count);
                if slice == f.genesis_slice {
                    self.check_genesis(active.genesis.as_ref());
                }
                self.assemble_if_done();
            }
            Err(Fault::Peer(why)) => self.ban(peer, Asked::Slice(slice), why),
            Err(Fault::Local(why)) => self.phase = Phase::Failed(why),
        }
    }

    /// The snapshot being fetched, in the fetch phase.
    fn fetch_mut(&mut self) -> Option<&mut Fetch> {
        match &mut self.phase {
            Phase::Fetch(f) => Some(f),
            _ => None,
        }
    }

    /// Takes a page of `slice` into `active`: `Some(count)` when the slice
    /// is complete and verified.
    fn ingest(
        active: &mut Active,
        parts: &Path,
        slice: u32,
        depth: u8,
        summary: &Summary,
        entries: &[Entry],
        more: bool,
    ) -> Result<Option<u64>, Fault> {
        if entries.is_empty() && more {
            return Err(Fault::Peer("a page with no entry that says more follow"));
        }
        let genesis = genesis_key();
        let root = active
            .root
            .as_mut()
            .expect("a slice in progress has a root");
        for Entry { key, value } in entries {
            if !solo_host::storage::committed(key) {
                return Err(Fault::Peer("a node-local entry"));
            }
            let path = keccak256(key);
            if slice_of(&path, depth) != slice {
                return Err(Fault::Peer("an entry outside its slice"));
            }
            root.push(path, keccak256(value), &mut |_, _| {})
                .map_err(|_| Fault::Peer("entries out of path order"))?;
            if *key == genesis {
                active.genesis = Some(value.clone());
            }
            write_entry(&mut active.file, key, value)?;
            active.last = Some(path);
            active.count += 1;
        }
        if more {
            return Ok(None);
        }
        let root = active.root.take().expect("taken once, at the end");
        let mut none = |_: &Hash, _: &[u8; NODE_LEN]| {};
        if root.finish_at(usize::from(depth), &mut none) != summary_hash(summary) {
            return Err(Fault::Peer("a slice that does not hash to its summary"));
        }
        // Verified: the part file is flushed and renamed into place.
        active.file.flush()?;
        let count = active.count;
        let tmp = parts.join(format!("{slice}.tmp"));
        fs::rename(tmp, parts.join(format!("{slice}-{count}")))?;
        Ok(Some(count))
    }

    /// Puts the snapshot file together once every slice is verified.
    fn assemble_if_done(&mut self) {
        let parts = self.config.dir.join("parts");
        let path = self.config.dir.join("snapshot.snap");
        let Some(f) = self.fetch_mut() else {
            return;
        };
        if !f.todo.is_empty() || !f.active.is_empty() {
            return;
        }
        let files: Vec<PathBuf> = f
            .done
            .iter()
            .map(|(slice, count)| parts.join(format!("{slice}-{count}")))
            .collect();
        let header = SnapshotHeader {
            entries: f.done.values().sum(),
            ..f.header.clone()
        };
        self.phase = match Snapshot::assemble(&path, &header, &files) {
            Ok(snapshot) => Phase::Done(Box::new(snapshot)),
            Err(e) => Phase::Failed(e.to_string()),
        };
    }

    /// Abandons request `id`: its peer left (`strike` false) or let it time
    /// out, which counts against it.
    fn cancel(&mut self, id: u64, strike: bool) {
        let pending = self.pending.remove(&id).expect("pending");
        let p = self.peers.get_mut(&pending.peer).expect("known");
        p.busy -= 1;
        if strike {
            p.strikes += 1;
            if p.strikes >= MAX_STRIKES {
                self.ban(pending.peer, pending.asked, "requests that time out");
                return;
            }
        }
        self.requeue(pending.peer, pending.asked);
    }

    /// Hands what a request asked for to whoever asks next.
    fn requeue(&mut self, peer: [u8; 32], asked: Asked) {
        match asked {
            Asked::Offers => self.peers.get_mut(&peer).expect("known").asked = false,
            Asked::Manifest => self.manifest_asked = false,
            Asked::Slice(slice) => {
                // Once: a banned peer's slices go back when it is banned.
                if let Phase::Fetch(f) = &mut self.phase
                    && f.active.remove(&slice).is_some()
                {
                    let tmp = self.config.dir.join("parts").join(format!("{slice}.tmp"));
                    let _ = fs::remove_file(tmp);
                    f.todo.push_front(slice);
                }
            }
        }
    }

    /// Stops asking `peer`, handing back what it was asked.
    fn ban(&mut self, peer: [u8; 32], asked: Asked, why: &'static str) {
        self.peers.get_mut(&peer).expect("known").banned = true;
        self.events.push(SyncEvent::Banned { peer, why });
        // Every slice it holds goes back to the queue, between pages too.
        let held: Vec<u32> = match &self.phase {
            Phase::Fetch(f) => f
                .active
                .iter()
                .filter(|(_, a)| a.peer == peer)
                .map(|(slice, _)| *slice)
                .collect(),
            _ => Vec::new(),
        };
        for slice in held {
            self.requeue(peer, Asked::Slice(slice));
        }
        self.requeue(peer, asked);
        let others: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| p.peer == peer)
            .map(|(id, _)| *id)
            .collect();
        for id in others {
            self.cancel(id, false);
        }
    }

    /// Back to discovery, dropping the requests of the target's slices.
    fn rediscover(&mut self) {
        let asked: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| p.asked != Asked::Offers)
            .map(|(id, _)| *id)
            .collect();
        for id in asked {
            let pending = self.pending.remove(&id).expect("pending");
            self.peers.get_mut(&pending.peer).expect("known").busy -= 1;
        }
        if let Phase::Fetch(f) = &self.phase {
            for slice in f.active.keys() {
                let _ = fs::remove_file(self.config.dir.join("parts").join(format!("{slice}.tmp")));
            }
        }
        // Offers may have changed since: every peer is asked again.
        for p in self.peers.values_mut() {
            p.offers = None;
            p.asked = false;
        }
        self.first_answer = None;
        // The same target chosen again resumes from the slices on disk.
        self.saved = fs::read(self.config.dir.join("manifest"))
            .ok()
            .and_then(|b| Manifest::from_bytes(&b).ok());
        self.phase = Phase::Discover;
    }
}

/// Takes a node, opened fresh over a disk store, from the snapshot its state
/// sync assembled to running (spec 22 §7.4, step 5): imports it (which
/// checks its order, root and genesis hash again), deletes the sync's
/// directory and starts the driver, which syncs blocks from the snapshot's
/// height on.
///
/// # Errors
/// What the import or the start reports.
pub fn finish(node: &mut crate::Node, snapshot: &Snapshot) -> Result<(), crate::NodeError> {
    node.import_snapshot(snapshot)?;
    let _ = snapshot.path().parent().map(fs::remove_dir_all);
    node.start(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer that refuses everything, as a full disk would.
    struct Full;

    impl Write for Full {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("the disk is full"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn sync(dir: &Path, genesis_hash: Option<Vec<u8>>) -> StateSync {
        StateSync::new(SyncConfig {
            chain_id: 1,
            trust: Trust::Genesis(solo_abi::chain::ValidatorSet::default()),
            genesis_hash,
            dir: dir.to_path_buf(),
        })
        .unwrap()
    }

    fn offer() -> Offer {
        Offer {
            epoch: 0,
            height: 1,
            state_root: [0; 32],
            entries: 0,
        }
    }

    #[test]
    fn an_empty_genesis_slice_is_another_genesis_unless_none_was_stored() {
        let dir = solo_scratch::Scratch::new("statesync-unit", "empty-genesis");
        let manifest = Manifest {
            header: Vec::new(),
            depth: 0,
            slices: vec![Summary::Empty],
        };
        let mut expecting = sync(&dir, Some(vec![1]));
        expecting.enter_fetch(
            offer(),
            SnapshotHeader::default(),
            manifest.clone(),
            BTreeMap::new(),
        );
        assert_eq!(
            expecting.failed(),
            Some("the snapshot is of a chain with another genesis block")
        );
        // A kernel that stores no genesis block expects none: the empty
        // state is complete at once.
        let mut none = sync(&dir.join("none"), None);
        none.enter_fetch(
            offer(),
            SnapshotHeader::default(),
            manifest,
            BTreeMap::new(),
        );
        assert_eq!(none.done().unwrap().header.entries, 0);
    }

    #[test]
    fn a_disk_that_refuses_a_page_ends_the_sync() {
        let dir = solo_scratch::Scratch::new("statesync-unit", "full-disk");
        let mut s = sync(&dir, None);
        let manifest = Manifest {
            header: Vec::new(),
            depth: 0,
            slices: vec![Summary::Branch { hash: [1; 32] }],
        };
        s.enter_fetch(
            offer(),
            SnapshotHeader::default(),
            manifest,
            BTreeMap::new(),
        );
        let f = s.fetch_mut().unwrap();
        f.todo.clear();
        f.active.insert(
            0,
            Active {
                peer: [1; 32],
                root: Some(SortedRoot::new(keccak256)),
                last: None,
                count: 0,
                file: BufWriter::with_capacity(1, Box::new(Full)),
                waiting: true,
                genesis: None,
            },
        );
        let entry = Entry {
            key: b"k".to_vec(),
            value: b"v".to_vec(),
        };
        s.on_slice([1; 32], 0, &[entry], true);
        assert_eq!(s.failed(), Some("the disk is full"));
        assert!(Full.flush().is_ok());
    }
}
