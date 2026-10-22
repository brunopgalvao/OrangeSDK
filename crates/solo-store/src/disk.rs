//! The chain store on disk (spec 22 §2–§4): one `redb` file per node.
//!
//! Tables:
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `state` | the stored key | its value: the flat state, `local/` keys included |
//! | `nodes` | node hash | `references (u32) ‖ preimage (65 bytes)`: a trie node, with how many live parents and roots name it |
//! | `history` | `(key, version)` | `0x00` (absent) or `0x01 ‖ value`: what the key held before `version`'s span first wrote it |
//! | `written` | `(version, key)` | `()`: the keys each version's span wrote, to prune by |
//! | `versions` | version | `root? ‖ written (u32) ‖ entries (u64)`: the header root the version's trie is kept for, if any, how many keys its span wrote and how many committed entries it holds |
//! | `meta` | name | `latest`, `oldest`, `current` (the root of the state as it is), `kernel` (the code hash of the kernel that wrote last), `genesis` (the genesis root), `format` |
//!
//! A *version* is a sealed block height: the genesis state is version 0 and
//! each executed block seals its height. Between seals the store buffers the
//! kernel's writes in memory and reads through them; [`DiskStore::seal`]
//! writes the block's state, history, trie nodes and version row in one
//! transaction and [`DiskStore::flush`] writes the buffer without sealing
//! (after `kernel_init`, a finalization or a kernel switch). Trie nodes are
//! content-addressed and reference-counted: a block writes the nodes on the
//! paths of the keys it changed, counting each new parent, and pruning a
//! version releases its root, deleting what no live root reaches.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use redb::{
    Database, ReadOnlyTable, ReadTransaction, ReadableDatabase, ReadableTable,
    ReadableTableMetadata, Table, TableDefinition,
};
use solo_host::storage::committed;
use solo_host::{Storage, Writes};
use solo_trie::{BRANCH_TAG, EMPTY, Hash, NODE_LEN, NodeSource, PathNode, Trie, node_halves};

/// The file under the data directory that holds the chain store.
pub const CHAIN_FILE: &str = "chain.redb";

/// Entries of the state in key order: what a scan or a snapshot holds.
pub type Entries = Vec<(Vec<u8>, Vec<u8>)>;

/// The store layout this release writes; a file of another format is refused.
pub const FORMAT: u32 = 1;

/// A file whose freed pages outweigh its live ones by this many bytes is
/// compacted when it is opened.
pub const COMPACTION_SLACK: u64 = 8 << 20;

const STATE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("state");
const NODES: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("nodes");
const HISTORY: TableDefinition<(&[u8], u64), &[u8]> = TableDefinition::new("history");
const WRITTEN: TableDefinition<(u64, &[u8]), ()> = TableDefinition::new("written");
const VERSIONS: TableDefinition<u64, &[u8]> = TableDefinition::new("versions");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

/// Why the store could not do what was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The database refused: an I/O error, a lock, a corrupt file.
    Db(String),
    /// The file is of another format than this release writes.
    Format(u32),
    /// The file's contents contradict each other.
    Corrupt(&'static str),
    /// A fault injected by [`DiskStore::inject`] (tests of crash recovery).
    Injected,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Db(why) => write!(f, "chain store: {why}"),
            StoreError::Format(found) => write!(
                f,
                "chain store: format {found}, this release reads format {FORMAT}"
            ),
            StoreError::Corrupt(what) => write!(f, "chain store is corrupt: {what}"),
            StoreError::Injected => write!(f, "chain store: injected fault"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Any `redb` error, as a store error: call sites convert theirs with
/// `redb::Error::from` first, so this stays one function, not one per type,
/// and it takes the error by value so that `map_err` takes it as a function.
#[allow(clippy::needless_pass_by_value)]
fn db(e: redb::Error) -> StoreError {
    StoreError::Db(e.to_string())
}

/// A read the store cannot survive failing: a disk that errors under a
/// kernel call leaves the node nothing to answer with.
fn read<T>(r: Result<T, redb::StorageError>) -> T {
    r.expect("chain store read")
}

/// A fault to inject into the next write, for tests of crash recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The next transaction is built and then dropped instead of committed,
    /// as a crash in the middle of a block's write leaves the file.
    DropNextCommit,
}

/// What the store has done, for telemetry (spec 11 §4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StoreStats {
    /// Size of the store file in bytes.
    pub size_bytes: u64,
    /// Bytes of keys, values and nodes written since the store was opened.
    pub write_bytes: u64,
    /// Bytes the last commit wrote.
    pub last_commit_bytes: u64,
    /// Transactions committed since the store was opened.
    pub commits: u64,
    /// Trie nodes written since the store was opened.
    pub nodes_written: u64,
    /// Versions the store keeps, oldest to latest.
    pub versions: u64,
    /// Trie nodes the file holds, over every kept root.
    pub nodes: u64,
}

type NodesRead = ReadOnlyTable<&'static [u8; 32], &'static [u8]>;

/// Where the lazily loaded tries read their nodes: the `nodes` table as of
/// the last commit, shared by the store and every trie it hands out and
/// renewed after each commit. Empty while the file is compacted and once
/// the store is dropped, when a trie that outlived it finds nothing.
#[derive(Default)]
struct Nodes {
    table: RwLock<Option<NodesRead>>,
}

impl NodeSource for Nodes {
    fn node(&self, hash: &Hash) -> Option<Vec<u8>> {
        let table = self.table.read().unwrap_or_else(PoisonError::into_inner);
        let row = read(table.as_ref()?.get(hash));
        row.map(|r| r.value()[4..].to_vec())
    }
}

/// The read side: one transaction and its tables, renewed after each commit
/// so that reads see what was written and cost no transaction each.
struct Reader {
    _txn: ReadTransaction,
    state: ReadOnlyTable<&'static [u8], &'static [u8]>,
    history: ReadOnlyTable<(&'static [u8], u64), &'static [u8]>,
}

impl Reader {
    /// Opens a reader on the database as it is, and points `nodes` at the
    /// same snapshot's node table.
    fn open(database: &Database, nodes: &Nodes) -> Result<Reader, StoreError> {
        let txn = database
            .begin_read()
            .map_err(redb::Error::from)
            .map_err(db)?;
        let state = txn
            .open_table(STATE)
            .map_err(redb::Error::from)
            .map_err(db)?;
        let history = txn
            .open_table(HISTORY)
            .map_err(redb::Error::from)
            .map_err(db)?;
        let table = txn
            .open_table(NODES)
            .map_err(redb::Error::from)
            .map_err(db)?;
        *nodes.table.write().unwrap_or_else(PoisonError::into_inner) = Some(table);
        Ok(Reader {
            _txn: txn,
            state,
            history,
        })
    }
}

/// The encoding of a history row.
fn encode_old(old: Option<&[u8]>) -> Vec<u8> {
    match old {
        None => vec![0],
        Some(value) => {
            let mut out = Vec::with_capacity(value.len() + 1);
            out.push(1);
            out.extend_from_slice(value);
            out
        }
    }
}

fn decode_old(row: &[u8]) -> Option<Vec<u8>> {
    match row.first() {
        Some(1) => Some(row[1..].to_vec()),
        _ => None,
    }
}

/// A version row: whether the root is a header root, the root, the writes
/// of the span and the committed entries at the version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VersionRow {
    root: Option<Hash>,
    written: u32,
    entries: u64,
}

impl VersionRow {
    fn encode(&self) -> [u8; 45] {
        let mut out = [0u8; 45];
        if let Some(root) = self.root {
            out[0] = 1;
            out[1..33].copy_from_slice(&root);
        }
        out[33..37].copy_from_slice(&self.written.to_le_bytes());
        out[37..].copy_from_slice(&self.entries.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<VersionRow> {
        let bytes: &[u8; 45] = bytes.try_into().ok()?;
        let mut root = EMPTY;
        root.copy_from_slice(&bytes[1..33]);
        Some(VersionRow {
            root: (bytes[0] == 1).then_some(root),
            written: u32::from_le_bytes(bytes[33..37].try_into().expect("4 bytes")),
            entries: u64::from_le_bytes(bytes[37..].try_into().expect("8 bytes")),
        })
    }
}

fn node_row(refs: u32, preimage: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + NODE_LEN);
    out.extend_from_slice(&refs.to_le_bytes());
    out.extend_from_slice(preimage);
    out
}

fn node_refs(row: &[u8]) -> u32 {
    u32::from_le_bytes(row[..4].try_into().expect("4 bytes"))
}

/// Writes the nodes a block created into the `nodes` table, counting the
/// references of each new parent (spec 22 §3.2). A node is new when its row
/// does not exist yet; the walk down a key's path stops at the first node
/// whose row exists and was not written on this walk, since its subtree is
/// on disk and counted. Every node a block creates lies on the path of a key
/// the block wrote, so the walks over those keys reach them all.
#[derive(Default)]
struct Persist {
    /// Path nodes written or passed in this transaction.
    done: HashSet<Hash>,
    /// References to nodes whose rows are not written yet.
    deferred: HashMap<Hash, u32>,
    bytes: u64,
    nodes: u64,
}

type NodesTable<'txn> = Table<'txn, &'static [u8; 32], &'static [u8]>;

impl Persist {
    fn path(&mut self, table: &mut NodesTable<'_>, path: &[PathNode]) -> Result<(), StoreError> {
        for node in path {
            let Some(preimage) = node.preimage else { break };
            if self.done.contains(&node.hash) {
                continue;
            }
            if table
                .get(&node.hash)
                .map_err(redb::Error::from)
                .map_err(db)?
                .is_some()
            {
                break;
            }
            let refs = self.deferred.remove(&node.hash).unwrap_or(0);
            table
                .insert(&node.hash, node_row(refs, &preimage).as_slice())
                .map_err(redb::Error::from)
                .map_err(db)?;
            self.bytes += 32 + 4 + NODE_LEN as u64;
            self.nodes += 1;
            if preimage[0] == BRANCH_TAG {
                let (left, right) = node_halves(&preimage);
                for child in [left, right] {
                    if child != EMPTY {
                        self.bump(table, &child)?;
                    }
                }
            }
            self.done.insert(node.hash);
        }
        Ok(())
    }

    /// One more parent or root names `hash`.
    fn bump(&mut self, table: &mut NodesTable<'_>, hash: &Hash) -> Result<(), StoreError> {
        if *hash == EMPTY {
            return Ok(());
        }
        let row = table
            .get(hash)
            .map_err(redb::Error::from)
            .map_err(db)?
            .map(|r| r.value().to_vec());
        match row {
            Some(row) => {
                let refs = node_refs(&row) + 1;
                table
                    .insert(hash, node_row(refs, &row[4..]).as_slice())
                    .map_err(redb::Error::from)
                    .map_err(db)?;
                self.bytes += 4;
            }
            None => *self.deferred.entry(*hash).or_default() += 1,
        }
        Ok(())
    }

    fn finish(self) -> Result<(u64, u64), StoreError> {
        if !self.deferred.is_empty() {
            return Err(StoreError::Corrupt(
                "a trie node was named before it was written",
            ));
        }
        Ok((self.bytes, self.nodes))
    }
}

/// One root fewer names `hash`: deletes what no live root reaches any more.
fn release(table: &mut NodesTable<'_>, hash: &Hash) -> Result<u64, StoreError> {
    let mut freed = 0;
    let mut stack = vec![*hash];
    while let Some(hash) = stack.pop() {
        if hash == EMPTY {
            continue;
        }
        let row = table
            .get(&hash)
            .map_err(redb::Error::from)
            .map_err(db)?
            .map(|r| r.value().to_vec());
        let row = row.ok_or(StoreError::Corrupt("a live root names a missing node"))?;
        let refs = node_refs(&row);
        if refs > 1 {
            table
                .insert(&hash, node_row(refs - 1, &row[4..]).as_slice())
                .map_err(redb::Error::from)
                .map_err(db)?;
            continue;
        }
        table.remove(&hash).map_err(redb::Error::from).map_err(db)?;
        freed += 1;
        if row[4] == BRANCH_TAG {
            let (left, right) = node_halves(&row[4..]);
            stack.push(left);
            stack.push(right);
        }
    }
    Ok(freed)
}

/// What [`DiskStore::prepare`] reads: the metadata, the write count of
/// every kept version and the node count.
type Prepared = (BTreeMap<String, Vec<u8>>, BTreeMap<u64, u32>, u64);

/// The chain store of one node.
pub struct DiskStore {
    path: PathBuf,
    db: Database,
    /// The node table the tries read, as of the last commit.
    nodes: Arc<Nodes>,
    /// The read side; `None` only while the file is being compacted.
    reader: Option<Reader>,
    /// The trie of the state as it is, pending writes included.
    trie: Trie,
    /// The root the `current` meta row holds: the trie as of the last commit.
    current: Hash,
    /// Writes since the last commit, by key.
    pending: Writes,
    /// What each committed key written since the last seal held before the
    /// span's first write of it.
    pending_old: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    oldest: u64,
    latest: u64,
    /// Whether any version has been sealed: a fresh store has none.
    sealed: bool,
    /// Committed entries in the state.
    entries: u64,
    /// Keys each kept version's span wrote.
    written: BTreeMap<u64, u32>,
    view: Option<u64>,
    kernel: Option<Hash>,
    genesis: Option<Hash>,
    stats: StoreStats,
    fault: Option<Fault>,
}

impl fmt::Debug for DiskStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiskStore")
            .field("path", &self.path)
            .field("oldest", &self.oldest)
            .field("latest", &self.latest)
            .field("pending", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl DiskStore {
    /// Opens the store in `dir` (creating the directory and the file as
    /// needed) and reads what a previous run left: the heads, the trie root
    /// and the kernel. Nothing of the state is read until it is asked for.
    ///
    /// # Errors
    /// When the file cannot be created, opened or read, is of another
    /// format, or is held by another process.
    pub fn open(dir: &Path) -> Result<DiskStore, StoreError> {
        std::fs::create_dir_all(dir).map_err(|e| StoreError::Db(e.to_string()))?;
        let path = dir.join(CHAIN_FILE);
        let mut database = Database::create(&path)
            .map_err(redb::Error::from)
            .map_err(db)?;
        let (meta, written, nodes) = Self::prepare(&mut database)?;
        let db = database;
        let format = meta
            .get("format")
            .and_then(|b| b.as_slice().try_into().ok())
            .map_or(0, u32::from_le_bytes);
        if format != FORMAT {
            return Err(StoreError::Format(format));
        }
        let number = |name: &str| {
            meta.get(name)
                .and_then(|b| b.as_slice().try_into().ok())
                .map(u64::from_le_bytes)
        };
        let hash = |name: &str| -> Option<Hash> {
            meta.get(name).and_then(|b| b.as_slice().try_into().ok())
        };
        let (latest, sealed) = number("latest").map_or((0, false), |l| (l, true));
        let current = hash("current").unwrap_or(EMPTY);
        let entries = number("entries").unwrap_or(0);
        let node_table = Arc::new(Nodes::default());
        let reader = Some(Reader::open(&db, &node_table)?);
        let trie = Trie::from_root(
            current,
            usize::try_from(entries).unwrap_or(usize::MAX),
            solo_trie::keccak256,
            node_table.clone(),
        );
        let size_bytes = std::fs::metadata(&path).map_or(0, |m| m.len());
        let oldest = number("oldest").unwrap_or(0);
        Ok(DiskStore {
            path,
            db,
            nodes: node_table,
            reader,
            trie,
            current,
            pending: Writes::new(),
            pending_old: BTreeMap::new(),
            oldest,
            latest,
            sealed,
            entries,
            written,
            view: None,
            kernel: hash("kernel"),
            genesis: hash("genesis"),
            stats: StoreStats {
                size_bytes,
                versions: if sealed { latest - oldest + 1 } else { 0 },
                nodes,
                ..StoreStats::default()
            },
            fault: None,
        })
    }

    /// The first transaction of an open: creates every table, so that reads
    /// can open them, stamps a new file's format, reads the metadata and
    /// the per-version write counts, and compacts a file whose freed pages
    /// outweigh its live bytes by [`COMPACTION_SLACK`] (pruning frees pages
    /// the database reuses; when far more is free than live, the file gives
    /// the space back).
    fn prepare(database: &mut Database) -> Result<Prepared, StoreError> {
        let txn = database
            .begin_write()
            .map_err(redb::Error::from)
            .map_err(db)?;
        txn.open_table(STATE)
            .map_err(redb::Error::from)
            .map_err(db)?;
        txn.open_table(HISTORY)
            .map_err(redb::Error::from)
            .map_err(db)?;
        txn.open_table(WRITTEN)
            .map_err(redb::Error::from)
            .map_err(db)?;
        let meta: BTreeMap<String, Vec<u8>> = {
            let mut table = txn
                .open_table(META)
                .map_err(redb::Error::from)
                .map_err(db)?;
            if table
                .get("format")
                .map_err(redb::Error::from)
                .map_err(db)?
                .is_none()
            {
                table
                    .insert("format", FORMAT.to_le_bytes().as_slice())
                    .map_err(redb::Error::from)
                    .map_err(db)?;
            }
            table
                .iter()
                .map_err(redb::Error::from)
                .map_err(db)?
                .map(|r| r.map(|(k, v)| (k.value().to_owned(), v.value().to_vec())))
                .collect::<Result<_, _>>()
                .map_err(redb::Error::from)
                .map_err(db)?
        };
        let written: BTreeMap<u64, u32> = {
            let table = txn
                .open_table(VERSIONS)
                .map_err(redb::Error::from)
                .map_err(db)?;
            table
                .iter()
                .map_err(redb::Error::from)
                .map_err(db)?
                .map(|r| {
                    r.map(|(k, v)| {
                        (
                            k.value(),
                            VersionRow::decode(v.value()).map_or(0, |row| row.written),
                        )
                    })
                })
                .collect::<Result<_, _>>()
                .map_err(redb::Error::from)
                .map_err(db)?
        };
        let stats = txn.stats().map_err(redb::Error::from).map_err(db)?;
        let nodes = txn
            .open_table(NODES)
            .map_err(redb::Error::from)
            .map_err(db)?
            .len()
            .map_err(redb::Error::from)
            .map_err(db)?;
        txn.commit().map_err(redb::Error::from).map_err(db)?;
        if stats.fragmented_bytes() > stats.stored_bytes() + COMPACTION_SLACK {
            database.compact().map_err(redb::Error::from).map_err(db)?;
        }
        Ok((meta, written, nodes))
    }

    /// Compacts the file now, giving freed pages back to the file system.
    /// Returns whether anything changed.
    ///
    /// # Errors
    /// When the database refuses.
    pub fn compact(&mut self) -> Result<bool, StoreError> {
        // Compaction needs the database to itself: no transaction open.
        self.reader = None;
        *self
            .nodes
            .table
            .write()
            .unwrap_or_else(PoisonError::into_inner) = None;
        let compacted = self.db.compact().map_err(redb::Error::from).map_err(db);
        self.reader = Some(Reader::open(&self.db, &self.nodes)?);
        self.stats.size_bytes = std::fs::metadata(&self.path).map_or(0, |m| m.len());
        compacted
    }

    fn reader(&self) -> &Reader {
        self.reader
            .as_ref()
            .expect("the reader is open between compactions")
    }

    /// The store file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether no version has been sealed yet: the genesis has not been
    /// applied, so the node must run `kernel_init`.
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        !self.sealed
    }

    /// The latest sealed version: the executed height.
    #[must_use]
    pub fn head(&self) -> u64 {
        self.latest
    }

    /// The code hash of the kernel that last wrote the store.
    #[must_use]
    pub fn kernel(&self) -> Option<Hash> {
        self.kernel
    }

    /// Records the kernel that writes from now on; written with the next commit.
    pub fn set_kernel(&mut self, kernel: Hash) {
        self.kernel = Some(kernel);
    }

    /// The state commitment of the genesis state, once version 0 is sealed.
    #[must_use]
    pub fn genesis_root(&self) -> Option<Hash> {
        self.genesis
    }

    /// Injects `fault` into the next commit (tests of crash recovery).
    pub fn inject(&mut self, fault: Fault) {
        self.fault = Some(fault);
    }

    /// What the store has done.
    #[must_use]
    pub fn stats(&self) -> StoreStats {
        self.stats
    }

    /// The versions the store can read as, oldest and latest; `None` before
    /// the genesis is sealed.
    #[must_use]
    pub fn versions(&self) -> Option<(u64, u64)> {
        self.sealed.then_some((self.oldest, self.latest))
    }

    /// How many key writes the history holds (see
    /// [`solo_host::MemStorage::history_keys`]).
    #[must_use]
    pub fn history_keys(&self) -> usize {
        self.written
            .range(self.oldest + 1..)
            .map(|(_, n)| *n as usize)
            .sum()
    }

    /// The oldest version the store can still read as while holding at most
    /// `keys` key writes of history (see
    /// [`solo_host::MemStorage::oldest_within`]).
    #[must_use]
    pub fn oldest_within(&self, keys: usize) -> u64 {
        let mut held = 0usize;
        for (version, written) in self.written.range(self.oldest + 1..).rev() {
            held += *written as usize;
            if held > keys {
                return *version;
            }
        }
        self.oldest
    }

    /// Makes reads see the committed entries as they were when `version`
    /// was sealed, or the current state for `None` (see
    /// [`solo_host::MemStorage::set_view`]).
    ///
    /// # Errors
    /// The versions the store can read as, when `version` is not among them.
    pub fn set_view(&mut self, version: Option<u64>) -> Result<(), Option<(u64, u64)>> {
        match version {
            Some(v) if !(self.sealed && (self.oldest..=self.latest).contains(&v)) => {
                Err(self.versions())
            }
            view => {
                self.view = view;
                Ok(())
            }
        }
    }

    /// The trie behind the header root of `version`, loading its nodes from
    /// the file as proofs need them; `None` for a version the store does not
    /// keep or kept no header root for.
    #[must_use]
    pub fn trie_at(&self, version: u64) -> Option<Trie> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(VERSIONS).ok()?;
        let row = read(table.get(version))?;
        let row = VersionRow::decode(row.value())?;
        Some(Trie::from_root(
            row.root?,
            usize::try_from(row.entries).unwrap_or(usize::MAX),
            solo_trie::keccak256,
            self.nodes.clone(),
        ))
    }

    /// Records the value `key` holds before a write, the first time it is
    /// written since the last seal.
    fn note(&mut self, key: &[u8]) {
        if committed(key) && !self.pending_old.contains_key(key) {
            // A flush before a restart may have journaled the span's old
            // value already; the first write's value is the span's.
            let journaled = read(self.reader().history.get((key, self.latest + 1)))
                .map(|row| decode_old(row.value()));
            let old = journaled.unwrap_or_else(|| self.current_value(key));
            self.pending_old.insert(key.to_vec(), old);
        }
    }

    /// The value as it is, pending writes included, whatever the view.
    fn current_value(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self.pending.get(key) {
            Some(value) => value.clone(),
            None => read(self.reader().state.get(key)).map(|v| v.value().to_vec()),
        }
    }

    /// The value `key` held when version `at` was sealed, given `current`.
    fn value_at(&self, key: &[u8], at: u64, current: Option<Vec<u8>>) -> Option<Vec<u8>> {
        let later = read(
            self.reader()
                .history
                .range::<(&[u8], u64)>((key, at + 1)..=(key, u64::MAX)),
        )
        .next();
        if let Some(row) = later {
            let (_, old) = read(row);
            return decode_old(old.value());
        }
        match self.pending_old.get(key) {
            Some(old) => old.clone(),
            None => current,
        }
    }

    /// Seals `version`: writes the pending state, its history as
    /// `version`'s, the trie nodes the span created, and the version row
    /// with `committed`, the trie behind the block's header root, when the
    /// block has one. The genesis state is sealed as version 0 with no
    /// committed trie: its root is the state's.
    ///
    /// # Errors
    /// When the database refuses or a fault was injected; nothing of the
    /// block is then on disk, and the buffer is kept for another try.
    pub fn seal(&mut self, version: u64, committed: Option<&Trie>) -> Result<(), StoreError> {
        self.commit(Some(version), committed)
    }

    /// Writes the pending state without sealing a version.
    ///
    /// # Errors
    /// As [`DiskStore::seal`].
    pub fn flush(&mut self) -> Result<(), StoreError> {
        self.commit(None, None)
    }

    #[allow(clippy::too_many_lines)]
    fn commit(
        &mut self,
        version: Option<u64>,
        header_trie: Option<&Trie>,
    ) -> Result<(), StoreError> {
        let txn = self
            .db
            .begin_write()
            .map_err(redb::Error::from)
            .map_err(db)?;
        let span = version.unwrap_or(self.latest + 1);
        let mut bytes = 0u64;
        let mut entries = self.entries;
        let committed_root = header_trie.map(Trie::root);
        let (node_bytes, nodes_written, node_count, span_writes) = {
            let mut state = txn
                .open_table(STATE)
                .map_err(redb::Error::from)
                .map_err(db)?;
            for (key, value) in &self.pending {
                let was = if let Some(value) = value {
                    bytes += (key.len() + value.len()) as u64;
                    state
                        .insert(key.as_slice(), value.as_slice())
                        .map_err(redb::Error::from)
                        .map_err(db)?
                        .is_some()
                } else {
                    bytes += key.len() as u64;
                    state
                        .remove(key.as_slice())
                        .map_err(redb::Error::from)
                        .map_err(db)?
                        .is_some()
                };
                if committed(key) {
                    match (was, value.is_some()) {
                        (false, true) => entries += 1,
                        (true, false) => entries -= 1,
                        _ => {}
                    }
                }
            }
            let mut history = txn
                .open_table(HISTORY)
                .map_err(redb::Error::from)
                .map_err(db)?;
            let mut written = txn
                .open_table(WRITTEN)
                .map_err(redb::Error::from)
                .map_err(db)?;
            for (key, old) in &self.pending_old {
                let row = encode_old(old.as_deref());
                bytes += (key.len() + row.len() + 16) as u64;
                history
                    .insert((key.as_slice(), span), row.as_slice())
                    .map_err(redb::Error::from)
                    .map_err(db)?;
                written
                    .insert((span, key.as_slice()), ())
                    .map_err(redb::Error::from)
                    .map_err(db)?;
            }
            let mut nodes = txn
                .open_table(NODES)
                .map_err(redb::Error::from)
                .map_err(db)?;
            let mut persist = Persist::default();
            let keys: Vec<&[u8]> = self
                .pending
                .keys()
                .map(Vec::as_slice)
                .filter(|k| committed(k))
                .collect();
            if let Some(trie) = header_trie {
                for key in &keys {
                    persist.path(&mut nodes, &trie.path_nodes(key))?;
                }
                persist.bump(&mut nodes, &trie.root())?;
            }
            for key in &keys {
                persist.path(&mut nodes, &self.trie.path_nodes(key))?;
            }
            // The version's root and the current root each hold a reference;
            // the previous current root gives its own back.
            let version_root = match version {
                Some(_) if self.sealed => committed_root,
                Some(_) => Some(self.trie.root()),
                None => None,
            };
            if let Some(root) = &version_root {
                persist.bump(&mut nodes, root)?;
            }
            persist.bump(&mut nodes, &self.trie.root())?;
            release(&mut nodes, &self.current)?;
            let mut versions = txn
                .open_table(VERSIONS)
                .map_err(redb::Error::from)
                .map_err(db)?;
            let mut meta = txn
                .open_table(META)
                .map_err(redb::Error::from)
                .map_err(db)?;
            if let Some(v) = version {
                let span_writes = written
                    .range::<(u64, &[u8])>((span, &[][..])..(span + 1, &[][..]))
                    .map_err(redb::Error::from)
                    .map_err(db)?
                    .count();
                let row = VersionRow {
                    root: version_root,
                    written: u32::try_from(span_writes).unwrap_or(u32::MAX),
                    entries,
                };
                versions
                    .insert(v, row.encode().as_slice())
                    .map_err(redb::Error::from)
                    .map_err(db)?;
                meta.insert("latest", v.to_le_bytes().as_slice())
                    .map_err(redb::Error::from)
                    .map_err(db)?;
                if !self.sealed {
                    meta.insert("oldest", v.to_le_bytes().as_slice())
                        .map_err(redb::Error::from)
                        .map_err(db)?;
                    meta.insert("genesis", self.trie.root().as_slice())
                        .map_err(redb::Error::from)
                        .map_err(db)?;
                }
            }
            meta.insert("current", self.trie.root().as_slice())
                .map_err(redb::Error::from)
                .map_err(db)?;
            meta.insert("entries", entries.to_le_bytes().as_slice())
                .map_err(redb::Error::from)
                .map_err(db)?;
            if let Some(kernel) = &self.kernel {
                meta.insert("kernel", kernel.as_slice())
                    .map_err(redb::Error::from)
                    .map_err(db)?;
            }
            let (node_bytes, nodes_written) = persist.finish()?;
            let span_writes = written
                .range::<(u64, &[u8])>((span, &[][..])..(span + 1, &[][..]))
                .map_err(redb::Error::from)
                .map_err(db)?
                .count();
            let span_writes = u32::try_from(span_writes).unwrap_or(u32::MAX);
            (
                node_bytes,
                nodes_written,
                nodes.len().map_err(redb::Error::from).map_err(db)?,
                span_writes,
            )
        };
        if self.fault.take() == Some(Fault::DropNextCommit) {
            drop(txn);
            return Err(StoreError::Injected);
        }
        txn.commit().map_err(redb::Error::from).map_err(db)?;
        self.reader = Some(Reader::open(&self.db, &self.nodes)?);
        self.current = self.trie.root();
        self.entries = entries;
        self.pending.clear();
        if let Some(v) = version {
            if !self.sealed {
                self.oldest = v;
                self.genesis = Some(self.trie.root());
            }
            self.sealed = true;
            self.latest = v;
            self.written.insert(v, span_writes);
            self.pending_old.clear();
        }
        bytes += node_bytes;
        self.stats.write_bytes += bytes;
        self.stats.last_commit_bytes = bytes;
        self.stats.commits += 1;
        self.stats.nodes_written += nodes_written;
        self.stats.nodes = node_count;
        self.stats.versions = self.latest - self.oldest + 1;
        self.stats.size_bytes = std::fs::metadata(&self.path).map_or(0, |m| m.len());
        Ok(())
    }

    /// Forgets what reading as a version below `oldest` needs: the history
    /// rows of the versions up to `oldest`, and the tries of the versions
    /// below it, whose nodes are deleted where no kept root reaches them
    /// (see [`solo_host::MemStorage::prune`]).
    ///
    /// # Errors
    /// When the database refuses.
    pub fn prune(&mut self, oldest: u64) -> Result<(), StoreError> {
        let oldest = oldest.min(self.latest);
        if !self.sealed || oldest <= self.oldest {
            return Ok(());
        }
        let txn = self
            .db
            .begin_write()
            .map_err(redb::Error::from)
            .map_err(db)?;
        {
            let mut history = txn
                .open_table(HISTORY)
                .map_err(redb::Error::from)
                .map_err(db)?;
            let mut written = txn
                .open_table(WRITTEN)
                .map_err(redb::Error::from)
                .map_err(db)?;
            let mut keys = Vec::new();
            for version in self.oldest + 1..=oldest {
                let rows = written
                    .extract_from_if::<(u64, &[u8]), _>(
                        (version, &[][..])..(version + 1, &[][..]),
                        |_, ()| true,
                    )
                    .map_err(redb::Error::from)
                    .map_err(db)?;
                for row in rows {
                    let (key, _) = row.map_err(redb::Error::from).map_err(db)?;
                    keys.push((key.value().1.to_vec(), version));
                }
            }
            for (key, version) in keys {
                history
                    .remove((key.as_slice(), version))
                    .map_err(redb::Error::from)
                    .map_err(db)?;
            }
            let mut versions = txn
                .open_table(VERSIONS)
                .map_err(redb::Error::from)
                .map_err(db)?;
            let mut nodes = txn
                .open_table(NODES)
                .map_err(redb::Error::from)
                .map_err(db)?;
            for version in self.oldest..oldest {
                let row = versions
                    .remove(version)
                    .map_err(redb::Error::from)
                    .map_err(db)?;
                let row = row.and_then(|r| VersionRow::decode(r.value()));
                if let Some(root) = row.and_then(|r| r.root) {
                    release(&mut nodes, &root)?;
                }
            }
            let mut meta = txn
                .open_table(META)
                .map_err(redb::Error::from)
                .map_err(db)?;
            meta.insert("oldest", oldest.to_le_bytes().as_slice())
                .map_err(redb::Error::from)
                .map_err(db)?;
            self.stats.nodes = nodes.len().map_err(redb::Error::from).map_err(db)?;
        }
        txn.commit().map_err(redb::Error::from).map_err(db)?;
        self.reader = Some(Reader::open(&self.db, &self.nodes)?);
        self.written = self.written.split_off(&oldest);
        self.oldest = oldest;
        self.stats.commits += 1;
        self.stats.versions = self.latest - self.oldest + 1;
        Ok(())
    }

    /// The committed entries as they were when `version` was sealed, in key
    /// order, without `local/` keys: what a snapshot of that version holds.
    ///
    /// # Errors
    /// The versions the store can read as, when `version` is not among them.
    pub fn entries_at(&self, version: u64) -> Result<Entries, Option<(u64, u64)>> {
        if !(self.sealed && (self.oldest..=self.latest).contains(&version)) {
            return Err(self.versions());
        }
        let mut merged: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        for row in read(self.reader().state.iter()) {
            let (key, value) = read(row);
            if committed(key.value()) {
                merged.insert(key.value().to_vec(), Some(value.value().to_vec()));
            }
        }
        for (key, value) in &self.pending {
            if committed(key) {
                merged.insert(key.clone(), value.clone());
            }
        }
        let mut rewound = BTreeSet::new();
        for row in read(self.reader().history.iter()) {
            let (key, _) = read(row);
            let (key, written_at) = key.value();
            if written_at > version {
                rewound.insert(key.to_vec());
            }
        }
        rewound.extend(self.pending_old.keys().cloned());
        for key in rewound {
            let current = merged.get(&key).cloned().flatten();
            let then = self.value_at(&key, version, current);
            merged.insert(key, then);
        }
        Ok(merged
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect())
    }

    /// Replaces the state with `entries`, the whole committed state of
    /// version `version`, plus `local`, the node-local keys to set beside
    /// them: what importing a snapshot does. The store must hold the genesis
    /// alone (version 0 sealed, nothing else), so that the genesis root is
    /// known; the entries' trie is built and must hash to `root`, and the
    /// genesis version is pruned, leaving `version` as the oldest.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] when the store holds more than the genesis or
    /// the entries do not hash to `root`; otherwise when the database refuses.
    pub fn load(
        &mut self,
        version: u64,
        root: &Hash,
        entries: &[(Vec<u8>, Vec<u8>)],
        local: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StoreError> {
        if !self.sealed || self.latest != 0 || !self.pending.is_empty() || version == 0 {
            return Err(StoreError::Corrupt(
                "a snapshot loads over the genesis alone",
            ));
        }
        let mut trie = Trie::new();
        for (key, value) in entries {
            if !committed(key) {
                return Err(StoreError::Corrupt(
                    "a snapshot holds committed entries only",
                ));
            }
            trie.insert(key, value);
        }
        if trie.root() != *root {
            return Err(StoreError::Corrupt(
                "the snapshot's entries do not hash to its root",
            ));
        }
        for (key, _) in self.scan(&[]) {
            self.pending.insert(key, None);
        }
        for (key, value) in entries.iter().chain(local) {
            self.pending.insert(key.clone(), Some(value.clone()));
        }
        self.trie = trie;
        self.commit(Some(version), None)?;
        self.prune(version)?;
        // Later paths load from the file rather than keep the whole state.
        self.trie = Trie::from_root(
            *root,
            entries.len(),
            solo_trie::keccak256,
            self.nodes.clone(),
        );
        Ok(())
    }
}

impl Drop for DiskStore {
    fn drop(&mut self) {
        // A trie that outlives the store must not keep a read transaction
        // on a database that is gone.
        self.reader = None;
        *self
            .nodes
            .table
            .write()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }
}

impl Storage for DiskStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let current = self.current_value(key);
        match self.view {
            Some(at) if committed(key) => self.value_at(key, at, current),
            _ => current,
        }
    }

    fn set(&mut self, key: &[u8], value: &[u8]) {
        self.note(key);
        self.pending.insert(key.to_vec(), Some(value.to_vec()));
        if committed(key) {
            self.trie.insert(key, value);
        }
    }

    fn delete(&mut self, key: &[u8]) -> bool {
        let existed = self.current_value(key).is_some();
        self.note(key);
        self.pending.insert(key.to_vec(), None);
        if committed(key) {
            self.trie.remove(key);
        }
        existed
    }

    fn scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut merged: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        for row in read(self.reader().state.range::<&[u8]>(prefix..)) {
            let (key, value) = read(row);
            if !key.value().starts_with(prefix) {
                break;
            }
            merged.insert(key.value().to_vec(), Some(value.value().to_vec()));
        }
        for (key, value) in self.pending.range(prefix.to_vec()..) {
            if !key.starts_with(prefix) {
                break;
            }
            merged.insert(key.clone(), value.clone());
        }
        if let Some(at) = self.view {
            let mut rewound = BTreeSet::new();
            for row in read(self.reader().history.range::<(&[u8], u64)>((prefix, 0)..)) {
                let (key, _) = read(row);
                let (key, _) = key.value();
                if !key.starts_with(prefix) {
                    break;
                }
                rewound.insert(key.to_vec());
            }
            for key in self.pending_old.range(prefix.to_vec()..) {
                if !key.0.starts_with(prefix) {
                    break;
                }
                rewound.insert(key.0.clone());
            }
            for key in rewound {
                let current = merged.get(&key).cloned().flatten();
                let then = self.value_at(&key, at, current);
                merged.insert(key, then);
            }
        }
        merged
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect()
    }

    /// A copy-on-write clone of the maintained trie: O(1).
    fn state_trie(&self) -> Trie {
        self.trie.clone()
    }

    /// Buffers the writes and adopts `trie`, which already holds them.
    fn merge_layer(&mut self, writes: Writes, trie: Trie) {
        for key in writes.keys() {
            self.note(key);
        }
        self.pending.extend(writes);
        self.trie = trie;
    }
}

#[cfg(test)]
mod tests {
    use solo_host::Overlay;

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("solo-chain-store-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// The root by definition: a fresh trie over the committed entries.
    fn rebuilt(entries: &[(Vec<u8>, Vec<u8>)]) -> Hash {
        let mut t = Trie::new();
        for (k, v) in entries {
            if committed(k) {
                t.insert(k, v);
            }
        }
        t.root()
    }

    /// Executes one "block" the way the node does: the writes in a layer,
    /// the committed trie captured before the bookkeeping writes, the layer
    /// merged, the version sealed. Returns the header root.
    fn block(
        o: &mut Overlay<DiskStore>,
        height: u64,
        writes: &[(&[u8], Option<&[u8]>)],
        bookkeeping: &[(&[u8], &[u8])],
    ) -> Hash {
        o.push();
        for (k, v) in writes {
            match v {
                Some(v) => o.set(k, v),
                None => {
                    o.delete(k);
                }
            }
        }
        let committed = o.state_trie();
        for (k, v) in bookkeeping {
            o.set(k, v);
        }
        o.commit();
        o.base_mut().seal(height, Some(&committed)).unwrap();
        committed.root()
    }

    #[test]
    fn a_fresh_store_round_trips_through_a_reopen() {
        let dir = scratch("roundtrip");
        let mut store = DiskStore::open(&dir).unwrap();
        assert!(store.is_fresh());
        assert_eq!(
            (store.head(), store.versions(), store.kernel()),
            (0, None, None)
        );
        assert_eq!(store.genesis_root(), None);
        assert!(store.path().ends_with(CHAIN_FILE));
        assert!(format!("{store:?}").contains("DiskStore"));
        // The genesis: direct writes, a deletion of an absent key, a local key.
        store.set(b"acct/1", b"one");
        store.set(b"acct/2", b"two");
        store.set(b"local/finalized", b"0");
        assert!(!store.delete(b"missing"));
        assert!(store.delete(b"acct/2"));
        assert_eq!(store.get(b"acct/2"), None);
        store.set_kernel([7; 32]);
        store.seal(0, None).unwrap();
        let genesis = store.state_trie().root();
        assert_eq!(store.genesis_root(), Some(genesis));
        assert_eq!(genesis, rebuilt(&[(b"acct/1".to_vec(), b"one".to_vec())]));
        assert_eq!(store.versions(), Some((0, 0)));
        assert!(!store.is_fresh());
        let stats = store.stats();
        assert!(stats.write_bytes > 0 && stats.commits == 1 && stats.nodes == 1);
        assert_eq!(stats.versions, 1);
        drop(store);
        let again = DiskStore::open(&dir).unwrap();
        assert_eq!(again.head(), 0);
        assert_eq!(again.kernel(), Some([7; 32]));
        assert_eq!(again.genesis_root(), Some(genesis));
        assert_eq!(again.state_trie().root(), genesis);
        assert_eq!(again.get(b"acct/1"), Some(b"one".to_vec()));
        assert_eq!(again.get(b"local/finalized"), Some(b"0".to_vec()));
        assert_eq!(
            again.scan(b"acct/"),
            vec![(b"acct/1".to_vec(), b"one".to_vec())]
        );
        assert_eq!(again.stats().nodes, 1);
        assert_eq!(again.trie_at(0).unwrap().root(), genesis);
        // The genesis trie proves its entries after the reopen.
        let proof = again.trie_at(0).unwrap().prove(b"acct/1");
        assert_eq!(
            proof.verify(solo_trie::keccak256, &genesis, b"acct/1"),
            Ok(Some(solo_trie::keccak256(b"one")))
        );
    }

    #[test]
    #[allow(clippy::many_single_char_names, clippy::too_many_lines)]
    fn blocks_keep_history_tries_and_prune_them() {
        let dir = scratch("blocks");
        let mut o = Overlay::new(DiskStore::open(&dir).unwrap());
        o.set(b"a", b"0");
        o.set(b"local/x", b"0");
        o.base_mut().seal(0, None).unwrap();
        // Block 1 writes a (twice), b and a local key; block 2 deletes a
        // through a layer and rewrites b; block 3 writes nothing but a
        // bookkeeping key.
        let r1 = block(
            &mut o,
            1,
            &[
                (b"a", Some(b"1")),
                (b"a", Some(b"1b")),
                (b"b", Some(b"1")),
                (b"local/x", Some(b"1")),
            ],
            &[(b"block/1", b"h1"), (b"meta/height", b"1")],
        );
        let r2 = block(
            &mut o,
            2,
            &[(b"a", None), (b"b", Some(b"2"))],
            &[(b"block/2", b"h2"), (b"meta/height", b"2")],
        );
        let r3 = block(
            &mut o,
            3,
            &[],
            &[(b"block/3", b"h3"), (b"meta/height", b"3")],
        );
        assert_ne!(r1, r2);
        assert_eq!(
            r3,
            rebuilt(
                &o.scan(&[])
                    .into_iter()
                    .filter(|(k, _)| k != b"block/3" && k != b"meta/height")
                    .chain([(b"meta/height".to_vec(), b"2".to_vec())])
                    .collect::<Vec<_>>()
            )
        );
        let s = o.base_mut();
        s.set(b"c", b"later");
        assert_eq!(s.versions(), Some((0, 3)));
        assert_eq!(s.history_keys(), 4 + 4 + 2);
        // Reading every version: values, scans, local keys as they are.
        let read = |s: &mut DiskStore, v: u64| {
            s.set_view(Some(v)).unwrap();
            let out = (s.get(b"a"), s.get(b"b"), s.get(b"c"), s.scan(b""));
            s.set_view(None).unwrap();
            out
        };
        let (a, b, c, all) = read(s, 0);
        assert_eq!((a, b, c), (Some(b"0".to_vec()), None, None));
        assert_eq!(
            all,
            vec![
                (b"a".to_vec(), b"0".to_vec()),
                (b"local/x".to_vec(), b"1".to_vec())
            ]
        );
        let (a, b, c, all) = read(s, 1);
        assert_eq!((a, b, c), (Some(b"1b".to_vec()), Some(b"1".to_vec()), None));
        assert_eq!(all.len(), 5);
        let (a, b, _, _) = read(s, 2);
        assert_eq!((a, b), (None, Some(b"2".to_vec())));
        assert_eq!(read(s, 3).2, None);
        s.set_view(Some(1)).unwrap();
        assert_eq!(
            s.scan(b"b"),
            vec![
                (b"b".to_vec(), b"1".to_vec()),
                (b"block/1".to_vec(), b"h1".to_vec())
            ]
        );
        assert_eq!(
            s.scan(b"block/"),
            vec![(b"block/1".to_vec(), b"h1".to_vec())]
        );
        s.set_view(None).unwrap();
        assert_eq!(s.get(b"c"), Some(b"later".to_vec()));
        assert_eq!(s.set_view(Some(4)), Err(Some((0, 3))));
        // The tries of every version prove against their header roots.
        for (v, root, key, value) in [
            (1, r1, &b"a"[..], Some(&b"1b"[..])),
            (2, r2, b"a", None),
            (2, r2, b"b", Some(b"2")),
            (3, r3, b"block/2", Some(b"h2")),
        ] {
            let trie = s.trie_at(v).unwrap();
            assert_eq!(trie.root(), root);
            assert_eq!(
                trie.prove(key).verify(solo_trie::keccak256, &root, key),
                Ok(value.map(solo_trie::keccak256)),
                "{v} {key:?}"
            );
        }
        // Everything the same after a restart, pending write included once
        // it is sealed.
        s.seal(4, None).unwrap();
        let nodes_before = s.stats().nodes;
        let (oldest_within_2, keys) = (s.oldest_within(2), s.history_keys());
        drop(o);
        let mut s = DiskStore::open(&dir).unwrap();
        assert_eq!((s.versions(), s.history_keys()), (Some((0, 4)), keys));
        assert_eq!(s.oldest_within(2), oldest_within_2);
        assert_eq!(s.oldest_within(usize::MAX), 0);
        assert_eq!(s.oldest_within(0), 4);
        assert_eq!(read(&mut s, 1).0, Some(b"1b".to_vec()));
        assert_eq!(read(&mut s, 4).2, Some(b"later".to_vec()));
        assert_eq!(s.trie_at(2).unwrap().root(), r2);
        assert!(s.trie_at(4).is_none());
        assert!(s.trie_at(9).is_none());
        assert_eq!(s.stats().nodes, nodes_before);
        // Pruning below version 2 forgets what reading 0 and 1 needed and
        // releases their tries; what version 2 and later share stays.
        s.prune(2).unwrap();
        assert_eq!(s.versions(), Some((2, 4)));
        assert_eq!(s.set_view(Some(1)), Err(Some((2, 4))));
        assert_eq!(read(&mut s, 2).1, Some(b"2".to_vec()));
        assert!(s.trie_at(1).is_none());
        assert_eq!(s.trie_at(2).unwrap().root(), r2);
        assert!(s.stats().nodes < nodes_before);
        let proof = s.trie_at(3).unwrap().prove(b"b");
        assert_eq!(
            proof.verify(solo_trie::keccak256, &r3, b"b"),
            Ok(Some(solo_trie::keccak256(b"2")))
        );
        // Pruning at or below the oldest changes nothing; above the latest
        // prunes to it.
        s.prune(1).unwrap();
        assert_eq!(s.versions(), Some((2, 4)));
        s.prune(9).unwrap();
        assert_eq!(s.versions(), Some((4, 4)));
        assert_eq!(s.history_keys(), 0);
        assert_eq!(read(&mut s, 4).2, Some(b"later".to_vec()));
        // The current state's nodes all survive: every key still proves.
        let trie = s.state_trie();
        for (k, v) in s.scan(&[]) {
            if committed(&k) {
                assert_eq!(trie.get(&k), Some(solo_trie::keccak256(&v)), "{k:?}");
            }
        }
        drop(s);
        let s = DiskStore::open(&dir).unwrap();
        assert_eq!(s.versions(), Some((4, 4)));
        assert_eq!(s.get(b"b"), Some(b"2".to_vec()));
    }

    #[test]
    fn a_flush_between_seals_keeps_the_span_whole() {
        let dir = scratch("flush");
        let mut s = DiskStore::open(&dir).unwrap();
        s.set(b"k", b"genesis");
        s.seal(0, None).unwrap();
        // The span of version 1 writes k twice around a flush and a restart.
        s.set(b"k", b"first");
        s.set(b"local/finalized", b"1");
        s.flush().unwrap();
        assert_eq!(s.get(b"k"), Some(b"first".to_vec()));
        drop(s);
        let mut s = DiskStore::open(&dir).unwrap();
        assert_eq!(s.get(b"k"), Some(b"first".to_vec()));
        assert_eq!(s.versions(), Some((0, 0)));
        s.set(b"k", b"second");
        s.seal(1, None).unwrap();
        // Version 0 still reads the genesis value: the first write's old
        // value is the span's.
        s.set_view(Some(0)).unwrap();
        assert_eq!(s.get(b"k"), Some(b"genesis".to_vec()));
        assert_eq!(s.scan(b"k"), vec![(b"k".to_vec(), b"genesis".to_vec())]);
        s.set_view(None).unwrap();
        assert_eq!(s.get(b"k"), Some(b"second".to_vec()));
        // A write pending after the seal reads as the sealed value at the
        // latest version, and the entries of a version leave it out.
        s.set(b"k", b"third");
        s.set_view(Some(1)).unwrap();
        assert_eq!(s.get(b"k"), Some(b"second".to_vec()));
        s.set_view(None).unwrap();
        assert_eq!(
            s.entries_at(1).unwrap(),
            vec![(b"k".to_vec(), b"second".to_vec())]
        );
        assert_eq!(
            s.entries_at(0).unwrap(),
            vec![(b"k".to_vec(), b"genesis".to_vec())]
        );
        assert_eq!(s.entries_at(2), Err(Some((0, 1))));
        // A flush that only touches local keys seals nothing.
        s.flush().unwrap();
        assert_eq!(s.versions(), Some((0, 1)));
    }

    #[test]
    fn an_injected_fault_loses_only_the_block_in_flight() {
        let dir = scratch("fault");
        let mut s = DiskStore::open(&dir).unwrap();
        s.set(b"k", b"0");
        s.seal(0, None).unwrap();
        s.set(b"k", b"1");
        s.inject(Fault::DropNextCommit);
        assert_eq!(s.seal(1, None), Err(StoreError::Injected));
        assert_eq!(s.stats().commits, 1);
        // The buffer is kept: a second try lands it.
        assert_eq!(s.get(b"k"), Some(b"1".to_vec()));
        drop(s);
        let mut s = DiskStore::open(&dir).unwrap();
        assert_eq!((s.get(b"k"), s.head()), (Some(b"0".to_vec()), 0));
        s.set(b"k", b"1");
        s.seal(1, None).unwrap();
        assert_eq!((s.get(b"k"), s.head()), (Some(b"1".to_vec()), 1));
        assert_eq!(
            StoreError::Injected.to_string(),
            "chain store: injected fault"
        );
        assert!(StoreError::Db("x".into()).to_string().contains('x'));
        assert!(StoreError::Format(3).to_string().contains("format 3"));
        assert!(StoreError::Corrupt("why").to_string().contains("why"));
    }

    #[test]
    fn loading_a_snapshot_replaces_the_genesis() {
        let dir = scratch("load");
        let mut s = DiskStore::open(&dir).unwrap();
        s.set(b"acct/genesis", b"g");
        s.set(b"local/finalized", b"0");
        let entries = vec![
            (b"acct/1".to_vec(), b"one".to_vec()),
            (b"acct/2".to_vec(), b"two".to_vec()),
            (b"meta/height".to_vec(), b"7".to_vec()),
        ];
        let root = rebuilt(&entries);
        let local = vec![(b"local/finalized".to_vec(), b"7".to_vec())];
        // Only over the genesis alone.
        assert!(matches!(
            s.load(7, &root, &entries, &local),
            Err(StoreError::Corrupt(_))
        ));
        s.seal(0, None).unwrap();
        let genesis = s.genesis_root().unwrap();
        assert!(matches!(
            s.load(0, &root, &entries, &local),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            s.load(7, &[1; 32], &entries, &local),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            s.load(7, &root, &[(b"local/x".to_vec(), vec![])], &local),
            Err(StoreError::Corrupt(_))
        ));
        s.load(7, &root, &entries, &local).unwrap();
        assert_eq!(s.versions(), Some((7, 7)));
        assert_eq!(s.genesis_root(), Some(genesis));
        assert_eq!(s.state_trie().root(), root);
        assert_eq!(s.get(b"acct/genesis"), None);
        assert_eq!(s.get(b"local/finalized"), Some(b"7".to_vec()));
        assert_eq!(s.entries_at(7).unwrap(), entries);
        assert!(s.trie_at(7).is_none());
        assert!(s.trie_at(0).is_none());
        assert!(matches!(
            s.load(8, &root, &entries, &local),
            Err(StoreError::Corrupt(_))
        ));
        // A block on top proves against its own root after a restart.
        drop(s);
        let mut o = Overlay::new(DiskStore::open(&dir).unwrap());
        assert_eq!(o.base().state_trie().root(), root);
        let r8 = block(
            &mut o,
            8,
            &[(b"acct/1", Some(b"uno"))],
            &[(b"meta/height", b"8")],
        );
        let proof = o.base().trie_at(8).unwrap().prove(b"acct/2");
        assert_eq!(
            proof.verify(solo_trie::keccak256, &r8, b"acct/2"),
            Ok(Some(solo_trie::keccak256(b"two")))
        );
        o.base_mut().set_view(Some(7)).unwrap();
        assert_eq!(o.base().get(b"acct/1"), Some(b"one".to_vec()));
    }

    #[test]
    fn freed_space_is_given_back_by_compaction() {
        let dir = scratch("compact");
        let mut s = DiskStore::open(&dir).unwrap();
        s.seal(0, None).unwrap();
        let value = vec![0xABu8; 8192];
        for i in 0..2_000u32 {
            s.set(&i.to_be_bytes(), &value);
        }
        s.seal(1, None).unwrap();
        for i in 0..2_000u32 {
            s.delete(&i.to_be_bytes());
        }
        s.seal(2, None).unwrap();
        let full = s.stats().size_bytes;
        assert!(full > 16 << 20, "{full}");
        // The history still holds the values; pruning frees them, and the
        // file shrinks when compacted, now or at the next open.
        s.prune(2).unwrap();
        assert!(s.compact().unwrap());
        let shrunk = s.stats().size_bytes;
        assert!(shrunk < full / 4, "{shrunk} of {full}");
        assert!(!s.compact().unwrap());
        for i in 0..2_000u32 {
            s.set(&i.to_be_bytes(), &value);
        }
        s.seal(3, None).unwrap();
        for i in 0..2_000u32 {
            s.delete(&i.to_be_bytes());
        }
        s.seal(4, None).unwrap();
        s.prune(4).unwrap();
        let grown = s.stats().size_bytes;
        drop(s);
        let s = DiskStore::open(&dir).unwrap();
        let reopened = s.stats().size_bytes;
        assert!(reopened < grown / 4, "{reopened} of {grown}");
        assert_eq!(s.versions(), Some((4, 4)));
    }

    #[test]
    fn rows_that_do_not_decode_and_files_of_another_format_are_refused() {
        assert!(VersionRow::decode(&[0; 44]).is_none());
        let row = VersionRow {
            root: Some([5; 32]),
            written: 3,
            entries: 9,
        };
        assert_eq!(VersionRow::decode(&row.encode()), Some(row));
        assert_eq!(decode_old(&[]), None);
        assert_eq!(decode_old(&[0]), None);
        assert_eq!(decode_old(&[1, 2]), Some(vec![2]));
        assert_eq!(encode_old(None), vec![0]);
        let dir = scratch("format");
        drop(DiskStore::open(&dir).unwrap());
        let db = Database::open(dir.join(CHAIN_FILE)).unwrap();
        let txn = db.begin_write().unwrap();
        txn.open_table(META)
            .unwrap()
            .insert("format", 9u32.to_le_bytes().as_slice())
            .unwrap();
        txn.commit().unwrap();
        drop(db);
        assert_eq!(DiskStore::open(&dir).err(), Some(StoreError::Format(9)));
        // A file where the directory should be, and a store another process
        // (here: another handle) holds.
        let file = scratch("format-file");
        std::fs::write(&file, "x").unwrap();
        assert!(matches!(DiskStore::open(&file), Err(StoreError::Db(_))));
        let held = scratch("held");
        let _first = DiskStore::open(&held).unwrap();
        assert!(matches!(DiskStore::open(&held), Err(StoreError::Db(_))));
    }

    #[test]
    fn a_root_whose_node_is_gone_is_corruption() {
        let dir = scratch("corrupt");
        let mut s = DiskStore::open(&dir).unwrap();
        s.set(b"a", b"1");
        s.set(b"b", b"2");
        s.seal(0, None).unwrap();
        s.set(b"a", b"3");
        s.seal(1, None).unwrap();
        let root = s.trie_at(0).unwrap().root();
        drop(s);
        let db = Database::open(dir.join(CHAIN_FILE)).unwrap();
        let txn = db.begin_write().unwrap();
        txn.open_table(NODES).unwrap().remove(&root).unwrap();
        txn.commit().unwrap();
        drop(db);
        let mut s = DiskStore::open(&dir).unwrap();
        assert_eq!(
            s.prune(1),
            Err(StoreError::Corrupt("a live root names a missing node"))
        );
        // A node named before it is written is the same kind of defect.
        let txn = s.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(NODES).unwrap();
            let mut persist = Persist::default();
            persist.bump(&mut table, &[4; 32]).unwrap();
            assert!(persist.finish().is_err());
        }
        txn.abort().unwrap();
    }

    #[test]
    #[should_panic(expected = "a trie node its source holds")]
    fn a_trie_that_outlives_its_store_cannot_load() {
        let dir = scratch("outlive");
        let mut s = DiskStore::open(&dir).unwrap();
        for i in 0..8u8 {
            s.set(&[i], &[i]);
        }
        s.seal(0, None).unwrap();
        drop(s);
        let s = DiskStore::open(&dir).unwrap();
        let trie = s.state_trie();
        drop(s);
        let _ = trie.prove(&[1]);
    }
}
