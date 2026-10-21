//! The driver's node-local data on disk, so that a validator that restarts
//! resumes the view it left with what it did there and never votes twice in
//! one view (spec 06 §4.2, spec 08 §3 and §7).
//!
//! A store is a directory with two files: [`STATE_FILE`], the latest
//! `PersistState`, replaced atomically; and [`JOURNAL_FILE`], every
//! `persist_set` the kernel made, appended in order as `key length ‖ value
//! length` (both `u32` little-endian) `‖ key ‖ value`. Opening a store
//! replays the journal into the tables the node opens with and reads the
//! state the driver resumes from; a record cut short by a crash is dropped,
//! since nothing that depended on it was ever sent. The host syncs the store
//! before it sends anything the driver produced ([`crate::Transport::poll`]),
//! so a vote a peer holds is always a vote the node remembers after a
//! restart. The journal is rewritten from the live tables once it outgrows
//! them by more than [`COMPACTION_SLACK`].

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// The latest `PersistState`.
pub const STATE_FILE: &str = "driver.state";

/// The journal of `persist_set` writes.
pub const JOURNAL_FILE: &str = "persist.log";

/// How far the journal may outgrow twice the live tables before it is
/// rewritten from them.
pub const COMPACTION_SLACK: u64 = 1 << 20;

/// The node-local tables and driver state.
pub type Tables = BTreeMap<Vec<u8>, Vec<u8>>;

/// An open store directory.
#[derive(Debug)]
pub struct DriverStore {
    dir: PathBuf,
    journal: File,
    journal_len: u64,
    /// What `open` read, until the host takes it.
    loaded: Option<(Tables, Option<Vec<u8>>)>,
    /// `persist_set` writes not yet journaled.
    pub(crate) pending: Vec<(Vec<u8>, Vec<u8>)>,
    /// The state as last written.
    last_state: Option<Vec<u8>>,
}

/// A record's length field: `persist_set` takes `u32` lengths (spec 05 §4.6).
fn length(n: usize) -> [u8; 4] {
    u32::try_from(n)
        .expect("persist_set lengths are u32")
        .to_le_bytes()
}

/// One journal record.
fn record(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    out.extend_from_slice(&length(key.len()));
    out.extend_from_slice(&length(value.len()));
    out.extend_from_slice(key);
    out.extend_from_slice(value);
}

/// The tables a journal holds, and how many of its bytes are whole records.
fn replay(bytes: &[u8]) -> (Tables, u64) {
    let mut tables = Tables::new();
    let mut at = 0usize;
    while let Some(header) = bytes.get(at..at + 8) {
        let key_len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let value_len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        let key_end = at + 8 + key_len;
        let Some(key) = bytes.get(at + 8..key_end) else {
            break;
        };
        let Some(value) = bytes.get(key_end..key_end + value_len) else {
            break;
        };
        tables.insert(key.to_vec(), value.to_vec());
        at = key_end + value_len;
    }
    (tables, at as u64)
}

/// The bytes of `tables` as journal records.
fn serialize(tables: &Tables) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, value) in tables {
        record(&mut out, key, value);
    }
    out
}

/// Writes `bytes` to `path` so that a reader sees the old file or the new
/// one, never a mix: a temporary beside it, synced, then renamed over it.
fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut file = File::create(&tmp)?;
    file.write_all(bytes)?;
    file.sync_data()?;
    fs::rename(&tmp, path)
}

fn open_journal(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)
}

impl DriverStore {
    /// Opens the store in `dir`, creating it when it does not exist, and
    /// reads what a previous run left.
    ///
    /// # Errors
    /// If the directory or either file cannot be created or read.
    pub fn open(dir: &Path) -> io::Result<DriverStore> {
        fs::create_dir_all(dir)?;
        let mut journal = open_journal(&dir.join(JOURNAL_FILE))?;
        let mut bytes = Vec::new();
        journal.read_to_end(&mut bytes)?;
        let (tables, complete) = replay(&bytes);
        if complete < bytes.len() as u64 {
            // A record cut short by a crash was never synced before a send
            // that relied on it; the journal ends at the last whole one.
            journal.set_len(complete)?;
        }
        let state = match fs::read(dir.join(STATE_FILE)) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        Ok(DriverStore {
            dir: dir.to_path_buf(),
            journal,
            journal_len: complete,
            last_state: state.clone(),
            loaded: Some((tables, state)),
            pending: Vec::new(),
        })
    }

    /// The directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// What the previous run left, once: the tables to open the node with
    /// and the state to start the driver from.
    pub fn take_loaded(&mut self) -> (Tables, Option<Vec<u8>>) {
        self.loaded.take().unwrap_or_default()
    }

    /// Whether anything waits to be written.
    #[must_use]
    pub fn is_dirty(&self, state: Option<&[u8]>) -> bool {
        !self.pending.is_empty() || (state.is_some() && self.last_state.as_deref() != state)
    }

    /// Writes the driver `state` when it changed and the pending
    /// `persist_set` writes, synced to disk, and compacts the journal when
    /// it has outgrown the `live` tables. The state goes first: a crash in
    /// between leaves a state that knows every vote, with tables that may
    /// lack the last proposal, which the driver asks its peers for again.
    ///
    /// # Errors
    /// The first write that fails; what failed to reach disk is written
    /// again by the next call.
    pub fn sync(&mut self, state: Option<&[u8]>, live: &Tables) -> io::Result<()> {
        if let Some(state) = state
            && self.last_state.as_deref() != Some(state)
        {
            replace(&self.dir.join(STATE_FILE), state)?;
            self.last_state = Some(state.to_vec());
        }
        if !self.pending.is_empty() {
            let mut bytes = Vec::new();
            for (key, value) in &self.pending {
                record(&mut bytes, key, value);
            }
            self.journal.write_all(&bytes)?;
            self.journal.sync_data()?;
            self.journal_len += bytes.len() as u64;
            self.pending.clear();
        }
        let live_bytes = serialize(live);
        if self.journal_len > 2 * live_bytes.len() as u64 + COMPACTION_SLACK {
            let path = self.dir.join(JOURNAL_FILE);
            replace(&path, &live_bytes)?;
            self.journal = open_journal(&path)?;
            self.journal_len = live_bytes.len() as u64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("solo-store-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn tables(pairs: &[(&[u8], &[u8])]) -> Tables {
        pairs
            .iter()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect()
    }

    #[test]
    fn a_fresh_store_is_empty_and_a_synced_one_comes_back() {
        let dir = scratch("roundtrip");
        let mut store = DriverStore::open(&dir).unwrap();
        assert_eq!(store.dir(), dir.as_path());
        assert_eq!(store.take_loaded(), (Tables::new(), None));
        assert_eq!(store.take_loaded(), (Tables::new(), None));
        assert!(!store.is_dirty(None));
        // Nothing to write: no files change.
        store.sync(None, &Tables::new()).unwrap();
        assert!(!dir.join(STATE_FILE).exists());
        store.pending.push((b"a".to_vec(), b"1".to_vec()));
        assert!(store.is_dirty(None));
        assert!(store.is_dirty(Some(b"s1")));
        let live = tables(&[(b"a", b"1")]);
        store.sync(Some(b"s1"), &live).unwrap();
        assert!(!store.is_dirty(Some(b"s1")));
        assert!(store.is_dirty(Some(b"s2")));
        store.pending.push((b"a".to_vec(), b"2".to_vec()));
        store.pending.push((b"b".to_vec(), b"".to_vec()));
        let live = tables(&[(b"a", b"2"), (b"b", b"")]);
        store.sync(Some(b"s2"), &live).unwrap();
        // The same state again is not rewritten.
        let written = fs::metadata(dir.join(STATE_FILE))
            .unwrap()
            .modified()
            .unwrap();
        store.sync(Some(b"s2"), &live).unwrap();
        assert_eq!(
            fs::metadata(dir.join(STATE_FILE))
                .unwrap()
                .modified()
                .unwrap(),
            written
        );
        drop(store);
        let mut again = DriverStore::open(&dir).unwrap();
        assert_eq!(again.take_loaded(), (live.clone(), Some(b"s2".to_vec())));
        assert!(!again.is_dirty(Some(b"s2")));
        // A record cut short is dropped and the journal ends at the whole ones.
        let whole = fs::metadata(dir.join(JOURNAL_FILE)).unwrap().len();
        let mut journal = OpenOptions::new()
            .append(true)
            .open(dir.join(JOURNAL_FILE))
            .unwrap();
        journal.write_all(&[3, 0, 0, 0, 5, 0, 0, 0, b'x']).unwrap();
        drop(journal);
        let mut cut = DriverStore::open(&dir).unwrap();
        assert_eq!(cut.take_loaded().0, live);
        assert_eq!(fs::metadata(dir.join(JOURNAL_FILE)).unwrap().len(), whole);
        // A header alone, and a key without its value, are cut short too.
        assert_eq!(replay(&[1, 0, 0, 0, 1, 0, 0, 0]).1, 0);
        assert_eq!(replay(&[1, 0, 0, 0, 1, 0, 0, 0, b'k']).1, 0);
        assert_eq!(replay(&[0, 0, 0, 0, 0, 0, 0, 0]).1, 8);
    }

    #[test]
    fn the_journal_is_compacted_once_it_outgrows_the_tables() {
        let dir = scratch("compact");
        let mut store = DriverStore::open(&dir).unwrap();
        let value = vec![7u8; 4096];
        let live = tables(&[(b"k", &value)]);
        // Rewriting one key past the slack leaves a journal of one record.
        for _ in 0..300 {
            store.pending.push((b"k".to_vec(), value.clone()));
            store.sync(Some(b"s"), &live).unwrap();
        }
        // 300 records would be 1 231 500 bytes; the rewrite kept the bound.
        let len = fs::metadata(dir.join(JOURNAL_FILE)).unwrap().len();
        assert!(len <= 2 * 4105 + COMPACTION_SLACK, "{len}");
        assert_eq!((len % 4105, store.journal_len), (0, len));
        // Appends continue on the rewritten journal.
        store.pending.push((b"j".to_vec(), b"2".to_vec()));
        store.sync(None, &live).unwrap();
        let mut again = DriverStore::open(&dir).unwrap();
        let (tables, state) = again.take_loaded();
        assert_eq!(tables.get(b"j".as_slice()), Some(&b"2".to_vec()));
        assert_eq!(tables.get(b"k".as_slice()), Some(&value));
        assert_eq!(state, Some(b"s".to_vec()));
    }

    #[cfg(unix)]
    #[test]
    fn disk_refusals_are_reported_and_retried() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("refusals");
        let mut store = DriverStore::open(&dir).unwrap();
        store.pending.push((b"a".to_vec(), b"1".to_vec()));
        let live = tables(&[(b"a", b"1")]);
        // A directory that cannot be written refuses the state file.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        assert!(store.sync(Some(b"s"), &live).is_err());
        assert!(store.is_dirty(Some(b"s")));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        store.sync(Some(b"s"), &live).unwrap();
        assert!(!store.is_dirty(Some(b"s")));
        // A state file that cannot be read, or a journal that cannot be opened, refuses to open.
        fs::set_permissions(dir.join(STATE_FILE), fs::Permissions::from_mode(0o000)).unwrap();
        assert!(DriverStore::open(&dir).is_err());
        fs::set_permissions(dir.join(STATE_FILE), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(dir.join(JOURNAL_FILE), fs::Permissions::from_mode(0o000)).unwrap();
        assert!(DriverStore::open(&dir).is_err());
        fs::set_permissions(dir.join(JOURNAL_FILE), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(DriverStore::open(&dir).is_ok());
        // A file where the directory should be.
        let file = scratch("refusals-file");
        fs::write(&file, "x").unwrap();
        assert!(DriverStore::open(&file).is_err());
    }
}
