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
//! twice them by more than [`COMPACTION_SLACK`], which is looked at each
//! time the journal has grown by [`COMPACTION_CHECK`]: measuring the tables
//! costs a pass over them, too much for every sync, which comes before
//! every send.

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

/// How much the journal grows between two looks at whether it should be
/// compacted.
pub const COMPACTION_CHECK: u64 = COMPACTION_SLACK / 4;

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
    /// The journal length at which compaction is next looked at.
    check_at: u64,
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

/// How many bytes `tables` take as journal records.
fn serialized_len(tables: &Tables) -> u64 {
    tables
        .iter()
        .map(|(key, value)| 8 + key.len() as u64 + value.len() as u64)
        .sum()
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
            check_at: 0,
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
        if self.journal_len < self.check_at {
            return Ok(());
        }
        if self.journal_len > 2 * serialized_len(live) + COMPACTION_SLACK {
            let live_bytes = serialize(live);
            let path = self.dir.join(JOURNAL_FILE);
            replace(&path, &live_bytes)?;
            self.journal = open_journal(&path)?;
            self.journal_len = live_bytes.len() as u64;
        }
        self.check_at = self.journal_len + COMPACTION_CHECK;
        Ok(())
    }
}

/// The tables keyed by a height, little-endian after the prefix: the
/// finalized proposal's hash, its vote certificate and its threshold
/// certificate.
const BY_HEIGHT: [&[u8]; 3] = [b"final/", b"cert/", b"bcert/"];

/// The tables keyed by a view, little-endian after the prefix: block votes,
/// finalize votes and threshold partials per `(view, hash)`, and the
/// notarized hash per view.
const BY_VIEW: [&[u8]; 4] = [b"votes/", b"fin/", b"part/", b"notar/"];

/// The first hash each validator signed per kind and view: `sig/ ‖ kind ‖
/// view ‖ validator`.
const SIGNED: &[u8] = b"sig/";

/// What the reference kernel's driver keeps of each DKG run it took part
/// in (spec 15 §6.4): what it sent in each phase, `dkg/out/ ‖ epoch ‖
/// phase`; its rotation share, `dkg/rshare2/ ‖ active ‖ target`; and the
/// handoff it combined, `dkg/handoff/ ‖ target ‖ epoch`; ids and epochs
/// big-endian. Each prefix with where, after it, the epoch it is pruned by
/// lies.
const BY_RUN: [(&[u8], usize); 3] = [(b"dkg/out/", 0), (b"dkg/rshare2/", 8), (b"dkg/handoff/", 8)];

/// How many epochs of DKG runs, counting back from the newest the tables
/// hold, a node keeps the records of (spec 22 §8.1). A run is over within
/// the epoch after its own; the margin covers any key age.
pub const DKG_RETENTION: u64 = 256;

/// The epoch a DKG run record of `key` belongs to, if it is one.
fn run_epoch(key: &[u8]) -> Option<u64> {
    let (prefix, at) = BY_RUN.iter().find(|(p, _)| key.starts_with(p))?;
    let bytes = key.get(prefix.len() + at..prefix.len() + at + 8)?;
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

/// The `u64` that starts at `at` in `bytes`, little-endian.
fn le64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// Deletes from `tables` what consensus no longer needs below `cutoff`, a
/// finalized height (spec 22 §8.1): the proposals of heights below it, the
/// hash and certificates of every finalized height below it, and the
/// votes, partials, notarizations and first signatures of the views below
/// the view of the proposal finalized at `cutoff`; and the records of the
/// DKG runs more than [`DKG_RETENTION`] epochs older than the newest.
/// Everything else (the driver state, the entry and tip certificates,
/// evidence, the DKG pool) stays. Returns how many entries went.
pub fn prune_tables(tables: &mut Tables, cutoff: u64) -> usize {
    let newest_run = tables.keys().filter_map(|k| run_epoch(k)).max();
    let view_at = tables
        .get(&[b"final/".as_slice(), &cutoff.to_le_bytes()].concat())
        .and_then(|hash| tables.get(&[b"prop/".as_slice(), hash].concat()))
        .and_then(|proposal| le64(proposal, 0));
    let before = tables.len();
    tables.retain(|key, value| {
        let below_view = |at: usize| view_at.is_some_and(|v| le64(key, at).is_some_and(|w| w < v));
        if let Some(prefix) = BY_HEIGHT.iter().find(|p| key.starts_with(p)) {
            return le64(key, prefix.len()).is_none_or(|h| h >= cutoff);
        }
        if key.starts_with(b"prop/") {
            // A proposal's encoding starts with its view and its height.
            return le64(value, 8).is_none_or(|h| h >= cutoff);
        }
        if let Some(prefix) = BY_VIEW.iter().find(|p| key.starts_with(p)) {
            return !below_view(prefix.len());
        }
        if key.starts_with(SIGNED) {
            return !below_view(SIGNED.len() + 1);
        }
        if let (Some(epoch), Some(newest)) = (run_epoch(key), newest_run) {
            return epoch + DKG_RETENTION >= newest;
        }
        true
    });
    before - tables.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> solo_scratch::Scratch {
        solo_scratch::Scratch::new("store", name)
    }

    fn tables(pairs: &[(&[u8], &[u8])]) -> Tables {
        pairs
            .iter()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect()
    }

    #[test]
    fn pruning_keeps_what_consensus_still_needs() {
        let at = |prefix: &[u8], n: u64| [prefix, &n.to_le_bytes()[..]].concat();
        // Proposals: view and height first, as the encoding starts.
        let proposal = |view: u64, height: u64| [view.to_le_bytes(), height.to_le_bytes()].concat();
        let mut t = Tables::new();
        for b in 1..=6u8 {
            let (h, hash) = (u64::from(b), [b; 32]);
            t.insert(at(b"final/", h), hash.to_vec());
            t.insert(at(b"cert/", h), vec![1]);
            t.insert(at(b"bcert/", h), vec![2]);
            t.insert([b"prop/".as_slice(), &hash].concat(), proposal(10 * h, h));
            t.insert([at(b"votes/", 10 * h), hash.to_vec()].concat(), vec![3]);
            t.insert([at(b"fin/", 10 * h), hash.to_vec()].concat(), vec![3]);
            t.insert([at(b"part/", 10 * h), hash.to_vec()].concat(), vec![3]);
            t.insert(at(b"notar/", 10 * h), hash.to_vec());
            t.insert(
                [b"sig/".as_slice(), &[1], &(10 * h).to_le_bytes(), &[0; 4]].concat(),
                vec![4],
            );
        }
        // A proposal that lost its view at height 2, the driver's own keys,
        // evidence, and keys too short to carry a height or a view.
        t.insert(b"prop/fork".to_vec(), proposal(21, 2));
        t.insert(b"simplex/state".to_vec(), vec![5]);
        t.insert(b"evidence/x".to_vec(), vec![6]);
        t.insert(b"final/x".to_vec(), vec![7]);
        t.insert(b"prop/short".to_vec(), vec![8]);
        t.insert(b"votes/x".to_vec(), vec![9]);
        // DKG run records: epochs 3 and 300 of each kind; 3 is more than
        // DKG_RETENTION epochs older than 300. A record too short to name
        // its epoch, and the pool, stay.
        let run = |prefix: &[u8], epoch: u64, at: usize| {
            let mut key = prefix.to_vec();
            key.extend(vec![0; at]);
            key.extend(epoch.to_be_bytes());
            key.push(1);
            key
        };
        for epoch in [3, 300] {
            t.insert(run(b"dkg/out/", epoch, 0), vec![10]);
            t.insert(run(b"dkg/rshare2/", epoch, 8), vec![10]);
            t.insert(run(b"dkg/handoff/", epoch, 8), vec![10]);
        }
        t.insert(b"dkg/out/x".to_vec(), vec![11]);
        t.insert(b"dkg/pool".to_vec(), vec![12]);
        let all = t.len();
        // Below height 4 and view 40 everything goes: three heights of nine
        // entries each and the fork's proposal; and the three records of
        // the old DKG run.
        assert_eq!(prune_tables(&mut t, 4), 3 * 9 + 1 + 3);
        assert_eq!(t.len(), all - 31);
        for kept in [
            run(b"dkg/out/", 300, 0),
            run(b"dkg/rshare2/", 300, 8),
            run(b"dkg/handoff/", 300, 8),
            b"dkg/out/x".to_vec(),
            b"dkg/pool".to_vec(),
        ] {
            assert!(t.contains_key(&kept), "{kept:?}");
        }
        for h in 4..=6u64 {
            assert!(t.contains_key(&at(b"final/", h)));
            assert!(t.contains_key(&at(b"notar/", 10 * h)));
        }
        assert!(!t.contains_key(&at(b"final/", 3)));
        assert!(!t.contains_key(&at(b"notar/", 30)));
        for kept in [
            &b"simplex/state"[..],
            b"evidence/x",
            b"final/x",
            b"prop/short",
            b"votes/x",
        ] {
            assert!(t.contains_key(kept), "{kept:?}");
        }
        // Again at the same height: nothing more. At a height the tables do
        // not hold, the view-keyed entries stay, the heights go.
        assert_eq!(prune_tables(&mut t, 4), 0);
        let mut gap = t.clone();
        gap.remove(&at(b"final/", 5));
        assert_eq!(prune_tables(&mut gap, 5), 4);
        assert!(gap.contains_key(&at(b"notar/", 40)));
    }

    #[test]
    fn a_fresh_store_is_empty_and_a_synced_one_comes_back() {
        let dir = scratch("roundtrip");
        let mut store = DriverStore::open(&dir).unwrap();
        assert_eq!(store.dir(), dir.path());
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
        // The tables are measured once, at the first sync, and then not
        // again until the journal has grown by COMPACTION_CHECK: a sync
        // comes before every send, and a pass over large tables each time
        // cost a node most of its time and memory (found by the soak test).
        store.pending.push((b"k".to_vec(), value.clone()));
        store.sync(Some(b"s"), &live).unwrap();
        assert_eq!(store.check_at, 4105 + COMPACTION_CHECK);
        store.sync(Some(b"s"), &live).unwrap();
        assert_eq!(store.check_at, 4105 + COMPACTION_CHECK);
        // Rewriting one key past the slack leaves a journal of one record,
        // looked at every COMPACTION_CHECK bytes of journal.
        for _ in 0..399 {
            store.pending.push((b"k".to_vec(), value.clone()));
            store.sync(Some(b"s"), &live).unwrap();
        }
        // 400 records would be 1 642 000 bytes; the rewrite kept the bound.
        let len = fs::metadata(dir.join(JOURNAL_FILE)).unwrap().len();
        assert!(
            len <= 2 * 4105 + COMPACTION_SLACK + COMPACTION_CHECK + 4105,
            "{len}"
        );
        assert!(len < 400 * 4105, "{len}");
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
