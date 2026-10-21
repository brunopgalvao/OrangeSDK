//! Key-value storage with per-call overlays (spec 05 §4.2).
//!
//! Keys handed to the host by a sandboxed instance are prefixed with the
//! instance's 32-byte namespace before they reach the store, so two contracts
//! never see each other's keys. Writes go into an overlay layer per call
//! frame; a frame that halts normally has its layer merged into the one
//! below, any other termination discards it.
//!
//! The state commitment (spec 10) is the root of a [`Trie`] over the
//! committed entries: every visible key except those under [`LOCAL_PREFIX`].
//! A store supplies the trie of its own entries through
//! [`Storage::state_trie`], and [`MemStorage`] keeps one current on every
//! write. Each overlay layer builds the trie of everything visible through
//! it the first time a root or proof needs it, then keeps it and brings it up
//! to date with only the keys written since. So the hashing behind a root or
//! a proof is O(depth) per key written since the last one: never a pass over
//! the state, and never every pending write again. A layer merged into the
//! base hands its trie over rather than having its writes hashed twice.
//!
//! A [`MemStorage`] can also keep its history: the value every committed key
//! held before each numbered *version* changed it, so that it reads as it was
//! when a version was sealed ([`MemStorage::set_view`]). A node seals one
//! version per executed block and serves historical state from it (spec 20
//! §5).

use std::collections::{BTreeMap, BTreeSet};

use solo_trie::{Hash, HashFn, Trie};

/// Maximum key length in bytes an instance names (spec 05 §4.2).
pub const MAX_KEY_LEN: usize = 64;
/// Maximum key length in bytes the store holds: an instance's key behind a
/// sandboxed instance's 32-byte namespace (spec 05 §4.2, spec 10 §2).
pub const MAX_STORED_KEY_LEN: usize = 32 + MAX_KEY_LEN;
/// Maximum value length in bytes (spec 05 §4.2).
pub const MAX_VALUE_LEN: usize = 65_536;

/// Keys under this prefix are node-local bookkeeping, outside the state
/// commitment (spec 05 §4.3, spec 10 §2).
pub const LOCAL_PREFIX: &[u8] = b"local/";

/// Whether `key` is part of the state commitment (spec 10 §2).
#[must_use]
pub fn committed(key: &[u8]) -> bool {
    !key.starts_with(LOCAL_PREFIX)
}

/// The writes of one overlay layer, by key: the new value, or `None` for a
/// deletion.
pub type Writes = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// Applies one write to `trie`, unless the key is outside the commitment.
fn apply(trie: &mut Trie, key: &[u8], value: Option<&[u8]>) {
    if !committed(key) {
        return;
    }
    match value {
        Some(value) => trie.insert(key, value),
        None => {
            trie.remove(key);
        }
    }
}

/// The base store beneath the overlays.
pub trait Storage {
    /// The value at `key`.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    /// Sets `key` to `value`.
    fn set(&mut self, key: &[u8], value: &[u8]);
    /// Removes `key`; returns whether it existed.
    fn delete(&mut self, key: &[u8]) -> bool;
    /// All entries whose key starts with `prefix`, in bytewise key order.
    fn scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)>;

    /// The state trie (spec 10) of this store's committed entries. This
    /// default builds it from a full scan; a store that maintains its trie as
    /// it is written overrides it.
    fn state_trie(&self) -> Trie {
        let mut trie = Trie::new();
        for (key, value) in self.scan(&[]) {
            apply(&mut trie, &key, Some(&value));
        }
        trie
    }

    /// Applies the writes of the bottom overlay layer when it merges, given
    /// `trie`, the overlay's state trie of this store with the writes
    /// applied. This default writes them one by one and drops `trie`; a
    /// store that maintains its trie adopts `trie` instead of hashing the
    /// writes again.
    fn merge_layer(&mut self, writes: Writes, trie: Trie) {
        drop(trie);
        for (key, value) in writes {
            match value {
                Some(value) => self.set(&key, &value),
                None => {
                    self.delete(&key);
                }
            }
        }
    }
}

/// The history of a [`MemStorage`]'s committed entries.
#[derive(Debug, Default, Clone)]
struct History {
    /// The value each key written since the last seal held at that seal.
    pending: Writes,
    /// For each key written since the oldest version kept, by the version
    /// whose span (from the version before's seal to its own) first wrote
    /// it, the value it held before that span.
    versions: BTreeMap<Vec<u8>, BTreeMap<u64, Option<Vec<u8>>>>,
    /// The keys each sealed version wrote, to prune by.
    written: BTreeMap<u64, Vec<Vec<u8>>>,
    /// The oldest version the store can read as.
    oldest: u64,
    /// The latest version sealed.
    latest: u64,
    /// The version reads see, if not the current state.
    view: Option<u64>,
}

impl History {
    /// The value `key` held when version `at` was sealed, given `current`,
    /// the value it holds now.
    fn at(&self, key: &[u8], at: u64, current: Option<Vec<u8>>) -> Option<Vec<u8>> {
        let later = self
            .versions
            .get(key)
            .and_then(|v| v.range(at + 1..).next());
        match later.map(|(_, old)| old).or_else(|| self.pending.get(key)) {
            Some(old) => old.clone(),
            None => current,
        }
    }
}

/// An in-memory store that keeps the trie of its committed entries current,
/// and their history once [`MemStorage::keep_history`] starts it.
#[derive(Debug, Default, Clone)]
pub struct MemStorage {
    map: BTreeMap<Vec<u8>, Vec<u8>>,
    trie: Trie,
    history: Option<History>,
}

impl MemStorage {
    /// An empty store whose trie hashes with `hash`, which must be
    /// `keccak256` for the roots of spec 10: for a host with its own
    /// implementation of it.
    #[must_use]
    pub fn with_hasher(hash: HashFn) -> MemStorage {
        MemStorage {
            map: BTreeMap::new(),
            trie: Trie::with_hasher(hash),
            history: None,
        }
    }

    /// Starts keeping history, the current state being version `version`.
    pub fn keep_history(&mut self, version: u64) {
        self.history = Some(History {
            oldest: version,
            latest: version,
            ..History::default()
        });
    }

    /// Ends the current version's span: what was written since the last seal
    /// becomes version `version`'s, which must be above every version sealed
    /// before. Without history, does nothing.
    pub fn seal(&mut self, version: u64) {
        let Some(history) = self.history.as_mut() else {
            return;
        };
        let pending = std::mem::take(&mut history.pending);
        let mut keys = Vec::with_capacity(pending.len());
        for (key, old) in pending {
            history
                .versions
                .entry(key.clone())
                .or_default()
                .insert(version, old);
            keys.push(key);
        }
        history.written.insert(version, keys);
        history.latest = version;
    }

    /// Forgets what reading as a version below `oldest` needs, which can no
    /// longer be read. Without history, does nothing.
    pub fn prune(&mut self, oldest: u64) {
        let Some(history) = self.history.as_mut() else {
            return;
        };
        let oldest = oldest.min(history.latest);
        if oldest <= history.oldest {
            return;
        }
        // Reading as version v needs the versions above v: those up to
        // `oldest` go.
        let kept = history.written.split_off(&(oldest + 1));
        for (version, keys) in std::mem::replace(&mut history.written, kept) {
            for key in keys {
                if let Some(versions) = history.versions.get_mut(&key) {
                    versions.remove(&version);
                    if versions.is_empty() {
                        history.versions.remove(&key);
                    }
                }
            }
        }
        history.oldest = oldest;
    }

    /// The versions the store can read as, oldest and latest; `None` without
    /// history.
    #[must_use]
    pub fn versions(&self) -> Option<(u64, u64)> {
        self.history.as_ref().map(|h| (h.oldest, h.latest))
    }

    /// Makes reads ([`Storage::get`], [`Storage::scan`]) see the committed
    /// entries as they were when `version` was sealed, or the current state
    /// for `None`. Keys outside the commitment read as they are. Writes must
    /// not reach the store while a view is set: a node reads historical
    /// state through an overlay layer it discards.
    ///
    /// # Errors
    /// The versions the store can read as, when `version` is not among them
    /// or the store keeps no history.
    pub fn set_view(&mut self, version: Option<u64>) -> Result<(), Option<(u64, u64)>> {
        let range = self.versions();
        match (self.history.as_mut(), version) {
            (Some(history), Some(v)) if (history.oldest..=history.latest).contains(&v) => {
                history.view = Some(v);
                Ok(())
            }
            (Some(history), None) => {
                history.view = None;
                Ok(())
            }
            (None, None) => Ok(()),
            _ => Err(range),
        }
    }

    /// Records the value `key` holds before a write, the first time it is
    /// written since the last seal.
    fn note(&mut self, key: &[u8]) {
        if let Some(history) = self.history.as_mut()
            && committed(key)
            && !history.pending.contains_key(key)
        {
            history
                .pending
                .insert(key.to_vec(), self.map.get(key).cloned());
        }
    }

    /// The version reads see, if a view is set.
    fn viewed(&self) -> Option<(&History, u64)> {
        let history = self.history.as_ref()?;
        Some((history, history.view?))
    }

    /// Number of keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl Storage for MemStorage {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let current = self.map.get(key).cloned();
        match self.viewed() {
            Some((history, at)) if committed(key) => history.at(key, at, current),
            _ => current,
        }
    }

    fn set(&mut self, key: &[u8], value: &[u8]) {
        self.note(key);
        self.map.insert(key.to_vec(), value.to_vec());
        apply(&mut self.trie, key, Some(value));
    }

    fn delete(&mut self, key: &[u8]) -> bool {
        self.note(key);
        let existed = self.map.remove(key).is_some();
        if existed {
            apply(&mut self.trie, key, None);
        }
        existed
    }

    fn scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let current = self
            .map
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()));
        let Some((history, at)) = self.viewed() else {
            return current.collect();
        };
        // The current entries, then every key written since the version
        // read as, with the value it held then.
        let mut merged: BTreeMap<Vec<u8>, Option<Vec<u8>>> =
            current.map(|(k, v)| (k, Some(v))).collect();
        let written = history
            .versions
            .range(prefix.to_vec()..)
            .map(|(k, _)| k)
            .take_while(|k| k.starts_with(prefix))
            .chain(
                history
                    .pending
                    .range(prefix.to_vec()..)
                    .map(|(k, _)| k)
                    .take_while(|k| k.starts_with(prefix)),
            );
        for key in written {
            let current = merged.get(key).cloned().flatten();
            merged.insert(key.clone(), history.at(key, at, current));
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

    /// Writes the map and adopts `trie`, which already holds the writes.
    fn merge_layer(&mut self, writes: Writes, trie: Trie) {
        for key in writes.keys() {
            self.note(key);
        }
        for (key, value) in writes {
            match value {
                Some(value) => {
                    self.map.insert(key, value);
                }
                None => {
                    self.map.remove(&key);
                }
            }
        }
        self.trie = trie;
    }
}

/// One overlay layer: its writes and, once a root or proof has needed it,
/// the state trie of everything visible through it.
#[derive(Debug, Default)]
struct Layer {
    writes: Writes,
    /// The trie of the base with this layer and every one below applied, as
    /// of the last time it was brought up to date; `None` until first needed.
    trie: Option<Trie>,
    /// Committed keys written in this layer since `trie` was brought up to
    /// date, to apply before it is next used. Empty while `trie` is `None`.
    stale: BTreeSet<Vec<u8>>,
}

impl Layer {
    fn write(&mut self, key: &[u8], value: Option<Vec<u8>>) {
        if self.trie.is_some() && committed(key) {
            self.stale.insert(key.to_vec());
        }
        self.writes.insert(key.to_vec(), value);
    }

    /// Applies the stale keys to the trie, if built, and returns a clone of
    /// it.
    fn catch_up(&mut self) -> Option<Trie> {
        let trie = self.trie.as_mut()?;
        for key in std::mem::take(&mut self.stale) {
            apply(trie, &key, self.writes[&key].as_deref());
        }
        Some(trie.clone())
    }
}

/// A stack of write layers over a base store.
///
/// The layers that have built their trie are always the bottom ones: a
/// layer is built from the one below, which is built first. Only the highest
/// built layer can have stale keys, since a layer is written only while it
/// is on top.
#[derive(Debug)]
pub struct Overlay<S: Storage> {
    base: S,
    layers: Vec<Layer>,
}

impl<S: Storage> Overlay<S> {
    /// Wraps `base` with no layers; reads and writes go straight to it until
    /// [`Overlay::push`].
    pub fn new(base: S) -> Overlay<S> {
        Overlay {
            base,
            layers: Vec::new(),
        }
    }

    /// The base store.
    pub fn base(&self) -> &S {
        &self.base
    }

    /// The base store, mutably: for a host that manages it (history,
    /// views) between calls, with no layer open.
    pub fn base_mut(&mut self) -> &mut S {
        &mut self.base
    }

    /// Consumes the overlay, returning the base store. Open layers are dropped.
    pub fn into_base(self) -> S {
        self.base
    }

    /// Number of open layers.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.layers.len()
    }

    /// Opens a new layer.
    pub fn push(&mut self) {
        self.layers.push(Layer::default());
    }

    /// Merges the top layer into the one below, or into the base if it was the
    /// only layer. Does nothing with no layers.
    pub fn commit(&mut self) {
        let Some(mut top) = self.layers.pop() else {
            return;
        };
        if let Some(below) = self.layers.last_mut() {
            if top.trie.is_some() {
                // Built from `below`, which saw no writes since: it holds both.
                below.trie = top.trie;
                below.stale = top.stale;
            } else if below.trie.is_some() {
                below
                    .stale
                    .extend(top.writes.keys().filter(|k| committed(k)).cloned());
            }
            below.writes.extend(top.writes);
            return;
        }
        match top.catch_up() {
            Some(trie) => self.base.merge_layer(top.writes, trie),
            None => {
                for (k, v) in top.writes {
                    match v {
                        Some(v) => self.base.set(&k, &v),
                        None => {
                            self.base.delete(&k);
                        }
                    }
                }
            }
        }
    }

    /// Drops the top layer. Does nothing with no layers.
    pub fn discard(&mut self) {
        self.layers.pop();
    }

    /// Reads through the layers to the base.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        for layer in self.layers.iter().rev() {
            if let Some(v) = layer.writes.get(key) {
                return v.clone();
            }
        }
        self.base.get(key)
    }

    /// Writes into the top layer, or the base with no layers.
    pub fn set(&mut self, key: &[u8], value: &[u8]) {
        match self.layers.last_mut() {
            Some(layer) => layer.write(key, Some(value.to_vec())),
            None => self.base.set(key, value),
        }
    }

    /// Deletes in the top layer, or the base with no layers. Returns whether
    /// the key was visible before.
    pub fn delete(&mut self, key: &[u8]) -> bool {
        let existed = self.get(key).is_some();
        match self.layers.last_mut() {
            Some(layer) => layer.write(key, None),
            None => {
                self.base.delete(key);
            }
        }
        existed
    }

    /// The state trie of everything visible (spec 10 §2): the base store's
    /// committed entries with every open layer applied.
    ///
    /// Brings the highest built layer's trie up to date, then builds each
    /// layer above it from the one beneath, keeping every one. Once up to
    /// date this is an O(1) copy-on-write clone; bringing it up to date
    /// hashes only the keys written since the last call.
    pub fn state_trie(&mut self) -> Trie {
        let mut from = 0;
        let mut built = None;
        if let Some(i) = self.layers.iter().rposition(|l| l.trie.is_some()) {
            built = self.layers[i].catch_up();
            from = i + 1;
        }
        let mut trie = built.unwrap_or_else(|| self.base.state_trie());
        for layer in &mut self.layers[from..] {
            for (key, value) in &layer.writes {
                apply(&mut trie, key, value.as_deref());
            }
            layer.trie = Some(trie.clone());
        }
        trie
    }

    /// The state commitment of everything visible (spec 10 §4): what
    /// `storage_commit` returns.
    pub fn commitment(&mut self) -> Hash {
        self.state_trie().root()
    }

    /// Entries under `prefix` as visible through every layer, in key order.
    pub fn scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut merged: BTreeMap<Vec<u8>, Option<Vec<u8>>> = self
            .base
            .scan(prefix)
            .into_iter()
            .map(|(k, v)| (k, Some(v)))
            .collect();
        for layer in &self.layers {
            for (k, v) in layer
                .writes
                .range(prefix.to_vec()..)
                .take_while(|(k, _)| k.starts_with(prefix))
            {
                merged.insert(k.clone(), v.clone());
            }
        }
        merged
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect()
    }
}

/// Prefixes `key` with `namespace` (spec 05 §4.2).
#[must_use]
pub fn namespaced(namespace: &[u8; 32], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + key.len());
    out.extend_from_slice(namespace);
    out.extend_from_slice(key);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_storage_basics() {
        let mut s = MemStorage::default();
        assert!(s.is_empty());
        s.set(b"a/1", b"x");
        s.set(b"a/2", b"y");
        s.set(b"b/1", b"z");
        assert_eq!(s.len(), 3);
        assert_eq!(s.get(b"a/1"), Some(b"x".to_vec()));
        assert_eq!(s.get(b"nope"), None);
        assert_eq!(
            s.scan(b"a/"),
            vec![
                (b"a/1".to_vec(), b"x".to_vec()),
                (b"a/2".to_vec(), b"y".to_vec())
            ]
        );
        assert!(s.delete(b"a/1"));
        assert!(!s.delete(b"a/1"));
        assert_eq!(s.scan(b"a/"), vec![(b"a/2".to_vec(), b"y".to_vec())]);
        let c = s.clone();
        assert_eq!(c.len(), 2);
        assert!(format!("{s:?}").contains("MemStorage"));
    }

    #[test]
    fn overlay_layers_commit_and_discard() {
        let mut base = MemStorage::default();
        base.set(b"k1", b"base");
        base.set(b"k2", b"base");
        let mut o = Overlay::new(base);
        assert_eq!(o.depth(), 0);
        // No layers: straight through.
        o.set(b"k3", b"direct");
        assert!(o.delete(b"k2"));
        assert_eq!(o.base().get(b"k3"), Some(b"direct".to_vec()));
        assert_eq!(o.base().get(b"k2"), None);
        o.commit();
        o.discard();
        // One layer, discarded.
        o.push();
        o.set(b"k1", b"l1");
        assert!(o.delete(b"k3"));
        assert_eq!(o.get(b"k1"), Some(b"l1".to_vec()));
        assert_eq!(o.get(b"k3"), None);
        assert_eq!(o.scan(b"k"), vec![(b"k1".to_vec(), b"l1".to_vec())]);
        o.discard();
        assert_eq!(o.get(b"k1"), Some(b"base".to_vec()));
        assert_eq!(o.get(b"k3"), Some(b"direct".to_vec()));
        // Two layers, inner committed into outer, outer committed into base.
        o.push();
        o.set(b"k1", b"outer");
        o.push();
        o.set(b"k4", b"inner");
        assert!(!o.delete(b"missing"));
        assert!(o.delete(b"k1"));
        assert_eq!(o.get(b"k1"), None);
        assert_eq!(o.depth(), 2);
        o.commit();
        assert_eq!(o.depth(), 1);
        assert_eq!(o.get(b"k1"), None);
        assert_eq!(o.get(b"k4"), Some(b"inner".to_vec()));
        assert_eq!(
            o.scan(b"k"),
            vec![
                (b"k3".to_vec(), b"direct".to_vec()),
                (b"k4".to_vec(), b"inner".to_vec())
            ]
        );
        o.commit();
        let base = o.into_base();
        assert_eq!(base.get(b"k1"), None);
        assert_eq!(base.get(b"k4"), Some(b"inner".to_vec()));
        assert_eq!(base.get(b"missing"), None);
    }

    /// The root by definition: a fresh trie over the visible committed entries.
    fn rebuilt(o: &Overlay<MemStorage>) -> [u8; 32] {
        let mut t = Trie::new();
        for (k, v) in o.scan(&[]) {
            if committed(&k) {
                t.insert(&k, &v);
            }
        }
        t.root()
    }

    #[test]
    fn commitment_covers_visible_committed_keys() {
        let mut o = Overlay::new(MemStorage::default());
        assert_eq!(o.commitment(), solo_trie::EMPTY);
        o.set(b"a", b"1");
        o.set(b"local/height", b"9");
        let root = o.commitment();
        let mut only_a = Trie::new();
        only_a.insert(b"a", b"1");
        assert_eq!(root, only_a.root());
        // Local keys never move the root, written or deleted, in a layer or not.
        o.push();
        o.set(b"local/finalized", b"1");
        assert!(o.delete(b"local/height"));
        assert_eq!(o.commitment(), root);
        // Pending writes count before they reach the base, and leave it alone.
        o.set(b"b", b"2");
        o.push();
        assert!(o.delete(b"a"));
        assert!(!o.delete(b"never"));
        assert_eq!(o.commitment(), rebuilt(&o));
        let mut only_b = Trie::new();
        only_b.insert(b"b", b"2");
        assert_eq!(o.commitment(), only_b.root());
        assert_eq!(
            o.state_trie()
                .prove(b"b")
                .verify(solo_trie::keccak256, &only_b.root(), b"b"),
            Ok(Some(solo_trie::keccak256(b"2")))
        );
        assert_eq!(o.base().state_trie().root(), root);
        o.commit();
        o.commit();
        assert_eq!(o.commitment(), only_b.root());
        assert_eq!(o.base().state_trie().root(), only_b.root());
        assert_eq!(o.base().get(b"local/height"), None);
        // Deleting a base key that is absent changes nothing.
        let mut base = o.into_base();
        assert!(!base.delete(b"a"));
        assert!(base.delete(b"local/finalized"));
        assert_eq!(base.state_trie().root(), only_b.root());
        // An empty value is present, not absent.
        base.set(b"empty", b"");
        assert_ne!(base.state_trie().root(), only_b.root());
    }

    #[test]
    fn layer_tries_follow_every_path() {
        let mut o = Overlay::new(MemStorage::default());
        o.set(b"base", b"0");
        // Built on first use, then kept up to date with what is written.
        o.push();
        o.set(b"a", b"1");
        assert_eq!(o.commitment(), rebuilt(&o));
        o.set(b"b", b"2");
        assert!(o.delete(b"a"));
        o.set(b"local/x", b"node");
        // An unbuilt layer merged into a built one leaves its keys stale there.
        o.push();
        o.set(b"c", b"3");
        o.set(b"local/y", b"node");
        o.commit();
        assert_eq!(o.commitment(), rebuilt(&o));
        // A built layer merged into the one below hands its trie down.
        o.push();
        o.set(b"d", b"4");
        assert_eq!(o.commitment(), rebuilt(&o));
        o.commit();
        assert_eq!(o.commitment(), rebuilt(&o));
        // Two unbuilt layers merged, then built from the built one beneath,
        // then discarded: the layer beneath is as it was.
        let root = o.commitment();
        o.push();
        o.push();
        o.set(b"e", b"5");
        o.commit();
        assert_eq!(o.commitment(), rebuilt(&o));
        assert_ne!(o.commitment(), root);
        o.discard();
        assert_eq!(o.commitment(), root);
        // A built bottom layer with stale keys merges into the base whole.
        assert!(o.delete(b"base"));
        o.commit();
        assert_eq!(o.depth(), 0);
        assert_eq!(o.base().state_trie().root(), rebuilt(&o));
        assert_eq!(o.base().get(b"a"), None);
        assert_eq!(o.base().get(b"base"), None);
        assert_eq!(o.base().get(b"local/x"), Some(b"node".to_vec()));
        let mut expected = Trie::new();
        for (k, v) in [(b"b", b"2"), (b"c", b"3"), (b"d", b"4")] {
            expected.insert(k, v);
        }
        assert_eq!(o.commitment(), expected.root());
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn history_reads_every_sealed_version() {
        let mut s = MemStorage::default();
        s.set(b"a", b"0");
        s.set(b"local/x", b"0");
        // No history yet: sealing, pruning and clearing a view do nothing.
        s.seal(1);
        s.prune(1);
        assert_eq!(s.versions(), None);
        assert_eq!(s.set_view(None), Ok(()));
        assert_eq!(s.set_view(Some(0)), Err(None));
        s.keep_history(0);
        // Version 1 writes a, b and a local key; version 2 deletes a, through
        // a merged layer; version 3 writes nothing; c is written after the
        // last seal.
        s.set(b"a", b"1");
        s.set(b"a", b"1b");
        s.set(b"b", b"1");
        s.set(b"local/x", b"1");
        s.seal(1);
        let mut o = Overlay::new(s);
        o.push();
        assert!(o.delete(b"a"));
        o.set(b"b", b"2");
        o.commit();
        let mut s = o.into_base();
        s.seal(2);
        s.seal(3);
        s.set(b"c", b"later");
        assert_eq!(s.versions(), Some((0, 3)));
        let read = |s: &mut MemStorage, v: u64| {
            s.set_view(Some(v)).unwrap();
            let out = (s.get(b"a"), s.get(b"b"), s.get(b"c"), s.scan(b""));
            s.set_view(None).unwrap();
            out
        };
        let (a, b, c, all) = read(&mut s, 0);
        assert_eq!((a, b, c), (Some(b"0".to_vec()), None, None));
        // Local keys read as they are, whatever the view.
        assert_eq!(
            all,
            vec![
                (b"a".to_vec(), b"0".to_vec()),
                (b"local/x".to_vec(), b"1".to_vec())
            ]
        );
        let (a, b, c, _) = read(&mut s, 1);
        assert_eq!((a, b, c), (Some(b"1b".to_vec()), Some(b"1".to_vec()), None));
        let (a, b, c, all) = read(&mut s, 2);
        assert_eq!((a, b, c), (None, Some(b"2".to_vec()), None));
        assert_eq!(all.len(), 2);
        assert_eq!(read(&mut s, 3).0, None);
        // Prefix scans see only their keys.
        s.set_view(Some(1)).unwrap();
        assert_eq!(s.scan(b"b"), vec![(b"b".to_vec(), b"1".to_vec())]);
        assert_eq!(s.get(b"local/x"), Some(b"1".to_vec()));
        s.set_view(None).unwrap();
        assert_eq!(s.get(b"c"), Some(b"later".to_vec()));
        // Out of range.
        assert_eq!(s.set_view(Some(4)), Err(Some((0, 3))));
        // Pruning below version 2 forgets what versions 0 and 1 needed.
        s.prune(2);
        assert_eq!(s.versions(), Some((2, 3)));
        assert_eq!(s.set_view(Some(1)), Err(Some((2, 3))));
        assert_eq!(read(&mut s, 2).1, Some(b"2".to_vec()));
        // Pruning again at or below the oldest changes nothing; above the
        // latest prunes to it.
        s.prune(1);
        assert_eq!(s.versions(), Some((2, 3)));
        s.prune(9);
        assert_eq!(s.versions(), Some((3, 3)));
        assert_eq!(read(&mut s, 3).2, None);
    }

    #[test]
    fn namespacing() {
        let ns = [7u8; 32];
        let k = namespaced(&ns, b"key");
        assert_eq!(k.len(), 35);
        assert_eq!(&k[..32], &ns);
        assert_eq!(&k[32..], b"key");
        let o = Overlay::new(MemStorage::default());
        assert!(format!("{o:?}").contains("Overlay"));
        assert_eq!(MAX_STORED_KEY_LEN, namespaced(&ns, &[0; MAX_KEY_LEN]).len());
    }
}
