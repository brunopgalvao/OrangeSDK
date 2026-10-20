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
//! [`Storage::state_trie`]; [`MemStorage`] keeps one up to date on every
//! write, so the root of the base plus a call's pending writes costs
//! O(depth) hashes per pending key rather than a pass over the whole state.

use std::collections::BTreeMap;

use solo_trie::Trie;

/// Maximum key length in bytes (spec 05 §4.2).
pub const MAX_KEY_LEN: usize = 64;
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

/// Writes not yet in the base store, by key: the new value, or `None` for a
/// deletion.
pub type Pending<'a> = BTreeMap<&'a [u8], Option<&'a [u8]>>;

/// Applies `pending` to `trie`, skipping keys outside the commitment.
pub fn apply(trie: &mut Trie, pending: &Pending<'_>) {
    for (key, value) in pending {
        if !committed(key) {
            continue;
        }
        match value {
            Some(value) => trie.insert(key, value),
            None => {
                trie.remove(key);
            }
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

    /// The state trie (spec 10) of this store's committed entries with
    /// `pending` applied on top, leaving the store unchanged. This default
    /// builds it from a full scan; a store that maintains its trie as it is
    /// written overrides it to cost O(depth) per pending key.
    fn state_trie(&self, pending: &Pending<'_>) -> Trie {
        let mut trie = Trie::new();
        for (key, value) in self.scan(&[]) {
            if committed(&key) {
                trie.insert(&key, &value);
            }
        }
        apply(&mut trie, pending);
        trie
    }
}

/// An in-memory store that keeps the trie of its committed entries current.
#[derive(Debug, Default, Clone)]
pub struct MemStorage {
    map: BTreeMap<Vec<u8>, Vec<u8>>,
    trie: Trie,
}

impl MemStorage {
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
        self.map.get(key).cloned()
    }

    fn set(&mut self, key: &[u8], value: &[u8]) {
        self.map.insert(key.to_vec(), value.to_vec());
        if committed(key) {
            self.trie.insert(key, value);
        }
    }

    fn delete(&mut self, key: &[u8]) -> bool {
        let existed = self.map.remove(key).is_some();
        if existed && committed(key) {
            self.trie.remove(key);
        }
        existed
    }

    fn scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.map
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// A copy-on-write clone of the maintained trie with `pending` applied.
    fn state_trie(&self, pending: &Pending<'_>) -> Trie {
        let mut trie = self.trie.clone();
        apply(&mut trie, pending);
        trie
    }
}

/// A stack of write layers over a base store. `None` in a layer is a deletion.
#[derive(Debug)]
pub struct Overlay<S: Storage> {
    base: S,
    layers: Vec<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
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
        self.layers.push(BTreeMap::new());
    }

    /// Merges the top layer into the one below, or into the base if it was the
    /// only layer. Does nothing with no layers.
    pub fn commit(&mut self) {
        let Some(top) = self.layers.pop() else { return };
        if let Some(below) = self.layers.last_mut() {
            below.extend(top);
        } else {
            for (k, v) in top {
                match v {
                    Some(v) => self.base.set(&k, &v),
                    None => {
                        self.base.delete(&k);
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
            if let Some(v) = layer.get(key) {
                return v.clone();
            }
        }
        self.base.get(key)
    }

    /// Writes into the top layer, or the base with no layers.
    pub fn set(&mut self, key: &[u8], value: &[u8]) {
        match self.layers.last_mut() {
            Some(layer) => {
                layer.insert(key.to_vec(), Some(value.to_vec()));
            }
            None => self.base.set(key, value),
        }
    }

    /// Deletes in the top layer, or the base with no layers. Returns whether
    /// the key was visible before.
    pub fn delete(&mut self, key: &[u8]) -> bool {
        let existed = self.get(key).is_some();
        match self.layers.last_mut() {
            Some(layer) => {
                layer.insert(key.to_vec(), None);
            }
            None => {
                self.base.delete(key);
            }
        }
        existed
    }

    /// The writes held in the open layers, merged, the newest per key.
    pub fn pending(&self) -> Pending<'_> {
        let mut merged = Pending::new();
        for layer in &self.layers {
            for (key, value) in layer {
                merged.insert(key, value.as_deref());
            }
        }
        merged
    }

    /// The state trie of everything visible: the base store's committed
    /// entries with the open layers applied (spec 10 §2).
    pub fn state_trie(&self) -> Trie {
        self.base.state_trie(&self.pending())
    }

    /// The state commitment of everything visible (spec 10 §4): what
    /// `storage_commit` returns.
    pub fn commitment(&self) -> [u8; 32] {
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
        assert_eq!(o.pending().len(), 5);
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
        assert_eq!(o.base().state_trie(&Pending::new()).root(), root);
        o.commit();
        o.commit();
        assert_eq!(o.commitment(), only_b.root());
        assert_eq!(o.base().state_trie(&Pending::new()).root(), only_b.root());
        // Deleting a base key that is absent changes nothing.
        let mut base = o.into_base();
        assert!(!base.delete(b"a"));
        assert!(base.delete(b"local/finalized"));
        assert_eq!(base.state_trie(&Pending::new()).root(), only_b.root());
        // An empty value is present, not absent.
        base.set(b"empty", b"");
        assert_ne!(base.state_trie(&Pending::new()).root(), only_b.root());
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
    }
}
