//! Key-value storage with per-call overlays (spec 05 §4.2).
//!
//! Keys handed to the host by a sandboxed instance are prefixed with the
//! instance's 32-byte namespace before they reach the store, so two contracts
//! never see each other's keys. Writes go into an overlay layer per call
//! frame; a frame that halts normally has its layer merged into the one
//! below, any other termination discards it.

use std::collections::BTreeMap;

/// Maximum key length in bytes (spec 05 §4.2).
pub const MAX_KEY_LEN: usize = 64;
/// Maximum value length in bytes (spec 05 §4.2).
pub const MAX_VALUE_LEN: usize = 65_536;

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
}

/// An in-memory store.
#[derive(Debug, Default, Clone)]
pub struct MemStorage {
    map: BTreeMap<Vec<u8>, Vec<u8>>,
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
    }

    fn delete(&mut self, key: &[u8]) -> bool {
        self.map.remove(key).is_some()
    }

    fn scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.map
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
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
