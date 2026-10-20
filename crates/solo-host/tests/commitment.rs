//! The state commitment through overlays (spec 10 §2): the tries that
//! `MemStorage` and the overlay layers keep write by write give the same
//! root as rebuilding from what is visible, however the writes are split into
//! layers, merged or discarded, and whenever roots are asked for; they agree
//! with the default rebuild of a store without a trie; and asking again
//! hashes only what was written since.

use std::cell::Cell;
use std::collections::BTreeMap;

use proptest::prelude::*;
use solo_host::storage::{LOCAL_PREFIX, committed};
use solo_host::{MemStorage, Overlay, Storage};
use solo_trie::{Hash, Trie, keccak256};

/// A store with only the required methods, so it takes the default
/// `state_trie` and `merge_layer`.
#[derive(Default)]
struct Plain(BTreeMap<Vec<u8>, Vec<u8>>);

impl Storage for Plain {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get(key).cloned()
    }

    fn set(&mut self, key: &[u8], value: &[u8]) {
        self.0.insert(key.to_vec(), value.to_vec());
    }

    fn delete(&mut self, key: &[u8]) -> bool {
        self.0.remove(key).is_some()
    }

    fn scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.0
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// The root by definition: a fresh trie over the visible committed entries.
fn rebuilt(entries: Vec<(Vec<u8>, Vec<u8>)>) -> [u8; 32] {
    let mut t = Trie::new();
    for (k, v) in entries {
        if committed(&k) {
            t.insert(&k, &v);
        }
    }
    t.root()
}

#[derive(Debug, Clone)]
enum Op {
    Set(u8, u8),
    Delete(u8),
    Push,
    Commit,
    Discard,
    /// Ask for the root and a proof of this key, and check them.
    Root(u8),
}

/// Keys 0..8 are committed, 8..12 are under `local/`.
fn key(k: u8) -> Vec<u8> {
    let mut key = if k < 8 {
        b"k/".to_vec()
    } else {
        LOCAL_PREFIX.to_vec()
    };
    key.push(k);
    key
}

fn ops() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(
        prop_oneof![
            4 => (0u8..12, any::<u8>()).prop_map(|(k, v)| Op::Set(k, v)),
            2 => (0u8..12).prop_map(Op::Delete),
            1 => Just(Op::Push),
            1 => Just(Op::Commit),
            1 => Just(Op::Discard),
            2 => (0u8..12).prop_map(Op::Root),
        ],
        0..80,
    )
}

fn step<S: Storage>(o: &mut Overlay<S>, op: &Op) {
    match op {
        Op::Set(k, v) => o.set(&key(*k), &[*v]),
        Op::Delete(k) => {
            o.delete(&key(*k));
        }
        Op::Push => o.push(),
        Op::Commit => o.commit(),
        Op::Discard => o.discard(),
        Op::Root(_) => {}
    }
}

/// What a root and proof of `k` show: the root, and the value hash proven.
fn root_and_proof<S: Storage>(o: &mut Overlay<S>, k: u8) -> (Hash, Option<Hash>) {
    let trie = o.state_trie();
    let proven = trie
        .prove(&key(k))
        .verify(keccak256, &trie.root(), &key(k))
        .expect("a proof from the trie verifies against its root");
    (trie.root(), proven)
}

proptest! {
    #[test]
    fn maintained_root_is_the_rebuilt_root(ops in ops()) {
        let mut mem = Overlay::new(MemStorage::default());
        let mut plain = Overlay::new(Plain::default());
        for op in &ops {
            step(&mut mem, op);
            step(&mut plain, op);
            if let Op::Root(k) = op {
                let (root, proven) = root_and_proof(&mut mem, *k);
                prop_assert_eq!(root, rebuilt(mem.scan(&[])));
                let visible = mem.get(&key(*k)).filter(|_| committed(&key(*k)));
                prop_assert_eq!(proven, visible.map(|v| keccak256(&v)));
                prop_assert_eq!(root_and_proof(&mut plain, *k), (root, proven));
            }
        }
        prop_assert_eq!(mem.commitment(), rebuilt(mem.scan(&[])));
        prop_assert_eq!(plain.commitment(), mem.commitment());
        while mem.depth() > 0 {
            mem.commit();
            plain.commit();
        }
        prop_assert_eq!(plain.commitment(), mem.commitment());
        let base = mem.into_base();
        prop_assert_eq!(base.state_trie().root(), rebuilt(base.scan(&[])));
    }

    /// Two stores that reach the same entries by different routes, one
    /// write at a time into the base or everything through one layer,
    /// commit to the same root.
    #[test]
    fn batching_does_not_matter(ops in ops()) {
        let mut direct = Overlay::new(MemStorage::default());
        let mut layered = Overlay::new(MemStorage::default());
        layered.push();
        for op in ops.iter().filter(|op| matches!(op, Op::Set(..) | Op::Delete(_))) {
            step(&mut direct, op);
            step(&mut layered, op);
        }
        prop_assert_eq!(layered.commitment(), direct.commitment());
        layered.commit();
        prop_assert_eq!(layered.depth(), 0);
        prop_assert_eq!(layered.commitment(), direct.commitment());
    }
}

#[test]
fn the_default_rebuild_skips_local_keys() {
    let mut plain = Overlay::new(Plain::default());
    plain.set(b"a", b"1");
    plain.set(b"local/a", b"2");
    assert_eq!(plain.get(b"local/a"), Some(b"2".to_vec()));
    let mut only_a = Trie::new();
    only_a.insert(b"a", b"1");
    assert_eq!(plain.commitment(), only_a.root());
    assert!(plain.delete(b"a"));
    assert_eq!(plain.commitment(), solo_trie::EMPTY);
    assert!(format!("{:?}", Op::Push.clone()).contains("Push"));
}

thread_local! {
    static HASHES: Cell<usize> = const { Cell::new(0) };
}

/// `keccak256`, counting calls on this thread.
fn counted(data: &[u8]) -> Hash {
    HASHES.with(|n| n.set(n.get() + 1));
    keccak256(data)
}

/// Hashes `f` makes.
fn hashes(f: impl FnOnce()) -> usize {
    let before = HASHES.with(Cell::get);
    f();
    HASHES.with(Cell::get) - before
}

#[test]
fn roots_and_proofs_hash_only_what_was_written_since() {
    // Spec 05 prices storage_commit and storage_proof flat: their work must
    // not grow with the writes already hashed by an earlier call.
    let mut o = Overlay::new(MemStorage::with_hasher(counted));
    for i in 0..256u16 {
        o.set(&i.to_be_bytes(), b"base");
    }
    o.push();
    for i in 256..1_256u16 {
        o.set(&i.to_be_bytes(), b"pending");
    }
    // The first root hashes each pending write once: key, value, and the
    // nodes on its path.
    let mut root = [0; 32];
    let first = hashes(|| root = o.commitment());
    assert!((3_000..30_000).contains(&first), "{first}");
    // Asking again, for roots or proofs, hashes nothing but the proved key.
    let again = hashes(|| {
        for _ in 0..100 {
            assert_eq!(o.commitment(), root);
            assert!(o.state_trie().prove(b"absent").siblings.len() < 40);
        }
    });
    assert_eq!(again, 100);
    // A write costs one path at the next root, however often it was written.
    let one = hashes(|| {
        for v in 0..50u8 {
            o.set(b"new", &[v]);
        }
        root = o.commitment();
    });
    assert!(one <= 3 + 40, "{one}");
    // A nested layer built and discarded leaves the outer one as it was.
    o.push();
    o.set(b"inner", b"x");
    assert_ne!(o.commitment(), root);
    o.discard();
    assert_eq!(hashes(|| assert_eq!(o.commitment(), root)), 0);
    // Merging into the base adopts the trie: the writes are not hashed again.
    assert_eq!(hashes(|| o.commit()), 0);
    assert_eq!(hashes(|| assert_eq!(o.commitment(), root)), 0);
    assert_eq!(root, rebuilt(o.scan(&[])));
}
