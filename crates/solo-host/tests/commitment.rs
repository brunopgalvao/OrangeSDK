//! The state commitment through overlays (spec 10 §2): the trie that
//! `MemStorage` maintains write by write gives the same root as rebuilding
//! from what is visible, however the writes are split into layers, merged
//! or discarded, and agrees with the default rebuild of a store without one.

use std::collections::BTreeMap;

use proptest::prelude::*;
use solo_host::storage::{LOCAL_PREFIX, Pending, committed};
use solo_host::{MemStorage, Overlay, Storage};
use solo_trie::Trie;

/// A store with only the required methods, so it takes the default
/// `state_trie`.
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
    }
}

proptest! {
    #[test]
    fn maintained_root_is_the_rebuilt_root(ops in ops()) {
        let mut mem = Overlay::new(MemStorage::default());
        let mut plain = Overlay::new(Plain::default());
        for op in &ops {
            step(&mut mem, op);
            step(&mut plain, op);
            prop_assert_eq!(mem.commitment(), rebuilt(mem.scan(&[])));
            prop_assert_eq!(plain.commitment(), mem.commitment());
        }
        while mem.depth() > 0 {
            mem.commit();
        }
        let base = mem.into_base();
        prop_assert_eq!(base.state_trie(&Pending::new()).root(), rebuilt(base.scan(&[])));
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
