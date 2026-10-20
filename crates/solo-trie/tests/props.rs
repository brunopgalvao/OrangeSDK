//! Properties of the trie against a direct model of spec 10 §4: the root is
//! a function of the entry set alone, updates and deletions round-trip, and
//! proofs show exactly the entries that are there.

use std::collections::BTreeMap;

use proptest::prelude::*;
use solo_trie::{
    EMPTY, Hash, HashFn, MAX_DEPTH, Proof, ProofError, Terminal, Trie, bit, branch_hash, keccak256,
    leaf_hash,
};

/// The root by the definition: zero for no entries, the leaf for one, and a
/// branch over the two halves split on bit `depth` otherwise.
fn model_root(hash: HashFn, leaves: &[(Hash, Hash)], depth: usize) -> Hash {
    match leaves {
        [] => EMPTY,
        [(path, value_hash)] => leaf_hash(hash, path, value_hash),
        _ => {
            let (right, left): (Vec<_>, Vec<_>) =
                leaves.iter().copied().partition(|(p, _)| bit(p, depth));
            branch_hash(
                hash,
                &model_root(hash, &left, depth + 1),
                &model_root(hash, &right, depth + 1),
            )
        }
    }
}

fn model(entries: &BTreeMap<Vec<u8>, Vec<u8>>) -> Hash {
    let leaves: Vec<(Hash, Hash)> = entries
        .iter()
        .map(|(k, v)| (keccak256(k), keccak256(v)))
        .collect();
    model_root(keccak256, &leaves, 0)
}

/// A hash that is the identity, zero-padded, on inputs up to 32 bytes, so a
/// test can choose paths: long shared prefixes and leaves at depth 256.
fn short(data: &[u8]) -> Hash {
    if data.len() <= 32 {
        let mut out = [0u8; 32];
        out[..data.len()].copy_from_slice(data);
        out
    } else {
        keccak256(data)
    }
}

fn entries() -> impl Strategy<Value = BTreeMap<Vec<u8>, Vec<u8>>> {
    prop::collection::btree_map(
        prop::collection::vec(any::<u8>(), 1..6),
        prop::collection::vec(any::<u8>(), 0..6),
        0..48,
    )
}

#[derive(Debug, Clone)]
enum Op {
    Set(u8, u8),
    Delete(u8),
}

fn ops() -> impl Strategy<Value = Vec<Op>> {
    // A small key space, so sets overwrite and deletes hit.
    prop::collection::vec(
        prop_oneof![
            (0u8..24, any::<u8>()).prop_map(|(k, v)| Op::Set(k, v)),
            (0u8..24).prop_map(Op::Delete),
        ],
        0..96,
    )
}

proptest! {
    #[test]
    fn root_is_the_model_in_any_order(
        (map, order) in entries().prop_flat_map(|m| {
            let keys: Vec<Vec<u8>> = m.keys().cloned().collect();
            (Just(m), Just(keys).prop_shuffle())
        })
    ) {
        let mut sorted = Trie::new();
        for (k, v) in &map {
            sorted.insert(k, v);
        }
        let mut shuffled = Trie::new();
        for k in &order {
            shuffled.insert(k, &map[k]);
        }
        prop_assert_eq!(sorted.root(), model(&map));
        prop_assert_eq!(shuffled.root(), sorted.root());
        prop_assert_eq!(shuffled.len(), map.len());
    }

    #[test]
    fn updates_track_the_model(ops in ops()) {
        let mut trie = Trie::new();
        let mut map = BTreeMap::new();
        for op in ops {
            match op {
                Op::Set(k, v) => {
                    trie.insert(&[k], &[v]);
                    map.insert(vec![k], vec![v]);
                }
                Op::Delete(k) => {
                    prop_assert_eq!(trie.remove(&[k]), map.remove(&vec![k]).is_some());
                }
            }
            prop_assert_eq!(trie.root(), model(&map));
            prop_assert_eq!(trie.len(), map.len());
        }
    }

    #[test]
    fn insert_then_delete_round_trips(base in entries(), extra in entries()) {
        let mut trie = Trie::new();
        for (k, v) in &base {
            trie.insert(k, v);
        }
        let root = trie.root();
        let snapshot = trie.clone();
        let added: Vec<&Vec<u8>> = extra.keys().filter(|k| !base.contains_key(*k)).collect();
        for k in &added {
            trie.insert(k, &extra[*k]);
        }
        for k in added.iter().rev() {
            prop_assert!(trie.remove(k));
        }
        prop_assert_eq!(trie.root(), root);
        prop_assert_eq!(snapshot.root(), root);
        for k in base.keys() {
            prop_assert!(trie.remove(k));
        }
        prop_assert_eq!(trie.root(), EMPTY);
        prop_assert!(trie.is_empty());
    }

    #[test]
    fn proofs_show_presence_and_absence(map in entries(), absent in entries()) {
        let mut trie = Trie::new();
        for (k, v) in &map {
            trie.insert(k, v);
        }
        let root = trie.root();
        for (k, v) in &map {
            let proof = trie.prove(k);
            prop_assert_eq!(proof.verify(keccak256, &root, k), Ok(Some(keccak256(v))));
            prop_assert_eq!(Proof::decode(&proof.encode()), Ok(proof.clone()));
            prop_assert_eq!(trie.get(k), Some(keccak256(v)));
        }
        for k in absent.keys().filter(|k| !map.contains_key(*k)) {
            let proof = trie.prove(k);
            prop_assert_eq!(proof.verify(keccak256, &root, k), Ok(None));
            prop_assert_eq!(Proof::decode(&proof.encode()), Ok(proof));
            prop_assert_eq!(trie.get(k), None);
        }
    }

    #[test]
    fn tampered_proofs_are_rejected(
        map in entries(),
        probe in prop::collection::vec(any::<u8>(), 1..6),
        at in any::<prop::sample::Index>(),
        flip in 1u8..=255,
    ) {
        let mut trie = Trie::new();
        for (k, v) in &map {
            trie.insert(k, v);
        }
        let root = trie.root();
        let mut bytes = trie.prove(&probe).encode();
        let i = at.index(bytes.len());
        bytes[i] ^= flip;
        let verdict = Proof::decode(&bytes).and_then(|p| p.verify(keccak256, &root, &probe));
        prop_assert!(verdict.is_err(), "byte {} of {} still verifies: {:?}", i, bytes.len(), verdict);
    }

    #[test]
    fn deep_paths(prefix in any::<[u8; 32]>(), split in 0usize..256, values in any::<(u8, u8)>()) {
        // Two paths equal on their first `split` bits: leaves at depth split + 1.
        let a = prefix;
        let mut b = prefix;
        b[split / 8] ^= 0x80 >> (split % 8);
        let mut trie = Trie::with_hasher(short);
        trie.insert(&a, &[values.0]);
        trie.insert(&b, &[values.1]);
        let root = trie.root();
        for (key, value) in [(a, values.0), (b, values.1)] {
            let proof = trie.prove(&key);
            prop_assert_eq!(proof.siblings.len(), split + 1);
            prop_assert_eq!(proof.verify(short, &root, &key), Ok(Some(short(&[value]))));
        }
        let leaves = [(a, short(&[values.0])), (b, short(&[values.1]))];
        prop_assert_eq!(root, model_root(short, &leaves, 0));
        // Removing one lifts the other back to the root.
        prop_assert!(trie.remove(&b));
        prop_assert_eq!(trie.root(), leaf_hash(short, &a, &short(&[values.0])));
    }
}

#[test]
fn deepest_leaves_and_bounds() {
    // Paths differing only in the last bit: a proof with the full 256 siblings.
    let a = [0u8; 32];
    let mut b = a;
    b[31] = 1;
    let mut trie = Trie::with_hasher(short);
    trie.insert(&a, b"x");
    trie.insert(&b, b"y");
    let proof = trie.prove(&b);
    assert_eq!(proof.siblings.len(), MAX_DEPTH);
    assert_eq!(proof.verify(short, &trie.root(), &b), Ok(Some(short(b"y"))));
    let bytes = proof.encode();
    assert_eq!(bytes.len(), 2 + 32 * 256 + 65);
    assert_eq!(Proof::decode(&bytes), Ok(proof.clone()));
    // A leaf at depth 256 that is not the key's: the paths differ above it.
    let mut wrong = proof.clone();
    wrong.terminal = Terminal::Leaf {
        path: a,
        value_hash: short(b"x"),
    };
    assert_eq!(
        wrong.verify(short, &trie.root(), &b),
        Err(ProofError::WrongLeaf)
    );
    // 257 siblings encode, but neither decode nor verify.
    let mut deep = proof;
    deep.siblings.push(EMPTY);
    assert_eq!(Proof::decode(&deep.encode()), Err(ProofError::TooDeep));
    assert_eq!(
        deep.verify(short, &trie.root(), &b),
        Err(ProofError::TooDeep)
    );
    // An empty trie proves every key absent with no siblings; nothing else does.
    let empty = Trie::with_hasher(short);
    assert_eq!(empty.prove(&a).verify(short, &EMPTY, &a), Ok(None));
    assert_eq!(
        empty.prove(&a).verify(short, &trie.root(), &a),
        Err(ProofError::RootMismatch)
    );
}
