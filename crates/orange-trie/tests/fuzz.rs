//! Seeded fuzzing of the state trie (spec 10) across its three forms: the
//! in-memory trie under random inserts and deletes, the sorted-stream root
//! of spec 22 §7 over the same entries, and a trie loaded on demand from the
//! nodes that stream emitted, edited further side by side with the
//! in-memory one. Roots, lookups and proofs agree everywhere; a proof with
//! any change never verifies to a different answer; and proof decoding is
//! canonical on random bytes. See `orange-fuzz` for the long mode.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use orange_fuzz::{Rng, evolve, zero_seeds};
use orange_trie::{
    EMPTY, Hash, HashFn, NodeSource, Proof, SortedRoot, Trie, bit, branch_hash, keccak256,
};

/// A hash that is the identity, zero-padded, on inputs up to 32 bytes, so
/// keys choose their paths: long shared prefixes and leaves deep down.
fn short(data: &[u8]) -> Hash {
    if data.len() <= 32 {
        let mut out = [0u8; 32];
        out[..data.len()].copy_from_slice(data);
        out
    } else {
        keccak256(data)
    }
}

/// Nodes by hash, as a store keeps them.
#[derive(Default)]
struct Nodes(Mutex<HashMap<Hash, Vec<u8>>>);

impl NodeSource for Nodes {
    fn node(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.0.lock().unwrap().get(hash).cloned()
    }
}

/// A key from a small space, so writes overwrite and deletes hit; with
/// the identity hash, keys that share most of their bits.
fn key(r: &mut Rng, identity: bool) -> Vec<u8> {
    if identity {
        let mut k = vec![0xA5; 32];
        let bit = r.index(256);
        k[bit / 8] ^= 0x80 >> (bit % 8);
        if r.chance(1, 2) {
            k[31] ^= u8::try_from(r.below(4)).unwrap();
        }
        k
    } else {
        vec![u8::try_from(r.below(40)).unwrap()]
    }
}

/// The sorted-stream root of `entries` (path to value hash), storing
/// every node it completes in `nodes`.
fn stream_root(hash: HashFn, entries: &BTreeMap<Hash, Hash>, nodes: &Nodes) -> Hash {
    let mut root = SortedRoot::new(hash);
    let mut store = nodes.0.lock().unwrap();
    let mut keep = |h: &Hash, pre: &[u8; 65]| {
        store.insert(*h, pre.to_vec());
    };
    for (path, value_hash) in entries {
        root.push(*path, *value_hash, &mut keep).unwrap();
    }
    // Out of order is refused and changes nothing.
    if let Some((last, _)) = entries.iter().next_back() {
        assert!(root.push(*last, EMPTY, &mut keep).is_err());
    }
    root.finish(&mut keep)
}

/// A proof's answer must be the truth whenever it verifies.
fn check_proof(trie: &Trie, r: &mut Rng, k: &[u8], truth: Option<Hash>) {
    let hash = trie.hasher();
    let root = trie.root();
    let proof = trie.prove(k);
    assert_eq!(proof.verify(hash, &root, k), Ok(truth));
    let bytes = proof.encode();
    assert_eq!(Proof::decode(&bytes).as_ref(), Ok(&proof));
    let forged = r.mutate(&bytes);
    if forged != bytes
        && let Ok(p) = Proof::decode(&forged)
        && let Ok(answer) = p.verify(hash, &root, k)
    {
        assert_eq!(answer, truth, "a forged proof verified to another answer");
    }
}

#[test]
fn trie_forms_agree_under_random_edits() {
    orange_fuzz::run("trie-forms", 40, |r| {
        let identity = r.chance(1, 3);
        let hash: HashFn = if identity { short } else { keccak256 };
        let mut trie = Trie::with_hasher(hash);
        let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        for _ in 0..r.below(60) {
            let k = key(r, identity);
            if r.chance(2, 3) {
                let v = vec![u8::try_from(r.below(256)).unwrap(); r.index(3)];
                trie.insert(&k, &v);
                model.insert(k, v);
            } else {
                assert_eq!(trie.remove(&k), model.remove(&k).is_some());
            }
        }
        assert_eq!(trie.len(), model.len());
        let entries: BTreeMap<Hash, Hash> = model.iter().map(|(k, v)| (hash(k), hash(v))).collect();
        let nodes = Arc::new(Nodes::default());
        let root = stream_root(hash, &entries, &nodes);
        assert_eq!(root, trie.root());

        // A subtree's hash at the depth its paths share, lifted to the
        // root through the empty siblings above it, is the root.
        if entries.len() >= 2 {
            let first = *entries.keys().next().unwrap();
            let last = *entries.keys().next_back().unwrap();
            let shared = (0..256)
                .take_while(|i| bit(&first, *i) == bit(&last, *i))
                .count();
            let mut sub = SortedRoot::new(hash);
            for (p, v) in &entries {
                sub.push(*p, *v, &mut |_, _| {}).unwrap();
            }
            let mut node = sub.finish_at(shared, &mut |_, _| {});
            for i in (0..shared).rev() {
                node = if bit(&first, i) {
                    branch_hash(hash, &EMPTY, &node)
                } else {
                    branch_hash(hash, &node, &EMPTY)
                };
            }
            assert_eq!(node, root);
        }

        // The same trie loaded on demand from the streamed nodes, then both
        // edited the same way.
        let mut lazy = Trie::from_root(root, model.len(), hash, nodes.clone());
        for _ in 0..r.below(30) {
            let k = key(r, identity);
            let truth = model.get(&k).map(|v| hash(v));
            assert_eq!(lazy.get(&k), truth);
            check_proof(&lazy, r, &k, truth);
            check_proof(&trie, r, &k, truth);
            if r.chance(1, 2) {
                let v = vec![u8::try_from(r.below(256)).unwrap()];
                trie.insert(&k, &v);
                lazy.insert(&k, &v);
                model.insert(k.clone(), v);
            } else {
                assert_eq!(lazy.remove(&k), model.remove(&k).is_some());
                trie.remove(&k);
            }
            assert_eq!(lazy.root(), trie.root());
            assert_eq!(lazy.len(), model.len());
            // Store what the edit changed, as a store does, so the next
            // load of this root finds every node.
            let mut store = nodes.0.lock().unwrap();
            for n in lazy.path_nodes(&k) {
                if let Some(pre) = n.preimage {
                    assert_eq!(hash(&pre), n.hash);
                    store.insert(n.hash, pre.to_vec());
                }
            }
        }
        let reloaded = Trie::from_root(lazy.root(), model.len(), hash, nodes);
        for (k, v) in &model {
            assert_eq!(reloaded.get(k), Some(hash(v)));
        }
    });
}

#[test]
fn proof_decoding_is_canonical() {
    let mut seeds = zero_seeds(3, 70);
    let mut trie = Trie::new();
    for i in 0u8..20 {
        trie.insert(&[i], &[i]);
    }
    seeds.push(trie.prove(&[3]).encode());
    seeds.push(trie.prove(&[200]).encode());
    let accepted = evolve("trie-proof-bytes", 5_000, seeds, |bytes| {
        let Ok(proof) = Proof::decode(bytes) else {
            return false;
        };
        assert_eq!(proof.encode(), bytes);
        assert_eq!(proof.encoded_len(), bytes.len());
        let _ = proof.verify(keccak256, &trie.root(), &[3]);
        true
    });
    assert!(accepted > 500, "{accepted}");
}
