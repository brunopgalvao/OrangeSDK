//! The root of entries given in ascending path order, in memory bounded by
//! the depth of the trie rather than the number of entries (spec 22 §7).
//!
//! A snapshot file lists its entries by path, so a verifier, an importing
//! store or an exporter checking its own output hashes them as they stream
//! past: [`SortedRoot`] keeps one subtree per pending branch point, at most
//! one per bit of the path, and hands every node it completes to a callback,
//! which a store writes to disk. The root is the trie's (spec 10 §4): equal
//! to [`crate::Trie::root`] over the same entries.

use alloc::vec::Vec;

use crate::{BRANCH_TAG, EMPTY, Hash, HashFn, LEAF_TAG, NODE_LEN, bit};

/// An entry whose path is not above the one before it: the stream is not
/// in strictly ascending path order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutOfOrder;

/// A completed subtree waiting for its parent.
#[derive(Debug, Clone, Copy)]
struct Subtree {
    /// Its node's hash at its own depth.
    hash: Hash,
    /// The path of one of its entries.
    path: Hash,
    /// For a branch, the bit at which its two sides part; `None` for a
    /// leaf, which is the same node at any depth.
    split: Option<usize>,
}

/// The root of a stream of `(path, value_hash)` entries in strictly
/// ascending path order, and every node of its trie as it completes.
#[derive(Debug)]
pub struct SortedRoot {
    hash: HashFn,
    stack: Vec<Subtree>,
    last: Option<Hash>,
    count: u64,
}

/// How many leading bits `a` and `b` share; 256 when they are equal.
fn common_bits(a: &Hash, b: &Hash) -> usize {
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        let diff = x ^ y;
        if diff != 0 {
            return i * 8 + diff.leading_zeros() as usize;
        }
    }
    256
}

impl SortedRoot {
    /// An empty stream hashed with `hash`.
    #[must_use]
    pub fn new(hash: HashFn) -> SortedRoot {
        SortedRoot {
            hash,
            stack: Vec::new(),
            last: None,
            count: 0,
        }
    }

    /// How many entries were pushed.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.count
    }

    /// Whether nothing was pushed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn node(
        &self,
        tag: u8,
        a: &Hash,
        b: &Hash,
        on_node: &mut dyn FnMut(&Hash, &[u8; NODE_LEN]),
    ) -> Hash {
        let mut preimage = [0u8; NODE_LEN];
        preimage[0] = tag;
        preimage[1..33].copy_from_slice(a);
        preimage[33..].copy_from_slice(b);
        let hash = (self.hash)(&preimage);
        on_node(&hash, &preimage);
        hash
    }

    /// The node of `subtree` placed at `depth`, above its own: a branch
    /// with an empty side at every bit its entries all share (spec 10 §4).
    fn lift(
        &self,
        subtree: &Subtree,
        depth: usize,
        on_node: &mut dyn FnMut(&Hash, &[u8; NODE_LEN]),
    ) -> Hash {
        let Some(split) = subtree.split else {
            return subtree.hash;
        };
        let mut hash = subtree.hash;
        for d in (depth..split).rev() {
            hash = if bit(&subtree.path, d) {
                self.node(BRANCH_TAG, &EMPTY, &hash, on_node)
            } else {
                self.node(BRANCH_TAG, &hash, &EMPTY, on_node)
            };
        }
        hash
    }

    /// Joins the two subtrees on top of the stack under the branch where
    /// their paths part.
    fn merge(&mut self, on_node: &mut dyn FnMut(&Hash, &[u8; NODE_LEN])) {
        let right = self.stack.pop().expect("two subtrees");
        let left = self.stack.pop().expect("two subtrees");
        let split = common_bits(&left.path, &right.path);
        let l = self.lift(&left, split + 1, on_node);
        let r = self.lift(&right, split + 1, on_node);
        let hash = self.node(BRANCH_TAG, &l, &r, on_node);
        self.stack.push(Subtree {
            hash,
            path: left.path,
            split: Some(split),
        });
    }

    /// Adds the entry at `path` with `value_hash`, passing `on_node` every
    /// node it completes (hash and 65-byte preimage).
    ///
    /// # Errors
    /// [`OutOfOrder`] when `path` is not above the last one pushed; nothing
    /// is added then.
    pub fn push(
        &mut self,
        path: Hash,
        value_hash: Hash,
        on_node: &mut dyn FnMut(&Hash, &[u8; NODE_LEN]),
    ) -> Result<(), OutOfOrder> {
        if self.last.is_some_and(|last| path <= last) {
            return Err(OutOfOrder);
        }
        if let Some(top) = self.stack.last() {
            let parts = common_bits(&top.path, &path);
            while self.stack.len() >= 2 {
                let n = self.stack.len();
                if common_bits(&self.stack[n - 2].path, &self.stack[n - 1].path) <= parts {
                    break;
                }
                self.merge(on_node);
            }
        }
        let hash = self.node(LEAF_TAG, &path, &value_hash, on_node);
        self.stack.push(Subtree {
            hash,
            path,
            split: None,
        });
        self.last = Some(path);
        self.count += 1;
        Ok(())
    }

    /// The root of everything pushed, completing the nodes still pending.
    pub fn finish(self, on_node: &mut dyn FnMut(&Hash, &[u8; NODE_LEN])) -> Hash {
        self.finish_at(0, on_node)
    }

    /// The subtree hash `T(S, depth)` (spec 10 §4) of everything pushed,
    /// whose paths must all share their first `depth` bits: the node at
    /// that depth above them, as a slice of a snapshot's manifest names it
    /// (spec 22 §7.4). At depth 0 it is the root.
    pub fn finish_at(
        mut self,
        depth: usize,
        on_node: &mut dyn FnMut(&Hash, &[u8; NODE_LEN]),
    ) -> Hash {
        while self.stack.len() >= 2 {
            self.merge(on_node);
        }
        match self.stack.pop() {
            None => EMPTY,
            Some(top) => self.lift(&top, depth, on_node),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::vec;

    use super::*;
    use crate::{Trie, keccak256};

    fn sorted(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<(Hash, Hash)> {
        let mut by_path: Vec<(Hash, Hash)> = entries
            .iter()
            .map(|(k, v)| (keccak256(k), keccak256(v)))
            .collect();
        by_path.sort_unstable();
        by_path
    }

    fn streamed(by_path: &[(Hash, Hash)]) -> (Hash, BTreeMap<Hash, [u8; NODE_LEN]>) {
        let mut nodes = BTreeMap::new();
        let mut keep = |h: &Hash, p: &[u8; NODE_LEN]| {
            assert!(nodes.insert(*h, *p).is_none(), "each node once");
        };
        let mut root = SortedRoot::new(keccak256);
        for (path, value) in by_path {
            root.push(*path, *value, &mut keep).unwrap();
        }
        assert_eq!(root.len(), by_path.len() as u64);
        (root.finish(&mut keep), nodes)
    }

    #[test]
    fn the_streamed_root_is_the_tries() {
        for n in [0u16, 1, 2, 3, 7, 64, 300] {
            let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..n)
                .map(|i| {
                    let [hi, lo] = i.to_be_bytes();
                    (vec![b'k', hi, lo], vec![lo])
                })
                .collect();
            let mut trie = Trie::new();
            for (k, v) in &entries {
                trie.insert(k, v);
            }
            let (root, nodes) = streamed(&sorted(&entries));
            assert_eq!(root, trie.root(), "{n} entries");
            // Every node on every key's path was handed out, and nothing else:
            // what a store writes is exactly the trie.
            let mut on_paths = BTreeMap::new();
            for (k, _) in &entries {
                for node in trie.path_nodes(k) {
                    if let Some(preimage) = node.preimage {
                        on_paths.insert(node.hash, preimage);
                    }
                }
            }
            assert_eq!(nodes, on_paths, "{n} entries");
        }
    }

    #[test]
    fn long_shared_prefixes_get_their_empty_siblings() {
        // Paths sharing 200 and 255 bits, and one at the other end.
        let mut a = [0u8; 32];
        a[31] = 1;
        let mut b = a;
        b[31] = 0;
        let mut c = [0u8; 32];
        c[25] = 0x80;
        let far = [0xFF; 32];
        let by_path = vec![(b, [1; 32]), (a, [2; 32]), (c, [3; 32]), (far, [4; 32])];
        let mut trie = Trie::new();
        for (p, v) in &by_path {
            trie.insert_hashed(*p, *v);
        }
        assert_eq!(streamed(&by_path).0, trie.root());
        // Subtrees at a depth their paths all share: the slices of a
        // snapshot's manifest (spec 22 §7.4).
        let pair = crate::branch_hash(
            keccak256,
            &crate::leaf_hash(keccak256, &b, &[1; 32]),
            &crate::leaf_hash(keccak256, &a, &[2; 32]),
        );
        let subtree = |entries: &[(Hash, Hash)], depth: usize| {
            let mut root = SortedRoot::new(keccak256);
            for (p, v) in entries {
                root.push(*p, *v, &mut |_: &Hash, _: &[u8; NODE_LEN]| {})
                    .unwrap();
            }
            root.finish_at(depth, &mut |_: &Hash, _: &[u8; NODE_LEN]| {})
        };
        assert_eq!(subtree(&by_path[..2], 255), pair);
        let lifted = (201..255).fold(pair, |h, _| crate::branch_hash(keccak256, &h, &EMPTY));
        assert_eq!(subtree(&by_path[..2], 201), lifted);
        let three = crate::branch_hash(
            keccak256,
            &lifted,
            &crate::leaf_hash(keccak256, &c, &[3; 32]),
        );
        assert_eq!(subtree(&by_path[..3], 200), three);
        assert_eq!(
            subtree(&by_path[2..3], 200),
            crate::leaf_hash(keccak256, &c, &[3; 32])
        );
        assert_eq!(subtree(&[], 9), EMPTY);
        assert_eq!(common_bits(&a, &a), 256);
        assert_eq!(common_bits(&a, &b), 255);
    }

    #[test]
    fn an_entry_out_of_order_is_refused() {
        let mut root = SortedRoot::new(keccak256);
        let mut none = |_: &Hash, _: &[u8; NODE_LEN]| {};
        assert!(root.is_empty());
        root.push([2; 32], [0; 32], &mut none).unwrap();
        assert_eq!(root.push([2; 32], [0; 32], &mut none), Err(OutOfOrder));
        assert_eq!(root.push([1; 32], [0; 32], &mut none), Err(OutOfOrder));
        assert_eq!(root.len(), 1);
        assert!(!root.is_empty());
        assert_eq!(
            root.finish(&mut none),
            crate::leaf_hash(keccak256, &[2; 32], &[0; 32])
        );
        assert_eq!(SortedRoot::new(keccak256).finish(&mut none), EMPTY);
    }
}
