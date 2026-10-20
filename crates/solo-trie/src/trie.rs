//! The trie itself: canonical shape, incremental updates, proof generation.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::proof::{Proof, Terminal};
use crate::{EMPTY, Hash, HashFn, bit, branch_hash, leaf_hash};

/// One entry: its path, its value hash and the leaf hash of the two.
#[derive(Debug)]
struct Leaf {
    path: Hash,
    value_hash: Hash,
    hash: Hash,
}

/// A subtree with at least two entries, and its cached hash.
#[derive(Debug, Clone)]
struct Branch {
    left: Node,
    right: Node,
    hash: Hash,
}

/// A subtree. Children are shared, so cloning a trie is O(1) and an update
/// to a clone copies only the nodes on the updated path.
#[derive(Debug, Clone)]
enum Node {
    Empty,
    Leaf(Arc<Leaf>),
    Branch(Arc<Branch>),
}

impl Node {
    fn hash(&self) -> Hash {
        match self {
            Node::Empty => EMPTY,
            Node::Leaf(leaf) => leaf.hash,
            Node::Branch(branch) => branch.hash,
        }
    }

    fn branch(left: Node, right: Node, hash: HashFn) -> Node {
        let digest = branch_hash(hash, &left.hash(), &right.hash());
        Node::Branch(Arc::new(Branch {
            left,
            right,
            hash: digest,
        }))
    }
}

/// What an insert did.
enum Edit {
    /// The key held this value already.
    Unchanged,
    /// The key held another value.
    Replaced,
    /// The key was absent.
    Added,
}

/// Inserts `leaf` into the subtree `node` at `depth`, whose entries all share
/// the leaf's first `depth` path bits, rehashing the nodes it passes.
fn insert(node: &mut Node, depth: usize, leaf: Arc<Leaf>, hash: HashFn) -> Edit {
    match node {
        Node::Empty => {
            *node = Node::Leaf(leaf);
            Edit::Added
        }
        Node::Leaf(existing) if existing.path == leaf.path => {
            if existing.value_hash == leaf.value_hash {
                Edit::Unchanged
            } else {
                *node = Node::Leaf(leaf);
                Edit::Replaced
            }
        }
        Node::Leaf(existing) => {
            *node = split(Arc::clone(existing), leaf, depth, hash);
            Edit::Added
        }
        Node::Branch(branch) => {
            let branch = Arc::make_mut(branch);
            let child = if bit(&leaf.path, depth) {
                &mut branch.right
            } else {
                &mut branch.left
            };
            let edit = insert(child, depth + 1, leaf, hash);
            if !matches!(edit, Edit::Unchanged) {
                branch.hash = branch_hash(hash, &branch.left.hash(), &branch.right.hash());
            }
            edit
        }
    }
}

/// The subtree at `depth` holding exactly the two leaves `a` and `b`, whose
/// paths differ but agree on their first `depth` bits: a branch where they
/// first differ, under one branch with an empty side per shared bit.
fn split(a: Arc<Leaf>, b: Arc<Leaf>, depth: usize, hash: HashFn) -> Node {
    let (a_right, b_right) = (bit(&a.path, depth), bit(&b.path, depth));
    let (left, right) = if a_right == b_right {
        let below = split(a, b, depth + 1, hash);
        if a_right {
            (Node::Empty, below)
        } else {
            (below, Node::Empty)
        }
    } else if a_right {
        (Node::Leaf(b), Node::Leaf(a))
    } else {
        (Node::Leaf(a), Node::Leaf(b))
    };
    Node::branch(left, right, hash)
}

/// Removes the entry at `path` from the subtree `node` at `depth`; returns
/// whether it was there. A branch left with one leaf and an empty side
/// becomes that leaf, which then rises as far as its new siblings allow.
fn remove(node: &mut Node, depth: usize, path: &Hash, hash: HashFn) -> bool {
    match node {
        Node::Empty => false,
        Node::Leaf(leaf) => {
            if leaf.path != *path {
                return false;
            }
            *node = Node::Empty;
            true
        }
        Node::Branch(branch) => {
            let branch = Arc::make_mut(branch);
            let child = if bit(path, depth) {
                &mut branch.right
            } else {
                &mut branch.left
            };
            if !remove(child, depth + 1, path, hash) {
                return false;
            }
            let lone = match (&branch.left, &branch.right) {
                (Node::Leaf(leaf), Node::Empty) | (Node::Empty, Node::Leaf(leaf)) => {
                    Some(Arc::clone(leaf))
                }
                _ => None,
            };
            match lone {
                Some(leaf) => *node = Node::Leaf(leaf),
                None => {
                    branch.hash = branch_hash(hash, &branch.left.hash(), &branch.right.hash());
                }
            }
            true
        }
    }
}

/// A binary Merkle trie over `(key, value)` entries (spec 10).
///
/// Cloning is O(1): the clone shares every node, and later updates to
/// either copy only the nodes on their paths. A host uses this to compute
/// the root of committed state plus pending writes without touching the
/// committed trie.
#[derive(Debug, Clone)]
pub struct Trie {
    root: Node,
    len: usize,
    hash: HashFn,
}

#[cfg(feature = "keccak")]
impl Default for Trie {
    fn default() -> Trie {
        Trie::new()
    }
}

impl Trie {
    /// An empty trie hashing with `keccak256`.
    #[cfg(feature = "keccak")]
    #[must_use]
    pub fn new() -> Trie {
        Trie::with_hasher(crate::keccak256)
    }

    /// An empty trie hashing with `hash`, which must be `keccak256` for the
    /// roots of spec 10.
    #[must_use]
    pub fn with_hasher(hash: HashFn) -> Trie {
        Trie {
            root: Node::Empty,
            len: 0,
            hash,
        }
    }

    /// The hash function.
    #[must_use]
    pub fn hasher(&self) -> HashFn {
        self.hash
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the trie has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The root hash; [`crate::EMPTY`] for an empty trie.
    #[must_use]
    pub fn root(&self) -> Hash {
        self.root.hash()
    }

    /// Sets `key` to `value`.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        let (path, value_hash) = ((self.hash)(key), (self.hash)(value));
        self.insert_hashed(path, value_hash);
    }

    /// Sets the entry at `path` to `value_hash`, both already hashed.
    pub fn insert_hashed(&mut self, path: Hash, value_hash: Hash) {
        let leaf = Arc::new(Leaf {
            path,
            value_hash,
            hash: leaf_hash(self.hash, &path, &value_hash),
        });
        if matches!(insert(&mut self.root, 0, leaf, self.hash), Edit::Added) {
            self.len += 1;
        }
    }

    /// Removes `key`; returns whether it was present.
    pub fn remove(&mut self, key: &[u8]) -> bool {
        let path = (self.hash)(key);
        self.remove_hashed(&path)
    }

    /// Removes the entry at `path`; returns whether it was present.
    pub fn remove_hashed(&mut self, path: &Hash) -> bool {
        let removed = remove(&mut self.root, 0, path, self.hash);
        if removed {
            self.len -= 1;
        }
        removed
    }

    /// The value hash stored for `key`, if present.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<Hash> {
        let path = (self.hash)(key);
        match self.prove_hashed(&path).terminal {
            Terminal::Leaf {
                path: found,
                value_hash,
            } if found == path => Some(value_hash),
            _ => None,
        }
    }

    /// The proof for `key` against [`Trie::root`]: of its value hash if
    /// present, of its absence otherwise.
    #[must_use]
    pub fn prove(&self, key: &[u8]) -> Proof {
        let path = (self.hash)(key);
        self.prove_hashed(&path)
    }

    /// The proof for the entry at `path` (spec 10 §5.2).
    #[must_use]
    pub fn prove_hashed(&self, path: &Hash) -> Proof {
        let mut siblings = Vec::new();
        let mut node = &self.root;
        loop {
            match node {
                Node::Empty => {
                    return Proof {
                        siblings,
                        terminal: Terminal::Empty,
                    };
                }
                Node::Leaf(leaf) => {
                    return Proof {
                        siblings,
                        terminal: Terminal::Leaf {
                            path: leaf.path,
                            value_hash: leaf.value_hash,
                        },
                    };
                }
                Node::Branch(branch) => {
                    let (next, sibling) = if bit(path, siblings.len()) {
                        (&branch.right, &branch.left)
                    } else {
                        (&branch.left, &branch.right)
                    };
                    siblings.push(sibling.hash());
                    node = next;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keccak256;

    #[test]
    fn empty_trie() {
        let mut t = Trie::default();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert_eq!(t.root(), EMPTY);
        assert!(!t.remove(b"absent"));
        assert_eq!(t.get(b"absent"), None);
        let p = t.prove(b"absent");
        assert!(p.siblings.is_empty());
        assert_eq!(p.terminal, Terminal::Empty);
        assert_eq!(t.hasher()(b"x"), keccak256(b"x"));
        assert!(alloc::format!("{t:?}").contains("Trie"));
    }

    #[test]
    fn one_entry_is_its_leaf() {
        let mut t = Trie::new();
        t.insert(b"k", b"v");
        let (path, value_hash) = (keccak256(b"k"), keccak256(b"v"));
        assert_eq!(t.root(), leaf_hash(keccak256, &path, &value_hash));
        assert_eq!(t.get(b"k"), Some(value_hash));
        // Same value: nothing changes. Another value: replaced, still one entry.
        t.insert(b"k", b"v");
        assert_eq!(t.len(), 1);
        t.insert(b"k", b"w");
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(b"k"), Some(keccak256(b"w")));
        assert!(t.remove(b"k"));
        assert!(!t.remove(b"k"));
        assert_eq!(t.root(), EMPTY);
    }

    #[test]
    fn clones_share_until_written() {
        let mut a = Trie::new();
        for i in 0u8..20 {
            a.insert(&[i], &[i]);
        }
        let root = a.root();
        let mut b = a.clone();
        b.insert(b"new", b"x");
        assert!(b.remove(&[3]));
        // Absent keys and unchanged values leave both alone.
        assert!(!b.remove(b"never"));
        b.insert(&[4], &[4]);
        assert_eq!(a.root(), root);
        assert_ne!(b.root(), root);
        assert_eq!(a.len(), 20);
        assert_eq!(b.len(), 20);
    }
}
