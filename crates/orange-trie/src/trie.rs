//! The trie itself: canonical shape, incremental updates, proof generation,
//! and nodes loaded on demand from a [`NodeSource`] for a trie kept on disk.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use crate::proof::{Proof, Terminal};
use crate::{BRANCH_TAG, EMPTY, Hash, HashFn, LEAF_TAG, NODE_LEN, bit, branch_hash, leaf_hash};

/// Where a trie opened from a root hash finds the nodes it has not loaded:
/// a store that keeps every node's 65-byte preimage (spec 10 §4) under its
/// hash. A trie built in memory needs none.
pub trait NodeSource {
    /// The preimage of the node with this hash, `0x00 ‖ path ‖ value_hash`
    /// for a leaf or `0x01 ‖ left ‖ right` for a branch, if the source holds
    /// it.
    fn node(&self, hash: &Hash) -> Option<Vec<u8>>;
}

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
/// to a clone copies only the nodes on the updated path. A `Stub` is a node
/// the trie has not loaded from its source yet: its hash is known, its
/// contents are read when a path first passes through it.
#[derive(Debug, Clone)]
enum Node {
    Empty,
    Leaf(Arc<Leaf>),
    Branch(Arc<Branch>),
    Stub(Hash),
}

impl Node {
    fn hash(&self) -> Hash {
        match self {
            Node::Empty => EMPTY,
            Node::Leaf(leaf) => leaf.hash,
            Node::Branch(branch) => branch.hash,
            Node::Stub(hash) => *hash,
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

    /// The node's preimage (spec 10 §4), for a loaded leaf or branch.
    fn preimage(&self) -> Option<[u8; NODE_LEN]> {
        let mut out = [0u8; NODE_LEN];
        let (tag, a, b) = match self {
            Node::Leaf(leaf) => (LEAF_TAG, leaf.path, leaf.value_hash),
            Node::Branch(branch) => (BRANCH_TAG, branch.left.hash(), branch.right.hash()),
            Node::Empty | Node::Stub(_) => return None,
        };
        out[0] = tag;
        out[1..33].copy_from_slice(&a);
        out[33..].copy_from_slice(&b);
        Some(out)
    }
}

/// A child named by its hash in a stored branch: empty, or a stub to load.
fn child(hash: Hash) -> Node {
    if hash == EMPTY {
        Node::Empty
    } else {
        Node::Stub(hash)
    }
}

/// The hash function and the source of unloaded nodes, as every update
/// needs them.
#[derive(Clone, Copy)]
struct Ctx<'a> {
    hash: HashFn,
    source: Option<&'a dyn NodeSource>,
}

impl Ctx<'_> {
    /// The node whose hash is `hash`, from the source.
    ///
    /// # Panics
    /// If the source does not hold it: a store that lost a node of a root it
    /// still serves is corrupt, and nothing here can repair it.
    fn load(&self, hash: &Hash) -> Node {
        let bytes = self.source.and_then(|s| s.node(hash));
        decode(hash, bytes.as_deref()).expect("a trie node its source holds")
    }
}

/// The node with hash `hash` and preimage `bytes`.
fn decode(hash: &Hash, bytes: Option<&[u8]>) -> Option<Node> {
    let bytes = bytes.filter(|b| b.len() == NODE_LEN)?;
    let (a, b) = crate::node_halves(bytes);
    match bytes[0] {
        LEAF_TAG => Some(Node::Leaf(Arc::new(Leaf {
            path: a,
            value_hash: b,
            hash: *hash,
        }))),
        BRANCH_TAG => Some(Node::Branch(Arc::new(Branch {
            left: child(a),
            right: child(b),
            hash: *hash,
        }))),
        _ => None,
    }
}

/// Replaces a stub with the node it names, so that the update below it can
/// proceed in memory.
fn resolve(node: &mut Node, ctx: Ctx<'_>) {
    if let Node::Stub(hash) = node {
        *node = ctx.load(hash);
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
fn insert(node: &mut Node, depth: usize, leaf: Arc<Leaf>, ctx: Ctx<'_>) -> Edit {
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
            *node = split(Arc::clone(existing), leaf, depth, ctx.hash);
            Edit::Added
        }
        Node::Branch(branch) => {
            let branch = Arc::make_mut(branch);
            let child = if bit(&leaf.path, depth) {
                &mut branch.right
            } else {
                &mut branch.left
            };
            let edit = insert(child, depth + 1, leaf, ctx);
            if !matches!(edit, Edit::Unchanged) {
                branch.hash = branch_hash(ctx.hash, &branch.left.hash(), &branch.right.hash());
            }
            edit
        }
        // A subtree not loaded yet: load it, then go on as if it had been.
        Node::Stub(hash) => {
            let hash = *hash;
            *node = ctx.load(&hash);
            insert(node, depth, leaf, ctx)
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
fn remove(node: &mut Node, depth: usize, path: &Hash, ctx: Ctx<'_>) -> bool {
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
            let right = bit(path, depth);
            let (child, other) = if right {
                (&mut branch.right, &mut branch.left)
            } else {
                (&mut branch.left, &mut branch.right)
            };
            if !remove(child, depth + 1, path, ctx) {
                return false;
            }
            // Whether the other side is a leaf that must rise is only known
            // once it is loaded.
            if matches!(child, Node::Empty) {
                resolve(other, ctx);
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
                    branch.hash = branch_hash(ctx.hash, &branch.left.hash(), &branch.right.hash());
                }
            }
            true
        }
        // A subtree not loaded yet: load it, then go on as if it had been.
        Node::Stub(hash) => {
            let hash = *hash;
            *node = ctx.load(&hash);
            remove(node, depth, path, ctx)
        }
    }
}

/// A node on a key's path, as [`Trie::path_nodes`] lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathNode {
    /// The node's hash.
    pub hash: Hash,
    /// Its preimage (spec 10 §4), or `None` for a node the trie has not
    /// loaded, whose subtree its source holds whole.
    pub preimage: Option<[u8; NODE_LEN]>,
}

/// A binary Merkle trie over `(key, value)` entries (spec 10).
///
/// Cloning is O(1): the clone shares every node, and later updates to
/// either copy only the nodes on their paths. A host uses this to compute
/// the root of committed state plus pending writes without touching the
/// committed trie. A trie opened from a root with [`Trie::from_root`] loads
/// the nodes a path needs from its [`NodeSource`] as updates and proofs
/// reach them, and keeps the ones updates passed.
#[derive(Clone)]
pub struct Trie {
    root: Node,
    len: usize,
    hash: HashFn,
    source: Option<Arc<dyn NodeSource>>,
}

impl fmt::Debug for Trie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Trie")
            .field("root", &self.root)
            .field("len", &self.len)
            .field("lazy", &self.source.is_some())
            .finish_non_exhaustive()
    }
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
            source: None,
        }
    }

    /// The trie whose root is `root` and whose nodes `source` holds, with
    /// `len` entries: nothing is read until a path needs it. An
    /// [`EMPTY`] root is the empty trie.
    #[must_use]
    pub fn from_root(root: Hash, len: usize, hash: HashFn, source: Arc<dyn NodeSource>) -> Trie {
        Trie {
            root: child(root),
            len,
            hash,
            source: Some(source),
        }
    }

    fn ctx(&self) -> Ctx<'_> {
        Ctx {
            hash: self.hash,
            source: self.source.as_deref(),
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
        let ctx = Ctx {
            hash: self.hash,
            source: self.source.as_deref(),
        };
        if matches!(insert(&mut self.root, 0, leaf, ctx), Edit::Added) {
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
        let ctx = Ctx {
            hash: self.hash,
            source: self.source.as_deref(),
        };
        let removed = remove(&mut self.root, 0, path, ctx);
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

    /// The proof for the entry at `path` (spec 10 §5.2). Nodes the trie has
    /// not loaded are read from its source for the proof and not kept.
    #[must_use]
    pub fn prove_hashed(&self, path: &Hash) -> Proof {
        let ctx = self.ctx();
        let mut siblings = Vec::new();
        let mut node = self.root.clone();
        loop {
            node = match node {
                Node::Stub(hash) => ctx.load(&hash),
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
                    next.clone()
                }
            };
        }
    }

    /// The nodes on `key`'s path from the root down to the leaf or empty
    /// subtree the path ends in, each with its preimage, stopping after the
    /// first node the trie has not loaded (its subtree is in the source
    /// already, unchanged). A store that keeps the trie's nodes writes the
    /// nodes a block changed by walking the paths of the keys it wrote.
    #[must_use]
    pub fn path_nodes(&self, key: &[u8]) -> Vec<PathNode> {
        let path = (self.hash)(key);
        let mut nodes = Vec::new();
        let mut node = &self.root;
        loop {
            match node {
                Node::Empty => return nodes,
                Node::Stub(hash) => {
                    nodes.push(PathNode {
                        hash: *hash,
                        preimage: None,
                    });
                    return nodes;
                }
                Node::Leaf(_) | Node::Branch(_) => nodes.push(PathNode {
                    hash: node.hash(),
                    preimage: node.preimage(),
                }),
            }
            let Node::Branch(branch) = node else {
                return nodes;
            };
            node = if bit(&path, nodes.len() - 1) {
                &branch.right
            } else {
                &branch.left
            };
        }
    }
}

#[cfg(test)]
mod tests {
    // The test source counts in a cell; no thread shares it.
    #![allow(clippy::arc_with_non_send_sync)]

    use alloc::collections::BTreeMap;
    use core::cell::RefCell;

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
        assert!(t.path_nodes(b"absent").is_empty());
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
        let nodes = t.path_nodes(b"k");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].hash, t.root());
        assert_eq!(nodes[0].preimage.unwrap()[0], LEAF_TAG);
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

    /// A node source over a map, counting what it serves.
    #[derive(Default)]
    struct Store {
        nodes: RefCell<BTreeMap<Hash, Vec<u8>>>,
        reads: RefCell<usize>,
    }

    impl Store {
        /// Keeps every node on the paths of `keys` in `trie`.
        fn keep(&self, trie: &Trie, keys: &[&[u8]]) {
            for key in keys {
                for node in trie.path_nodes(key) {
                    if let Some(preimage) = node.preimage {
                        self.nodes.borrow_mut().insert(node.hash, preimage.to_vec());
                    }
                }
            }
        }
    }

    impl NodeSource for Store {
        fn node(&self, hash: &Hash) -> Option<Vec<u8>> {
            *self.reads.borrow_mut() += 1;
            self.nodes.borrow().get(hash).cloned()
        }
    }

    #[test]
    fn a_trie_opened_from_a_root_loads_what_its_paths_need() {
        let keys: Vec<Vec<u8>> = (0u8..40).map(|i| alloc::vec![i, i ^ 0x55]).collect();
        let refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
        let mut built = Trie::new();
        for key in &refs {
            built.insert(key, key);
        }
        let store = Arc::new(Store::default());
        store.keep(&built, &refs);
        let root = built.root();
        // Opened lazily: nothing read yet, the root known.
        let mut lazy = Trie::from_root(root, built.len(), keccak256, store.clone());
        assert_eq!((lazy.root(), lazy.len()), (root, 40));
        assert_eq!(*store.reads.borrow(), 0);
        assert!(alloc::format!("{lazy:?}").contains("lazy: true"));
        // Proofs read a path and keep nothing.
        for key in &refs {
            assert_eq!(lazy.prove(key), built.prove(key));
            assert_eq!(lazy.get(key), Some(keccak256(key)));
        }
        assert_eq!(lazy.get(b"absent"), None);
        assert_eq!(lazy.prove(b"absent"), built.prove(b"absent"));
        let after_proofs = *store.reads.borrow();
        assert!(after_proofs > 40, "{after_proofs}");
        assert_eq!(lazy.path_nodes(refs[0]).len(), 1);
        assert!(lazy.path_nodes(refs[0])[0].preimage.is_none());
        // Updates resolve the nodes they pass and agree with the built trie.
        built.insert(b"new", b"1");
        lazy.insert(b"new", b"1");
        assert_eq!(lazy.root(), built.root());
        assert_eq!(lazy.len(), 41);
        built.insert(refs[7], b"changed");
        lazy.insert(refs[7], b"changed");
        lazy.insert(refs[7], b"changed");
        assert_eq!(lazy.root(), built.root());
        assert!(built.remove(refs[3]));
        assert!(lazy.remove(refs[3]));
        assert!(!lazy.remove(refs[3]));
        assert!(!lazy.remove(b"never"));
        assert_eq!(lazy.root(), built.root());
        assert_eq!(lazy.len(), 40);
        // A path updated in memory lists loaded nodes down to the leaf, then
        // a path through an untouched subtree ends at the first stub.
        let path = lazy.path_nodes(b"new");
        assert!(path.iter().all(|n| n.preimage.is_some()));
        assert_eq!(path.last().unwrap().preimage.unwrap()[0], LEAF_TAG);
        assert!(path[0].preimage.unwrap()[0] == BRANCH_TAG);
        let untouched = refs.iter().find(|k| {
            let nodes = lazy.path_nodes(k);
            nodes.last().is_some_and(|n| n.preimage.is_none())
        });
        assert!(untouched.is_some());
        // Removing down to a lone leaf beside a stub loads the stub to let
        // the leaf rise; a clone of the lazy trie goes its own way.
        let mut fork = lazy.clone();
        for key in refs.iter().skip(1) {
            fork.remove(key);
        }
        assert!(fork.remove(b"new"));
        let mut only_first = Trie::new();
        only_first.insert(refs[0], refs[0]);
        assert_eq!(fork.root(), only_first.root());
        assert_eq!(fork.len(), 1);
        assert_eq!(lazy.root(), built.root());
        // Everything persisted again reopens to the same root and proofs.
        let all: Vec<&[u8]> = refs.iter().copied().chain([&b"new"[..]]).collect();
        store.keep(&lazy, &all);
        let reopened = Trie::from_root(lazy.root(), lazy.len(), keccak256, store.clone());
        for key in &all {
            assert_eq!(reopened.prove(key), built.prove(key), "{key:?}");
        }
        assert_eq!(Trie::from_root(EMPTY, 0, keccak256, store).root(), EMPTY);
    }

    #[test]
    fn node_decoding_rejects_what_is_not_a_node() {
        let h = [9u8; 32];
        assert!(decode(&h, None).is_none());
        assert!(decode(&h, Some(&[0u8; 64])).is_none());
        let mut bad = [0u8; NODE_LEN];
        bad[0] = 7;
        assert!(decode(&h, Some(&bad)).is_none());
        let mut branch = [0u8; NODE_LEN];
        branch[0] = BRANCH_TAG;
        branch[33..].copy_from_slice(&[1; 32]);
        let node = decode(&h, Some(&branch)).unwrap();
        assert_eq!(node.hash(), h);
        assert_eq!(node.preimage(), Some(branch));
        assert!(Node::Empty.preimage().is_none());
        assert!(Node::Stub(h).preimage().is_none());
    }

    #[test]
    #[should_panic(expected = "a trie node its source holds")]
    fn a_missing_node_is_a_corrupt_source() {
        let store = Arc::new(Store::default());
        let lazy = Trie::from_root([1; 32], 1, keccak256, store);
        let _ = lazy.prove(b"k");
    }
}
