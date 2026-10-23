//! The binary Merkle trie of the state commitment (spec 10).
//!
//! A sparse binary Merkle tree over 256-bit paths, `path = keccak256(key)`,
//! in which an empty subtree hashes to zero and a subtree holding a single
//! entry is that entry's leaf. The shape is a function of the set of keys
//! alone, so the root does not depend on the order of updates, and an update
//! rehashes only the nodes on one path: O(depth) hashes, with depth about
//! `log2(n)` for `n` keys. A [`Proof`] carries the sibling hashes along a
//! key's path and verifies against the root alone, showing either the key's
//! value hash or that the key is absent.
//!
//! `no_std` with `alloc`. The hash function is a plain function pointer so
//! that a guest can supply the host's `keccak256`; the `keccak` feature
//! (default) provides one from `tiny-keccak`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod proof;
mod sorted;
mod trie;

pub use proof::{Proof, ProofError, TERMINAL_EMPTY, TERMINAL_LEAF, Terminal};
pub use sorted::{OutOfOrder, SortedRoot};
pub use trie::{NodeSource, PathNode, Trie};

/// A 32-byte digest: a path, a value hash or a node hash.
pub type Hash = [u8; 32];

/// The hash function of the trie. Spec 10 fixes it to `keccak256`; it is a
/// parameter only so that the caller can choose the implementation.
pub type HashFn = fn(&[u8]) -> Hash;

/// The hash of an empty subtree, and the root of an empty trie (spec 10 §4).
pub const EMPTY: Hash = [0; 32];

/// First byte of a leaf node's preimage (spec 10 §4).
pub const LEAF_TAG: u8 = 0x00;

/// First byte of a branch node's preimage (spec 10 §4).
pub const BRANCH_TAG: u8 = 0x01;

/// Most siblings a proof can carry: a path has 256 bits, so no leaf sits
/// deeper than 256 (spec 10 §5).
pub const MAX_DEPTH: usize = 256;

/// Length of a node's preimage (spec 10 §4): a tag byte and two hashes.
pub const NODE_LEN: usize = 65;

/// The two hashes of a node's preimage: a leaf's path and value hash, or a
/// branch's left and right child hashes.
///
/// # Panics
/// If `preimage` is shorter than [`NODE_LEN`].
#[must_use]
pub fn node_halves(preimage: &[u8]) -> (Hash, Hash) {
    let mut a = EMPTY;
    let mut b = EMPTY;
    a.copy_from_slice(&preimage[1..33]);
    b.copy_from_slice(&preimage[33..NODE_LEN]);
    (a, b)
}

/// `keccak256` of `data`.
#[cfg(feature = "keccak")]
#[must_use]
pub fn keccak256(data: &[u8]) -> Hash {
    use tiny_keccak::Hasher;
    let mut out = [0u8; 32];
    let mut k = tiny_keccak::Keccak::v256();
    k.update(data);
    k.finalize(&mut out);
    out
}

/// Bit `depth` of `path`, most significant bit of byte 0 first (spec 10 §3).
/// `true` is a one bit: the right child.
///
/// # Panics
/// If `depth` is 256 or more.
#[must_use]
pub fn bit(path: &Hash, depth: usize) -> bool {
    (path[depth / 8] >> (7 - depth % 8)) & 1 == 1
}

/// The hash of a leaf: `H(0x00 || path || value_hash)` (spec 10 §4).
#[must_use]
pub fn leaf_hash(hash: HashFn, path: &Hash, value_hash: &Hash) -> Hash {
    node_hash(hash, LEAF_TAG, path, value_hash)
}

/// The hash of a branch: `H(0x01 || left || right)` (spec 10 §4).
#[must_use]
pub fn branch_hash(hash: HashFn, left: &Hash, right: &Hash) -> Hash {
    node_hash(hash, BRANCH_TAG, left, right)
}

fn node_hash(hash: HashFn, tag: u8, a: &Hash, b: &Hash) -> Hash {
    let mut preimage = [0u8; 65];
    preimage[0] = tag;
    preimage[1..33].copy_from_slice(a);
    preimage[33..].copy_from_slice(b);
    hash(&preimage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_are_most_significant_first() {
        let mut path = EMPTY;
        path[0] = 0b1000_0001;
        path[31] = 0b0000_0001;
        assert!(bit(&path, 0));
        assert!(!bit(&path, 1));
        assert!(bit(&path, 7));
        assert!(!bit(&path, 8));
        assert!(bit(&path, 255));
        assert!(!bit(&path, 254));
    }

    #[test]
    fn node_halves_split_a_preimage() {
        let mut preimage = [0u8; NODE_LEN];
        preimage[1..33].copy_from_slice(&[3; 32]);
        preimage[33..].copy_from_slice(&[4; 32]);
        assert_eq!(node_halves(&preimage), ([3; 32], [4; 32]));
    }

    #[test]
    fn node_hashes_are_domain_separated() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_ne!(leaf_hash(keccak256, &a, &b), branch_hash(keccak256, &a, &b));
        let mut preimage = [0u8; 65];
        preimage[1..33].copy_from_slice(&a);
        preimage[33..].copy_from_slice(&b);
        assert_eq!(leaf_hash(keccak256, &a, &b), keccak256(&preimage));
        preimage[0] = 1;
        assert_eq!(branch_hash(keccak256, &a, &b), keccak256(&preimage));
    }
}
