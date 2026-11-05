//! Ethereum's hexary Merkle-Patricia trie (Yellow Paper, appendices C and
//! D): verification of the proofs `eth_getProof` returns, and a builder
//! that produces such proofs, for tests and relayer tooling.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use orange_rlp::{Item, decode, encode_bytes, encode_item, encode_list};

use crate::{Crypto, Hash};

/// A proof that does not prove anything against the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadProof;

fn nibbles(key: &[u8]) -> Vec<u8> {
    key.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect()
}

/// Hex-prefix decoding: the nibbles of a path and whether it ends a leaf.
fn hex_prefix_decode(encoded: &[u8]) -> Result<(Vec<u8>, bool), BadProof> {
    let first = *encoded.first().ok_or(BadProof)?;
    let flag = first >> 4;
    if flag > 3 || flag & 1 == 0 && first & 0x0f != 0 {
        return Err(BadProof);
    }
    let mut path = Vec::new();
    if flag & 1 == 1 {
        path.push(first & 0x0f);
    }
    path.extend(nibbles(&encoded[1..]));
    Ok((path, flag & 2 == 2))
}

/// How a parent refers to a child: by hash, or embedded when the child's
/// encoding is shorter than 32 bytes.
enum Child {
    Hash(Hash),
    Inline(Vec<u8>),
    Empty,
}

fn child(item: &Item<'_>) -> Result<Child, BadProof> {
    match item {
        Item::Bytes([]) => Ok(Child::Empty),
        Item::Bytes(b) => Ok(Child::Hash((*b).try_into().map_err(|_| BadProof)?)),
        Item::List(_) => {
            let mut raw = Vec::new();
            encode_item(item, &mut raw);
            Ok(Child::Inline(raw))
        }
    }
}

/// Verifies `proof` (the nodes from the root down, RLP-encoded, as
/// `eth_getProof` returns them) for `key`, the trie key itself (for the
/// state and storage tries, the `keccak256` of the address or slot),
/// against `root`. Returns the value stored under the key, or `None` when
/// the proof shows the key is absent.
///
/// # Errors
/// [`BadProof`] when a node does not hash to its reference, does not
/// decode, the proof ends early, or nodes are left over.
pub fn verify(
    c: &dyn Crypto,
    root: &Hash,
    key: &[u8],
    proof: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, BadProof> {
    let path = nibbles(key);
    let mut next = Child::Hash(*root);
    let mut used = 0;
    let mut at = 0;
    let found = loop {
        let raw = match next {
            Child::Hash(h) => {
                let node = proof.get(used).ok_or(BadProof)?;
                used += 1;
                if c.keccak256(node) != h {
                    return Err(BadProof);
                }
                node.clone()
            }
            Child::Inline(raw) => raw,
            Child::Empty => break None,
        };
        let node = decode(&raw).map_err(|_| BadProof)?;
        let items = node.list().map_err(|_| BadProof)?;
        match items.len() {
            17 => {
                let Some(&nibble) = path.get(at) else {
                    let value = items[16].bytes().map_err(|_| BadProof)?;
                    break (!value.is_empty()).then(|| value.to_vec());
                };
                at += 1;
                next = child(&items[usize::from(nibble)])?;
            }
            2 => {
                let (prefix, leaf) = hex_prefix_decode(items[0].bytes().map_err(|_| BadProof)?)?;
                let rest = &path[at..];
                if leaf {
                    let value = items[1].bytes().map_err(|_| BadProof)?;
                    break (rest == prefix.as_slice()).then(|| value.to_vec());
                }
                if !rest.starts_with(&prefix) {
                    break None;
                }
                at += prefix.len();
                next = child(&items[1])?;
            }
            _ => return Err(BadProof),
        }
    };
    if used != proof.len() {
        return Err(BadProof);
    }
    Ok(found)
}

/// A trie built in memory from its entries: its root and proofs.
#[derive(Debug, Clone, Default)]
pub struct Trie {
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Trie {
    /// An empty trie.
    #[must_use]
    pub fn new() -> Trie {
        Trie::default()
    }

    /// Sets `key` (the trie key, already hashed where the trie requires it)
    /// to `value`, which must not be empty.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        self.entries.insert(key.to_vec(), value.to_vec());
    }

    /// The root.
    #[must_use]
    pub fn root(&self, c: &dyn Crypto) -> Hash {
        c.keccak256(&self.encode(c, None, &mut Vec::new()))
    }

    /// The proof of `key`, root node first; a proof of absence if it is not in the trie.
    #[must_use]
    pub fn prove(&self, c: &dyn Crypto, key: &[u8]) -> Vec<Vec<u8>> {
        let mut proof = Vec::new();
        let root = self.encode(c, Some(&nibbles(key)), &mut proof);
        proof.push(root);
        proof.reverse();
        proof
    }

    fn encode(&self, c: &dyn Crypto, target: Option<&[u8]>, proof: &mut Vec<Vec<u8>>) -> Vec<u8> {
        let items: Vec<(Vec<u8>, &[u8])> = self
            .entries
            .iter()
            .map(|(k, v)| (nibbles(k), v.as_slice()))
            .collect();
        node(c, &items, 0, target, proof)
    }
}

fn hex_prefix(path: &[u8], leaf: bool) -> Vec<u8> {
    let flag = if leaf { 2 } else { 0 };
    let mut out = Vec::with_capacity(path.len() / 2 + 1);
    let rest = if path.len() % 2 == 1 {
        out.push(((flag + 1) << 4) | path[0]);
        &path[1..]
    } else {
        out.push(flag << 4);
        path
    };
    out.extend(rest.chunks(2).map(|p| (p[0] << 4) | p[1]));
    out
}

/// Appends how a parent refers to `encoded`, and records it in `proof`
/// when the target's path goes through it and it is referenced by hash.
fn reference(
    c: &dyn Crypto,
    encoded: Vec<u8>,
    on_path: bool,
    proof: &mut Vec<Vec<u8>>,
    out: &mut Vec<u8>,
) {
    if encoded.len() < 32 {
        out.extend_from_slice(&encoded);
    } else {
        encode_bytes(&c.keccak256(&encoded), out);
        if on_path {
            proof.push(encoded);
        }
    }
}

/// The encoding of the node over `items` (nibble paths and values) whose
/// paths agree before `depth`. Nodes on `target`'s path are collected into
/// `proof`, deepest first, except the one returned.
fn node(
    c: &dyn Crypto,
    items: &[(Vec<u8>, &[u8])],
    depth: usize,
    target: Option<&[u8]>,
    proof: &mut Vec<Vec<u8>>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    match items {
        [] => return alloc::vec![0x80],
        [(path, value)] => {
            encode_bytes(&hex_prefix(&path[depth..], true), &mut payload);
            encode_bytes(value, &mut payload);
        }
        _ => {
            let first = &items[0].0;
            let shared = (depth..first.len())
                .take_while(|&i| items.iter().all(|(p, _)| p.get(i) == Some(&first[i])))
                .count();
            let on_path =
                |d: usize| target.is_some_and(|t| t.get(depth..d) == Some(&first[depth..d]));
            if shared > 0 {
                encode_bytes(
                    &hex_prefix(&first[depth..depth + shared], false),
                    &mut payload,
                );
                let here = on_path(depth + shared);
                let branch = node(c, items, depth + shared, target.filter(|_| here), proof);
                reference(c, branch, here, proof, &mut payload);
            } else {
                let mut value: &[u8] = &[];
                for nibble in 0..16u8 {
                    let group: Vec<(Vec<u8>, &[u8])> = items
                        .iter()
                        .filter(|(p, _)| p.get(depth) == Some(&nibble))
                        .cloned()
                        .collect();
                    if group.is_empty() {
                        payload.push(0x80);
                        continue;
                    }
                    let here = target.is_some_and(|t| t.get(depth) == Some(&nibble));
                    let sub = node(c, &group, depth + 1, target.filter(|_| here), proof);
                    reference(c, sub, here, proof, &mut payload);
                }
                if let Some((_, v)) = items.iter().find(|(p, _)| p.len() == depth) {
                    value = v;
                }
                encode_bytes(value, &mut payload);
            }
        }
    }
    let mut out = Vec::new();
    encode_list(&payload, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::testing::Native;

    /// The trie root of geth's test vectors (`trie/trie_test.go`, `TestInsert`).
    #[test]
    fn roots_match_known_values() {
        let c = Native;
        let mut t = Trie::new();
        assert_eq!(t.root(&c), c.keccak256(&[0x80]));
        t.insert(b"doe", b"reindeer");
        t.insert(b"dog", b"puppy");
        t.insert(b"dogglesworth", b"cat");
        let expected = "8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3";
        assert_eq!(crate::testing::hex(&t.root(&c)), expected);
    }

    #[test]
    fn proofs_verify_presence_and_absence_and_reject_tampering() {
        let c = Native;
        let mut t = Trie::new();
        let keys: Vec<Hash> = (0u8..40).map(|i| c.keccak256(&[i])).collect();
        for (i, k) in keys.iter().enumerate() {
            t.insert(k, &vec![1u8; 1 + i % 40]);
        }
        // Short values make embedded leaves; keys sharing a prefix make extensions.
        t.insert(&[0xAB; 32], b"x");
        let mut close = [0xAB; 32];
        close[31] = 0xAC;
        t.insert(&close, b"y");
        let root = t.root(&c);
        for (i, k) in keys.iter().enumerate() {
            let proof = t.prove(&c, k);
            assert_eq!(
                verify(&c, &root, k, &proof),
                Ok(Some(vec![1u8; 1 + i % 40]))
            );
            let mut extra = proof.clone();
            extra.push(vec![0x80]);
            assert_eq!(verify(&c, &root, k, &extra), Err(BadProof));
            assert_eq!(
                verify(&c, &root, k, &proof[..proof.len() - 1]),
                Err(BadProof)
            );
        }
        assert_eq!(
            verify(&c, &root, &close, &t.prove(&c, &close)),
            Ok(Some(b"y".to_vec()))
        );
        assert_eq!(
            verify(&c, &root, &[0xAB; 32], &t.prove(&c, &[0xAB; 32])),
            Ok(Some(b"x".to_vec()))
        );
        // Absent keys: one ending in an empty branch slot, one diverging in a
        // leaf, one diverging in an extension.
        for absent in [
            [0xFF; 32],
            {
                let mut k = keys[3];
                k[31] ^= 1;
                k
            },
            {
                let mut k = [0xAB; 32];
                k[20] = 0;
                k
            },
        ] {
            assert_eq!(verify(&c, &root, &absent, &t.prove(&c, &absent)), Ok(None));
        }
        // A tampered node no longer hashes to its reference.
        let mut bad = t.prove(&c, &keys[0]);
        let last = bad.len() - 1;
        bad[last][5] ^= 1;
        assert_eq!(verify(&c, &root, &keys[0], &bad), Err(BadProof));
        assert_eq!(verify(&c, &root, &keys[0], &[]), Err(BadProof));
    }

    #[test]
    fn malformed_nodes_are_rejected() {
        let c = Native;
        let check = |node: Vec<u8>, key: &[u8]| verify(&c, &c.keccak256(&node), key, &[node]);
        let list = |items: &[Vec<u8>]| {
            let mut p = Vec::new();
            for i in items {
                p.extend_from_slice(i);
            }
            let mut out = Vec::new();
            encode_list(&p, &mut out);
            out
        };
        let bytes = |b: &[u8]| {
            let mut out = Vec::new();
            encode_bytes(b, &mut out);
            out
        };
        // Not RLP, not a list, a list of 3, a leaf with a bad flag or a
        // nonzero pad nibble or an empty path encoding.
        assert_eq!(check(vec![0xC1], &[1]), Err(BadProof));
        assert_eq!(check(bytes(b"abc"), &[1]), Err(BadProof));
        assert_eq!(
            check(list(&[bytes(b"a"), bytes(b"b"), bytes(b"c")]), &[1]),
            Err(BadProof)
        );
        assert_eq!(
            check(list(&[bytes(&[0x40]), bytes(b"v")]), &[1]),
            Err(BadProof)
        );
        assert_eq!(
            check(list(&[bytes(&[0x21]), bytes(b"v")]), &[1]),
            Err(BadProof)
        );
        assert_eq!(check(list(&[bytes(&[]), bytes(b"v")]), &[1]), Err(BadProof));
        assert_eq!(check(list(&[list(&[]), bytes(b"v")]), &[1]), Err(BadProof));
        // A leaf whose value is a list, a branch child of the wrong length,
        // a branch value that is a list, an extension child that is junk.
        assert_eq!(
            check(list(&[bytes(&[0x20, 0x01]), list(&[])]), &[1]),
            Err(BadProof)
        );
        let mut children: Vec<Vec<u8>> = (0..16).map(|_| bytes(&[])).collect();
        children[0] = bytes(&[1, 2, 3]);
        children.push(bytes(&[]));
        assert_eq!(check(list(&children), &[0x01]), Err(BadProof));
        let mut children: Vec<Vec<u8>> = (0..16).map(|_| bytes(&[])).collect();
        children.push(list(&[]));
        assert_eq!(check(list(&children), &[]), Err(BadProof));
        // A branch value at the end of the key, and an empty one.
        let mut children: Vec<Vec<u8>> = (0..16).map(|_| bytes(&[])).collect();
        children.push(bytes(b"val"));
        assert_eq!(check(list(&children), &[]), Ok(Some(b"val".to_vec())));
        let mut children: Vec<Vec<u8>> = (0..16).map(|_| bytes(&[])).collect();
        children.push(bytes(&[]));
        assert_eq!(check(list(&children), &[]), Ok(None));
        assert_eq!(
            check(list(&[bytes(&[0x00, 0x01]), bytes(&[9; 5])]), &[0x01]),
            Err(BadProof)
        );
    }

    #[test]
    fn a_branch_holds_a_value_for_a_key_that_ends_there() {
        let c = Native;
        let mut t = Trie::new();
        t.insert(&[0x12], b"short");
        t.insert(&[0x12, 0x34], b"long-enough-value-to-be-hashed-separately");
        t.insert(&[0x12, 0x35], b"another-long-enough-value-to-be-hashed");
        let root = t.root(&c);
        assert_eq!(
            verify(&c, &root, &[0x12], &t.prove(&c, &[0x12])),
            Ok(Some(b"short".to_vec()))
        );
        assert_eq!(
            verify(&c, &root, &[0x12, 0x34], &t.prove(&c, &[0x12, 0x34])),
            Ok(Some(b"long-enough-value-to-be-hashed-separately".to_vec()))
        );
    }
}
