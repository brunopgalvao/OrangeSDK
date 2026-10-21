//! Roots of Ethereum's hexary Merkle-Patricia trie (Yellow Paper,
//! appendices C and D): the transactions and receipts roots of a block
//! header (spec 20 §3) and, for the conformance runner, the state root of a
//! post-state. Only roots are built here; Solo proves its own state with the
//! binary trie of spec 10.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use solo_rlp::{encode_bytes, encode_list, encode_uint};

/// Root of the empty trie, `keccak256(rlp(""))`.
pub const EMPTY_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// Root of the trie holding `entries`: keys as stored, values already
/// encoded as the trie's user requires (RLP for state and storage, the
/// transaction or receipt encoding for a block's tries).
#[must_use]
pub fn root(entries: &BTreeMap<Vec<u8>, Vec<u8>>, keccak: fn(&[u8]) -> [u8; 32]) -> [u8; 32] {
    let items: Vec<(Vec<u8>, &[u8])> = entries
        .iter()
        .map(|(k, v)| (nibbles(k), v.as_slice()))
        .collect();
    keccak(&node(&items, 0, keccak))
}

/// Root of the trie a block header commits a list with: item `i` under the
/// key `rlp(i)` (the transactions and receipts roots).
#[must_use]
pub fn ordered_root(values: &[Vec<u8>], keccak: fn(&[u8]) -> [u8; 32]) -> [u8; 32] {
    let entries = values
        .iter()
        .enumerate()
        .map(|(i, value)| {
            let mut key = Vec::new();
            encode_uint(i as u128, &mut key);
            (key, value.clone())
        })
        .collect();
    root(&entries, keccak)
}

fn nibbles(key: &[u8]) -> Vec<u8> {
    key.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect()
}

/// Hex-prefix encoding of a nibble path (Yellow Paper, appendix C).
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
    out.extend(rest.chunks(2).map(|pair| (pair[0] << 4) | pair[1]));
    out
}

/// How a node is referenced from its parent: inline when its encoding is
/// shorter than 32 bytes, by hash otherwise.
fn reference(encoded: &[u8], out: &mut Vec<u8>, keccak: fn(&[u8]) -> [u8; 32]) {
    if encoded.len() < 32 {
        out.extend_from_slice(encoded);
    } else {
        encode_bytes(&keccak(encoded), out);
    }
}

/// The RLP encoding of the node holding `items`, sorted by path, all of
/// which agree on their first `depth` nibbles.
fn node(items: &[(Vec<u8>, &[u8])], depth: usize, keccak: fn(&[u8]) -> [u8; 32]) -> Vec<u8> {
    let mut payload = Vec::new();
    match items {
        [] => {
            let mut out = Vec::new();
            encode_bytes(&[], &mut out);
            return out;
        }
        [(path, value)] => {
            encode_bytes(&hex_prefix(&path[depth..], true), &mut payload);
            encode_bytes(value, &mut payload);
        }
        _ => {
            let first = &items[0].0;
            let last = &items[items.len() - 1].0;
            let shared = first[depth..]
                .iter()
                .zip(&last[depth..])
                .take_while(|(a, b)| a == b)
                .count();
            if shared > 0 {
                encode_bytes(
                    &hex_prefix(&first[depth..depth + shared], false),
                    &mut payload,
                );
                reference(&node(items, depth + shared, keccak), &mut payload, keccak);
            } else {
                // Sorted paths: one that ends here comes first.
                let (value, rest) = if first.len() == depth {
                    (items[0].1, &items[1..])
                } else {
                    (&[][..], items)
                };
                for nibble in 0..16 {
                    let start = rest.partition_point(|(p, _)| p[depth] < nibble);
                    let end = rest.partition_point(|(p, _)| p[depth] <= nibble);
                    reference(
                        &node(&rest[start..end], depth + 1, keccak),
                        &mut payload,
                        keccak,
                    );
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
    use super::*;
    use alloc::vec;
    use tiny_keccak::{Hasher, Keccak};

    fn keccak(data: &[u8]) -> [u8; 32] {
        let mut k = Keccak::v256();
        k.update(data);
        let mut out = [0u8; 32];
        k.finalize(&mut out);
        out
    }

    fn h(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn trie(pairs: &[(&str, &str)]) -> [u8; 32] {
        root(
            &pairs
                .iter()
                .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
                .collect(),
            keccak,
        )
    }

    #[test]
    fn empty_root_is_the_hash_it_names() {
        assert_eq!(keccak(&[0x80]), EMPTY_ROOT);
        assert_eq!(root(&BTreeMap::new(), keccak), EMPTY_ROOT);
        assert_eq!(ordered_root(&[], keccak), EMPTY_ROOT);
    }

    /// Vectors from ethereum/tests `TrieTests/trietest.json` and
    /// `trieanyorder.json`, by their names there.
    #[test]
    fn known_roots() {
        assert_eq!(
            trie(&[("foo", "bar"), ("food", "bass")]).to_vec(),
            h("17beaa1648bafa633cda809c90c04af50fc8aed3cb40d16efbddee6fdf63c4c3")
        );
        // Extension, branch with a value, inline and hashed children.
        assert_eq!(
            trie(&[
                ("doe", "reindeer"),
                ("dog", "puppy"),
                ("dogglesworth", "cat")
            ])
            .to_vec(),
            h("8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3")
        );
        assert_eq!(
            trie(&[
                ("do", "verb"),
                ("dog", "puppy"),
                ("doge", "coin"),
                ("horse", "stallion")
            ])
            .to_vec(),
            h("5991bb8c6514148a29db676a14ac506cd2cd5775ace63c30a4fe457715e9ac84")
        );
        // A key that ends at a branch below an extension ("testy"), short
        // values inlined in a branch ("smallValues"), a single item.
        assert_eq!(
            trie(&[("test", "test"), ("te", "testy")]).to_vec(),
            h("8452568af70d8d140f58d941338542f645fcca50094b20f3c3d8c3df49337928")
        );
        assert_eq!(
            trie(&[("be", "e"), ("dog", "puppy"), ("bed", "d")]).to_vec(),
            h("3f67c7a47520f79faa29255d2d3c084a7a6df0453116ed7232ff10277a8be68b")
        );
        assert_eq!(
            trie(&[("A", &"a".repeat(50))]).to_vec(),
            h("d23786fb4a010da3ce639d66d5e904a11dbc02746d1ce25029e53290cabf28ab")
        );
        // Keys given in hex ("hex"), and the final state of "branch-value-update".
        let hex = [("0045", "0123456789"), ("4500", "9876543210")]
            .iter()
            .map(|(k, v)| (h(k), h(v)))
            .collect();
        assert_eq!(
            root(&hex, keccak).to_vec(),
            h("285505fcabe84badc8aa310e2aae17eddc7d120aabec8a476902c8184b3a3503")
        );
        assert_eq!(
            trie(&[("abc", "abc"), ("abcd", "abcd")]).to_vec(),
            h("7a320748f780ad9ad5b0837302075ce0eeba6c26e3d8562c67ccc0f1b273298a")
        );
        // Keys that end at branches whose other children are hashed
        // ("insert-middle-leaf").
        assert_eq!(
            trie(&[
                ("key1aa", "0123456789012345678901234567890123456789xxx"),
                ("key1", "0123456789012345678901234567890123456789Very_Long"),
                ("key2bb", "aval3"),
                ("key2", "short"),
                ("key3cc", "aval3"),
                ("key3", "1234567890123456789012345678901"),
            ])
            .to_vec(),
            h("cb65032e2f76c48b82b5c24b3db8f670ce73982869d38cd39a624f23d62a9e89")
        );
    }

    #[test]
    fn hex_prefix_encodes_every_parity_and_kind() {
        assert_eq!(hex_prefix(&[1, 2, 3, 4, 5], false), vec![0x11, 0x23, 0x45]);
        assert_eq!(
            hex_prefix(&[0, 1, 2, 3, 4, 5], false),
            vec![0x00, 0x01, 0x23, 0x45]
        );
        assert_eq!(
            hex_prefix(&[0x0f, 1, 0x0c, 0x0b, 8], true),
            vec![0x3f, 0x1c, 0xb8]
        );
        assert_eq!(
            hex_prefix(&[0, 0x0f, 1, 0x0c, 0x0b, 8], true),
            vec![0x20, 0x0f, 0x1c, 0xb8]
        );
    }
}
