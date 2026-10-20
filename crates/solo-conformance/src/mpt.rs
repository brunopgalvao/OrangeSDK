//! Ethereum's commitments that state tests pin: the root of the hexary
//! Merkle-Patricia trie over the accounts (Yellow Paper, appendix D) and the
//! hash of the RLP-encoded logs.
//!
//! Solo commits to its state with its own binary trie (spec 10); this module
//! exists only to compare a post-state with Ethereum's expected root.

use std::collections::BTreeMap;

use solo_abi::chain::Log;
use solo_host::hash::keccak256;
use solo_rlp::{encode_bytes, encode_list, encode_uint};

use crate::fixture::{Account, State};

/// `keccak256` of the empty code.
pub const EMPTY_CODE_HASH: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

/// Root of the empty trie, `keccak256(rlp(""))`.
pub const EMPTY_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// Root of the trie holding `entries` (keys and values as stored, values
/// already RLP-encoded where the trie's user requires it).
#[must_use]
pub fn root(entries: &BTreeMap<Vec<u8>, Vec<u8>>) -> [u8; 32] {
    let items: Vec<(Vec<u8>, &[u8])> = entries
        .iter()
        .map(|(k, v)| (nibbles(k), v.as_slice()))
        .collect();
    keccak256(&node(&items, 0))
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
fn reference(encoded: &[u8], out: &mut Vec<u8>) {
    if encoded.len() < 32 {
        out.extend_from_slice(encoded);
    } else {
        encode_bytes(&keccak256(encoded), out);
    }
}

/// The RLP encoding of the node holding `items`, sorted by path, all of
/// which agree on their first `depth` nibbles.
fn node(items: &[(Vec<u8>, &[u8])], depth: usize) -> Vec<u8> {
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
                reference(&node(items, depth + shared), &mut payload);
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
                    reference(&node(&rest[start..end], depth + 1), &mut payload);
                }
                encode_bytes(value, &mut payload);
            }
        }
    }
    let mut out = Vec::new();
    encode_list(&payload, &mut out);
    out
}

/// A big-endian integer without leading zero bytes, as RLP encodes it.
fn trimmed(value: &[u8]) -> &[u8] {
    let zeros = value.iter().take_while(|b| **b == 0).count();
    &value[zeros..]
}

fn storage_root(account: &Account) -> [u8; 32] {
    let entries = account
        .storage
        .iter()
        .filter(|(_, v)| **v != [0; 32])
        .map(|(k, v)| {
            let mut value = Vec::new();
            encode_bytes(trimmed(v), &mut value);
            (keccak256(k).to_vec(), value)
        })
        .collect();
    root(&entries)
}

/// Ethereum's state root of `state`.
#[must_use]
pub fn state_root(state: &State) -> [u8; 32] {
    let entries = state
        .iter()
        .map(|(address, account)| {
            let mut fields = Vec::new();
            encode_uint(u128::from(account.nonce), &mut fields);
            encode_bytes(trimmed(&account.balance), &mut fields);
            encode_bytes(&storage_root(account), &mut fields);
            encode_bytes(&keccak256(&account.code), &mut fields);
            let mut value = Vec::new();
            encode_list(&fields, &mut value);
            (keccak256(address).to_vec(), value)
        })
        .collect();
    root(&entries)
}

/// `keccak256(rlp(logs))`, the logs hash of a state test.
#[must_use]
pub fn logs_hash(logs: &[Log]) -> [u8; 32] {
    let mut list = Vec::new();
    for log in logs {
        let mut fields = Vec::new();
        encode_bytes(&log.address, &mut fields);
        let mut topics = Vec::new();
        for topic in &log.topics.0 {
            encode_bytes(topic, &mut topics);
        }
        encode_list(&topics, &mut fields);
        encode_bytes(&log.data, &mut fields);
        encode_list(&fields, &mut list);
    }
    let mut out = Vec::new();
    encode_list(&list, &mut out);
    keccak256(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solo_abi::codec::Seq;

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
        )
    }

    #[test]
    fn constants_are_the_hashes_they_name() {
        assert_eq!(keccak256(&[]), EMPTY_CODE_HASH);
        assert_eq!(keccak256(&[0x80]), EMPTY_ROOT);
        assert_eq!(root(&BTreeMap::new()), EMPTY_ROOT);
        assert_eq!(state_root(&State::new()), EMPTY_ROOT);
    }

    /// Vectors from ethereum/tests `TrieTests/trietest.json` and `trieanyorder.json`.
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
        // An odd-length leaf path after a branch, and a key that ends at the root branch.
        assert_eq!(
            trie(&[("a", "A"), ("b", "B")]).to_vec(),
            trie(&[("b", "B"), ("a", "A")]).to_vec()
        );
        assert_eq!(
            trie(&[("", "root"), ("a", "A")]),
            trie(&[("a", "A"), ("", "root")])
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

    /// The post-state of `mcopy_on_empty_memory` (execution-spec-tests,
    /// fusaka-devnet-5@v2.1.0) and the root the fixture expects.
    #[test]
    fn state_root_of_a_fixture() {
        let mut state = State::new();
        let account = |balance: &str, nonce, code: &str, storage: &[(&str, &str)]| {
            let mut b = [0u8; 32];
            let raw = h(balance);
            b[32 - raw.len()..].copy_from_slice(&raw);
            Account {
                balance: b,
                nonce,
                code: h(code),
                storage: storage
                    .iter()
                    .map(|(k, v)| {
                        let (mut key, mut value) = ([0u8; 32], [0u8; 32]);
                        let (k, v) = (h(k), h(v));
                        key[32 - k.len()..].copy_from_slice(&k);
                        value[32 - v.len()..].copy_from_slice(&v);
                        (key, value)
                    })
                    .collect(),
            }
        };
        let address = |s: &str| <[u8; 20]>::try_from(h(s)).unwrap();
        state.insert(
            address("9e1080f49e0d780fc839446198e8414ea89e9f80"),
            account(
                "00",
                1,
                "6040356020356000355e5960005559600020600155",
                &[
                    (
                        "01",
                        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                    ),
                    ("02", "00"),
                ],
            ),
        );
        state.insert(
            address("aa60f1b2a2b487c5cef8ae58d8d21cf5609787c3"),
            account("3635c9adc5de9904f8", 1, "", &[]),
        );
        state.insert(
            address("2adc25665018aa1fe0e6bc666dac8fc2697ff9ba"),
            account("02181c", 0, "", &[]),
        );
        assert_eq!(
            state_root(&state).to_vec(),
            h("e8f59d9fbd5edc4aff602efa653f5831428d180debfc189ca6d4cc2d90b8278b")
        );
    }

    #[test]
    fn logs_hash_of_no_logs_and_of_one() {
        assert_eq!(
            logs_hash(&[]).to_vec(),
            h("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")
        );
        let log = Log {
            address: [0x11; 20],
            topics: Seq(vec![[0x22; 32]]),
            data: vec![0x33],
        };
        let mut fields = Vec::new();
        encode_bytes(&[0x11; 20], &mut fields);
        let mut topics = Vec::new();
        encode_bytes(&[0x22; 32], &mut topics);
        encode_list(&topics, &mut fields);
        encode_bytes(&[0x33], &mut fields);
        let mut item = Vec::new();
        encode_list(&fields, &mut item);
        let mut list = Vec::new();
        encode_list(&item, &mut list);
        assert_eq!(logs_hash(&[log]), keccak256(&list));
    }
}
