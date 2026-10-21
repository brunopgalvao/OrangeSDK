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

pub use solo_eth::mpt::EMPTY_ROOT;

/// Root of the trie holding `entries` (keys and values as stored, values
/// already RLP-encoded where the trie's user requires it).
#[must_use]
pub fn root(entries: &BTreeMap<Vec<u8>, Vec<u8>>) -> [u8; 32] {
    solo_eth::mpt::root(entries, keccak256)
}

fn storage_root(account: &Account) -> [u8; 32] {
    let entries = account
        .storage
        .iter()
        .filter(|(_, v)| **v != [0; 32])
        .map(|(k, v)| {
            let mut value = Vec::new();
            encode_bytes(solo_eth::trim(v), &mut value);
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
            encode_bytes(solo_eth::trim(&account.balance), &mut fields);
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
        solo_eth::header::encode_log(log, &mut list);
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

    #[test]
    fn constants_are_the_hashes_they_name() {
        assert_eq!(keccak256(&[]), EMPTY_CODE_HASH);
        assert_eq!(keccak256(&[0x80]), EMPTY_ROOT);
        assert_eq!(root(&BTreeMap::new()), EMPTY_ROOT);
        assert_eq!(state_root(&State::new()), EMPTY_ROOT);
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
