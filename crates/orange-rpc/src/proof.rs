//! `eth_getProof` with Orange's state proofs (spec 20 §4): the account and its
//! storage slots, each with the spec 10 proof of its entry against the
//! block's state root, in the response shape of EIP-1186 with a field naming
//! the proof format.

use orange_abi::Encode;
use orange_abi::chain::keys;
use orange_trie::Proof;
use serde_json::{Value, json};

use crate::hex::{data, quantity, quantity_be};

/// The value of `proofFormat`: the binary trie of spec 10, version 0.
pub const PROOF_FORMAT: &str = "orange-binary-trie-v0";

/// `keccak256` of the empty code: an account without code reports it as
/// its `codeHash`, as Ethereum does.
pub const EMPTY_CODE_HASH: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

/// The state key of an account (spec 20 §4): `acct/ ‖ address`.
#[must_use]
pub fn account_key(address: &[u8; 20]) -> Vec<u8> {
    [keys::ACCOUNT, address.as_slice()].concat()
}

/// The state key of a storage slot (spec 20 §4): `slot/ ‖ address ‖ slot`.
#[must_use]
pub fn slot_key(address: &[u8; 20], slot: &[u8; 32]) -> Vec<u8> {
    [keys::SLOT, address.as_slice(), slot.as_slice()].concat()
}

/// A proof as `eth_getProof` lists it: each sibling hash from the root down,
/// then the terminal, `0x00` for an empty subtree or `0x01 ‖ path ‖ value
/// hash` for a leaf; the spec 10 §5.1 encoding without its sibling count.
#[must_use]
pub fn elements(proof: &Proof) -> Vec<Value> {
    let mut out: Vec<Value> = proof.siblings.iter().map(|s| json!(data(s))).collect();
    let encoded = proof.encode();
    out.push(json!(data(&encoded[2 + 32 * proof.siblings.len()..])));
    out
}

/// One slot of `storageProof`: the key as requested, the value and the proof.
#[must_use]
pub fn storage_entry(key: &str, value: &[u8; 32], proof: &Proof) -> Value {
    json!({
        "key": key,
        "value": quantity_be(value),
        "proof": elements(proof),
    })
}

/// The account part of the response. `account` is `None` for an account
/// that is not in state; `storage` the entries of [`storage_entry`].
#[must_use]
pub fn response(
    address: &[u8; 20],
    account: Option<&orange_abi::chain::Account>,
    state_root: &[u8; 32],
    account_proof: &Proof,
    storage: &[Value],
) -> Value {
    let default = orange_abi::chain::Account::default();
    let a = account.unwrap_or(&default);
    let code_hash = if a.code_hash == [0; 32] {
        EMPTY_CODE_HASH
    } else {
        a.code_hash
    };
    json!({
        "address": data(address),
        "balance": quantity(a.balance),
        "nonce": quantity(u128::from(a.nonce)),
        "codeHash": data(&code_hash),
        "storageHash": data(state_root),
        "accountProof": elements(account_proof),
        "storageProof": storage,
        "proofFormat": PROOF_FORMAT,
        "stateRoot": data(state_root),
        "accountKey": data(&account_key(address)),
        "accountValue": data(&account.map(Encode::to_bytes).unwrap_or_default()),
    })
}
