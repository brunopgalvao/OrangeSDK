//! Hand-built cases for the tests that drive the conformance guest directly:
//! one legacy call to a contract, from a funded key, in an Osaka block.

// Each test binary uses its own part of this module.
#![allow(dead_code)]

use k256::ecdsa::SigningKey;
use solo_abi::chain::Allocation;
use solo_abi::codec::Seq;
use solo_abi::conformance::{Case, Env};
use solo_host::hash::keccak256;
use solo_rlp::{encode_bytes, encode_list, encode_uint};

/// Osaka's per-transaction gas cap (EIP-7825).
pub const TX_GAS: u64 = 1 << 24;
/// The contract every case calls.
pub const CONTRACT: [u8; 20] = [0xC0; 20];

/// `bytes` without its leading zeros.
pub fn strip(bytes: &[u8]) -> &[u8] {
    &bytes[bytes.iter().take_while(|b| **b == 0).count()..]
}

/// A pre-EIP-155 legacy call from the key `[1; 32]` and that key's address.
pub fn signed_call(to: [u8; 20], gas: u64) -> (Vec<u8>, [u8; 20]) {
    signed_call_with(to, gas, &[])
}

/// [`signed_call`] with calldata.
pub fn signed_call_with(to: [u8; 20], gas: u64, data: &[u8]) -> (Vec<u8>, [u8; 20]) {
    let key = SigningKey::from_slice(&[1; 32]).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let from: [u8; 20] = keccak256(&point.as_bytes()[1..])[12..].try_into().unwrap();
    let mut fields = Vec::new();
    encode_uint(0, &mut fields);
    encode_uint(10, &mut fields);
    encode_uint(u128::from(gas), &mut fields);
    encode_bytes(&to, &mut fields);
    encode_uint(0, &mut fields);
    encode_bytes(data, &mut fields);
    let mut payload = Vec::new();
    encode_list(&fields, &mut payload);
    let (sig, rid) = key.sign_prehash_recoverable(&keccak256(&payload)).unwrap();
    encode_uint(27 + u128::from(rid.to_byte()), &mut fields);
    encode_bytes(strip(&sig.r().to_bytes()), &mut fields);
    encode_bytes(strip(&sig.s().to_bytes()), &mut fields);
    let mut tx = Vec::new();
    encode_list(&fields, &mut tx);
    (tx, from)
}

/// An account holding `code` (with nonce 1) or none (nonce 0).
pub fn account(address: [u8; 20], balance: u128, code: Vec<u8>) -> Allocation {
    Allocation {
        address,
        balance,
        nonce: u64::from(!code.is_empty()),
        code,
        storage: Seq(Vec::new()),
    }
}

/// A call with `gas` to `CONTRACT` holding `code`, with `others` also in the
/// pre-state.
pub fn case(code: Vec<u8>, gas: u64, others: Vec<Allocation>) -> Case {
    let (tx, from) = signed_call(CONTRACT, gas);
    let mut allocations = vec![
        account(from, 1_000_000_000_000_000_000, Vec::new()),
        account(CONTRACT, 0, code),
    ];
    allocations.extend(others);
    Case {
        env: Env {
            chain_id: 1,
            gas_limit: 30_000_000,
            base_fee: 7,
            timestamp: 1_000,
            number: 1,
            ..Env::default()
        },
        allocations: Seq(allocations),
        tx,
    }
}
