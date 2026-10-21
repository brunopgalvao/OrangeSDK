//! Solo chains for the bridge tests: the reference kernel, signed legacy
//! transactions, and genesis files with and without the threshold key.

#![allow(dead_code)]

use std::sync::OnceLock;

use k256::ecdsa::SigningKey;
use solo_abi::Encode;
use solo_abi::chain::{Allocation, GenesisParams, Validator, ValidatorSet};
use solo_abi::codec::Seq;
use solo_abi::staking::{StakingParams, ValidatorKey};
use solo_abi::types::Genesis;
use solo_node::keystore::encryption_key;
use solo_node::validator_id;
use solo_rlp::{encode_bytes, encode_list, encode_uint};
use solo_trie::keccak256;

pub const KERNEL: &[u8] = include_bytes!("../../../solo-node/tests/fixtures/kernel.elf");
pub const CHAIN_ID: u64 = 1337;
pub const ETHER: u128 = 1_000_000_000_000_000_000;

/// The kernel recompiled once per test binary.
pub fn kernel_module() -> &'static [u8] {
    static MODULE: OnceLock<Vec<u8>> = OnceLock::new();
    MODULE.get_or_init(|| {
        solo_recompile::recompile(
            &solo_recompile::Input::load(KERNEL).unwrap(),
            &solo_recompile::Options::default(),
        )
        .unwrap()
    })
}

pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

pub fn address(key: &SigningKey) -> [u8; 20] {
    validator_id(key)[12..].try_into().unwrap()
}

/// A legacy EIP-155 transaction from `key`, at gas price 1 gwei.
pub fn tx(
    key: &SigningKey,
    nonce: u64,
    to: Option<[u8; 20]>,
    value: u128,
    data: &[u8],
    gas: u64,
) -> Vec<u8> {
    tx_priced(key, nonce, to, value, data, gas, 1_000_000_000)
}

/// A legacy EIP-155 transaction from `key` at gas price `price`.
pub fn tx_priced(
    key: &SigningKey,
    nonce: u64,
    to: Option<[u8; 20]>,
    value: u128,
    data: &[u8],
    gas: u64,
    price: u128,
) -> Vec<u8> {
    let to: &[u8] = to.as_ref().map_or(&[], |t| &t[..]);
    let fields = |out: &mut Vec<u8>| {
        encode_uint(u128::from(nonce), out);
        encode_uint(price, out);
        encode_uint(u128::from(gas), out);
        encode_bytes(to, out);
        encode_uint(value, out);
        encode_bytes(data, out);
    };
    let mut unsigned = Vec::new();
    fields(&mut unsigned);
    encode_uint(u128::from(CHAIN_ID), &mut unsigned);
    encode_uint(0, &mut unsigned);
    encode_uint(0, &mut unsigned);
    let mut list = Vec::new();
    encode_list(&unsigned, &mut list);
    let (sig, rid) = key.sign_prehash_recoverable(&keccak256(&list)).unwrap();
    let mut signed = Vec::new();
    fields(&mut signed);
    encode_uint(
        u128::from(CHAIN_ID * 2 + 35 + u64::from(rid.to_byte())),
        &mut signed,
    );
    let strip = |b: &[u8]| -> Vec<u8> { b[b.iter().take_while(|x| **x == 0).count()..].to_vec() };
    encode_bytes(&strip(&sig.r().to_bytes()), &mut signed);
    encode_bytes(&strip(&sig.s().to_bytes()), &mut signed);
    let mut out = Vec::new();
    encode_list(&signed, &mut out);
    out
}

/// The address `CREATE` gives `sender` at `nonce`.
pub fn create_address(sender: &[u8; 20], nonce: u64) -> [u8; 20] {
    let mut body = Vec::new();
    encode_bytes(sender, &mut body);
    encode_uint(u128::from(nonce), &mut body);
    let mut list = Vec::new();
    encode_list(&body, &mut list);
    keccak256(&list)[12..].try_into().unwrap()
}

/// A chain of the validators `keys` with weight 1000 gwei each, `funded`
/// accounts holding 100 ether, and `staking` (with every key's encryption
/// key registered at genesis when staking is on).
pub fn genesis(
    keys: &[SigningKey],
    funded: &[[u8; 20]],
    slot_ms: u64,
    staking: Option<StakingParams>,
) -> Genesis {
    let allocations = funded
        .iter()
        .map(|a| Allocation {
            address: *a,
            balance: 100 * ETHER,
            ..Allocation::default()
        })
        .collect();
    let set = ValidatorSet {
        validators: Seq(keys
            .iter()
            .map(|k| Validator {
                id: validator_id(k),
                weight: 1_000,
            })
            .collect()),
    };
    let staking = staking.map(|s| StakingParams {
        keys: Seq(keys
            .iter()
            .map(|k| ValidatorKey {
                id: validator_id(k),
                dkg_key: encryption_key(k).to_vec(),
            })
            .collect()),
        ..s
    });
    let params = GenesisParams {
        slot_ms,
        max_txs: 16,
        allocations: Seq(allocations),
        staking: staking.unwrap_or_default(),
        ..GenesisParams::default()
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: set.to_bytes(),
    }
}
