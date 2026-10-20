//! Shared fixtures: a recompiled kernel, a funded wallet, a started node.

#![allow(dead_code)]

use k256::ecdsa::SigningKey;
use solo_abi::Encode;
use solo_abi::chain::{Allocation, GenesisParams};
use solo_abi::codec::Seq;
use solo_abi::types::Genesis;
use solo_host::hash::keccak256;
use solo_node::Node;
use solo_recompile::{Input, Options, recompile};
use solo_rlp::{encode_bytes, encode_list, encode_uint};

pub const KERNEL: &[u8] = include_bytes!("../../../solo-node/tests/fixtures/kernel.elf");
pub const CHAIN_ID: u64 = 1337;
pub const SLOT_MS: u64 = 400;
pub const ETHER: u128 = 1_000_000_000_000_000_000;
pub const GAS_PRICE: u128 = 1_000_000_000;

pub fn kernel_module() -> Vec<u8> {
    recompile(&Input::load(KERNEL).unwrap(), &Options::default()).unwrap()
}

pub struct Wallet {
    pub key: SigningKey,
    pub address: [u8; 20],
}

impl Wallet {
    pub fn new(seed: u8) -> Wallet {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let digest = keccak256(&point.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&digest[12..]);
        Wallet { key, address }
    }

    /// An EIP-155 legacy transfer signed for `CHAIN_ID`.
    pub fn transfer(&self, nonce: u64, to: [u8; 20], value: u128, gas_limit: u64) -> Vec<u8> {
        self.transfer_on(nonce, to, value, gas_limit, CHAIN_ID, &[])
    }

    pub fn transfer_on(
        &self,
        nonce: u64,
        to: [u8; 20],
        value: u128,
        gas_limit: u64,
        chain_id: u64,
        data: &[u8],
    ) -> Vec<u8> {
        let fields = |out: &mut Vec<u8>| {
            encode_uint(u128::from(nonce), out);
            encode_uint(GAS_PRICE, out);
            encode_uint(u128::from(gas_limit), out);
            encode_bytes(&to, out);
            encode_uint(value, out);
            encode_bytes(data, out);
        };
        let mut unsigned = Vec::new();
        fields(&mut unsigned);
        encode_uint(u128::from(chain_id), &mut unsigned);
        encode_uint(0, &mut unsigned);
        encode_uint(0, &mut unsigned);
        let mut list = Vec::new();
        encode_list(&unsigned, &mut list);
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(&keccak256(&list))
            .unwrap();
        let v = chain_id * 2 + 35 + u64::from(rid.to_byte());
        let mut signed = Vec::new();
        fields(&mut signed);
        encode_uint(u128::from(v), &mut signed);
        let r = sig.r().to_bytes();
        let s = sig.s().to_bytes();
        encode_bytes(strip(&r), &mut signed);
        encode_bytes(strip(&s), &mut signed);
        let mut out = Vec::new();
        encode_list(&signed, &mut out);
        out
    }
}

fn strip(b: &[u8]) -> &[u8] {
    let skip = b.iter().take_while(|x| **x == 0).count();
    &b[skip..]
}

/// The node's consensus key; the single validator.
pub fn node_key() -> SigningKey {
    SigningKey::from_slice(&[0x42; 32]).unwrap()
}

pub fn genesis(alice: &Wallet) -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        allocations: Seq(vec![Allocation {
            address: alice.address,
            balance: 100 * ETHER,
            ..Allocation::default()
        }]),
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: solo_node::Sim::validator_set(&[node_key()]).to_bytes(),
    }
}

pub fn node(alice: &Wallet) -> Node {
    let config = solo_node::NodeConfig {
        now_ms: 1_000,
        key: Some(node_key()),
        ..solo_node::NodeConfig::default()
    };
    let mut node = Node::open(&kernel_module(), &genesis(alice), config).unwrap();
    node.start(None).unwrap();
    node
}
