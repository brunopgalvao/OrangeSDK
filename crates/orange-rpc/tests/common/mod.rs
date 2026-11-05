//! Shared fixtures: a recompiled kernel, funded wallets that sign every
//! transaction type, the test contract, a started node.

#![allow(dead_code)]

use k256::ecdsa::SigningKey;
use orange_abi::Encode;
use orange_abi::chain::{Allocation, GenesisParams};
use orange_abi::codec::Seq;
use orange_abi::types::Genesis;
use orange_host::hash::keccak256;
use orange_node::Node;
use orange_recompile::{Input, Options, recompile};
use orange_rlp::{encode_bytes, encode_list, encode_uint};
use orange_rpc::Rpc;
use serde_json::{Value, json};

pub const KERNEL: &[u8] = include_bytes!("../../../orange-node/tests/fixtures/kernel.elf");
/// Creation bytecode of `orange-node/tests/fixtures/Counter.sol`.
pub const COUNTER: &str = include_str!("../../../orange-node/tests/fixtures/Counter.bin");
/// Its deployed code.
pub const COUNTER_RUNTIME: &str =
    include_str!("../../../orange-node/tests/fixtures/Counter.bin-runtime");
pub const CHAIN_ID: u64 = 1337;
pub const SLOT_MS: u64 = 400;
pub const ETHER: u128 = 1_000_000_000_000_000_000;
pub const GAS_PRICE: u128 = 1_000_000_000;

pub fn kernel_module() -> Vec<u8> {
    recompile(&Input::load(KERNEL).unwrap(), &Options::default()).unwrap()
}

pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The four-byte selector of a function or error signature.
pub fn selector(signature: &str) -> Vec<u8> {
    keccak256(signature.as_bytes())[..4].to_vec()
}

/// A 32-byte big-endian word.
pub fn word(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// ABI-encoded call data: a selector and static words.
pub fn calldata(signature: &str, words: &[u64]) -> Vec<u8> {
    let mut out = selector(signature);
    for w in words {
        out.extend_from_slice(&word(*w));
    }
    out
}

/// ABI-encoded call data of a function taking one `string`.
pub fn calldata_string(signature: &str, text: &str) -> Vec<u8> {
    let mut out = selector(signature);
    out.extend_from_slice(&word(32));
    out.extend_from_slice(&word(text.len() as u64));
    let mut padded = text.as_bytes().to_vec();
    padded.resize(text.len().div_ceil(32) * 32, 0);
    out.extend_from_slice(&padded);
    out
}

/// Counter's creation code with its constructor argument.
pub fn counter_initcode(start: u64) -> Vec<u8> {
    let mut code = hex(COUNTER);
    code.extend_from_slice(&word(start));
    code
}

/// The address a creation by `sender` at `nonce` deploys to.
pub fn created_address(sender: &[u8; 20], nonce: u64) -> [u8; 20] {
    let mut body = Vec::new();
    encode_bytes(sender, &mut body);
    encode_uint(u128::from(nonce), &mut body);
    let mut list = Vec::new();
    encode_list(&body, &mut list);
    keccak256(&list)[12..].try_into().unwrap()
}

fn strip(b: &[u8]) -> &[u8] {
    let skip = b.iter().take_while(|x| **x == 0).count();
    &b[skip..]
}

fn access_list_rlp(items: &[([u8; 20], Vec<[u8; 32]>)], out: &mut Vec<u8>) {
    let mut body = Vec::new();
    for (address, keys) in items {
        let mut pair = Vec::new();
        encode_bytes(address, &mut pair);
        let mut list = Vec::new();
        for k in keys {
            encode_bytes(k, &mut list);
        }
        encode_list(&list, &mut pair);
        encode_list(&pair, &mut body);
    }
    encode_list(&body, out);
}

/// A legacy or access-list transaction's body fields.
pub struct Fields<'a> {
    pub nonce: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub gas_limit: u64,
    pub data: &'a [u8],
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
        let fields = Fields {
            nonce,
            to: Some(to),
            value,
            gas_limit,
            data,
        };
        self.legacy_on(&fields, GAS_PRICE, chain_id)
    }

    /// An EIP-155 legacy transaction at `GAS_PRICE`; `to` of `None` creates.
    pub fn legacy(&self, fields: &Fields<'_>) -> Vec<u8> {
        self.legacy_on(fields, GAS_PRICE, CHAIN_ID)
    }

    pub fn legacy_on(&self, f: &Fields<'_>, gas_price: u128, chain_id: u64) -> Vec<u8> {
        let body = |out: &mut Vec<u8>| {
            encode_uint(u128::from(f.nonce), out);
            encode_uint(gas_price, out);
            encode_uint(u128::from(f.gas_limit), out);
            encode_bytes(f.to.as_ref().map_or(&[][..], |t| &t[..]), out);
            encode_uint(f.value, out);
            encode_bytes(f.data, out);
        };
        let mut unsigned = Vec::new();
        body(&mut unsigned);
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
        body(&mut signed);
        encode_uint(u128::from(v), &mut signed);
        encode_bytes(strip(&sig.r().to_bytes()), &mut signed);
        encode_bytes(strip(&sig.s().to_bytes()), &mut signed);
        let mut out = Vec::new();
        encode_list(&signed, &mut out);
        out
    }

    /// Signs a typed transaction whose unsigned fields are already encoded.
    fn typed(&self, tx_type: u8, fields: &[u8]) -> Vec<u8> {
        let mut unsigned = vec![tx_type];
        encode_list(fields, &mut unsigned);
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(&keccak256(&unsigned))
            .unwrap();
        let mut body = fields.to_vec();
        encode_uint(u128::from(rid.to_byte()), &mut body);
        encode_bytes(strip(&sig.r().to_bytes()), &mut body);
        encode_bytes(strip(&sig.s().to_bytes()), &mut body);
        let mut out = vec![tx_type];
        encode_list(&body, &mut out);
        out
    }

    fn tail(f: &Fields<'_>, access: &[([u8; 20], Vec<[u8; 32]>)], out: &mut Vec<u8>) {
        encode_uint(u128::from(f.gas_limit), out);
        encode_bytes(f.to.as_ref().map_or(&[][..], |t| &t[..]), out);
        encode_uint(f.value, out);
        encode_bytes(f.data, out);
        access_list_rlp(access, out);
    }

    /// An EIP-2930 access-list transaction at `GAS_PRICE`.
    pub fn access_list_tx(&self, f: &Fields<'_>, access: &[([u8; 20], Vec<[u8; 32]>)]) -> Vec<u8> {
        let mut fields = Vec::new();
        encode_uint(u128::from(CHAIN_ID), &mut fields);
        encode_uint(u128::from(f.nonce), &mut fields);
        encode_uint(GAS_PRICE, &mut fields);
        Self::tail(f, access, &mut fields);
        self.typed(1, &fields)
    }

    /// An EIP-1559 dynamic-fee transaction.
    pub fn dynamic(
        &self,
        f: &Fields<'_>,
        max_fee: u128,
        tip: u128,
        access: &[([u8; 20], Vec<[u8; 32]>)],
    ) -> Vec<u8> {
        let mut fields = Vec::new();
        encode_uint(u128::from(CHAIN_ID), &mut fields);
        encode_uint(u128::from(f.nonce), &mut fields);
        encode_uint(tip, &mut fields);
        encode_uint(max_fee, &mut fields);
        Self::tail(f, access, &mut fields);
        self.typed(2, &fields)
    }

    /// This wallet's EIP-7702 authorization of `address` at `nonce`, as an
    /// RLP list item.
    pub fn authorization(&self, chain_id: u64, address: [u8; 20], nonce: u64) -> Vec<u8> {
        let mut body = Vec::new();
        encode_uint(u128::from(chain_id), &mut body);
        encode_bytes(&address, &mut body);
        encode_uint(u128::from(nonce), &mut body);
        let mut message = vec![0x05];
        encode_list(&body, &mut message);
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(&keccak256(&message))
            .unwrap();
        encode_uint(u128::from(rid.to_byte()), &mut body);
        encode_bytes(strip(&sig.r().to_bytes()), &mut body);
        encode_bytes(strip(&sig.s().to_bytes()), &mut body);
        let mut out = Vec::new();
        encode_list(&body, &mut out);
        out
    }

    /// An EIP-7702 set-code transaction carrying the encoded `auths`.
    pub fn set_code(&self, f: &Fields<'_>, max_fee: u128, tip: u128, auths: &[Vec<u8>]) -> Vec<u8> {
        let mut fields = Vec::new();
        encode_uint(u128::from(CHAIN_ID), &mut fields);
        encode_uint(u128::from(f.nonce), &mut fields);
        encode_uint(tip, &mut fields);
        encode_uint(max_fee, &mut fields);
        Self::tail(f, &[], &mut fields);
        encode_list(&auths.concat(), &mut fields);
        self.typed(4, &fields)
    }
}

/// The node's consensus key; the single validator.
pub fn node_key() -> SigningKey {
    SigningKey::from_slice(&[0x42; 32]).unwrap()
}

/// A genesis that gives each wallet 100 ether.
pub fn genesis_funding(wallets: &[&Wallet]) -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        allocations: Seq(wallets
            .iter()
            .map(|w| Allocation {
                address: w.address,
                balance: 100 * ETHER,
                ..Allocation::default()
            })
            .collect()),
        ..GenesisParams::default()
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: orange_node::Sim::validator_set(&[node_key()]).to_bytes(),
    }
}

pub fn genesis(alice: &Wallet) -> Genesis {
    genesis_funding(&[alice])
}

/// A started single-validator node at time 1000 that funds every wallet.
pub fn node_funding(wallets: &[&Wallet]) -> Node {
    let config = orange_node::NodeConfig {
        now_ms: 1_000,
        key: Some(node_key()),
        ..orange_node::NodeConfig::default()
    };
    let mut node = Node::open(&kernel_module(), &genesis_funding(wallets), config).unwrap();
    node.start(None).unwrap();
    node
}

pub fn node(alice: &Wallet) -> Node {
    node_funding(&[alice])
}

/// Calls a method; the error as `(code, message, data)`.
#[allow(clippy::needless_pass_by_value)]
pub fn call(rpc: &mut Rpc, method: &str, params: Value) -> Result<Value, (i64, String, Value)> {
    let response =
        rpc.handle(&json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params }));
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 7);
    if let Some(err) = response.get("error") {
        Err((
            err["code"].as_i64().unwrap(),
            err["message"].as_str().unwrap().to_owned(),
            err.get("data").cloned().unwrap_or(Value::Null),
        ))
    } else {
        Ok(response["result"].clone())
    }
}

pub fn ok(rpc: &mut Rpc, method: &str, params: Value) -> Value {
    call(rpc, method, params).unwrap_or_else(|e| panic!("{method}: {e:?}"))
}

pub fn err(rpc: &mut Rpc, method: &str, params: Value) -> (i64, String) {
    let (code, message, _) = call(rpc, method, params).expect_err(method);
    (code, message)
}

pub fn err_code(rpc: &mut Rpc, method: &str, params: Value) -> i64 {
    err(rpc, method, params).0
}
