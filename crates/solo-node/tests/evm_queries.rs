//! Contracts on a single node through the typed query helpers: deployment,
//! the code and storage queries, messages through the call query, logs in
//! receipts, and the query budget. The contract is
//! `fixtures/Counter.sol`, compiled once and committed as bytecode.

use k256::ecdsa::SigningKey;
use solo_abi::Encode;
use solo_abi::chain::{AccessItem, Allocation, CallRequest, GenesisParams, call_status};
use solo_abi::codec::Seq;
use solo_abi::types::Genesis;
use solo_host::hash::keccak256;
use solo_node::{Node, NodeConfig, NodeError, Sim};
use solo_recompile::{Input, Options, recompile};
use solo_rlp::{encode_bytes, encode_list, encode_uint};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const COUNTER: &str = include_str!("fixtures/Counter.bin");
const COUNTER_RUNTIME: &str = include_str!("fixtures/Counter.bin-runtime");
const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 400;
const ETHER: u128 = 1_000_000_000_000_000_000;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn selector(signature: &str) -> Vec<u8> {
    keccak256(signature.as_bytes())[..4].to_vec()
}

fn word(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

fn strip(b: &[u8]) -> &[u8] {
    let skip = b.iter().take_while(|x| **x == 0).count();
    &b[skip..]
}

struct Wallet {
    key: SigningKey,
    address: [u8; 20],
}

impl Wallet {
    fn new(seed: u8) -> Wallet {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let mut address = [0u8; 20];
        address.copy_from_slice(&keccak256(&point.as_bytes()[1..])[12..]);
        Wallet { key, address }
    }

    /// An EIP-155 legacy transaction; `to` of `None` creates a contract.
    fn send(&self, nonce: u64, to: Option<[u8; 20]>, data: &[u8], gas_limit: u64) -> Vec<u8> {
        let fields = unsigned_fields(nonce, to, data, gas_limit);
        let mut unsigned = fields.clone();
        encode_uint(u128::from(CHAIN_ID), &mut unsigned);
        encode_uint(0, &mut unsigned);
        encode_uint(0, &mut unsigned);
        let mut list = Vec::new();
        encode_list(&unsigned, &mut list);
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(&keccak256(&list))
            .unwrap();
        let mut signed = fields;
        encode_uint(
            u128::from(CHAIN_ID * 2 + 35 + u64::from(rid.to_byte())),
            &mut signed,
        );
        encode_bytes(strip(&sig.r().to_bytes()), &mut signed);
        encode_bytes(strip(&sig.s().to_bytes()), &mut signed);
        let mut out = Vec::new();
        encode_list(&signed, &mut out);
        out
    }
}

fn unsigned_fields(nonce: u64, to: Option<[u8; 20]>, data: &[u8], gas_limit: u64) -> Vec<u8> {
    let mut out = Vec::new();
    encode_uint(u128::from(nonce), &mut out);
    encode_uint(1_000_000_000, &mut out);
    encode_uint(u128::from(gas_limit), &mut out);
    encode_bytes(to.as_ref().map_or(&[][..], |t| &t[..]), &mut out);
    encode_uint(0, &mut out);
    encode_bytes(data, &mut out);
    out
}

fn node(alice: &Wallet) -> Node {
    let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        allocations: Seq(vec![Allocation {
            address: alice.address,
            balance: 100 * ETHER,
            ..Allocation::default()
        }]),
        ..GenesisParams::default()
    };
    let genesis = Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: Sim::validator_set(std::slice::from_ref(&key)).to_bytes(),
    };
    let config = NodeConfig {
        now_ms: 1_000,
        key: Some(key),
        ..NodeConfig::default()
    };
    let module = recompile(&Input::load(KERNEL).unwrap(), &Options::default()).unwrap();
    let mut node = Node::open(&module, &genesis, config).unwrap();
    node.start(None).unwrap();
    node
}

/// The address a creation by `sender` at `nonce` deploys to.
fn created_address(sender: &[u8; 20], nonce: u64) -> [u8; 20] {
    let mut body = Vec::new();
    encode_bytes(sender, &mut body);
    encode_uint(u128::from(nonce), &mut body);
    let mut list = Vec::new();
    encode_list(&body, &mut list);
    keccak256(&list)[12..].try_into().unwrap()
}

#[test]
fn contracts_through_the_node() {
    let alice = Wallet::new(1);
    let mut node = node(&alice);
    let mut initcode = hex(COUNTER);
    initcode.extend_from_slice(&word(5));
    let deploy = node
        .submit(&alice.send(0, None, &initcode, 500_000))
        .unwrap();
    node.tick(1_000 + SLOT_MS).unwrap();
    let receipt = node.receipt(&deploy).unwrap().unwrap();
    assert_eq!(receipt.status, 1);
    let counter = created_address(&alice.address, 0);
    assert_eq!(receipt.contract, Some(counter));
    assert_eq!(receipt.to, [0; 20], "a creation has no recipient");

    // Code and storage.
    assert_eq!(node.code(&counter).unwrap(), hex(COUNTER_RUNTIME));
    assert!(node.code(&alice.address).unwrap().is_empty());
    assert!(node.code(&[7; 20]).unwrap().is_empty());
    assert_eq!(node.storage(&counter, &word(0)).unwrap(), word(5));
    assert_eq!(
        node.storage(&counter, &word(1)).unwrap()[12..],
        alice.address
    );
    assert_eq!(node.storage(&counter, &word(2)).unwrap(), [0; 32]);
    assert_eq!(node.storage(&alice.address, &word(0)).unwrap(), [0; 32]);

    // A read through the call query, and a revert with its reason.
    let mut request = CallRequest {
        from: alice.address,
        to: Some(counter),
        value: 0,
        data: selector("count()"),
        gas: 0,
        access_list: Seq(vec![]),
    };
    let read = node.call(&request).unwrap();
    assert_eq!(read.status, call_status::SUCCESS);
    assert_eq!(read.output, word(5));
    assert!(read.gas_used > 21_000);
    request.data = selector("halt()");
    let halted = node.call(&request).unwrap();
    assert_eq!(halted.status, call_status::HALT);
    request.data = [
        selector("divide(uint256,uint256)"),
        word(1).to_vec(),
        word(0).to_vec(),
    ]
    .concat();
    let reverted = node.call(&request).unwrap();
    assert_eq!(reverted.status, call_status::REVERT);
    assert_eq!(reverted.output[..4], selector("Panic(uint256)")[..]);
    // The caller cannot pay the value: the message does not run.
    request.value = 1_000 * ETHER;
    assert_eq!(node.call(&request).unwrap().status, call_status::INVALID);

    // A state change through a transaction: storage moves and the receipt carries the log.
    let increment = [selector("increment(uint256)"), word(2).to_vec()].concat();
    let tx = node
        .submit(&alice.send(1, Some(counter), &increment, 100_000))
        .unwrap();
    node.tick(1_000 + 2 * SLOT_MS).unwrap();
    let receipt = node.receipt(&tx).unwrap().unwrap();
    assert_eq!(receipt.status, 1);
    assert_eq!(receipt.to, counter);
    assert_eq!(receipt.contract, None);
    assert_eq!(receipt.cumulative_gas_used, receipt.gas_used);
    assert_eq!(receipt.logs.0.len(), 1);
    let log = &receipt.logs.0[0];
    assert_eq!(log.address, counter);
    assert_eq!(
        log.topics.0[0],
        keccak256(b"Incremented(address,uint256,uint256)")
    );
    assert_eq!(log.topics.0[2], word(7));
    assert_eq!(log.data, word(2));
    assert_eq!(node.storage(&counter, &word(0)).unwrap(), word(7));
    // A creation through the call query runs the initcode and keeps nothing.
    let created = node
        .call(&CallRequest {
            from: alice.address,
            to: None,
            value: 0,
            data: initcode,
            gas: 1_000_000,
            access_list: Seq(vec![]),
        })
        .unwrap();
    assert_eq!(created.status, call_status::SUCCESS);
    assert_eq!(created.output, hex(COUNTER_RUNTIME));
    assert!(
        node.code(&created_address(&alice.address, 2))
            .unwrap()
            .is_empty()
    );

    // Starved kernel calls surface as node errors.
    node.kernel_gas = 0;
    assert!(matches!(node.code(&counter), Err(NodeError::Kernel { .. })));
    assert!(matches!(
        node.storage(&counter, &word(0)),
        Err(NodeError::Kernel { .. })
    ));
    assert!(node.call(&request).unwrap_err().is_out_of_gas());
    // A budget the executor refuses fails the call before it starts.
    node.kernel_gas = -1;
    let refused = node.call(&request).unwrap_err();
    assert!(matches!(refused, NodeError::Kernel { .. }));
    assert!(!refused.is_out_of_gas());
}

#[test]
fn access_lists_and_the_query_budget() {
    let alice = Wallet::new(1);
    let mut node = node(&alice);
    let mut initcode = hex(COUNTER);
    initcode.extend_from_slice(&word(5));
    node.submit(&alice.send(0, None, &initcode, 500_000))
        .unwrap();
    node.tick(1_000 + SLOT_MS).unwrap();
    let counter = created_address(&alice.address, 0);
    let mut count = CallRequest {
        from: alice.address,
        to: Some(counter),
        value: 0,
        data: selector("count()"),
        gas: 0,
        access_list: Seq(vec![]),
    };
    let read = node.call(&count).unwrap();
    assert_eq!(read.output, word(5));

    // An access list is charged up front and warms what it names: 2400 for
    // the account and 1900 for the key, and the slot read then costs 100
    // instead of 2100. The callee is warm anyway.
    count.access_list = Seq(vec![AccessItem {
        address: counter,
        keys: Seq(vec![word(0)]),
    }]);
    let listed = node.call(&count).unwrap();
    assert_eq!(listed.output, word(5));
    assert_eq!(listed.gas_used, read.gas_used + 2_400 + 1_900 - 2_000);
    count.access_list = Seq(vec![]);

    // The call query sees the head block: its number and its timestamp.
    let block = |code: &str| CallRequest {
        to: None,
        data: hex(code),
        ..count.clone()
    };
    // NUMBER (TIMESTAMP) PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN
    let number = node.call(&block("4360005260206000f3")).unwrap();
    assert_eq!(number.output, word(1));
    let timestamp = node.call(&block("4260005260206000f3")).unwrap();
    let head = node.block_by_number(1).unwrap().unwrap();
    assert_eq!(timestamp.output, word(head.timestamp_ms / 1000));

    // Queries run within their own budget: a message that loops until its
    // EVM gas runs out (JUMPDEST PUSH1 0 JUMP) stops at the budget instead,
    // while ordinary calls fit.
    let looping = block("5b600056");
    node.query_gas = 2_000_000;
    let aborted = node.call(&looping).unwrap_err();
    assert!(aborted.is_out_of_gas(), "{aborted}");
    assert_eq!(node.call(&count).unwrap().output, word(5));
    let short = CallRequest {
        gas: 60_000,
        ..looping
    };
    assert_eq!(node.call(&short).unwrap().status, call_status::HALT);
}
