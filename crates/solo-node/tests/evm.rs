//! Contracts on the reference kernel, driven through a node: signed
//! transactions into the mempool, blocks per slot, receipts, and the code,
//! storage and call queries. Deployment by transaction and by genesis
//! predeploy, storage, logs, reverts, running out of gas, value into
//! contracts, CREATE and CREATE2 addresses, SELFDESTRUCT, typed
//! transactions, exact fee accounting, block opcodes, precompiles (the ones
//! the host accelerates checked against host-side k256, sha2 and p256), and
//! one contract scenario across simulated validators.
//!
//! The contracts are `fixtures/evm/Contracts.sol`, compiled once into the
//! hex files beside it.

use std::cell::Cell;
use std::sync::OnceLock;

use k256::ecdsa::SigningKey;
use solo_abi::chain::{
    Account, Allocation, BlockHeader, CallRequest, CallResult, GenesisParams, Log, Proposal,
    Receipt, StorageQuery, StorageSlot, call_status, keys, query, reason,
};
use solo_abi::codec::Seq;
use solo_abi::types::{Block, Effect, ExecuteSummary, Genesis, Input};
use solo_abi::{Decode, Encode};
use solo_host::hash::{keccak256, sha256};
use solo_node::{Node, NodeConfig, NodeError, Sim, SubmitError};
use solo_rlp::{encode_bytes, encode_list, encode_uint};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const STORE_BIN: &str = include_str!("fixtures/evm/Store.bin");
const STORE_RUNTIME: &str = include_str!("fixtures/evm/Store.runtime");
const PROBE_RUNTIME: &str = include_str!("fixtures/evm/Probe.runtime");
const FACTORY_RUNTIME: &str = include_str!("fixtures/evm/Factory.runtime");
const DOOMED_BIN: &str = include_str!("fixtures/evm/Doomed.bin");
const DOOMED_RUNTIME: &str = include_str!("fixtures/evm/Doomed.runtime");

const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 400;
/// 2023-11-14T22:13:20Z, so block timestamps look like real ones.
const START_MS: u64 = 1_700_000_000_000;
const ETHER: u128 = 1_000_000_000_000_000_000;
const GWEI: u128 = 1_000_000_000;
const BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// Where the genesis predeploys live.
const STORE: [u8; 20] = [0x51; 20];
const PROBE: [u8; 20] = [0x52; 20];
const FACTORY: [u8; 20] = [0x53; 20];
/// The block beneficiary: with a zero base fee, every fee lands here.
const BENEFICIARY: [u8; 20] = [0; 20];

/// The kernel recompiled once for every test in this file.
fn kernel_module() -> &'static [u8] {
    static MODULE: OnceLock<Vec<u8>> = OnceLock::new();
    MODULE.get_or_init(|| {
        solo_recompile::recompile(
            &solo_recompile::Input::load(KERNEL).unwrap(),
            &solo_recompile::Options::default(),
        )
        .unwrap()
    })
}

fn hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn word(n: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&n.to_be_bytes());
    w
}

fn address_word(address: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(address);
    w
}

fn last20(hash: &[u8; 32]) -> [u8; 20] {
    let mut a = [0u8; 20];
    a.copy_from_slice(&hash[12..]);
    a
}

/// ABI calldata: the selector of `signature` and static arguments.
fn calldata(signature: &str, args: &[[u8; 32]]) -> Vec<u8> {
    let mut data = keccak256(signature.as_bytes())[..4].to_vec();
    for arg in args {
        data.extend_from_slice(arg);
    }
    data
}

fn topic(signature: &str) -> [u8; 32] {
    keccak256(signature.as_bytes())
}

/// The ABI encoding of Solidity's `Error(string)` revert data.
fn revert_reason(text: &str) -> Vec<u8> {
    let mut out = calldata("Error(string)", &[word(32), word(text.len() as u128)]);
    let mut tail = text.as_bytes().to_vec();
    tail.resize(text.len().div_ceil(32) * 32, 0);
    out.extend_from_slice(&tail);
    out
}

/// `Store`'s creation code with its constructor argument.
fn store_init(initial: u128) -> Vec<u8> {
    let mut code = hex(STORE_BIN);
    code.extend_from_slice(&word(initial));
    code
}

/// The address `CREATE` gives: `keccak256(rlp([sender, nonce]))[12..]`.
fn create_address(sender: &[u8; 20], nonce: u64) -> [u8; 20] {
    let mut body = Vec::new();
    encode_bytes(sender, &mut body);
    encode_uint(u128::from(nonce), &mut body);
    let mut list = Vec::new();
    encode_list(&body, &mut list);
    last20(&keccak256(&list))
}

/// The address `CREATE2` gives: `keccak256(0xff ‖ sender ‖ salt ‖ keccak256(initcode))[12..]`.
fn create2_address(sender: &[u8; 20], salt: &[u8; 32], initcode: &[u8]) -> [u8; 20] {
    let mut preimage = vec![0xFF];
    preimage.extend_from_slice(sender);
    preimage.extend_from_slice(salt);
    preimage.extend_from_slice(&keccak256(initcode));
    last20(&keccak256(&preimage))
}

/// Gas a call to an existing account is charged: intrinsic gas plus
/// `execution`, or the EIP-7623 calldata floor if that is more.
#[allow(clippy::naive_bytecount)]
fn charged(data: &[u8], execution: u64) -> u64 {
    let zeros = data.iter().filter(|b| **b == 0).count() as u64;
    let nonzero = data.len() as u64 - zeros;
    let intrinsic = 21_000 + 4 * zeros + 16 * nonzero;
    let floor = 21_000 + 10 * (zeros + 4 * nonzero);
    (intrinsic + execution).max(floor)
}

/// An access list: addresses with their storage keys.
type AccessList = Vec<([u8; 20], Vec<[u8; 32]>)>;

/// How a transaction pays.
enum Fee {
    /// Legacy (EIP-155) at this gas price.
    Legacy(u128),
    /// EIP-2930 at this gas price.
    AccessList(u128, AccessList),
    /// EIP-1559 with this maximum fee and priority fee per gas.
    Dynamic(u128, u128, AccessList),
}

fn strip(b: &[u8]) -> &[u8] {
    let skip = b.iter().take_while(|x| **x == 0).count();
    &b[skip..]
}

struct Wallet {
    key: SigningKey,
    address: [u8; 20],
    nonce: Cell<u64>,
}

impl Wallet {
    fn new(seed: u8) -> Wallet {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let address = last20(&keccak256(&point.as_bytes()[1..]));
        Wallet {
            key,
            address,
            nonce: Cell::new(0),
        }
    }

    /// `r`, `s` (minimal big-endian) and the y parity of a signature over `keccak256(payload)`.
    fn signature(&self, payload: &[u8]) -> (Vec<u8>, Vec<u8>, u64) {
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(&keccak256(payload))
            .unwrap();
        (
            strip(&sig.r().to_bytes()).to_vec(),
            strip(&sig.s().to_bytes()).to_vec(),
            u64::from(rid.to_byte()),
        )
    }

    /// A signed transaction with an explicit nonce.
    fn sign(
        &self,
        nonce: u64,
        fee: &Fee,
        to: Option<[u8; 20]>,
        value: u128,
        data: &[u8],
        gas: u64,
    ) -> Vec<u8> {
        let to: &[u8] = to.as_ref().map_or(&[], |t| &t[..]);
        let mut fields = Vec::new();
        let (tx_type, list) = match fee {
            Fee::Legacy(price) => {
                encode_uint(u128::from(nonce), &mut fields);
                encode_uint(*price, &mut fields);
                encode_uint(u128::from(gas), &mut fields);
                encode_bytes(to, &mut fields);
                encode_uint(value, &mut fields);
                encode_bytes(data, &mut fields);
                let mut unsigned = fields.clone();
                encode_uint(u128::from(CHAIN_ID), &mut unsigned);
                encode_uint(0, &mut unsigned);
                encode_uint(0, &mut unsigned);
                let mut payload = Vec::new();
                encode_list(&unsigned, &mut payload);
                let (r, s, parity) = self.signature(&payload);
                encode_uint(u128::from(CHAIN_ID * 2 + 35 + parity), &mut fields);
                encode_bytes(&r, &mut fields);
                encode_bytes(&s, &mut fields);
                let mut out = Vec::new();
                encode_list(&fields, &mut out);
                return out;
            }
            Fee::AccessList(price, list) => {
                encode_uint(u128::from(CHAIN_ID), &mut fields);
                encode_uint(u128::from(nonce), &mut fields);
                encode_uint(*price, &mut fields);
                (1u8, list)
            }
            Fee::Dynamic(max_fee, tip, list) => {
                encode_uint(u128::from(CHAIN_ID), &mut fields);
                encode_uint(u128::from(nonce), &mut fields);
                encode_uint(*tip, &mut fields);
                encode_uint(*max_fee, &mut fields);
                (2u8, list)
            }
        };
        encode_uint(u128::from(gas), &mut fields);
        encode_bytes(to, &mut fields);
        encode_uint(value, &mut fields);
        encode_bytes(data, &mut fields);
        let mut entries = Vec::new();
        for (address, keys) in list {
            let mut pair = Vec::new();
            encode_bytes(address, &mut pair);
            let mut encoded_keys = Vec::new();
            for k in keys {
                encode_bytes(k, &mut encoded_keys);
            }
            encode_list(&encoded_keys, &mut pair);
            encode_list(&pair, &mut entries);
        }
        encode_list(&entries, &mut fields);
        let mut payload = vec![tx_type];
        encode_list(&fields, &mut payload);
        let (r, s, parity) = self.signature(&payload);
        encode_uint(u128::from(parity), &mut fields);
        encode_bytes(&r, &mut fields);
        encode_bytes(&s, &mut fields);
        let mut out = vec![tx_type];
        encode_list(&fields, &mut out);
        out
    }

    /// A signed transaction with the wallet's next nonce.
    fn send(&self, fee: &Fee, to: Option<[u8; 20]>, value: u128, data: &[u8], gas: u64) -> Vec<u8> {
        let nonce = self.nonce.get();
        self.nonce.set(nonce + 1);
        self.sign(nonce, fee, to, value, data, gas)
    }
}

/// The single validator of the one-node chains.
fn node_key() -> SigningKey {
    SigningKey::from_slice(&[0x42; 32]).unwrap()
}

fn genesis(validators: &[SigningKey], allocations: Vec<Allocation>) -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 16,
        allocations: Seq(allocations),
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: Sim::validator_set(validators).to_bytes(),
    }
}

fn funded(address: [u8; 20], balance: u128) -> Allocation {
    Allocation {
        address,
        balance,
        ..Allocation::default()
    }
}

/// A contract at genesis, nonce 1 as if it had been created.
fn predeploy(address: [u8; 20], runtime: &str, storage: &[([u8; 32], [u8; 32])]) -> Allocation {
    Allocation {
        address,
        balance: 0,
        nonce: 1,
        code: hex(runtime),
        storage: Seq(storage
            .iter()
            .map(|(key, value)| StorageSlot {
                key: *key,
                value: *value,
            })
            .collect()),
    }
}

/// A one-validator chain and its clock.
struct Chain {
    node: Node,
    now_ms: u64,
}

impl Chain {
    fn new(allocations: Vec<Allocation>) -> Chain {
        let config = NodeConfig {
            now_ms: START_MS,
            key: Some(node_key()),
            ..NodeConfig::default()
        };
        let mut node = Node::open(
            kernel_module(),
            &genesis(&[node_key()], allocations),
            config,
        )
        .expect("kernel loads and applies genesis");
        node.start(None).unwrap();
        Chain {
            node,
            now_ms: START_MS,
        }
    }

    /// Submits `txs`, produces the next block, checks it carries all of them,
    /// and returns their receipts in submission order.
    fn block(&mut self, txs: &[Vec<u8>]) -> Vec<Receipt> {
        let hashes: Vec<[u8; 32]> = txs
            .iter()
            .map(|raw| self.node.submit(raw).expect("admitted"))
            .collect();
        let height = self.node.block_number().unwrap();
        self.now_ms += SLOT_MS;
        self.node.tick(self.now_ms).unwrap();
        assert_eq!(
            self.node.block_number().unwrap(),
            height + 1,
            "one block per slot"
        );
        let header = self.node.block_by_number(height + 1).unwrap().unwrap();
        assert_eq!(
            header.tx_hashes.0.len(),
            txs.len(),
            "every transaction included"
        );
        hashes
            .iter()
            .map(|h| self.node.receipt(h).unwrap().expect("receipt"))
            .collect()
    }

    /// One transaction in its own block.
    fn run(&mut self, tx: Vec<u8>) -> Receipt {
        self.block(&[tx]).remove(0)
    }

    fn query<T: Decode>(&mut self, method: &str, params: &[u8]) -> T {
        let result = self.node.query(method, params).unwrap();
        assert_eq!(result.status, 0, "{method}");
        T::from_bytes(&result.body).unwrap()
    }

    fn code(&mut self, address: [u8; 20]) -> Vec<u8> {
        self.query(query::CODE, &address)
    }

    fn storage(&mut self, address: [u8; 20], slot: [u8; 32]) -> [u8; 32] {
        self.query(query::STORAGE, &StorageQuery { address, slot }.to_bytes())
    }

    fn call(
        &mut self,
        from: [u8; 20],
        to: Option<[u8; 20]>,
        value: u128,
        data: &[u8],
        gas: u64,
    ) -> CallResult {
        let request = CallRequest {
            from,
            to,
            value,
            data: data.to_vec(),
            gas,
        };
        self.query(query::CALL, &request.to_bytes())
    }

    fn account(&mut self, address: [u8; 20]) -> Account {
        self.node.account(&address).unwrap()
    }

    fn balance(&mut self, address: [u8; 20]) -> u128 {
        self.account(address).balance
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn deploy_by_transaction_store_and_log() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut chain = Chain::new(vec![
        funded(alice.address, 100 * ETHER),
        funded(bob.address, 100 * ETHER),
    ]);
    let deploy = alice.send(&Fee::Legacy(GWEI), None, 0, &store_init(5), 1_000_000);
    let receipt = chain.run(deploy);
    let store = create_address(&alice.address, 0);
    assert_eq!(receipt.status, 1);
    assert_eq!(
        receipt.contract,
        Some(store),
        "the CREATE address of (sender, nonce)"
    );
    assert_eq!(receipt.to, [0; 20], "a creation has no recipient");
    assert!(receipt.logs.0.is_empty());
    assert!(receipt.gas_used > 53_000 && receipt.gas_used < 1_000_000);
    assert_eq!(receipt.cumulative_gas_used, receipt.gas_used);
    assert_eq!((receipt.tx_type, receipt.effective_gas_price), (0, GWEI));
    // The deployed code is the runtime part of the creation code, keyed by its hash.
    let runtime = hex(STORE_RUNTIME);
    assert_eq!(chain.code(store), runtime);
    let account = chain.account(store);
    assert_eq!(account.code_hash, keccak256(&runtime));
    assert_eq!(account.nonce, 1, "contracts start at nonce 1 (EIP-161)");
    assert_eq!(
        chain
            .node
            .state_get(&[keys::CODE, &account.code_hash[..]].concat()),
        Some(runtime)
    );
    assert_eq!(chain.storage(store, word(0)), word(5));
    assert_eq!(chain.account(alice.address).nonce, 1);
    // Two writes in one block: each logs the writer and the old and new value,
    // and gas accumulates. (The mempool admits one transaction per sender per
    // block, since it checks nonces against the state.)
    let set9 = alice.send(
        &Fee::Legacy(GWEI),
        Some(store),
        0,
        &calldata("set(uint256)", &[word(9)]),
        100_000,
    );
    let set10 = bob.send(
        &Fee::Legacy(GWEI),
        Some(store),
        0,
        &calldata("set(uint256)", &[word(10)]),
        100_000,
    );
    let receipts = chain.block(&[set9, set10]);
    let set = topic("Set(address,uint256,uint256)");
    for (i, (who, old, new)) in [(&alice, 5, 9), (&bob, 9, 10)].into_iter().enumerate() {
        let r = &receipts[i];
        assert_eq!(
            (r.status, r.index, r.height),
            (1, u32::try_from(i).unwrap(), 2)
        );
        assert_eq!(r.to, store);
        assert_eq!(r.contract, None);
        assert_eq!(
            r.logs.0,
            vec![Log {
                address: store,
                topics: Seq(vec![set, address_word(&who.address), word(old)]),
                data: word(new).to_vec(),
            }]
        );
    }
    assert_eq!(
        receipts[1].cumulative_gas_used,
        receipts[0].gas_used + receipts[1].gas_used
    );
    let header = chain.node.block_by_number(2).unwrap().unwrap();
    assert_eq!(header.gas_used, receipts[1].cumulative_gas_used);
    assert_eq!(chain.storage(store, word(0)), word(10));
    let read = chain.call(
        alice.address,
        Some(store),
        0,
        &calldata("value()", &[]),
        100_000,
    );
    assert_eq!(read.status, call_status::SUCCESS);
    assert_eq!(read.output, word(10));
    // A slot never written reads as zero, and an address without code has none.
    assert_eq!(chain.storage(store, word(7)), [0; 32]);
    assert!(chain.code(alice.address).is_empty());
    // Clearing a slot earns the EIP-3529 refund of 4 800 and removes the key: the
    // two writes cost the same but for the refund and 12 gas of calldata.
    let slot_key = [keys::SLOT, &store[..], &word(0)[..]].concat();
    assert!(chain.node.state_get(&slot_key).is_some());
    let before = chain.balance(alice.address);
    let r11 = chain.run(alice.send(
        &Fee::Legacy(GWEI),
        Some(store),
        0,
        &calldata("set(uint256)", &[word(11)]),
        100_000,
    ));
    let r0 = chain.run(alice.send(
        &Fee::Legacy(GWEI),
        Some(store),
        0,
        &calldata("set(uint256)", &[word(0)]),
        100_000,
    ));
    assert_eq!((r11.status, r0.status), (1, 1));
    assert_eq!(r11.gas_used - r0.gas_used, 4_800 + 12);
    assert_eq!(chain.storage(store, word(0)), [0; 32]);
    assert_eq!(chain.node.state_get(&slot_key), None);
    assert_eq!(
        chain.balance(alice.address),
        before - u128::from(r11.gas_used + r0.gas_used) * GWEI,
        "the refund is paid back to the sender"
    );
}

/// Runtime code that returns 42, followed by `padding` zero bytes.
fn padded_runtime(padding: usize) -> Vec<u8> {
    let mut code = vec![0x60, 0x2A, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3];
    code.resize(code.len() + padding, 0);
    code
}

#[test]
fn code_larger_than_a_read_buffer() {
    // The kernel reads values into a 4 KiB buffer first; code beyond it must come
    // back whole, trailing zeros included, from genesis and from a deployment.
    let alice = Wallet::new(1);
    let runtime = padded_runtime(10_000);
    let at_genesis = Allocation {
        address: STORE,
        code: runtime.clone(),
        ..Allocation::default()
    };
    let mut chain = Chain::new(vec![funded(alice.address, 100 * ETHER), at_genesis]);
    assert_eq!(chain.code(STORE), runtime);
    let read = chain.call(alice.address, Some(STORE), 0, &[], 100_000);
    assert_eq!(
        (read.status, read.output),
        (call_status::SUCCESS, word(42).to_vec())
    );
    // Initcode: copy the runtime that follows these 12 bytes into memory and return it.
    let len = u16::try_from(runtime.len()).unwrap().to_be_bytes();
    let mut initcode = vec![
        0x61, len[0], len[1], 0x80, 0x60, 0x0C, 0x60, 0x00, 0x39, 0x60, 0x00, 0xF3,
    ];
    initcode.extend_from_slice(&runtime);
    let r = chain.run(alice.send(&Fee::Legacy(GWEI), None, 0, &initcode, 3_000_000));
    assert_eq!(r.status, 1);
    let deployed = r.contract.unwrap();
    assert_eq!(chain.code(deployed), runtime);
    assert_eq!(chain.account(deployed).code_hash, keccak256(&runtime));
    let read = chain.call(alice.address, Some(deployed), 0, &[], 100_000);
    assert_eq!(read.output, word(42));
}

#[test]
fn genesis_predeploys() {
    let alice = Wallet::new(1);
    let runtime = hex(STORE_RUNTIME);
    let mut store = predeploy(
        STORE,
        STORE_RUNTIME,
        &[(word(0), word(42)), (word(3), [0; 32])],
    );
    store.balance = 3 * ETHER;
    let mut veteran = funded(alice.address, 10 * ETHER);
    veteran.nonce = 5;
    let mut chain = Chain::new(vec![veteran, store]);
    // Before any block, the predeploy is a contract like any other.
    let account = chain.account(STORE);
    assert_eq!(
        account,
        Account {
            balance: 3 * ETHER,
            nonce: 1,
            code_hash: keccak256(&runtime)
        }
    );
    assert_eq!(chain.code(STORE), runtime);
    assert_eq!(chain.storage(STORE, word(0)), word(42));
    let read = chain.call(
        alice.address,
        Some(STORE),
        0,
        &calldata("value()", &[]),
        100_000,
    );
    assert_eq!(
        (read.status, read.output),
        (call_status::SUCCESS, word(42).to_vec())
    );
    // The layout: code under its hash, non-zero slots under address and slot, zero slots absent.
    let slot = |n: u128| [keys::SLOT, &STORE[..], &word(n)[..]].concat();
    assert_eq!(
        chain
            .node
            .state_get(&[keys::CODE, &account.code_hash[..]].concat()),
        Some(runtime)
    );
    assert_eq!(chain.node.state_get(&slot(0)), Some(word(42).to_vec()));
    assert_eq!(chain.node.state_get(&slot(3)), None);
    assert_eq!(
        chain
            .node
            .state_scan(&[keys::SLOT, &STORE[..]].concat())
            .len(),
        1
    );
    // The genesis nonce holds for an account without code too.
    assert_eq!(chain.account(alice.address).nonce, 5);
    let stale = alice.sign(0, &Fee::Legacy(GWEI), Some(STORE), 0, &[], 100_000);
    assert_eq!(
        chain.node.submit(&stale),
        Err(SubmitError::Rejected(reason::BAD_NONCE))
    );
    let set = alice.sign(
        5,
        &Fee::Legacy(GWEI),
        Some(STORE),
        0,
        &calldata("set(uint256)", &[word(43)]),
        100_000,
    );
    let receipt = chain.run(set);
    assert_eq!(receipt.status, 1);
    assert_eq!(
        receipt.logs.0[0].topics.0[2],
        word(42),
        "the old value came from genesis"
    );
    assert_eq!(chain.storage(STORE, word(0)), word(43));
    assert_eq!(chain.account(alice.address).nonce, 6);
}

#[test]
#[allow(clippy::too_many_lines)]
fn reverts_and_out_of_gas_keep_state_but_charge() {
    let alice = Wallet::new(1);
    let start = 100 * ETHER;
    let mut chain = Chain::new(vec![
        funded(alice.address, start),
        predeploy(STORE, STORE_RUNTIME, &[(word(0), word(1))]),
    ]);
    let price = 2 * GWEI;
    // A revert after a write and a log: status 0, nothing kept, gas charged, nonce used.
    let revert = alice.send(
        &Fee::Legacy(price),
        Some(STORE),
        0,
        &calldata("setAndRevert(uint256)", &[word(7)]),
        200_000,
    );
    let r = chain.run(revert);
    assert_eq!(r.status, 0);
    assert!(r.logs.0.is_empty(), "a reverted transaction keeps no logs");
    assert!(
        r.gas_used > 21_000 && r.gas_used < 200_000,
        "a revert returns the unused gas"
    );
    assert_eq!(chain.storage(STORE, word(0)), word(1));
    let a = chain.account(alice.address);
    assert_eq!(a.nonce, 1);
    let mut fees = u128::from(r.gas_used) * price;
    assert_eq!(a.balance, start - fees);
    // The same call as a query reports the revert reason.
    let query = chain.call(
        alice.address,
        Some(STORE),
        0,
        &calldata("setAndRevert(uint256)", &[word(7)]),
        200_000,
    );
    assert_eq!(query.status, call_status::REVERT);
    assert_eq!(query.output, revert_reason("nope"));
    assert_eq!(query.gas_used, r.gas_used);
    // Out of gas: the whole limit is spent and the writes made so far are undone.
    let burn = alice.send(
        &Fee::Legacy(price),
        Some(STORE),
        0,
        &calldata("burn()", &[]),
        100_000,
    );
    let r = chain.run(burn);
    assert_eq!((r.status, r.gas_used), (0, 100_000));
    assert!(r.logs.0.is_empty());
    assert_eq!(chain.storage(STORE, word(0)), word(1));
    let a = chain.account(alice.address);
    assert_eq!(a.nonce, 2);
    fees += 100_000 * price;
    assert_eq!(a.balance, start - fees);
    assert_eq!(
        chain.balance(BENEFICIARY),
        fees,
        "fees go to the zero-address beneficiary"
    );
    let query = chain.call(
        alice.address,
        Some(STORE),
        0,
        &calldata("burn()", &[]),
        50_000,
    );
    assert_eq!((query.status, query.gas_used), (call_status::HALT, 50_000));
    assert!(query.output.is_empty());
    // A creation whose constructor runs out of gas leaves no contract behind.
    let starved = alice.send(&Fee::Legacy(price), None, 0, &store_init(3), 80_000);
    let r = chain.run(starved);
    assert_eq!((r.status, r.gas_used, r.contract), (0, 80_000, None));
    assert!(chain.code(create_address(&alice.address, 2)).is_empty());
    assert_eq!(chain.account(alice.address).nonce, 3);
    // An invalid opcode halts the same way as running out of gas.
    let invalid = alice.send(&Fee::Legacy(price), None, 0, &[0xFE], 60_000);
    let r = chain.run(invalid);
    assert_eq!((r.status, r.gas_used), (0, 60_000));
    assert_eq!(
        chain.storage(STORE, word(0)),
        word(1),
        "every failure left the slot alone"
    );
}

#[test]
fn value_into_contracts() {
    let alice = Wallet::new(1);
    let mut chain = Chain::new(vec![
        funded(alice.address, 100 * ETHER),
        predeploy(STORE, STORE_RUNTIME, &[]),
        predeploy(FACTORY, FACTORY_RUNTIME, &[]),
    ]);
    let price = GWEI;
    // `Store` accepts value through `receive` and records who paid.
    let pay = alice.send(&Fee::Legacy(price), Some(STORE), 2 * ETHER, &[], 100_000);
    let r = chain.run(pay);
    assert_eq!(r.status, 1);
    assert_eq!(r.value, 2 * ETHER);
    assert_eq!(chain.balance(STORE), 2 * ETHER);
    let paid_slot = keccak256(&[address_word(&alice.address), word(1)].concat());
    assert_eq!(chain.storage(STORE, paid_slot), word(2 * ETHER));
    let mut spent = 2 * ETHER + u128::from(r.gas_used) * price;
    assert_eq!(chain.balance(alice.address), 100 * ETHER - spent);
    // `Factory` has neither `receive` nor a fallback: the transfer reverts and the value stays.
    let refused = alice.send(&Fee::Legacy(price), Some(FACTORY), ETHER, &[], 100_000);
    let r = chain.run(refused);
    assert_eq!(r.status, 0);
    assert_eq!(chain.balance(FACTORY), 0);
    spent += u128::from(r.gas_used) * price;
    assert_eq!(chain.balance(alice.address), 100 * ETHER - spent);
}

#[test]
#[allow(clippy::too_many_lines)]
fn create_and_create2_addresses() {
    let alice = Wallet::new(1);
    let mut chain = Chain::new(vec![
        funded(alice.address, 100 * ETHER),
        predeploy(FACTORY, FACTORY_RUNTIME, &[]),
    ]);
    let fee = Fee::Legacy(GWEI);
    let made = topic("Made(address)");
    let runtime = hex(STORE_RUNTIME);
    // CREATE from a contract uses the contract's nonce, 1 for a fresh one.
    let r = chain.run(alice.send(
        &fee,
        Some(FACTORY),
        0,
        &calldata("make(uint256)", &[word(11)]),
        1_000_000,
    ));
    assert_eq!(r.status, 1);
    let child = create_address(&FACTORY, 1);
    assert_eq!(
        r.logs.0,
        vec![Log {
            address: FACTORY,
            topics: Seq(vec![made]),
            data: address_word(&child).to_vec()
        }]
    );
    assert_eq!(
        r.contract, None,
        "a creation inside a call is not the receipt's contract"
    );
    assert_eq!(chain.code(child), runtime);
    assert_eq!(chain.storage(child, word(0)), word(11));
    assert_eq!(chain.account(FACTORY).nonce, 2);
    assert_eq!(chain.account(child).nonce, 1);
    // CREATE2 depends on the salt and the initcode, not on the nonce.
    let salt = [0x5A; 32];
    let child2 = create2_address(&FACTORY, &salt, &store_init(12));
    let r = chain.run(alice.send(
        &fee,
        Some(FACTORY),
        0,
        &calldata("make2(bytes32,uint256)", &[salt, word(12)]),
        1_000_000,
    ));
    assert_eq!(r.status, 1);
    assert_eq!(r.logs.0[0].data, address_word(&child2));
    assert_eq!(chain.code(child2), runtime);
    assert_eq!(chain.storage(child2, word(0)), word(12));
    assert_eq!(chain.account(FACTORY).nonce, 3);
    // The same salt and initcode again collide; Solidity turns the failed CREATE2 into a revert.
    let r = chain.run(alice.send(
        &fee,
        Some(FACTORY),
        0,
        &calldata("make2(bytes32,uint256)", &[salt, word(12)]),
        1_000_000,
    ));
    assert_eq!(r.status, 0);
    assert_eq!(chain.account(FACTORY).nonce, 3);
    // Value sent to a CREATE2 address before deployment is still there after it.
    let salt2 = [0x5B; 32];
    let child3 = create2_address(&FACTORY, &salt2, &store_init(13));
    assert_eq!(
        chain
            .run(alice.send(&fee, Some(child3), ETHER, &[], 21_000))
            .status,
        1
    );
    assert_eq!(
        chain.account(child3),
        Account {
            balance: ETHER,
            ..Account::default()
        }
    );
    let r = chain.run(alice.send(
        &fee,
        Some(FACTORY),
        0,
        &calldata("make2(bytes32,uint256)", &[salt2, word(13)]),
        1_000_000,
    ));
    assert_eq!(r.status, 1);
    let account = chain.account(child3);
    assert_eq!((account.balance, account.nonce), (ETHER, 1));
    assert_eq!(account.code_hash, keccak256(&runtime));
    // A creation transaction's address comes from the sender's nonce at the time.
    let nonce = alice.nonce.get();
    let r = chain.run(alice.send(&fee, None, 0, &store_init(14), 1_000_000));
    assert_eq!(r.contract, Some(create_address(&alice.address, nonce)));
    assert_eq!(
        chain.storage(create_address(&alice.address, nonce), word(0)),
        word(14)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn selfdestruct_removes_only_what_the_transaction_created() {
    let alice = Wallet::new(1);
    let heir = [0xE1; 20];
    let mut chain = Chain::new(vec![
        funded(alice.address, 100 * ETHER),
        predeploy(FACTORY, FACTORY_RUNTIME, &[]),
    ]);
    let fee = Fee::Legacy(GWEI);
    // Created, written to, and destroyed in one transaction: nothing of it remains.
    let salt = [0x77; 32];
    let doomed = create2_address(&FACTORY, &salt, &hex(DOOMED_BIN));
    let r = chain.run(alice.send(
        &fee,
        Some(FACTORY),
        ETHER,
        &calldata(
            "makeAndDestroy(bytes32,address)",
            &[salt, address_word(&heir)],
        ),
        1_000_000,
    ));
    assert_eq!(r.status, 1);
    assert_eq!(r.logs.0[0].data, address_word(&doomed));
    assert_eq!(chain.account(doomed), Account::default());
    assert!(chain.code(doomed).is_empty());
    assert_eq!(
        chain.storage(doomed, word(0)),
        [0; 32],
        "the constructor's write is gone"
    );
    assert_eq!(
        chain.node.state_get(&[keys::ACCOUNT, &doomed[..]].concat()),
        None
    );
    assert!(
        chain
            .node
            .state_scan(&[keys::SLOT, &doomed[..]].concat())
            .is_empty()
    );
    assert_eq!(chain.balance(heir), ETHER, "the value went to the heir");
    assert_eq!(chain.balance(FACTORY), 0);
    // Initcode that self-destructs: the creation succeeds and leaves no account.
    let mut initcode = vec![0x73];
    initcode.extend_from_slice(&heir);
    initcode.push(0xFF);
    let nonce = alice.nonce.get();
    let r = chain.run(alice.send(&fee, None, ETHER, &initcode, 100_000));
    let ghost = create_address(&alice.address, nonce);
    assert_eq!((r.status, r.contract), (1, Some(ghost)));
    assert_eq!(chain.account(ghost), Account::default());
    assert_eq!(
        chain.node.state_get(&[keys::ACCOUNT, &ghost[..]].concat()),
        None
    );
    assert_eq!(chain.balance(heir), 2 * ETHER);
    // A contract from an earlier transaction only hands over its balance (EIP-6780).
    let nonce = alice.nonce.get();
    let r = chain.run(alice.send(&fee, None, ETHER, &hex(DOOMED_BIN), 1_000_000));
    let survivor = create_address(&alice.address, nonce);
    assert_eq!(r.contract, Some(survivor));
    let r = chain.run(alice.send(
        &fee,
        Some(survivor),
        0,
        &calldata("destroy(address)", &[address_word(&heir)]),
        100_000,
    ));
    assert_eq!(r.status, 1);
    assert_eq!(chain.balance(heir), 3 * ETHER);
    let account = chain.account(survivor);
    assert_eq!((account.balance, account.nonce), (0, 1));
    assert_eq!(chain.code(survivor), hex(DOOMED_RUNTIME));
    assert_eq!(chain.storage(survivor, word(0)), word(7));
}

#[test]
#[allow(clippy::too_many_lines)]
fn typed_transactions_and_exact_fees() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let start = 100 * ETHER;
    let mut chain = Chain::new(vec![
        funded(alice.address, start),
        funded(bob.address, start),
        predeploy(STORE, STORE_RUNTIME, &[(word(0), word(8))]),
    ]);
    let getter = calldata("value()", &[]);
    // The same read as a legacy transaction and as EIP-2930 with the callee and slot 0
    // listed: listing costs 2 400 + 1 900, the warm read saves 2 100 - 100.
    let plain = alice.send(&Fee::Legacy(3 * GWEI), Some(STORE), 0, &getter, 100_000);
    let listed = bob.send(
        &Fee::AccessList(3 * GWEI, vec![(STORE, vec![word(0)])]),
        Some(STORE),
        0,
        &getter,
        100_000,
    );
    let receipts = chain.block(&[plain, listed]);
    assert_eq!(receipts[0].tx_type, 0);
    assert_eq!(receipts[1].tx_type, 1);
    assert_eq!(
        receipts[1].gas_used,
        receipts[0].gas_used + 2_400 + 1_900 - 2_000
    );
    for r in &receipts {
        assert_eq!((r.status, r.effective_gas_price), (1, 3 * GWEI));
    }
    let mut alice_fees = u128::from(receipts[0].gas_used) * 3 * GWEI;
    let mut bob_fees = u128::from(receipts[1].gas_used) * 3 * GWEI;
    // EIP-1559 with a zero base fee: the price paid is the priority fee, not the maximum.
    let dynamic = alice.send(
        &Fee::Dynamic(10 * GWEI, 2 * GWEI, vec![]),
        Some(STORE),
        ETHER,
        &[],
        100_000,
    );
    let capped = bob.send(
        &Fee::Dynamic(GWEI, 5 * GWEI, vec![(STORE, vec![])]),
        Some(STORE),
        0,
        &calldata("set(uint256)", &[word(9)]),
        100_000,
    );
    assert_eq!(
        chain.node.submit(&capped),
        Err(SubmitError::Rejected(reason::FEE_TOO_LOW)),
        "a priority fee above the maximum fee is malformed"
    );
    bob.nonce.set(bob.nonce.get() - 1);
    let set = bob.send(
        &Fee::Dynamic(4 * GWEI, 4 * GWEI, vec![(STORE, vec![word(0)])]),
        Some(STORE),
        0,
        &calldata("set(uint256)", &[word(9)]),
        100_000,
    );
    let receipts = chain.block(&[dynamic, set]);
    assert_eq!((receipts[0].status, receipts[0].tx_type), (1, 2));
    assert_eq!(receipts[0].effective_gas_price, 2 * GWEI);
    assert_eq!(receipts[1].effective_gas_price, 4 * GWEI);
    assert_eq!(chain.storage(STORE, word(0)), word(9));
    alice_fees += u128::from(receipts[0].gas_used) * 2 * GWEI;
    bob_fees += u128::from(receipts[1].gas_used) * 4 * GWEI;
    // Every wei is accounted for: senders pay gas used times the price paid, the store
    // holds the value, and the zero-address beneficiary collects every fee.
    assert_eq!(chain.balance(alice.address), start - ETHER - alice_fees);
    assert_eq!(chain.balance(bob.address), start - bob_fees);
    assert_eq!(chain.balance(STORE), ETHER);
    assert_eq!(chain.balance(BENEFICIARY), alice_fees + bob_fees);
    assert_eq!(
        chain.balance(alice.address)
            + chain.balance(bob.address)
            + chain.balance(STORE)
            + chain.balance(BENEFICIARY),
        2 * start,
        "no wei created or destroyed"
    );
}

#[test]
fn empty_accounts_are_not_kept() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let stranger = [0x99; 20];
    let mut chain = Chain::new(vec![
        funded(alice.address, 100 * ETHER),
        funded(bob.address, ETHER),
    ]);
    let account_key = |a: &[u8; 20]| [keys::ACCOUNT, &a[..]].concat();
    // Free transactions touch the beneficiary (a zero fee), a stranger (a zero-value
    // transfer) and the identity precompile; EIP-161 removes what they leave empty.
    let receipts = chain.block(&[
        alice.send(&Fee::Legacy(0), Some(stranger), 0, &[], 21_000),
        bob.send(&Fee::Legacy(0), Some(precompile(4)), 0, &[1, 2, 3], 30_000),
    ]);
    assert!(
        receipts
            .iter()
            .all(|r| r.status == 1 && r.effective_gas_price == 0)
    );
    assert_eq!(chain.node.state_get(&account_key(&stranger)), None);
    assert_eq!(chain.node.state_get(&account_key(&BENEFICIARY)), None);
    assert_eq!(chain.node.state_get(&account_key(&precompile(4))), None);
    assert_eq!(
        chain.balance(alice.address),
        100 * ETHER,
        "nothing was paid"
    );
    // One wei is enough to exist.
    chain.run(alice.send(&Fee::Legacy(0), Some(stranger), 1, &[], 21_000));
    assert!(chain.node.state_get(&account_key(&stranger)).is_some());
    assert_eq!(chain.balance(stranger), 1);
}

#[test]
#[allow(clippy::too_many_lines)]
fn block_opcodes_agree_with_headers() {
    let alice = Wallet::new(1);
    let mut chain = Chain::new(vec![
        funded(alice.address, 100 * ETHER),
        predeploy(PROBE, PROBE_RUNTIME, &[]),
    ]);
    chain.block(&[]);
    let r = chain.run(alice.send(
        &Fee::Legacy(GWEI),
        Some(PROBE),
        0,
        &calldata("record()", &[]),
        100_000,
    ));
    assert_eq!(r.status, 1);
    let header = chain.node.block_by_number(2).unwrap().unwrap();
    let block1 = chain.node.executed[0].1;
    let seen = &r.logs.0[0];
    assert_eq!(
        seen.topics.0,
        vec![topic(
            "Seen(uint256,uint256,bytes32,uint256,address,uint256,uint256,uint256)"
        )]
    );
    let fields: Vec<[u8; 32]> = seen
        .data
        .chunks(32)
        .map(|c| c.try_into().unwrap())
        .collect();
    assert_eq!(fields.len(), 8);
    assert_eq!(fields[0], word(2), "NUMBER is the block height");
    assert_eq!(
        fields[1],
        word(u128::from(header.timestamp_ms / 1000)),
        "TIMESTAMP is the header's, in seconds"
    );
    assert_eq!(fields[1], word(u128::from((START_MS + 2 * SLOT_MS) / 1000)));
    assert_eq!(
        fields[2], header.parent_hash,
        "BLOCKHASH of the parent is the header's parent hash"
    );
    assert_eq!(fields[2], block1);
    assert_eq!(fields[3], word(u128::from(CHAIN_ID)), "CHAINID");
    assert_eq!(
        fields[4],
        address_word(&BENEFICIARY),
        "COINBASE is the zero address"
    );
    assert_eq!(fields[5], word(0), "BASEFEE is zero");
    assert_eq!(fields[6], word(u128::from(BLOCK_GAS_LIMIT)), "GASLIMIT");
    assert_eq!(fields[7], word(0), "PREVRANDAO is zero");
    // A call query runs in the block after the latest, at the latest block's time.
    let now = chain.call(
        alice.address,
        Some(PROBE),
        0,
        &calldata("current()", &[]),
        100_000,
    );
    assert_eq!(now.status, call_status::SUCCESS);
    assert_eq!(
        now.output,
        [
            word(3),
            word(u128::from(header.timestamp_ms / 1000)),
            word(u128::from(CHAIN_ID))
        ]
        .concat()
    );
    let block2 = chain.node.executed[1].1;
    let hash_of = |chain: &mut Chain, n: u128| {
        chain
            .call(
                alice.address,
                Some(PROBE),
                0,
                &calldata("hashOf(uint256)", &[word(n)]),
                100_000,
            )
            .output
    };
    assert_eq!(hash_of(&mut chain, 2), block2);
    assert_eq!(hash_of(&mut chain, 1), block1);
    // The genesis block has no header, so its hash is zero, as block 1's parent hash
    // and the RPC's block 0 say; the block being built has none yet either.
    assert_eq!(hash_of(&mut chain, 0), [0; 32]);
    assert_eq!(hash_of(&mut chain, 3), [0; 32]);
}

/// Square-and-multiply on numbers below 2^64.
fn mod_pow(base: u64, mut exp: u64, modulus: u64) -> u64 {
    let m = u128::from(modulus);
    let mut b = u128::from(base) % m;
    let mut acc = 1u128;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc * b % m;
        }
        b = b * b % m;
        exp >>= 1;
    }
    u64::try_from(acc).unwrap()
}

fn precompile(n: u8) -> [u8; 20] {
    let mut a = [0u8; 20];
    a[19] = n;
    a
}

/// Where the relay of `relay_runtime` lives.
const RELAY: [u8; 20] = [0x54; 20];

/// Runtime code that passes its calldata to precompile `n` and logs, with no
/// topics, what came back: receipts carry no return data, logs do.
fn relay_runtime(n: u8) -> Vec<u8> {
    vec![
        0x36, 0x60, 0x00, 0x60, 0x00, 0x37, // CALLDATACOPY(0, 0, CALLDATASIZE)
        0x60, 0x20, 0x60, 0x00, 0x36, 0x60, 0x00, 0x60, n, 0x5A,
        0xFA, // STATICCALL(GAS, n, 0, CALLDATASIZE, 0, 32)
        0x50, // POP the success flag
        0x3D, 0x60, 0x00, 0xA0, // LOG0(0, RETURNDATASIZE)
        0x00, // STOP
    ]
}

#[test]
#[allow(clippy::too_many_lines)]
fn precompiles_match_host_side_vectors() {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut chain = Chain::new(vec![
        funded(alice.address, 100 * ETHER),
        funded(bob.address, 100 * ETHER),
        predeploy(PROBE, PROBE_RUNTIME, &[]),
        Allocation {
            address: RELAY,
            nonce: 1,
            code: relay_runtime(1),
            ..Allocation::default()
        },
    ]);
    let call = |chain: &mut Chain, to: [u8; 20], data: &[u8]| {
        chain.call(alice.address, Some(to), 0, data, 1_000_000)
    };
    // ecrecover (0x01): a k256 signature recovers its signer, in low-s and high-s form.
    let signer = Wallet::new(7);
    let digest = keccak256(b"solo ecrecover vector");
    let (sig, rid) = signer.key.sign_prehash_recoverable(&digest).unwrap();
    let r_bytes: [u8; 32] = sig.r().to_bytes().into();
    let s_bytes: [u8; 32] = sig.s().to_bytes().into();
    let high_s: [u8; 32] = (-*sig.s()).to_bytes().into();
    let v = 27 + u128::from(rid.to_byte());
    let input = [digest, word(v), r_bytes, s_bytes].concat();
    let out = call(&mut chain, precompile(1), &input);
    assert_eq!(
        (out.status, out.output.clone()),
        (call_status::SUCCESS, address_word(&signer.address).to_vec())
    );
    assert_eq!(out.gas_used, charged(&input, 3_000));
    let flipped = [digest, word(55 - v), r_bytes, high_s].concat();
    assert_eq!(
        call(&mut chain, precompile(1), &flipped).output,
        address_word(&signer.address),
        "(r, n - s) with the other parity is the same signature"
    );
    let bad_v = [digest, word(29), r_bytes, s_bytes].concat();
    let out = call(&mut chain, precompile(1), &bad_v);
    assert_eq!(
        (out.status, out.output.len()),
        (call_status::SUCCESS, 0),
        "a bad v returns nothing"
    );
    // The same through Solidity's `ecrecover`.
    let via = call(
        &mut chain,
        PROBE,
        &calldata(
            "recover(bytes32,uint8,bytes32,bytes32)",
            &[digest, word(v), r_bytes, s_bytes],
        ),
    );
    assert_eq!(via.output, address_word(&signer.address));
    // sha256 (0x02).
    let message: Vec<u8> = (0..100u8).collect();
    for data in [&b"abc"[..], &message[..]] {
        let out = call(&mut chain, precompile(2), data);
        assert_eq!(out.output, sha256(data));
        assert_eq!(
            out.gas_used,
            charged(data, 60 + 12 * (data.len() as u64).div_ceil(32))
        );
    }
    let mut padded = [0u8; 32];
    padded[..3].copy_from_slice(b"abc");
    let via = call(
        &mut chain,
        PROBE,
        &calldata("sha(bytes)", &[word(32), word(3), padded]),
    );
    assert_eq!(via.output, sha256(b"abc"));
    // identity (0x04).
    let out = call(&mut chain, precompile(4), &message);
    assert_eq!(out.output, message);
    assert_eq!(out.gas_used, charged(&message, 15 + 3 * 4));
    // modexp (0x05): lengths, then base, exponent, modulus; Osaka's minimum price is 500.
    let mut small = [word(1), word(1), word(1)].concat();
    small.extend_from_slice(&[3, 5, 7]);
    let out = call(&mut chain, precompile(5), &small);
    assert_eq!(out.output, vec![243 % 7]);
    assert_eq!(out.gas_used, charged(&small, 500));
    let (base, exp, modulus) = (
        0x0123_4567_89AB_CDEFu64,
        65_537u64,
        0xFFFF_FFFF_FFFF_FFC5u64,
    );
    let mut big = [word(8), word(3), word(8)].concat();
    big.extend_from_slice(&base.to_be_bytes());
    big.extend_from_slice(&exp.to_be_bytes()[5..]);
    big.extend_from_slice(&modulus.to_be_bytes());
    let out = call(&mut chain, precompile(5), &big);
    assert_eq!(out.output, mod_pow(base, exp, modulus).to_be_bytes());
    // P256VERIFY (0x100, Osaka): a p256 signature verifies; a different message does not.
    let p256_key = p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap();
    let hash = sha256(b"solo p256 vector");
    let p256_sig: p256::ecdsa::Signature = p256_key.sign_prehash(&hash).unwrap();
    let point = p256_key.verifying_key().to_encoded_point(false);
    let mut input = hash.to_vec();
    input.extend_from_slice(&p256_sig.r().to_bytes());
    input.extend_from_slice(&p256_sig.s().to_bytes());
    input.extend_from_slice(point.x().unwrap());
    input.extend_from_slice(point.y().unwrap());
    let mut p256_verify = [0u8; 20];
    p256_verify[18] = 1;
    let out = call(&mut chain, p256_verify, &input);
    assert_eq!(
        (out.status, out.output.clone()),
        (call_status::SUCCESS, word(1).to_vec())
    );
    assert_eq!(out.gas_used, charged(&input, 6_900));
    input[0] ^= 1;
    let out = call(&mut chain, p256_verify, &input);
    assert_eq!((out.status, out.output.len()), (call_status::SUCCESS, 0));
    // Precompiles in block execution: transactions straight to sha256 and ecrecover. A
    // receipt shows only status and gas, which are the same whether recovery succeeds
    // or not.
    let price = GWEI;
    let receipts = chain.block(&[
        alice.send(&Fee::Legacy(price), Some(precompile(2)), 0, b"abc", 100_000),
        bob.send(
            &Fee::Legacy(price),
            Some(precompile(1)),
            0,
            &flipped,
            100_000,
        ),
    ]);
    assert_eq!(receipts[0].status, 1);
    assert_eq!(receipts[0].gas_used, charged(b"abc", 72));
    assert_eq!(receipts[1].status, 1);
    assert_eq!(receipts[1].gas_used, charged(&flipped, 3_000));
    // What ecrecover returns in a block, through the relay's log: the signer for the
    // high-s form, nothing for a bad v.
    let receipts = chain.block(&[
        alice.send(&Fee::Legacy(price), Some(RELAY), 0, &flipped, 100_000),
        bob.send(&Fee::Legacy(price), Some(RELAY), 0, &bad_v, 100_000),
    ]);
    let logged = |data: Vec<u8>| {
        vec![Log {
            address: RELAY,
            topics: Seq(vec![]),
            data,
        }]
    };
    assert_eq!(
        receipts[0].logs.0,
        logged(address_word(&signer.address).to_vec())
    );
    assert_eq!(receipts[1].logs.0, logged(vec![]));
}

#[test]
#[allow(clippy::too_many_lines)]
fn call_query_leaves_state_untouched() {
    let alice = Wallet::new(1);
    let mut chain = Chain::new(vec![
        funded(alice.address, 100 * ETHER),
        predeploy(STORE, STORE_RUNTIME, &[(word(0), word(42))]),
    ]);
    chain.block(&[]);
    let before = chain.node.state_scan(b"");
    // A write, a payment and a creation, each run and thrown away.
    let set = chain.call(
        alice.address,
        Some(STORE),
        0,
        &calldata("set(uint256)", &[word(1)]),
        100_000,
    );
    assert_eq!(set.status, call_status::SUCCESS);
    assert!(set.gas_used > 21_000);
    let pay = chain.call(alice.address, Some(STORE), ETHER, &[], 100_000);
    assert_eq!(pay.status, call_status::SUCCESS);
    let create = chain.call(alice.address, None, 0, &store_init(5), 1_000_000);
    assert_eq!(create.status, call_status::SUCCESS);
    assert_eq!(
        create.output,
        hex(STORE_RUNTIME),
        "a creation returns the runtime code"
    );
    // The nonce is not checked, and a contract may be the caller (EIP-3607 is for transactions).
    let from_contract = chain.call(STORE, Some(STORE), 0, &calldata("value()", &[]), 100_000);
    assert_eq!(
        (from_contract.status, from_contract.output),
        (call_status::SUCCESS, word(42).to_vec())
    );
    // A caller that cannot pay the value is invalid; gas 0 means the per-transaction cap.
    let broke = chain.call([0x0B; 20], Some(STORE), 1, &[], 100_000);
    assert_eq!(broke.status, call_status::INVALID);
    let uncapped = chain.call(alice.address, Some(STORE), 0, &calldata("value()", &[]), 0);
    assert_eq!(uncapped.status, call_status::SUCCESS);
    assert_eq!(chain.node.state_scan(b""), before, "no kernel key changed");
    assert_eq!(chain.storage(STORE, word(0)), word(42));
    assert_eq!(
        chain.account(alice.address),
        Account {
            balance: 100 * ETHER,
            ..Account::default()
        }
    );
    assert_eq!(chain.node.block_number().unwrap(), 1);
}

/// Whether every node has a receipt for `hash`.
fn executed_everywhere(hash: [u8; 32]) -> impl FnMut(&mut Sim) -> bool {
    move |s| {
        s.nodes
            .iter_mut()
            .all(|n| n.receipt(&hash).unwrap().is_some())
    }
}

#[test]
fn contract_across_validators() {
    let keys: Vec<SigningKey> = (1..=4u8)
        .map(|i| SigningKey::from_slice(&[0x20 + i; 32]).unwrap())
        .collect();
    let alice = Wallet::new(1);
    let genesis = genesis(&keys, vec![funded(alice.address, 100 * ETHER)]);
    let config = NodeConfig {
        now_ms: START_MS,
        ..NodeConfig::default()
    };
    let mut sim = Sim::new(kernel_module(), &genesis, &keys, 0, &config, 20).unwrap();
    // Deploy through one validator, write through another once the deployment is in.
    let deploy = sim
        .submit(
            0,
            &alice.send(&Fee::Legacy(GWEI), None, 0, &store_init(5), 1_000_000),
        )
        .unwrap();
    assert!(
        sim.run_until(40 * SLOT_MS, executed_everywhere(deploy))
            .unwrap(),
        "deployment executed everywhere"
    );
    let store = create_address(&alice.address, 0);
    let set = alice.send(
        &Fee::Dynamic(2 * GWEI, GWEI, vec![]),
        Some(store),
        0,
        &calldata("set(uint256)", &[word(77)]),
        100_000,
    );
    let set = sim.submit(2, &set).unwrap();
    assert!(
        sim.run_until(40 * SLOT_MS, executed_everywhere(set))
            .unwrap(),
        "write executed everywhere"
    );
    let height = sim.nodes[0].receipt(&set).unwrap().unwrap().height;
    assert!(
        sim.run_until(40 * SLOT_MS, |s| s
            .finalized_heights()
            .unwrap()
            .iter()
            .all(|h| *h >= height))
            .unwrap(),
        "{:?}",
        sim.finalized_heights().unwrap()
    );
    // Every validator holds the same blocks (state roots included), receipts and
    // contract state.
    let reference: Vec<_> = (1..=height)
        .map(|h| sim.nodes[0].block_by_number(h).unwrap().unwrap())
        .collect();
    let receipt = sim.nodes[0].receipt(&set).unwrap();
    for node in &mut sim.nodes {
        for (h, header) in (1..=height).zip(&reference) {
            assert_eq!(node.block_by_number(h).unwrap().as_ref(), Some(header));
        }
        assert_eq!(node.receipt(&set).unwrap(), receipt);
        let slot = node
            .query(
                query::STORAGE,
                &StorageQuery {
                    address: store,
                    slot: word(0),
                }
                .to_bytes(),
            )
            .unwrap();
        assert_eq!(<[u8; 32]>::from_bytes(&slot.body).unwrap(), word(77));
    }
    assert_eq!(receipt.unwrap().logs.0[0].topics.0[2], word(5));
}

/// An EIP-7702 delegation designator: `0xef0100 ‖ address`.
fn delegation(to: &[u8; 20]) -> Vec<u8> {
    [&[0xEF, 0x01, 0x00][..], &to[..]].concat()
}

#[test]
fn malformed_delegation_code_runs_as_legacy() {
    // Code from genesis that starts with 0xEF01 but is no delegation designator runs as
    // legacy code, as geth runs it: 0xEF is an invalid opcode, so a call halts. It must not
    // trap the kernel, which would drop the whole block.
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let broken = [0x61; 20];
    let delegated = [0x62; 20];
    let mut chain = Chain::new(vec![
        funded(alice.address, 100 * ETHER),
        funded(bob.address, 100 * ETHER),
        predeploy(STORE, STORE_RUNTIME, &[(word(0), word(42))]),
        Allocation {
            address: broken,
            nonce: 1,
            code: vec![0xEF, 0x01, 0x00],
            ..Allocation::default()
        },
        Allocation {
            address: delegated,
            code: delegation(&STORE),
            storage: Seq(vec![StorageSlot {
                key: word(0),
                value: word(77),
            }]),
            ..Allocation::default()
        },
    ]);
    assert_eq!(chain.code(broken), vec![0xEF, 0x01, 0x00]);
    let out = chain.call(alice.address, Some(broken), 0, &[], 100_000);
    assert_eq!((out.status, out.gas_used), (call_status::HALT, 100_000));
    // In a block, the call halts and the transaction beside it runs.
    let receipts = chain.block(&[
        alice.send(&Fee::Legacy(GWEI), Some(broken), 0, &[], 100_000),
        bob.send(
            &Fee::Legacy(GWEI),
            Some(STORE),
            0,
            &calldata("set(uint256)", &[word(43)]),
            100_000,
        ),
    ]);
    assert_eq!((receipts[0].status, receipts[0].gas_used), (0, 100_000));
    assert_eq!(receipts[1].status, 1);
    assert_eq!(chain.storage(STORE, word(0)), word(43));
    chain.block(&[]);
    // A well-formed designator delegates: the delegate's code runs on the delegator's storage.
    let read = chain.call(
        alice.address,
        Some(delegated),
        0,
        &calldata("value()", &[]),
        100_000,
    );
    assert_eq!(
        (read.status, read.output),
        (call_status::SUCCESS, word(77).to_vec())
    );
}

#[test]
fn only_externally_owned_accounts_send() {
    // Genesis can give a key's address code, or a nonce no transaction may carry (EIP-2681).
    // Validation must refuse what execution would refuse, or the transaction could be
    // included again and again for free.
    let coder = Wallet::new(3);
    let broken = Wallet::new(4);
    let exhausted = Wallet::new(5);
    let delegator = Wallet::new(6);
    let bob = Wallet::new(2);
    let mut exhausted_account = funded(exhausted.address, ETHER);
    exhausted_account.nonce = u64::MAX;
    let with_code = |w: &Wallet, code: Vec<u8>| Allocation {
        address: w.address,
        balance: ETHER,
        code,
        ..Allocation::default()
    };
    let mut chain = Chain::new(vec![
        with_code(&coder, vec![0x00]),
        with_code(&broken, vec![0xEF, 0x01, 0x00]),
        exhausted_account,
        with_code(&delegator, delegation(&STORE)),
        predeploy(STORE, STORE_RUNTIME, &[]),
    ]);
    let transfer = |w: &Wallet, nonce: u64| {
        w.sign(nonce, &Fee::Legacy(GWEI), Some(bob.address), 1, &[], 21_000)
    };
    for raw in [transfer(&coder, 0), transfer(&broken, 0)] {
        assert_eq!(
            chain.node.submit(&raw),
            Err(SubmitError::Rejected(reason::SENDER_NOT_EOA))
        );
    }
    assert_eq!(
        chain.node.submit(&transfer(&exhausted, u64::MAX)),
        Err(SubmitError::Rejected(reason::BAD_NONCE))
    );
    // A delegation designator leaves its account able to send (EIP-7702).
    let r = chain.run(transfer(&delegator, 0));
    assert_eq!(r.status, 1);
    assert_eq!(chain.account(delegator.address).nonce, 1);
    assert_eq!(chain.balance(bob.address), 1);
}

#[test]
fn storage_needs_code_or_a_nonce_at_genesis() {
    // revm leaves out EIP-7610, so a CREATE could land on an account that has storage but
    // neither code nor nonce, and the old slots would show through the new contract. The
    // reference kernel refuses such an account at genesis.
    let alice = Wallet::new(1);
    let orphan = Allocation {
        address: [0x63; 20],
        storage: Seq(vec![StorageSlot {
            key: word(0),
            value: word(0x99),
        }]),
        ..Allocation::default()
    };
    let config = NodeConfig {
        now_ms: START_MS,
        key: Some(node_key()),
        ..NodeConfig::default()
    };
    let refused = Node::open(
        kernel_module(),
        &genesis(&[node_key()], vec![orphan.clone()]),
        config,
    );
    assert!(
        matches!(
            refused,
            Err(NodeError::Kernel {
                export: "kernel_init",
                ..
            })
        ),
        "{:?}",
        refused.err()
    );
    // A zero value is no storage at all.
    let mut zero = orphan.clone();
    zero.storage.0[0].value = [0; 32];
    // With a nonce, CREATE2 onto the account collides, and a zero-value call keeps it.
    let salt = [0x5C; 32];
    let target = create2_address(&FACTORY, &salt, &store_init(0));
    let mut aged = orphan;
    aged.address = target;
    aged.nonce = 1;
    let mut chain = Chain::new(vec![
        funded(alice.address, 100 * ETHER),
        predeploy(FACTORY, FACTORY_RUNTIME, &[]),
        zero,
        aged,
    ]);
    assert!(
        chain
            .node
            .state_scan(&[keys::SLOT, &[0x63; 20][..]].concat())
            .is_empty()
    );
    let r = chain.run(alice.send(
        &Fee::Legacy(GWEI),
        Some(FACTORY),
        0,
        &calldata("make2(bytes32,uint256)", &[salt, word(0)]),
        1_000_000,
    ));
    assert_eq!(r.status, 0, "the CREATE2 collides");
    assert!(chain.code(target).is_empty());
    let r = chain.run(alice.send(&Fee::Legacy(GWEI), Some(target), 0, &[], 21_000));
    assert_eq!(r.status, 1);
    assert_eq!(chain.account(target).nonce, 1);
    assert_eq!(chain.storage(target, word(0)), word(0x99));
}

/// Executes a block of `txs` at `height` directly, as a driver's
/// `ExecuteBlock` would, and returns the stored header and the summary.
fn execute_directly(
    chain: &mut Chain,
    height: u64,
    txs: &[&Vec<u8>],
) -> (BlockHeader, ExecuteSummary) {
    let header = BlockHeader {
        height,
        timestamp_ms: chain.now_ms + height,
        ..BlockHeader::default()
    };
    let block = Block {
        header: header.to_bytes(),
        txs: Seq(txs.iter().map(|raw| (*raw).clone()).collect()),
        participation: vec![],
    };
    let Some(Input::BlockExecuted { result, .. }) = chain
        .node
        .apply_effect(Effect::ExecuteBlock { block })
        .unwrap()
    else {
        panic!("executing a block reports it executed")
    };
    (chain.node.block_by_number(height).unwrap().unwrap(), result)
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_block_repeating_a_transaction_leaves_its_receipt_alone() {
    // The driver keeps out what has run or what an unexecuted ancestor carries, but a
    // faulty leader can still repeat a transaction. A transaction has one receipt, in the
    // block that lists it; a repeat that cannot run is left out of the block.
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut chain = Chain::new(vec![
        funded(alice.address, 100 * ETHER),
        funded(bob.address, 100 * ETHER),
    ]);
    let hash = |raw: &Vec<u8>| keccak256(raw);
    let receipt = |chain: &mut Chain, raw: &Vec<u8>| chain.node.receipt(&keccak256(raw)).unwrap();
    let first = alice.send(&Fee::Legacy(GWEI), Some(bob.address), ETHER, &[], 21_000);
    let original = chain.run(first.clone());
    // A creation that halts on an invalid opcode spends its whole limit, after which a
    // transaction with the same limit no longer fits the block and cannot run there.
    let big = 16_000_000;
    let a = alice.send(&Fee::Legacy(GWEI), None, 0, &[0xFE], big);
    let b = bob.send(&Fee::Legacy(GWEI), Some(alice.address), 1, &[], big);
    let (header, summary) = execute_directly(&mut chain, 2, &[&first, &a, &b, &first]);
    assert_eq!(header.tx_hashes.0, vec![hash(&a), hash(&b)]);
    assert_eq!(summary.tx_count, 2);
    assert_eq!(receipt(&mut chain, &first), Some(original));
    let ra = receipt(&mut chain, &a).unwrap();
    assert_eq!(
        (ra.status, ra.gas_used, ra.height, ra.index),
        (0, big, 2, 0)
    );
    assert_eq!(header.gas_used, big);
    let rb = receipt(&mut chain, &b).unwrap();
    assert_eq!(
        (rb.status, rb.gas_used, rb.height, rb.index),
        (0, 0, 2, 1),
        "could not run"
    );
    assert_eq!(chain.account(alice.address).nonce, 2);
    assert_eq!(chain.account(bob.address).nonce, 0);
    // `b` still validates. A block where it cannot run again leaves it out and its failed
    // receipt alone, and the node drops it from the mempool all the same.
    chain.node.submit(&b).unwrap();
    let a2 = alice.send(&Fee::Legacy(GWEI), None, 0, &[0xFE], big);
    let (header, _) = execute_directly(&mut chain, 3, &[&a2, &b]);
    assert_eq!(header.tx_hashes.0, vec![hash(&a2)]);
    assert_eq!(receipt(&mut chain, &b), Some(rb));
    assert!(chain.node.mempool().is_empty());
    // Once it can run, it runs and its receipt moves to the block that ran it; a repeat
    // in that same block is left out.
    let (header, summary) = execute_directly(&mut chain, 4, &[&b, &b]);
    assert_eq!(header.tx_hashes.0, vec![hash(&b)]);
    assert_eq!(summary.tx_count, 1);
    let rb = receipt(&mut chain, &b).unwrap();
    assert_eq!(
        (rb.status, rb.gas_used, rb.height, rb.index, rb.from),
        (1, 21_000, 4, 0, bob.address)
    );
    assert_eq!(chain.account(bob.address).nonce, 1);
    // A transaction that could not run and still cannot keeps its first failed receipt.
    let early = alice.sign(9, &Fee::Legacy(GWEI), Some(bob.address), 1, &[], 21_000);
    let (header, _) = execute_directly(&mut chain, 5, &[&early]);
    assert_eq!(header.tx_hashes.0, vec![hash(&early)]);
    let failed = receipt(&mut chain, &early).unwrap();
    assert_eq!((failed.status, failed.height), (0, 5));
    let (header, summary) = execute_directly(&mut chain, 6, &[&early]);
    assert!(header.tx_hashes.0.is_empty());
    assert_eq!((summary.tx_count, summary.gas_used), (0, 0));
    assert_eq!(receipt(&mut chain, &early), Some(failed));
}

/// Hashes of the transactions the finalized proposals of `node` carry, one
/// entry per inclusion, read from what its driver persisted.
fn finalized_inclusions(node: &Node, height: u64) -> Vec<[u8; 32]> {
    let persisted = node.persisted();
    let mut out = Vec::new();
    for h in 1..=height {
        let hash = &persisted[&[&b"final/"[..], &h.to_le_bytes()].concat()];
        let proposal =
            Proposal::from_bytes(&persisted[&[&b"prop/"[..], &hash[..]].concat()]).unwrap();
        out.extend(proposal.txs.0.iter().map(|raw| keccak256(raw)));
    }
    out
}

#[test]
fn high_latency_includes_a_transaction_once() {
    // With one-way latency above a third of a slot, the next leader proposes before it has
    // executed the block it extends. It must not carry that block's transactions again.
    let keys: Vec<SigningKey> = (1..=4u8)
        .map(|i| SigningKey::from_slice(&[0x30 + i; 32]).unwrap())
        .collect();
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let genesis = genesis(&keys, vec![funded(alice.address, 100 * ETHER)]);
    let config = NodeConfig {
        now_ms: START_MS,
        ..NodeConfig::default()
    };
    let mut sim = Sim::new(kernel_module(), &genesis, &keys, 0, &config, 150).unwrap();
    sim.advance(10 * SLOT_MS).unwrap();
    let tx = sim
        .submit(
            0,
            &alice.send(&Fee::Legacy(GWEI), Some(bob.address), ETHER, &[], 21_000),
        )
        .unwrap();
    assert!(
        sim.run_until(40 * SLOT_MS, executed_everywhere(tx))
            .unwrap(),
        "executed everywhere"
    );
    sim.advance(10 * SLOT_MS).unwrap();
    for node in &mut sim.nodes {
        let receipt = node.receipt(&tx).unwrap().unwrap();
        assert_eq!(
            (receipt.status, receipt.from, receipt.gas_used),
            (1, alice.address, 21_000)
        );
        let height = node.finalized_height().unwrap();
        assert!(height > receipt.height + 2, "{height}");
        let listing: Vec<u64> = (1..=height)
            .filter(|h| {
                node.block_by_number(*h)
                    .unwrap()
                    .unwrap()
                    .tx_hashes
                    .0
                    .contains(&tx)
            })
            .collect();
        assert_eq!(listing, vec![receipt.height]);
        let inclusions = finalized_inclusions(node, height);
        assert_eq!(inclusions.iter().filter(|h| **h == tx).count(), 1);
        assert_eq!(node.account(&bob.address).unwrap().balance, ETHER);
    }
}
