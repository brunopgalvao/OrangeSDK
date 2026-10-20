//! Kernel modules and native contracts end to end (spec 16): a genesis
//! module installed and initialized by the kernel, its block hooks, the
//! capability rules, storage namespaces, a Solidity contract calling the
//! module as a native contract (return data, reverts, value, static and
//! delegate calls, gas), write keys that must fit behind the namespace,
//! failing hooks, a governance install, and validators agreeing on the
//! state module calls leave.
//!
//! The module is `guest/modules/counter` (fixture `counter.elf`, built by
//! `tools/build-guest.sh`); the Solidity caller is `fixtures/modules/Caller.sol`.

mod support;

use std::sync::OnceLock;

use solo_abi::chain::{Allocation, CallRequest, GenesisParams, StorageSlot, call_status, reason};
use solo_abi::codec::Seq;
use solo_abi::modules::{
    self, CallContext, INSTALLED_TOPIC, Install, MODULE_ADDRESS, ModuleCall, ModuleQuery,
    ModuleRecord, capability,
};
use solo_abi::types::{Genesis, ModuleInstall};
use solo_abi::{Decode, Encode};
use solo_host::code::code_key;
use solo_host::hash::keccak256;
use solo_host::{Executor, Flags, MemStorage, ModuleCache};
use solo_node::{Node, NodeConfig, NodeError, Sim, SubmitError};
use solo_upgrade::Action;
use solo_vm::builder::ModuleBuilder;
use solo_vm::host::Capability;
use solo_vm::isa::{Instruction, Reg};
use support::{
    CHAIN_ID, ETHER, SLOT_MS, STAGE_GAS, Wallet, alice, governance, governed, include, keys,
    run_until, stage_actions, v1,
};

const COUNTER_ELF: &[u8] = include_bytes!("fixtures/counter.elf");
const CALLER_RUNTIME: &str = include_str!("fixtures/modules/Caller.runtime");

/// The genesis module, installed with hooks and a starting count of 5.
const COUNTER: [u8; 20] = [0x42; 20];
/// The same module by designator only: its own namespace, no `init`.
const TWIN: [u8; 20] = [0x43; 20];
/// The same module installed privileged: full keys.
const PRIVILEGED: [u8; 20] = [0x44; 20];
/// The Solidity caller, with `COUNTER` in slot 0.
const CALLER: [u8; 20] = [0x45; 20];
/// The privileged-import module, reached by designator from the EVM.
const BLOCKED: [u8; 20] = [0x46; 20];

const GAS: u64 = 1_000_000;

fn counter() -> &'static [u8] {
    static MODULE: OnceLock<Vec<u8>> = OnceLock::new();
    MODULE.get_or_init(|| {
        solo_recompile::recompile(
            &solo_recompile::Input::load(COUNTER_ELF).unwrap(),
            &solo_recompile::Options::default(),
        )
        .unwrap()
    })
}

fn counter_hash() -> [u8; 32] {
    keccak256(counter())
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

fn calldata(signature: &str, args: &[[u8; 32]]) -> Vec<u8> {
    let mut data = keccak256(signature.as_bytes())[..4].to_vec();
    for arg in args {
        data.extend_from_slice(arg);
    }
    data
}

/// Calldata of `put(bytes,bytes)`.
fn put(key: &[u8], value: &[u8]) -> Vec<u8> {
    let padded = |b: &[u8]| {
        let mut v = word(b.len() as u128).to_vec();
        v.extend_from_slice(b);
        v.resize(32 + b.len().div_ceil(32) * 32, 0);
        v
    };
    let key = padded(key);
    let mut data = calldata(
        "put(bytes,bytes)",
        &[word(64), word(64 + key.len() as u128)],
    );
    data.extend(key);
    data.extend(padded(value));
    data
}

fn failed(code: u128) -> Vec<u8> {
    calldata("Failed(uint256)", &[word(code)])
}

/// A module whose `main` returns an empty success and that imports
/// `storage_commit`, which only the `Privileged` set may.
fn privileged_import() -> Vec<u8> {
    let mut b = ModuleBuilder::new().rodata(&[0, 0, 0]);
    b.import("output_write");
    b.import("storage_commit");
    let base = i64::from(b.layout.ro_base);
    b.block(&[
        Instruction::Li {
            rd: Reg::A0,
            imm: base,
        },
        Instruction::Li {
            rd: Reg::A1,
            imm: 3,
        },
        Instruction::Ecall { import: 0 },
        Instruction::Halt,
    ]);
    b.export("main", 0).build()
}

fn install(
    address: [u8; 20],
    code_hash: [u8; 32],
    capabilities: u64,
    init: &[u8],
) -> ModuleInstall {
    ModuleInstall {
        address,
        code_hash,
        capabilities,
        init: init.to_vec(),
    }
}

fn code_account(address: [u8; 20], code: &[u8]) -> Allocation {
    Allocation {
        address,
        code: code.to_vec(),
        ..Allocation::default()
    }
}

/// The test chain's allocations and genesis modules, before any change.
fn layout() -> (Vec<Allocation>, Vec<ModuleInstall>) {
    let allocations = vec![
        Allocation {
            address: alice().address,
            balance: 100 * ETHER,
            ..Allocation::default()
        },
        code_account(COUNTER, counter()),
        code_account(TWIN, &modules::designator(&counter_hash())),
        code_account(PRIVILEGED, counter()),
        Allocation {
            address: CALLER,
            code: hex(CALLER_RUNTIME),
            storage: Seq(vec![StorageSlot {
                key: [0; 32],
                value: address_word(&COUNTER),
            }]),
            ..Allocation::default()
        },
        code_account(BLOCKED, &privileged_import()),
    ];
    let installs = vec![
        install(
            COUNTER,
            counter_hash(),
            capability::HOOKS,
            &5u64.to_le_bytes(),
        ),
        install(
            PRIVILEGED,
            counter_hash(),
            capability::PRIVILEGED,
            &7u64.to_le_bytes(),
        ),
        install(
            BLOCKED,
            keccak256(&privileged_import()),
            capability::PRIVILEGED,
            b"",
        ),
    ];
    (allocations, installs)
}

fn genesis_of(
    validators: usize,
    allocations: Vec<Allocation>,
    installs: Vec<ModuleInstall>,
) -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 16,
        allocations: Seq(allocations),
        upgrades: governed(1, 0),
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(installs),
        params: params.to_bytes(),
        validators: Sim::validator_set(&keys(u8::try_from(validators).unwrap())).to_bytes(),
    }
}

fn genesis() -> Genesis {
    let (allocations, installs) = layout();
    genesis_of(1, allocations, installs)
}

fn open(genesis: &Genesis) -> Result<Node, NodeError> {
    let config = NodeConfig {
        now_ms: 1_000,
        key: Some(keys(1)[0].clone()),
        ..NodeConfig::default()
    };
    let mut node = Node::open(v1(), genesis, config)?;
    node.start(None)?;
    Ok(node)
}

fn start() -> Node {
    open(&genesis()).unwrap()
}

/// `eth_call` from Alice.
fn call(node: &mut Node, to: [u8; 20], value: u128, data: &[u8]) -> solo_abi::chain::CallResult {
    node.call(&CallRequest {
        from: alice().address,
        to: Some(to),
        value,
        data: data.to_vec(),
        gas: GAS,
        ..CallRequest::default()
    })
    .unwrap()
}

fn view(node: &mut Node, to: [u8; 20], signature: &str) -> u128 {
    let r = call(node, to, 0, &calldata(signature, &[]));
    assert_eq!(r.status, call_status::SUCCESS, "{signature}: {r:?}");
    u128::from_be_bytes(r.output[16..32].try_into().unwrap())
}

fn module_query(node: &mut Node, address: [u8; 20], data: &[u8]) -> solo_abi::types::QueryResult {
    let q = ModuleQuery {
        address,
        data: data.to_vec(),
    };
    node.query(modules::query::MODULE_QUERY, &q.to_bytes())
        .unwrap()
}

/// Alice's transactions, numbered from her next nonce.
struct Sender {
    wallet: Wallet,
    nonce: u64,
}

impl Sender {
    fn alice() -> Sender {
        Sender {
            wallet: alice(),
            nonce: 0,
        }
    }

    fn tx(&mut self, to: [u8; 20], value: u128, gas: u64, data: &[u8]) -> Vec<u8> {
        let raw = self.wallet.tx(self.nonce, to, value, gas, data);
        self.nonce += 1;
        raw
    }

    fn send(
        &mut self,
        node: &mut Node,
        to: [u8; 20],
        value: u128,
        data: &[u8],
    ) -> solo_abi::chain::Receipt {
        let raw = self.tx(to, value, GAS, data);
        include(node, &raw)
    }
}

#[test]
fn genesis_modules_are_installed_initialized_and_hooked() {
    let mut node = start();
    let record = node
        .query(modules::query::MODULE, &COUNTER.to_bytes())
        .unwrap();
    assert_eq!(record.status, 0);
    assert_eq!(
        ModuleRecord::from_bytes(&record.body).unwrap(),
        ModuleRecord {
            code_hash: counter_hash(),
            capabilities: capability::HOOKS,
            installed_at: 0,
        }
    );
    assert_eq!(
        node.query(modules::query::MODULE, &TWIN.to_bytes())
            .unwrap()
            .status,
        1,
        "a designator alone installs nothing"
    );
    assert_eq!(
        node.query(modules::query::MODULE, b"short").unwrap().status,
        2
    );
    assert_eq!(
        node.code(&COUNTER).unwrap(),
        modules::designator(&counter_hash())
    );
    // The module bytes stay in state under their hash, where the host finds them.
    assert_eq!(
        node.state_get(&code_key(&counter_hash())).unwrap(),
        counter()
    );
    // `init` wrote the starting count into the module's namespace.
    let ns = modules::namespace(&COUNTER);
    let key = |k: &[u8]| [&ns[..], k].concat();
    assert_eq!(
        node.state_get(&key(b"count")),
        Some(5u64.to_le_bytes().to_vec())
    );
    assert_eq!(view(&mut node, COUNTER, "count()"), 5);
    assert_eq!(view(&mut node, COUNTER, "initial()"), 5);

    // Block hooks: begin_block counts blocks, end_block records the height.
    run_until(&mut node, 20, &mut |n| n.block_number().unwrap() >= 3);
    let height = u128::from(node.block_number().unwrap());
    assert_eq!(view(&mut node, COUNTER, "blocks()"), height);
    assert_eq!(view(&mut node, COUNTER, "lastHeight()"), height);
    // The privileged install has no hooks, and writes full keys.
    assert_eq!(view(&mut node, PRIVILEGED, "blocks()"), 0);
    assert_eq!(node.state_get(b"count"), Some(7u64.to_le_bytes().to_vec()));
    assert_eq!(
        node.state_get(&[&modules::namespace(&PRIVILEGED)[..], b"count"].concat()),
        None
    );
}

#[test]
fn module_queries_reach_the_module() {
    let mut node = start();
    let count = module_query(&mut node, COUNTER, &calldata("count()", &[]));
    assert_eq!((count.status, count.body), (0, word(5).to_vec()));
    // A query has no caller and no value.
    let who = module_query(&mut node, COUNTER, &calldata("whoami()", &[]));
    assert_eq!(who.body, word(0).to_vec());
    let paid = module_query(&mut node, COUNTER, &calldata("paid()", &[]));
    assert_eq!(paid.body, word(0).to_vec());
    let reverted = module_query(&mut node, COUNTER, &calldata("fail(uint256)", &[word(3)]));
    assert_eq!((reverted.status, reverted.body), (4, failed(3)));
    let spun = module_query(&mut node, COUNTER, &calldata("spin()", &[]));
    assert_eq!(spun.status, 5);
    assert_eq!(module_query(&mut node, CALLER, b"").status, 1, "EVM code");
    assert_eq!(
        node.query(modules::query::MODULE_QUERY, b"")
            .unwrap()
            .status,
        2
    );
}

#[test]
fn bad_genesis_modules_stop_the_chain() {
    let refused = |change: &dyn Fn(&mut Vec<Allocation>, &mut Vec<ModuleInstall>)| {
        let (mut allocations, mut installs) = layout();
        change(&mut allocations, &mut installs);
        let err = open(&genesis_of(1, allocations, installs)).err();
        assert!(
            matches!(
                err,
                Some(NodeError::Kernel {
                    export: "kernel_init",
                    ..
                })
            ),
            "{err:?}"
        );
    };
    // A sandboxed module cannot import a privileged function: it never loads, so `init` fails.
    refused(&|_, installs| installs[2].capabilities = capability::HOOKS);
    // Capability bits this kernel does not define.
    refused(&|_, installs| installs[0].capabilities = 4);
    // The code hash must be the code of the allocation at the module's address.
    refused(&|_, installs| installs[0].code_hash = [9; 32]);
    // No modules in the system range.
    refused(&|allocations, installs| {
        let mut system = [0u8; 20];
        system[19] = 0x77;
        allocations.push(code_account(system, counter()));
        installs.push(install(system, counter_hash(), 0, b""));
    });
    // Two installs at one address: the second finds the designator, not the module.
    refused(&|_, installs| installs.push(installs[0].clone()));
    // A native contract's EVM storage must start empty: its slot 0 tracks
    // its writes within a transaction.
    let slot = || {
        Seq(vec![StorageSlot {
            key: [0; 32],
            value: word(1),
        }])
    };
    refused(&|allocations, _| allocations[1].storage = slot());
    refused(&|allocations, _| allocations[2].storage = slot());
    // A module too large for one storage value never reaches state.
    refused(&|allocations, installs| {
        let mut big = counter().to_vec();
        big.resize(modules::MAX_MODULE_SIZE + 1, 0);
        allocations[1].code.clone_from(&big);
        installs[0].code_hash = keccak256(&big);
    });
}

#[test]
fn sandboxed_calls_cannot_reach_privileged_functions() {
    let mut node = start();
    // From the EVM a module always runs sandboxed: a module that imports a
    // privileged function does not load, and the call halts with all its gas.
    let r = call(&mut node, BLOCKED, 0, b"");
    assert_eq!(r.status, call_status::HALT);
    assert_eq!(r.gas_used, GAS);
    let q = module_query(&mut node, BLOCKED, b"");
    assert_eq!(q.status, 5);
}

#[test]
fn namespaces_isolate_storage() {
    let mut node = start();
    let mut alice = Sender::alice();
    assert_eq!(
        view(&mut node, TWIN, "count()"),
        0,
        "no init, empty namespace"
    );
    let r = alice.send(&mut node, TWIN, 0, &calldata("add(uint256)", &[word(11)]));
    assert_eq!(r.status, 1);
    assert_eq!(view(&mut node, TWIN, "count()"), 11);
    assert_eq!(view(&mut node, COUNTER, "count()"), 5);
    assert_eq!(
        view(&mut node, PRIVILEGED, "count()"),
        0,
        "its keys are not namespaced"
    );
    let twin = modules::namespace(&TWIN);
    assert_eq!(
        node.state_get(&[&twin[..], b"count"].concat()),
        Some(11u64.to_le_bytes().to_vec())
    );
    // A native contract has no EVM storage, not even the slot that tracks its writes.
    assert_eq!(node.storage(&TWIN, &[0; 32]).unwrap(), [0; 32]);
}

#[test]
fn solidity_calls_a_native_contract() {
    let mut node = start();
    let mut alice = Sender::alice();
    let r = call(
        &mut node,
        CALLER,
        0,
        &calldata("addAndStore(uint256)", &[word(3)]),
    );
    assert_eq!(
        (r.status, r.output),
        (call_status::SUCCESS, word(8).to_vec())
    );
    assert_eq!(
        view(&mut node, COUNTER, "count()"),
        5,
        "eth_call keeps nothing"
    );
    let receipt = alice.send(
        &mut node,
        CALLER,
        0,
        &calldata("addAndStore(uint256)", &[word(3)]),
    );
    assert_eq!(receipt.status, 1);
    assert_eq!(view(&mut node, COUNTER, "count()"), 8);
    assert_eq!(view(&mut node, CALLER, "last()"), 8);
    // msg.sender inside the module is the calling contract.
    let r = call(&mut node, CALLER, 0, &calldata("sender()", &[]));
    assert_eq!(r.output, address_word(&CALLER).to_vec());
    // The designator is the code the EVM sees.
    let r = call(&mut node, CALLER, 0, &calldata("codeOf()", &[]));
    let designator = modules::designator(&counter_hash());
    assert_eq!(&r.output[..32], &word(34));
    assert_eq!(&r.output[32..], &keccak256(&designator));
    // Two calls in one transaction: the second sees the first's write.
    let r = call(
        &mut node,
        CALLER,
        0,
        &calldata("addTwice(uint256,uint256)", &[word(1), word(2)]),
    );
    assert_eq!(r.output, word(11).to_vec());
    let receipt = alice.send(
        &mut node,
        CALLER,
        0,
        &calldata("addTwice(uint256,uint256)", &[word(1), word(2)]),
    );
    assert_eq!(receipt.status, 1);
    assert_eq!(view(&mut node, COUNTER, "count()"), 11);
    // Hashing goes to the host.
    let mut data = calldata("hashOf(bytes)", &[word(32), word(3)]);
    data.extend_from_slice(b"abc");
    data.resize(data.len() + 29, 0);
    let r = call(&mut node, COUNTER, 0, &data);
    assert_eq!(r.output, keccak256(b"abc").to_vec());
    // Calldata the module does not understand reverts with no data.
    let r = call(&mut node, COUNTER, 0, &[1, 2]);
    assert_eq!((r.status, r.output), (call_status::REVERT, vec![]));
}

#[test]
fn reverts_propagate_and_undo_native_writes() {
    let mut node = start();
    let mut alice = Sender::alice();
    // The module's revert data reaches the caller, which can catch it ...
    let r = call(
        &mut node,
        CALLER,
        0,
        &calldata("tryFail(uint256)", &[word(7)]),
    );
    assert_eq!(r.status, call_status::SUCCESS);
    let mut expected = word(32).to_vec();
    expected.extend_from_slice(&word(36));
    let mut tail = failed(7);
    tail.resize(64, 0);
    expected.extend_from_slice(&tail);
    assert_eq!(r.output, expected);
    // ... or let it propagate.
    let r = call(
        &mut node,
        CALLER,
        0,
        &calldata("failThrough(uint256)", &[word(7)]),
    );
    assert_eq!((r.status, r.output), (call_status::REVERT, failed(7)));
    let receipt = alice.send(
        &mut node,
        CALLER,
        0,
        &calldata("failThrough(uint256)", &[word(7)]),
    );
    assert_eq!(receipt.status, 0);
    // A revert of the frame that called the module undoes the module's write.
    let receipt = alice.send(
        &mut node,
        CALLER,
        0,
        &calldata("addThenRevert(uint256)", &[word(4)]),
    );
    assert_eq!(receipt.status, 0);
    assert_eq!(view(&mut node, COUNTER, "count()"), 5);
    // Even when the transaction succeeds around it.
    let r = call(
        &mut node,
        CALLER,
        0,
        &calldata("addInRevertedFrame(uint256)", &[word(4)]),
    );
    assert_eq!(r.output, word(5).to_vec());
    let receipt = alice.send(
        &mut node,
        CALLER,
        0,
        &calldata("addInRevertedFrame(uint256)", &[word(4)]),
    );
    assert_eq!(receipt.status, 1);
    assert_eq!(view(&mut node, COUNTER, "count()"), 5);
    // A direct transaction that reverts.
    let receipt = alice.send(
        &mut node,
        COUNTER,
        0,
        &calldata("fail(uint256)", &[word(1)]),
    );
    assert_eq!(receipt.status, 0);
    // An overflowing add reverts in the module and writes nothing.
    let receipt = alice.send(
        &mut node,
        COUNTER,
        0,
        &calldata("add(uint256)", &[word(u128::from(u64::MAX))]),
    );
    assert_eq!(receipt.status, 0);
    assert_eq!(view(&mut node, COUNTER, "count()"), 5);
}

#[test]
fn static_delegate_and_value_calls() {
    let mut node = start();
    let mut alice = Sender::alice();
    // A static call may read but not write.
    let r = call(
        &mut node,
        CALLER,
        0,
        &calldata("staticAdd(uint256)", &[word(1)]),
    );
    assert_eq!(r.output, word(0).to_vec());
    let r = call(&mut node, CALLER, 0, &calldata("staticCount()", &[]));
    assert_eq!(r.output, [word(1), word(5)].concat());
    // A module runs only as its own account.
    let r = call(&mut node, CALLER, 0, &calldata("delegateCount()", &[]));
    assert_eq!(r.output, word(0).to_vec());
    // Value moves with the call and the module sees it.
    let receipt = alice.send(&mut node, CALLER, ETHER, &calldata("pay()", &[]));
    assert_eq!(receipt.status, 1);
    assert_eq!(node.account(&COUNTER).unwrap().balance, ETHER);
    let r = call(&mut node, COUNTER, 3, &calldata("paid()", &[]));
    assert_eq!(r.output, word(3).to_vec());
    // A reverted call keeps the value where it was.
    let receipt = alice.send(
        &mut node,
        COUNTER,
        ETHER,
        &calldata("fail(uint256)", &[word(1)]),
    );
    assert_eq!(receipt.status, 0);
    assert_eq!(node.account(&COUNTER).unwrap().balance, ETHER);
    // The account keeps its designator and its writes after taking value.
    assert_eq!(node.code(&COUNTER).unwrap().len(), modules::DESIGNATOR_LEN);
    // An EIP-7702 delegation to a native contract does not run the module.
    let delegated = [0x47; 20];
    let (mut allocations, installs) = layout();
    let mut designation = vec![0xEF, 0x01, 0x00];
    designation.extend_from_slice(&COUNTER);
    allocations.push(code_account(delegated, &designation));
    let mut other = open(&genesis_of(1, allocations, installs)).unwrap();
    let r = call(&mut other, delegated, 0, &calldata("count()", &[]));
    assert_eq!(r.status, call_status::HALT);
}

#[test]
fn write_keys_fit_behind_the_namespace() {
    let mut node = start();
    let mut alice = Sender::alice();
    let ns = modules::namespace(&TWIN);
    // A sandboxed module's key is stored behind its 32-byte namespace, so
    // 32 bytes is the longest key it can write.
    let r = alice.send(&mut node, TWIN, 0, &put(&[7; 32], b"v"));
    assert_eq!(r.status, 1);
    assert_eq!(
        node.state_get(&[&ns[..], &[7; 32]].concat()),
        Some(b"v".to_vec())
    );
    // A longer key makes the output not count: the call halts with all
    // its gas, and nothing it wrote is kept.
    for len in [33, 64] {
        let mut data = put(&vec![8; len], b"v");
        let r = alice.send(&mut node, TWIN, 0, &data);
        assert_eq!((r.status, r.gas_used), (0, GAS), "key of {len} bytes");
        data = put(&vec![8; len], b"v");
        let r = call(&mut node, TWIN, 0, &data);
        assert_eq!(r.status, call_status::HALT);
    }
    let r = call(&mut node, TWIN, 0, &put(b"short", b"v"));
    assert_eq!(r.status, call_status::SUCCESS);
}

#[test]
fn failing_hooks_change_nothing_and_blocks_go_on() {
    let mut node = start();
    let mut alice = Sender::alice();
    let set_hooks = |node: &mut Node, alice: &mut Sender, mode: u128| {
        let r = alice.send(
            node,
            COUNTER,
            0,
            &calldata("setHooks(uint256)", &[word(mode)]),
        );
        assert_eq!(r.status, 1);
        r.height
    };
    let counts = |node: &mut Node| {
        (
            view(node, COUNTER, "blocks()"),
            view(node, COUNTER, "lastHeight()"),
        )
    };
    // Hooks that revert after writing: the block that turned them on counted
    // itself before the transaction, and its end_block already failed.
    let on = u128::from(set_hooks(&mut node, &mut alice, 1));
    let frozen = (on, on - 1);
    assert_eq!(counts(&mut node), frozen);
    let mut height = node.block_number().unwrap();
    run_until(&mut node, 20, &mut |n| {
        n.block_number().unwrap() >= height + 3
    });
    assert_eq!(counts(&mut node), frozen);
    // Hooks that never finish: still nothing, and blocks go on, with
    // transactions in them.
    set_hooks(&mut node, &mut alice, 2);
    height = node.block_number().unwrap();
    run_until(&mut node, 20, &mut |n| {
        n.block_number().unwrap() >= height + 2
    });
    assert_eq!(counts(&mut node), frozen);
    let r = alice.send(&mut node, COUNTER, 0, &calldata("add(uint256)", &[word(1)]));
    assert_eq!(r.status, 1);
    assert_eq!(view(&mut node, COUNTER, "count()"), 6);
    // Back to hooks that return: end_block of that block runs again.
    let off = set_hooks(&mut node, &mut alice, 0);
    assert_eq!(counts(&mut node), (on, u128::from(off)));
    run_until(&mut node, 20, &mut |n| n.block_number().unwrap() >= off + 2);
    let height = node.block_number().unwrap();
    assert_eq!(
        counts(&mut node),
        (on + u128::from(height - off), u128::from(height))
    );
}

/// The VM gas the module uses for `call`, run directly on a host executor
/// over the same storage.
fn module_vm_gas(call: &ModuleCall, storage: &[(Vec<u8>, Vec<u8>)]) -> u64 {
    let mut exec = Executor::new(ModuleCache::default(), MemStorage::default());
    for (k, v) in storage {
        exec.state_mut().set(k, v);
    }
    exec.state_mut().set(&code_key(&counter_hash()), counter());
    let r = exec.call(
        &counter_hash(),
        modules::namespace(&COUNTER),
        &call.to_bytes(),
        1 << 30,
        Capability::Sandboxed,
        Flags {
            privileged: false,
            static_call: true,
        },
    );
    r.gas_used
}

#[test]
fn native_gas_is_one_unit_with_evm_gas() {
    let mut node = start();
    let mut alice = Sender::alice();
    let data = calldata("add(uint256)", &[word(3)]);
    let height = node.block_number().unwrap();
    let timestamp = node
        .block_by_number(height)
        .unwrap()
        .map_or(0, |h| h.timestamp_ms / 1000);
    let input = ModuleCall::Call {
        context: CallContext {
            address: COUNTER,
            caller: alice.wallet.address,
            value: 0,
            height,
            timestamp,
            is_static: false,
        },
        data: data.clone(),
        pending: Seq(vec![]),
    };
    let ns = modules::namespace(&COUNTER);
    let vm = module_vm_gas(
        &input,
        &[([&ns[..], b"count"].concat(), 5u64.to_le_bytes().to_vec())],
    );
    let write = modules::Write {
        key: b"count".to_vec(),
        value: Some(8u64.to_le_bytes().to_vec()),
    };
    // Intrinsic gas: 21 000, 16 per non-zero calldata byte, 4 per zero byte.
    let intrinsic = 21_000 + 16 * 5 + 4 * 31;
    let expected =
        intrinsic + modules::CALL_GAS + modules::evm_gas(vm) + modules::write_gas(&[write]);
    let r = call(&mut node, COUNTER, 0, &data);
    assert_eq!(r.status, call_status::SUCCESS);
    assert_eq!(r.gas_used, expected);
    let receipt = alice.send(&mut node, COUNTER, 0, &data);
    assert_eq!((receipt.status, receipt.gas_used), (1, expected));

    // A module that never finishes uses all the gas it was given, and no
    // more: 100 000 gas more given is exactly 100 000 more used.
    let spin = |node: &mut Node, gas: u128| {
        let r = call(
            node,
            CALLER,
            0,
            &calldata("spinWith(uint256)", &[word(gas)]),
        );
        assert_eq!(r.output, word(0).to_vec());
        r.gas_used
    };
    let (less, more) = (spin(&mut node, 200_000), spin(&mut node, 300_000));
    assert!(less > 200_000);
    assert_eq!(more - less, 100_000);
    // Gas enough to run but not to pay for the write: the call fails and writes nothing.
    let short = modules::CALL_GAS + modules::evm_gas(vm) + 100;
    let r = call(
        &mut node,
        CALLER,
        0,
        &calldata(
            "addWith(uint256,uint256)",
            &[word(u128::from(short)), word(1)],
        ),
    );
    assert_eq!(r.output, word(0).to_vec());
    let receipt = alice.send(
        &mut node,
        CALLER,
        0,
        &calldata(
            "addWith(uint256,uint256)",
            &[word(u128::from(short)), word(1)],
        ),
    );
    assert_eq!(receipt.status, 1);
    assert_eq!(view(&mut node, COUNTER, "count()"), 8);
    let r = call(
        &mut node,
        CALLER,
        0,
        &calldata("addWith(uint256,uint256)", &[word(50_000), word(1)]),
    );
    assert_eq!(r.output, word(1).to_vec());
    // Not even the base cost.
    let r = call(
        &mut node,
        CALLER,
        0,
        &calldata("addWith(uint256,uint256)", &[word(99), word(1)]),
    );
    assert_eq!(r.output, word(0).to_vec());
    // eth_call with the kernel's default gas still fits the query budget.
    let r = node
        .call(&CallRequest {
            from: alice.wallet.address,
            to: Some(COUNTER),
            data: calldata("count()", &[]),
            ..CallRequest::default()
        })
        .unwrap();
    assert_eq!(r.output, word(8).to_vec());
}

#[test]
#[allow(clippy::too_many_lines)]
fn governance_installs_a_staged_module() {
    let mut node = start();
    let gov = governance();
    let mut nonce = 0;
    let fresh = fresh_module();
    let code_hash = keccak256(&fresh);
    for action in stage_actions(&fresh) {
        assert_eq!(include(&mut node, &gov.action(nonce, &action)).status, 1);
        nonce += 1;
    }
    let target = [0x48; 20];
    let action = |install: &Install| install.encode();
    let send = |node: &mut Node, nonce: &mut u64, install: &Install| {
        let raw = gov.tx(*nonce, MODULE_ADDRESS, 0, STAGE_GAS, &action(install));
        *nonce += 1;
        include(node, &raw)
    };
    let good = Install {
        target,
        code_hash,
        capabilities: capability::HOOKS,
        init: 9u64.to_le_bytes().to_vec(),
    };
    // Refused installs revert: privileged, unknown bits, a system address,
    // unstaged code, an account that has sent transactions.
    for bad in [
        Install {
            capabilities: capability::PRIVILEGED,
            ..good.clone()
        },
        Install {
            capabilities: 8,
            ..good.clone()
        },
        Install {
            target: MODULE_ADDRESS,
            ..good.clone()
        },
        Install {
            code_hash: [1; 32],
            ..good.clone()
        },
        Install {
            target: gov.address,
            ..good.clone()
        },
    ] {
        let receipt = send(&mut node, &mut nonce, &bad);
        assert_eq!(receipt.status, 0, "{bad:?}");
    }
    assert_eq!(
        node.query(modules::query::MODULE, &target.to_bytes())
            .unwrap()
            .status,
        1
    );
    // An `init` that reverts installs nothing and takes the code it
    // assembled from staging back out of state.
    let reverting = Install {
        init: b"bad".to_vec(),
        ..good.clone()
    };
    assert_eq!(send(&mut node, &mut nonce, &reverting).status, 0);
    assert_eq!(node.state_get(&code_key(&code_hash)), None);
    assert_eq!(node.code(&target).unwrap(), Vec::<u8>::new());
    let receipt = send(&mut node, &mut nonce, &good);
    assert_eq!(receipt.status, 1);
    assert_eq!(receipt.logs.0.len(), 1);
    let log = &receipt.logs.0[0];
    assert_eq!(log.address, MODULE_ADDRESS);
    assert_eq!(
        log.topics.0,
        vec![INSTALLED_TOPIC, address_word(&target), code_hash]
    );
    assert_eq!(log.data, word(1).to_vec());
    let record = ModuleRecord::from_bytes(
        &node
            .query(modules::query::MODULE, &target.to_bytes())
            .unwrap()
            .body,
    )
    .unwrap();
    assert_eq!(record.installed_at, receipt.height);
    assert_eq!(view(&mut node, target, "count()"), 9);
    // Installing over an installed module reverts.
    assert_eq!(send(&mut node, &mut nonce, &good).status, 0);
    // A module whose code is already in state needs no staging.
    let again = Install {
        target: [0x49; 20],
        code_hash: counter_hash(),
        capabilities: 0,
        init: vec![],
    };
    assert_eq!(send(&mut node, &mut nonce, &again).status, 1);
    assert_eq!(view(&mut node, [0x49; 20], "blocks()"), 0, "no hooks");
    // Only governance may install, and only an install.
    let raw = alice().tx(0, MODULE_ADDRESS, 0, STAGE_GAS, &action(&good));
    assert_eq!(
        node.submit(&raw),
        Err(SubmitError::Rejected(reason::SYSTEM_ACTION))
    );
    let raw = gov.tx(nonce, MODULE_ADDRESS, 0, STAGE_GAS, b"junk");
    assert_eq!(
        node.submit(&raw),
        Err(SubmitError::Rejected(reason::SYSTEM_ACTION))
    );
    let raw = gov.tx(nonce, MODULE_ADDRESS, 1, STAGE_GAS, &action(&good));
    assert_eq!(
        node.submit(&raw),
        Err(SubmitError::Rejected(reason::SYSTEM_ACTION))
    );
    let raw = gov.unprotected_tx(nonce, MODULE_ADDRESS, STAGE_GAS, &action(&good));
    assert_eq!(
        node.submit(&raw),
        Err(SubmitError::Rejected(reason::SYSTEM_ACTION))
    );
    // Staged code that does not hash to the install's code hash is refused.
    let wrong = Action::Stage {
        code_hash: [2; 32],
        index: 0,
        chunk: vec![1, 2, 3],
    };
    assert_eq!(include(&mut node, &gov.action(nonce, &wrong)).status, 1);
    nonce += 1;
    let bad = Install {
        target: [0x4A; 20],
        code_hash: [2; 32],
        ..good
    };
    assert_eq!(send(&mut node, &mut nonce, &bad).status, 0);
    assert_eq!(view(&mut node, target, "count()"), 9);
}

/// The counter module with a debug section appended: the same program
/// under a code hash of its own, so a module not yet in state.
fn fresh_module() -> Vec<u8> {
    let mut code = counter().to_vec();
    code.extend_from_slice(&[0x7F, 1, 0x55]);
    code
}

#[test]
fn validators_agree_on_state_with_module_calls() {
    let validators = keys(4);
    let (allocations, installs) = layout();
    let genesis = genesis_of(4, allocations, installs);
    let template = NodeConfig {
        now_ms: 10_000,
        ..NodeConfig::default()
    };
    let mut sim = Sim::new(v1(), &genesis, &validators, 0, &template, 30).unwrap();
    let mut alice = Sender::alice();
    let txs = [
        alice.tx(
            CALLER,
            0,
            GAS,
            &calldata("addAndStore(uint256)", &[word(2)]),
        ),
        alice.tx(COUNTER, 0, GAS, &calldata("add(uint256)", &[word(3)])),
        alice.tx(
            CALLER,
            0,
            GAS,
            &calldata("addInRevertedFrame(uint256)", &[word(4)]),
        ),
        alice.tx(TWIN, 0, GAS, &calldata("add(uint256)", &[word(5)])),
    ];
    // One at a time: the mempool admits a nonce only once the one before it ran.
    for raw in &txs {
        let hash = sim.submit(0, raw).unwrap();
        let reached = sim
            .run_until(60 * SLOT_MS, |s| {
                s.nodes
                    .iter_mut()
                    .all(|n| n.receipt(&hash).unwrap().is_some())
            })
            .unwrap();
        assert!(reached, "transaction not executed everywhere");
    }
    let height = sim
        .nodes
        .iter_mut()
        .map(|n| n.block_number().unwrap())
        .min()
        .unwrap();
    let roots: Vec<_> = sim
        .nodes
        .iter_mut()
        .map(|n| n.block_by_number(height).unwrap().unwrap().state_root)
        .collect();
    assert!(roots.windows(2).all(|w| w[0] == w[1]), "{roots:?}");
    for node in &mut sim.nodes {
        assert_eq!(view(node, COUNTER, "count()"), 10);
        assert_eq!(view(node, TWIN, "count()"), 5);
        assert_eq!(view(node, CALLER, "last()"), 7);
    }
}
