//! The node's privileged host functions, exercised through small modules.

use std::cell::RefCell;
use std::rc::Rc;

use solo_host::{Executor, Flags, MemStorage, ModuleCache, Overlay};
use solo_node::extension::commitment;
use solo_node::{NodeExtension, NodeServices};
use solo_trie::{Proof, Trie, keccak256};
use solo_vm::builder::ModuleBuilder;
use solo_vm::host::Capability;
use solo_vm::isa::{Instruction, Reg, StoreWidth};
use solo_vm::status::{HostStatus, Termination};

const BUF: i64 = 0xFFFC_0000;

fn li(r: Reg, imm: i64) -> Instruction {
    Instruction::Li { rd: r, imm }
}

/// A module importing `output_write` (0) and `name` (1) whose body runs, then
/// reports `a0`/`a1` as its 16-byte output.
fn module(name: &str, body: &[Instruction], rodata: &[u8]) -> Vec<u8> {
    let mut b = ModuleBuilder::new();
    if !rodata.is_empty() {
        b = b.rodata(rodata);
    }
    b.import("output_write");
    b.import(name);
    let mut code = body.to_vec();
    code.extend([
        li(Reg::A7, BUF + 0x100),
        Instruction::Store {
            width: StoreWidth::D,
            rs1: Reg::A7,
            rs2: Reg::A0,
            off: 0,
        },
        Instruction::Store {
            width: StoreWidth::D,
            rs1: Reg::A7,
            rs2: Reg::A1,
            off: 8,
        },
        li(Reg::A0, BUF + 0x100),
        li(Reg::A1, 16),
        Instruction::Ecall { import: 0 },
        Instruction::Halt,
    ]);
    b.block(&code);
    b.export("main", 0).build()
}

fn setup() -> (Executor<MemStorage>, Rc<RefCell<NodeServices>>) {
    let services = Rc::new(RefCell::new(NodeServices {
        now_ms: 42,
        ..NodeServices::default()
    }));
    let mut exec = Executor::new(ModuleCache::default(), MemStorage::default());
    exec.set_extension(Box::new(NodeExtension::new(Rc::clone(&services))));
    (exec, services)
}

fn run(exec: &mut Executor<MemStorage>, bytes: &[u8]) -> (Termination, u64, u64) {
    let hash = exec
        .load(bytes, Capability::Privileged)
        .expect("privileged imports resolve");
    let r = exec.call(
        &hash,
        [0; 32],
        b"",
        1_000_000,
        Capability::Privileged,
        Flags::default(),
    );
    let a0 = r
        .output
        .get(..8)
        .map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()));
    let a1 = r
        .output
        .get(8..16)
        .map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()));
    (r.status, a0, a1)
}

#[test]
fn privileged_only() {
    let (mut exec, _) = setup();
    assert!(
        exec.load(&module("time_now", &[], &[]), Capability::Sandboxed)
            .is_err()
    );
    assert!(
        exec.load(
            &module("no_such_function", &[], &[]),
            Capability::Privileged
        )
        .is_err()
    );
}

#[test]
fn time_and_timers() {
    let (mut exec, services) = setup();
    let (status, now, _) = run(
        &mut exec,
        &module("time_now", &[Instruction::Ecall { import: 1 }], &[]),
    );
    assert_eq!(status, Termination::Halt);
    assert_eq!(now, 42);
    let body = vec![
        li(Reg::A0, 7),
        li(Reg::A1, 1_000),
        Instruction::Ecall { import: 1 },
    ];
    assert_eq!(
        run(&mut exec, &module("timer_set", &body, &[])).0,
        Termination::Halt
    );
    assert_eq!(services.borrow().timers.get(&7), Some(&1_000));
    let body = vec![li(Reg::A0, 7), Instruction::Ecall { import: 1 }];
    assert_eq!(
        run(&mut exec, &module("timer_cancel", &body, &[])).0,
        Termination::Halt
    );
    assert!(services.borrow().timers.is_empty());
}

#[test]
fn persistence() {
    let (mut exec, services) = setup();
    // persist_set("k", "value")
    let body = vec![
        li(Reg::A0, 0x1_0000),
        li(Reg::A1, 1),
        li(Reg::A2, 0x1_0001),
        li(Reg::A3, 5),
        Instruction::Ecall { import: 1 },
    ];
    assert_eq!(
        run(&mut exec, &module("persist_set", &body, b"kvalue")).0,
        Termination::Halt
    );
    assert_eq!(
        services.borrow().persisted.get(&b"k"[..]),
        Some(&b"value".to_vec())
    );
    // persist_get("k") into a 3-byte buffer reports the full length.
    let body = vec![
        li(Reg::A0, 0x1_0000),
        li(Reg::A1, 1),
        li(Reg::A2, BUF),
        li(Reg::A3, 3),
        Instruction::Ecall { import: 1 },
    ];
    let (status, len, _) = run(&mut exec, &module("persist_get", &body, b"kvalue"));
    assert_eq!((status, len), (Termination::Halt, 5));
    // Absent key.
    let body = vec![
        li(Reg::A0, 0x1_0001),
        li(Reg::A1, 1),
        li(Reg::A2, BUF),
        li(Reg::A3, 3),
        Instruction::Ecall { import: 1 },
    ];
    let (_, len, _) = run(&mut exec, &module("persist_get", &body, b"kvalue"));
    assert_eq!(len, u64::from(u32::MAX));
    // Bad pointers fault.
    let body = vec![
        li(Reg::A0, 0),
        li(Reg::A1, 1),
        li(Reg::A2, 0),
        li(Reg::A3, 1),
        Instruction::Ecall { import: 1 },
    ];
    assert_eq!(
        run(&mut exec, &module("persist_set", &body, &[])).0,
        Termination::HostError(HostStatus::MemoryFault.code())
    );
    let body = vec![
        li(Reg::A0, 0x1_0000),
        li(Reg::A1, 1),
        li(Reg::A2, 0),
        li(Reg::A3, 8),
        Instruction::Ecall { import: 1 },
    ];
    assert_eq!(
        run(&mut exec, &module("persist_get", &body, b"kvalue")).0,
        Termination::HostError(HostStatus::MemoryFault.code())
    );
}

#[test]
fn network_functions_queue_outbound_messages() {
    use solo_node::Outbound;
    let (mut exec, services) = setup();
    let cases: Vec<(&str, Vec<Instruction>, u64)> = vec![
        (
            "net_send",
            vec![
                li(Reg::A0, 0x1_0000),
                li(Reg::A1, 0x1_0000),
                li(Reg::A2, 3),
                li(Reg::A3, 7),
            ],
            0,
        ),
        (
            "net_broadcast",
            vec![li(Reg::A0, 1), li(Reg::A1, 0x1_0000), li(Reg::A2, 3)],
            0,
        ),
        (
            "net_disseminate",
            vec![li(Reg::A0, 0x1_0000), li(Reg::A1, 0x1_0000), li(Reg::A2, 3)],
            0,
        ),
        (
            "net_request",
            vec![li(Reg::A0, 0x1_0000), li(Reg::A1, 0x1_0000), li(Reg::A2, 3)],
            1,
        ),
        (
            "net_request",
            vec![li(Reg::A0, 0x1_0000), li(Reg::A1, 0x1_0000), li(Reg::A2, 3)],
            2,
        ),
        (
            "net_respond",
            vec![li(Reg::A0, 9), li(Reg::A1, 0x1_0000), li(Reg::A2, 3)],
            0,
        ),
        (
            "net_peer_score",
            vec![li(Reg::A0, 0x1_0000), li(Reg::A1, -5)],
            0,
        ),
    ];
    for (name, body, expected) in cases {
        let mut body = body;
        body.push(Instruction::Ecall { import: 1 });
        let rodata = [0xABu8; 64];
        let (status, a0, _) = run(&mut exec, &module(name, &body, &rodata));
        assert_eq!((status, a0), (Termination::Halt, expected), "{name}");
    }
    let queued = std::mem::take(&mut services.borrow_mut().outbound);
    assert_eq!(
        queued,
        vec![
            Outbound::Send {
                peer: [0xAB; 32],
                topic: 7,
                payload: vec![0xAB; 3]
            },
            Outbound::Broadcast {
                topic: 1,
                payload: vec![0xAB; 3]
            },
            Outbound::Disseminate {
                blob_id: [0xAB; 32],
                payload: vec![0xAB; 3]
            },
            Outbound::Request {
                peer: [0xAB; 32],
                request_id: 1,
                payload: vec![0xAB; 3]
            },
            Outbound::Request {
                peer: [0xAB; 32],
                request_id: 2,
                payload: vec![0xAB; 3]
            },
            Outbound::Respond {
                request_id: 9,
                payload: vec![0xAB; 3]
            },
            Outbound::PeerScore {
                peer: [0xAB; 32],
                delta: -5
            },
        ]
    );
    // A peer id that is not readable faults.
    let body = vec![
        li(Reg::A0, 0xFFFF_FFF0),
        li(Reg::A1, 0x1_0000),
        li(Reg::A2, 3),
        Instruction::Ecall { import: 1 },
    ];
    let (status, _, _) = run(&mut exec, &module("net_send", &body, &[0xAB; 64]));
    assert_eq!(
        status,
        Termination::HostError(HostStatus::MemoryFault.code())
    );
}

#[test]
fn sign_uses_the_node_key() {
    use k256::ecdsa::SigningKey;
    let (mut exec, services) = setup();
    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    // a0 role, a1 msg, a2 len, a3 dst, a4 cap.
    let body = |role: i64, len: i64, cap: i64| {
        vec![
            li(Reg::A0, role),
            li(Reg::A1, 0x1_0000),
            li(Reg::A2, len),
            li(Reg::A3, BUF),
            li(Reg::A4, cap),
            Instruction::Ecall { import: 1 },
        ]
    };
    let digest = [0x5Au8; 32];
    // No key: status 0, nothing written.
    let (status, a0, _) = run(&mut exec, &module("sign", &body(0, 32, 65), &digest));
    assert_eq!((status, a0), (Termination::Halt, 0));
    services.borrow_mut().key = Some(key.clone());
    let (status, a0, _) = run(&mut exec, &module("sign", &body(0, 32, 65), &digest));
    assert_eq!((status, a0), (Termination::Halt, 65));
    // Wrong role, short message, small buffer: status 0.
    for (role, len, cap) in [(1, 32, 65), (0, 31, 65), (0, 32, 64)] {
        let (status, a0, _) = run(&mut exec, &module("sign", &body(role, len, cap), &digest));
        assert_eq!((status, a0), (Termination::Halt, 0), "{role} {len} {cap}");
    }
    // The signature recovers to the key.
    let expected = solo_node::sign_recoverable(&key, &digest).unwrap();
    let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(
        &digest,
        &k256::ecdsa::Signature::from_slice(&expected[..64]).unwrap(),
        k256::ecdsa::RecoveryId::from_byte(expected[64]).unwrap(),
    )
    .unwrap();
    assert_eq!(&recovered, key.verifying_key());
    let id = solo_node::validator_id(&key);
    let point = key.verifying_key().to_encoded_point(false);
    assert_eq!(id, solo_host::hash::keccak256(&point.as_bytes()[1..]));
    // An unwritable destination faults.
    let mut bad = body(0, 32, 65);
    bad[3] = li(Reg::A3, 0xFFFF_FFF0);
    let (status, _, _) = run(&mut exec, &module("sign", &bad, &digest));
    assert_eq!(
        status,
        Termination::HostError(HostStatus::MemoryFault.code())
    );
}

#[test]
fn storage_commit_is_deterministic_and_order_independent() {
    let (mut exec, services) = setup();
    let body = vec![
        li(Reg::A0, BUF),
        Instruction::Ecall { import: 1 },
        li(Reg::A0, BUF),
        li(Reg::A1, 32),
        Instruction::Ecall { import: 0 },
        Instruction::Halt,
    ];
    let mut b = ModuleBuilder::new();
    b.import("output_write");
    b.import("storage_commit");
    b.block(&body);
    let bytes = b.export("main", 0).build();
    let hash = exec.load(&bytes, Capability::Privileged).unwrap();
    let empty = exec
        .call(
            &hash,
            [0; 32],
            b"",
            100_000,
            Capability::Privileged,
            Flags::default(),
        )
        .output;
    exec.state_mut().set(b"b", b"2");
    exec.state_mut().set(b"a", b"1");
    let root1 = exec
        .call(
            &hash,
            [0; 32],
            b"",
            100_000,
            Capability::Privileged,
            Flags::default(),
        )
        .output;
    assert_ne!(root1, empty);
    let mut other = Overlay::new(MemStorage::default());
    other.set(b"a", b"1");
    other.set(b"b", b"2");
    assert_eq!(root1, commitment(&mut other).to_vec());
    // The root of spec 10: the trie over exactly the committed entries.
    let mut trie = Trie::new();
    trie.insert(b"b", b"2");
    trie.insert(b"a", b"1");
    assert_eq!(root1, trie.root().to_vec());
    assert_eq!(empty, solo_trie::EMPTY.to_vec());
    other.set(b"b", b"3");
    assert_ne!(root1, commitment(&mut other).to_vec());
    // Node-local keys are outside it.
    exec.state_mut().set(b"local/finalized", b"7");
    let root2 = exec
        .call(
            &hash,
            [0; 32],
            b"",
            100_000,
            Capability::Privileged,
            Flags::default(),
        )
        .output;
    assert_eq!(root2, root1);
    // The node is handed the trie behind each root, to prove against later.
    let kept: Vec<Vec<u8>> = services
        .borrow()
        .commitments
        .iter()
        .map(|trie| trie.root().to_vec())
        .collect();
    assert_eq!(kept, [empty, root1, root2]);
    // A bad destination pointer faults.
    let body = vec![li(Reg::A0, 0), Instruction::Ecall { import: 1 }];
    assert_eq!(
        run(&mut exec, &module("storage_commit", &body, &[])).0,
        Termination::HostError(HostStatus::MemoryFault.code())
    );
}

/// Namespace of the sandboxed module in the proof tests.
const SANDBOX_NS: [u8; 32] = [7; 32];
/// The longest key a sandboxed module names; stored behind its namespace.
const SANDBOX_KEY: [u8; 64] = [b'q'; 64];
/// Where the 96-byte stored key `SANDBOX_NS || SANDBOX_KEY` sits in rodata.
const STORED_KEY_PTR: i64 = 0x1_000A;

/// Rodata of the proof modules: the pending entry `k = v`, probe keys, then
/// the stored key of the sandboxed module.
fn proof_rodata() -> Vec<u8> {
    [&b"kvzlocal/x"[..], &SANDBOX_NS, &SANDBOX_KEY].concat()
}

/// A module that sets `k = v` in its own layer, then writes its output as
/// `storage_commit` root (32) || `storage_proof` return value (8) || the
/// `cap` bytes `storage_proof` was given for the key at `key_ptr`.
fn proof_module(key_ptr: i64, key_len: i64, cap: i64) -> Vec<u8> {
    let mut b = ModuleBuilder::new().rodata(&proof_rodata());
    b.import("output_write");
    b.import("storage_set");
    b.import("storage_commit");
    b.import("storage_proof");
    b.block(&[
        li(Reg::A0, 0x1_0000),
        li(Reg::A1, 1),
        li(Reg::A2, 0x1_0001),
        li(Reg::A3, 1),
        Instruction::Ecall { import: 1 },
        li(Reg::A0, BUF),
        Instruction::Ecall { import: 2 },
        li(Reg::A0, key_ptr),
        li(Reg::A1, key_len),
        li(Reg::A2, BUF + 40),
        li(Reg::A3, cap),
        Instruction::Ecall { import: 3 },
        li(Reg::A7, BUF + 32),
        Instruction::Store {
            width: StoreWidth::D,
            rs1: Reg::A7,
            rs2: Reg::A0,
            off: 0,
        },
        li(Reg::A0, BUF),
        li(Reg::A1, 40 + cap),
        Instruction::Ecall { import: 0 },
        Instruction::Halt,
    ]);
    b.export("main", 0).build()
}

/// Runs a proof module: (status, root, returned length, proof bytes written).
fn prove(
    exec: &mut Executor<MemStorage>,
    key_ptr: i64,
    key_len: i64,
    cap: i64,
) -> (Termination, [u8; 32], usize, Vec<u8>) {
    let hash = exec
        .load(&proof_module(key_ptr, key_len, cap), Capability::Privileged)
        .unwrap();
    let r = exec.call(
        &hash,
        [0; 32],
        b"",
        1_000_000,
        Capability::Privileged,
        Flags::default(),
    );
    if r.status != Termination::Halt {
        return (r.status, [0; 32], 0, Vec::new());
    }
    let root: [u8; 32] = r.output[..32].try_into().unwrap();
    let len = usize::try_from(u64::from_le_bytes(r.output[32..40].try_into().unwrap())).unwrap();
    let written = len.min(usize::try_from(cap).unwrap());
    (r.status, root, len, r.output[40..40 + written].to_vec())
}

#[test]
fn storage_proof_proves_against_the_commitment() {
    let (mut exec, _) = setup();
    exec.state_mut().set(b"a", b"1");
    exec.state_mut().set(b"local/x", b"node-local");
    let mut expected = Trie::new();
    expected.insert(b"a", b"1");
    expected.insert(b"k", b"v");
    // The key written earlier in the same call: present, with its value.
    let (status, root, len, bytes) = prove(&mut exec, 0x1_0000, 1, 8_192);
    assert_eq!(status, Termination::Halt);
    assert_eq!(root, expected.root());
    assert_eq!(len, bytes.len());
    let proof = Proof::decode(&bytes).unwrap();
    assert_eq!(proof, expected.prove(b"k"));
    assert_eq!(
        proof.verify(keccak256, &root, b"k"),
        Ok(Some(keccak256(b"v")))
    );
    // An absent key and a node-local one are both proven absent.
    for (ptr, key_len, key) in [(0x1_0002, 1, &b"z"[..]), (0x1_0003, 7, b"local/x")] {
        let (_, root, _, bytes) = prove(&mut exec, ptr, key_len, 8_192);
        let proof = Proof::decode(&bytes).unwrap();
        assert_eq!(proof.verify(keccak256, &root, key), Ok(None), "{key:?}");
    }
    // The call halted, so its write is now in the state.
    assert_eq!(exec.state().get(b"k"), Some(b"v".to_vec()));
    // A short buffer gets a prefix; the full length is still returned.
    let (_, _, len, prefix) = prove(&mut exec, 0x1_0000, 1, 5);
    assert_eq!(prefix.len(), 5);
    assert!(len > 5);
    assert_eq!(prefix, expected.prove(b"k").encode()[..5]);
    // A sandboxed module's longest key is stored behind its namespace, 96
    // bytes in all; it moves the root, so it has a proof too.
    let mut b = ModuleBuilder::new().rodata(&SANDBOX_KEY);
    b.import("storage_set");
    b.block(&[
        li(Reg::A0, 0x1_0000),
        li(Reg::A1, 64),
        li(Reg::A2, 0x1_0000),
        li(Reg::A3, 1),
        Instruction::Ecall { import: 0 },
        Instruction::Halt,
    ]);
    let sandboxed = exec
        .load(&b.export("main", 0).build(), Capability::Sandboxed)
        .unwrap();
    let r = exec.call(
        &sandboxed,
        SANDBOX_NS,
        b"",
        100_000,
        Capability::Sandboxed,
        Flags::default(),
    );
    assert_eq!(r.status, Termination::Halt);
    let stored = solo_host::storage::namespaced(&SANDBOX_NS, &SANDBOX_KEY);
    assert_eq!(stored.len(), 96);
    assert_eq!(exec.state().get(&stored), Some(b"q".to_vec()));
    let (status, root, _, bytes) = prove(&mut exec, STORED_KEY_PTR, 96, 8_192);
    assert_eq!(status, Termination::Halt);
    expected.insert(&stored, b"q");
    assert_eq!(root, expected.root());
    assert_eq!(
        Proof::decode(&bytes)
            .unwrap()
            .verify(keccak256, &root, &stored),
        Ok(Some(keccak256(b"q")))
    );
    // Keys of no bytes or more than 96 have no proof: the call carries on
    // with 0 and nothing written.
    for key_len in [0, 97] {
        let (status, _, len, bytes) = prove(&mut exec, 0x1_0000, key_len, 64);
        assert_eq!(
            (status, len, bytes.len()),
            (Termination::Halt, 0, 0),
            "{key_len}"
        );
    }
    // Unreadable keys and unwritable destinations fault.
    let fault = Termination::HostError(HostStatus::MemoryFault.code());
    assert_eq!(prove(&mut exec, 0, 1, 64).0, fault);
    let mut b = ModuleBuilder::new().rodata(&proof_rodata());
    b.import("storage_proof");
    b.block(&[
        li(Reg::A0, 0x1_0000),
        li(Reg::A1, 1),
        li(Reg::A2, 0),
        li(Reg::A3, 64),
        Instruction::Ecall { import: 0 },
        Instruction::Halt,
    ]);
    let bytes = b.export("main", 0).build();
    assert_eq!(run(&mut exec, &bytes).0, fault);
}

/// Calls `storage_proof` directly with `gas`: the key "key" from rodata into
/// a buffer of `cap` bytes. Returns the result and the gas left.
fn proof_call(
    exec: &mut Executor<MemStorage>,
    cap: u64,
    gas: i64,
) -> (Result<(), Termination>, i64, u64) {
    let layout = ModuleBuilder::new().rodata(b"key").layout;
    let mut mem = solo_vm::memory::Memory::new(layout, b"key", &[]);
    let mut regs = [0u64; Reg::COUNT];
    regs[Reg::A0.index()] = 0x1_0000;
    regs[Reg::A1.index()] = 3;
    regs[Reg::A2.index()] = 0xFFFC_0000;
    regs[Reg::A3.index()] = cap;
    let mut gas = gas;
    let mut ctx = solo_vm::host::HostContext {
        regs: &mut regs,
        memory: &mut mem,
        gas: &mut gas,
    };
    let handle = solo_node::extension::Handle::StorageProof as u32;
    let r = solo_vm::host::Host::call(exec, handle, &mut ctx);
    (r, gas, regs[Reg::A0.index()])
}

#[test]
fn storage_proof_costs() {
    // 2 000, plus 1 per 32 bytes written: an empty trie's proof is 3 bytes.
    let (mut exec, _) = setup();
    assert_eq!(proof_call(&mut exec, 0, 10_000), (Ok(()), 8_000, 3));
    assert_eq!(proof_call(&mut exec, 64, 10_000), (Ok(()), 7_999, 3));
    // Out of gas for the base charge, or for the bytes written.
    assert!(proof_call(&mut exec, 64, 1_999).0.is_err());
    assert!(proof_call(&mut exec, 64, 2_000).0.is_err());
}

#[test]
fn storage_commit_costs() {
    // A flat 10 000, however many entries the state holds.
    let (mut exec, _) = setup();
    for i in 0u8..50 {
        exec.state_mut().set(&[i], &[i]);
    }
    for (gas, left) in [(10_000, Some(0)), (12_345, Some(2_345)), (9_999, None)] {
        let layout = ModuleBuilder::new().layout;
        let mut mem = solo_vm::memory::Memory::new(layout, &[], &[]);
        let mut regs = [0u64; Reg::COUNT];
        regs[Reg::A0.index()] = 0xFFFC_0000;
        let mut gas = gas;
        let mut ctx = solo_vm::host::HostContext {
            regs: &mut regs,
            memory: &mut mem,
            gas: &mut gas,
        };
        let handle = solo_node::extension::Handle::StorageCommit as u32;
        let r = solo_vm::host::Host::call(&mut exec, handle, &mut ctx);
        assert_eq!(r.ok().map(|()| gas), left);
    }
}

#[test]
fn unknown_handle_is_unavailable() {
    let (mut exec, _) = setup();
    let layout = ModuleBuilder::new().layout;
    let mut mem = solo_vm::memory::Memory::new(layout, &[], &[]);
    let mut regs = [0u64; Reg::COUNT];
    let mut gas = 100;
    let mut ctx = solo_vm::host::HostContext {
        regs: &mut regs,
        memory: &mut mem,
        gas: &mut gas,
    };
    assert_eq!(
        solo_vm::host::Host::call(&mut exec, 199, &mut ctx),
        Err(Termination::HostError(HostStatus::Unavailable.code()))
    );
    assert!(format!("{:?}", solo_node::extension::Handle::TimeNow).contains("TimeNow"));
    assert!(format!("{:?}", NodeServices::default()).contains("NodeServices"));
}
