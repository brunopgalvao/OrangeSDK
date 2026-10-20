//! The node's privileged host functions, exercised through small modules.

use std::cell::RefCell;
use std::rc::Rc;

use solo_host::{Executor, Flags, MemStorage, ModuleCache, Overlay};
use solo_node::extension::commitment;
use solo_node::{NodeExtension, NodeServices};
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
fn network_stubs_record_and_succeed() {
    let (mut exec, services) = setup();
    for (name, body) in [
        (
            "net_send",
            vec![li(Reg::A0, 0x1_0000), li(Reg::A1, 0x1_0000), li(Reg::A2, 3)],
        ),
        (
            "net_broadcast",
            vec![li(Reg::A0, 1), li(Reg::A1, 0x1_0000), li(Reg::A2, 3)],
        ),
        (
            "net_disseminate",
            vec![li(Reg::A0, 0x1_0000), li(Reg::A1, 0x1_0000), li(Reg::A2, 3)],
        ),
        (
            "net_request",
            vec![li(Reg::A0, 0x1_0000), li(Reg::A1, 0x1_0000), li(Reg::A2, 3)],
        ),
        (
            "net_respond",
            vec![li(Reg::A0, 9), li(Reg::A1, 0x1_0000), li(Reg::A2, 3)],
        ),
        (
            "net_peer_score",
            vec![li(Reg::A0, 0x1_0000), li(Reg::A1, -5)],
        ),
    ] {
        let mut body = body;
        body.push(Instruction::Ecall { import: 1 });
        let rodata = [0xABu8; 64];
        let (status, a0, _) = run(&mut exec, &module(name, &body, &rodata));
        assert_eq!((status, a0), (Termination::Halt, 0), "{name}");
    }
    let log = services.borrow().network.clone();
    assert_eq!(log.len(), 6);
    assert_eq!(log[0], ("net_send", vec![0xAB; 3]));
    assert_eq!(log[5], ("net_peer_score", vec![]));
}

#[test]
fn storage_commit_is_deterministic_and_order_independent() {
    let (mut exec, _) = setup();
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
    assert_eq!(root1, commitment(&other).to_vec());
    other.set(b"b", b"3");
    assert_ne!(root1, commitment(&other).to_vec());
    // A bad destination pointer faults.
    let body = vec![li(Reg::A0, 0), Instruction::Ecall { import: 1 }];
    assert_eq!(
        run(&mut exec, &module("storage_commit", &body, &[])).0,
        Termination::HostError(HostStatus::MemoryFault.code())
    );
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
