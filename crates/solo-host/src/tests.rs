//! Behavioural tests of the host ABI and executor through real modules.

use solo_vm::builder::ModuleBuilder;
use solo_vm::gas::CostTable;
use solo_vm::host::{Capability, HostContext};
use solo_vm::isa::{Instruction, LoadWidth, Reg, StoreWidth};
use solo_vm::memory::Memory;
use solo_vm::status::{HostStatus, Termination};

use crate::abi::{self, ABSENT};
use crate::cache::ModuleCache;
use crate::executor::{CallResult, Executor, Flags, MAX_DEPTH};
use crate::hash::{blake2b256, keccak256, sha256};
use crate::storage::MemStorage;

/// Writable scratch in the default layout's stack region.
const BUF: i64 = 0xFFFC_0000;
const NS: [u8; 32] = [0xAA; 32];

fn li(r: Reg, imm: i64) -> Instruction {
    Instruction::Li { rd: r, imm }
}

fn ecall(import: u32) -> Instruction {
    Instruction::Ecall { import }
}

fn sd(base: Reg, src: Reg, off: i64) -> Instruction {
    Instruction::Store {
        width: StoreWidth::D,
        rs1: base,
        rs2: src,
        off,
    }
}

fn ld(dst: Reg, base: Reg, off: i64) -> Instruction {
    Instruction::Load {
        width: LoadWidth::D,
        rd: dst,
        rs1: base,
        off,
    }
}

/// A module importing `imports` in order whose `main` runs `body` then halts.
fn module(imports: &[&str], body: &[Instruction], rodata: &[u8]) -> Vec<u8> {
    let mut b = ModuleBuilder::new();
    if !rodata.is_empty() {
        b = b.rodata(rodata);
    }
    for i in imports {
        b.import(i);
    }
    let mut code = body.to_vec();
    if code.last().is_none_or(Instruction::falls_through) {
        code.push(Instruction::Halt);
    }
    b.block(&code);
    b.export("main", 0).build()
}

/// Instructions that save `a0` and `a1` at `BUF + 0x100` and write those 16
/// bytes as the output, so tests can read a host function's results.
fn report() -> Vec<Instruction> {
    vec![
        li(Reg::A7, BUF + 0x100),
        sd(Reg::A7, Reg::A0, 0),
        sd(Reg::A7, Reg::A1, 8),
        li(Reg::A0, BUF + 0x100),
        li(Reg::A1, 16),
        ecall(OUTPUT_WRITE),
    ]
}

/// Import indices used by [`imports`].
const OUTPUT_WRITE: u32 = 0;
const INPUT_LEN: u32 = 1;
const INPUT_READ: u32 = 2;
const STORAGE_GET: u32 = 3;
const STORAGE_SET: u32 = 4;
const STORAGE_DELETE: u32 = 5;
const ITER_OPEN: u32 = 6;
const ITER_NEXT: u32 = 7;
const INVOKE: u32 = 8;
const INVOKE_OUT_LEN: u32 = 9;
const INVOKE_OUT_READ: u32 = 10;
const LOG: u32 = 11;
const METRIC: u32 = 12;
const GAS: u32 = 13;
const ABI: u32 = 14;

fn imports() -> Vec<&'static str> {
    vec![
        "output_write",
        "input_len",
        "input_read",
        "storage_get",
        "storage_set",
        "storage_delete",
        "storage_iter_open",
        "storage_iter_next",
        "invoke",
        "invoke_output_len",
        "invoke_output_read",
        "log_emit",
        "metric_emit",
        "gas_remaining",
        "abi_version",
    ]
}

fn executor() -> Executor<MemStorage> {
    Executor::new(ModuleCache::new(CostTable::V1), MemStorage::default())
}

fn load(exec: &mut Executor<MemStorage>, bytes: &[u8], cap: Capability) -> [u8; 32] {
    exec.cache_mut()
        .insert(bytes, cap, &abi::resolve_bool)
        .unwrap()
}

fn run(exec: &mut Executor<MemStorage>, bytes: &[u8], input: &[u8], gas: i64) -> CallResult {
    let hash = load(exec, bytes, Capability::Sandboxed);
    exec.call(
        &hash,
        NS,
        input,
        gas,
        Capability::Sandboxed,
        Flags::default(),
    )
}

/// The `(a0, a1)` a module saved with [`report`]; fails loudly if the call did not halt.
fn regs(r: &CallResult) -> (u64, u64) {
    assert_eq!(r.status, Termination::Halt, "call did not halt: {r:?}");
    assert!(r.output.len() >= 16, "no report in output: {r:?}");
    (
        u64::from_le_bytes(r.output[..8].try_into().unwrap()),
        u64::from_le_bytes(r.output[8..16].try_into().unwrap()),
    )
}

#[test]
fn resolve_table() {
    assert_eq!(abi::resolve("abi_version", Capability::Sandboxed), Some(1));
    assert_eq!(abi::resolve("invoke", Capability::Privileged), Some(30));
    assert_eq!(abi::resolve("storage_commit", Capability::Privileged), None);
    assert_eq!(abi::resolve("nope", Capability::Sandboxed), None);
    assert!(abi::resolve_bool("log_emit", Capability::Sandboxed));
    assert!(abi::FUNCTIONS.iter().all(|f| f.sandboxed));
    assert!(format!("{:?}", abi::FUNCTIONS[0]).contains("abi_version"));
    assert_eq!(
        Flags::from_bits(3),
        Flags {
            privileged: true,
            static_call: true
        }
    );
    assert_eq!(MAX_DEPTH, 1024);
}

#[test]
fn context_functions() {
    // Copy the input to BUF, then echo bytes 2.. of it as output; report len and version.
    let mut body = vec![
        ecall(INPUT_LEN),
        li(Reg::A6, 0),
        Instruction::Alu {
            op: solo_vm::isa::AluOp::Add,
            rd: Reg::A6,
            rs1: Reg::A0,
            rs2: Reg::ZERO,
        }, // a6 = len
        li(Reg::A0, BUF),
        li(Reg::A1, 2),
        li(Reg::A2, 100),
        ecall(INPUT_READ), // copies len-2 bytes (clamped)
        li(Reg::A1, 0),
        Instruction::Alu {
            op: solo_vm::isa::AluOp::Add,
            rd: Reg::A1,
            rs1: Reg::A0,
            rs2: Reg::ZERO,
        },
        li(Reg::A0, BUF),
        ecall(OUTPUT_WRITE),
    ];
    let mut exec = executor();
    let r = run(
        &mut exec,
        &module(&imports(), &body, &[]),
        b"hello!",
        10_000,
    );
    assert_eq!(r.status, Termination::Halt);
    assert_eq!(r.output, b"llo!");
    assert!(r.gas_used > 0 && r.gas_used < 200, "{}", r.gas_used);
    // Reading past the end copies nothing; version and gas are reported.
    body = vec![
        li(Reg::A0, BUF),
        li(Reg::A1, 50),
        li(Reg::A2, 4),
        ecall(INPUT_READ),
        ecall(ABI),
    ];
    body.extend([
        Instruction::Alu {
            op: solo_vm::isa::AluOp::Add,
            rd: Reg::A1,
            rs1: Reg::A0,
            rs2: Reg::ZERO,
        },
        ecall(GAS),
    ]);
    body.extend(report());
    let r = run(&mut exec, &module(&imports(), &body, &[]), b"hi", 1_000);
    assert_eq!(r.status, Termination::Halt);
    let (gas_left, version) = regs(&r);
    assert_eq!(version, 1);
    assert!(gas_left < 1_000 && gas_left > 800);
    // A second output_write replaces the first.
    let body = vec![
        li(Reg::A0, 0x1_0000),
        li(Reg::A1, 3),
        ecall(OUTPUT_WRITE),
        li(Reg::A0, 0x1_0000),
        li(Reg::A1, 1),
        ecall(OUTPUT_WRITE),
    ];
    let r = run(&mut exec, &module(&imports(), &body, b"xyz"), b"", 1_000);
    assert_eq!(r.status, Termination::Halt);
    assert_eq!(r.output, b"x");
    // Out-of-gas inside a host function surfaces as OutOfGas.
    let r = run(&mut exec, &module(&imports(), &body, b"xyz"), b"", 14);
    assert_eq!(r.status, Termination::OutOfGas);
    assert_eq!(r.gas_used, 14);
    // A bad pointer surfaces as a memory-fault host error.
    let body = vec![li(Reg::A0, 0), li(Reg::A1, 3), ecall(OUTPUT_WRITE)];
    let r = run(&mut exec, &module(&imports(), &body, &[]), b"", 1_000);
    assert_eq!(
        r.status,
        Termination::HostError(HostStatus::MemoryFault.code())
    );
}

/// `storage_set(key, value)` where key and value are in rodata at the given offsets.
fn set_instr(key_off: i64, key_len: i64, val_off: i64, val_len: i64) -> Vec<Instruction> {
    vec![
        li(Reg::A0, 0x1_0000 + key_off),
        li(Reg::A1, key_len),
        li(Reg::A2, 0x1_0000 + val_off),
        li(Reg::A3, val_len),
        ecall(STORAGE_SET),
    ]
}

/// `storage_iter_next(handle in a6, key -> BUF cap 64, value -> BUF+64 cap val_cap)`.
fn next_instr(val_cap: i64) -> Vec<Instruction> {
    vec![
        Instruction::Alu {
            op: solo_vm::isa::AluOp::Add,
            rd: Reg::A0,
            rs1: Reg::A6,
            rs2: Reg::ZERO,
        },
        li(Reg::A1, BUF),
        li(Reg::A2, 64),
        li(Reg::A3, BUF + 64),
        li(Reg::A4, val_cap),
        ecall(ITER_NEXT),
    ]
}

fn get_instr(key_off: i64, key_len: i64, cap: i64) -> Vec<Instruction> {
    vec![
        li(Reg::A0, 0x1_0000 + key_off),
        li(Reg::A1, key_len),
        li(Reg::A2, BUF),
        li(Reg::A3, cap),
        ecall(STORAGE_GET),
    ]
}

#[test]
fn storage_functions() {
    // rodata: "k1" "k2" "value-one" "v2"
    let ro = b"k1k2value-onev2";
    let mut exec = executor();
    // set k1=value-one, k2=v2; get k1 with cap 4 (truncated); report a0.
    let mut body = set_instr(0, 2, 4, 9);
    body.extend(set_instr(2, 2, 13, 2));
    body.extend(get_instr(0, 2, 4));
    body.extend(report());
    let r = run(&mut exec, &module(&imports(), &body, ro), b"", 100_000);
    assert_eq!(r.status, Termination::Halt);
    assert_eq!(regs(&r).0, 9, "full length reported despite truncation");
    let full = crate::storage::namespaced(&NS, b"k1");
    assert_eq!(exec.state().get(&full), Some(b"value-one".to_vec()));
    assert_eq!(exec.state().base().len(), 2);
    // get absent, delete present then absent, invalid key lengths, oversize value.
    let mut body = get_instr(2, 1, 100); // "k" absent
    body.extend(report());
    let r = run(&mut exec, &module(&imports(), &body, ro), b"", 100_000);
    assert_eq!(regs(&r).0, ABSENT);
    let mut body = vec![li(Reg::A0, 0x1_0000), li(Reg::A1, 2), ecall(STORAGE_DELETE)];
    body.extend([Instruction::Alu {
        op: solo_vm::isa::AluOp::Add,
        rd: Reg::A5,
        rs1: Reg::A0,
        rs2: Reg::ZERO,
    }]);
    body.extend([li(Reg::A0, 0x1_0000), li(Reg::A1, 2), ecall(STORAGE_DELETE)]);
    body.extend([Instruction::Alu {
        op: solo_vm::isa::AluOp::Add,
        rd: Reg::A1,
        rs1: Reg::A5,
        rs2: Reg::ZERO,
    }]);
    body.extend(report());
    let r = run(&mut exec, &module(&imports(), &body, ro), b"", 100_000);
    let (second, first) = regs(&r);
    assert_eq!(first, u64::from(HostStatus::Ok.code()));
    assert_eq!(second, u64::from(HostStatus::NotFound.code()));
    assert_eq!(exec.state().get(&full), None);
    for (key_len, val_len) in [(0, 1), (65, 1), (1, 70_000)] {
        let mut body = set_instr(0, key_len, 0, val_len);
        body.extend(report());
        let r = run(&mut exec, &module(&imports(), &body, ro), b"", 100_000);
        assert_eq!(
            regs(&r).0,
            u64::from(HostStatus::InvalidArgument.code()),
            "{key_len} {val_len}"
        );
    }
    let mut body = get_instr(0, 0, 1);
    body.extend(report());
    let r = run(&mut exec, &module(&imports(), &body, ro), b"", 100_000);
    assert_eq!(regs(&r).0, u64::from(HostStatus::InvalidArgument.code()));
    let mut body = vec![li(Reg::A0, 0x1_0000), li(Reg::A1, 0), ecall(STORAGE_DELETE)];
    body.extend(report());
    let r = run(&mut exec, &module(&imports(), &body, ro), b"", 100_000);
    assert_eq!(regs(&r).0, u64::from(HostStatus::InvalidArgument.code()));
    // A trap discards writes.
    let mut body = set_instr(0, 2, 4, 9);
    body.push(Instruction::Trap);
    let r = run(&mut exec, &module(&imports(), &body, ro), b"", 100_000);
    assert_eq!(r.status, Termination::Trap);
    assert_eq!(exec.state().get(&full), None);
}

#[test]
#[allow(clippy::too_many_lines)]
fn storage_iteration_and_privileged_keys() {
    let ro = b"ka01kb02kcprefix";
    let mut exec = executor();
    // Sandboxed: set ka=01, kb=02, kc=prefix; iterate prefix "k": report count via loop is complex,
    // so iterate twice and report key length and value length of the second entry, then the end marker.
    let mut body = set_instr(0, 2, 2, 2);
    body.extend(set_instr(4, 2, 6, 2));
    body.extend(set_instr(8, 2, 10, 6));
    body.extend([li(Reg::A0, 0x1_0000), li(Reg::A1, 1), ecall(ITER_OPEN)]); // prefix "k"
    body.push(Instruction::Alu {
        op: solo_vm::isa::AluOp::Add,
        rd: Reg::A6,
        rs1: Reg::A0,
        rs2: Reg::ZERO,
    }); // handle
    for _ in 0..4 {
        body.extend(next_instr(1));
    }
    body.extend(report());
    let r = run(&mut exec, &module(&imports(), &body, ro), b"", 100_000);
    assert_eq!(r.status, Termination::Halt);
    assert_eq!(regs(&r), (ABSENT, 0), "fourth next hits the end");
    // Keys came back without the namespace prefix: the second key was "kb" (2 bytes).
    let mut body = vec![li(Reg::A0, 0x1_0000), li(Reg::A1, 1), ecall(ITER_OPEN)];
    body.extend([
        li(Reg::A1, BUF),
        li(Reg::A2, 64),
        li(Reg::A3, BUF + 64),
        li(Reg::A4, 64),
        ecall(ITER_NEXT),
    ]);
    body.extend([li(Reg::A0, BUF), li(Reg::A1, 2), ecall(OUTPUT_WRITE)]);
    let r = run(&mut exec, &module(&imports(), &body, ro), b"", 100_000);
    assert_eq!(r.output, b"ka");
    // Bad handle and oversize prefix.
    let mut body = vec![
        li(Reg::A0, 7),
        li(Reg::A1, BUF),
        li(Reg::A2, 8),
        li(Reg::A3, BUF),
        li(Reg::A4, 8),
        ecall(ITER_NEXT),
    ];
    body.extend(report());
    let r = run(&mut exec, &module(&imports(), &body, ro), b"", 100_000);
    assert_eq!(regs(&r).0, u64::from(HostStatus::InvalidArgument.code()));
    let mut body = vec![li(Reg::A0, 0x1_0000), li(Reg::A1, 65), ecall(ITER_OPEN)];
    body.extend(report());
    let r = run(&mut exec, &module(&imports(), &body, ro), b"", 100_000);
    assert_eq!(regs(&r).0, u64::from(HostStatus::InvalidArgument.code()));
    // Privileged: keys are not namespaced, and the sandboxed entries are visible under their prefix.
    let mut body = vec![li(Reg::A0, 0x1_0000), li(Reg::A1, 0), ecall(ITER_OPEN)]; // empty prefix: everything
    body.extend([
        li(Reg::A1, BUF),
        li(Reg::A2, 64),
        li(Reg::A3, BUF + 64),
        li(Reg::A4, 64),
        ecall(ITER_NEXT),
    ]);
    body.extend(report());
    let bytes = module(&imports(), &body, ro);
    let hash = load(&mut exec, &bytes, Capability::Privileged);
    let r = exec.call(
        &hash,
        NS,
        b"",
        100_000,
        Capability::Privileged,
        Flags::default(),
    );
    assert_eq!(r.status, Termination::Halt);
    assert_eq!(regs(&r), (34, 2), "full key of 32 + 2 bytes, value 2 bytes");
    let mut body = set_instr(0, 2, 2, 2);
    body.extend(get_instr(0, 2, 64));
    body.extend(report());
    let bytes = module(&imports(), &body, ro);
    let hash = load(&mut exec, &bytes, Capability::Privileged);
    let r = exec.call(
        &hash,
        NS,
        b"",
        100_000,
        Capability::Privileged,
        Flags::default(),
    );
    assert_eq!(regs(&r).0, 2);
    assert_eq!(exec.state().get(b"ka"), Some(b"01".to_vec()));
}

#[test]
fn hashes() {
    let data = b"hello, solo";
    for (name, expected) in [
        ("hash_keccak256", keccak256(data)),
        ("hash_sha256", sha256(data)),
        ("hash_blake2b256", blake2b256(data)),
    ] {
        let body = vec![
            li(Reg::A0, 0x1_0000),
            li(Reg::A1, 11),
            li(Reg::A2, BUF),
            ecall(1),
            li(Reg::A0, BUF),
            li(Reg::A1, 32),
            ecall(0),
        ];
        let mut exec = executor();
        let r = run(
            &mut exec,
            &module(&["output_write", name], &body, data),
            b"",
            10_000,
        );
        assert_eq!(r.status, Termination::Halt, "{name}");
        assert_eq!(r.output, expected, "{name}");
    }
}

#[test]
fn host_writes_to_unmapped_memory_fault() {
    // keccak of 3 rodata bytes with the digest destination at address 0.
    let body = vec![
        li(Reg::A0, 0x1_0000),
        li(Reg::A1, 3),
        li(Reg::A2, 0),
        ecall(1),
    ];
    let mut exec = executor();
    let r = run(
        &mut exec,
        &module(&["output_write", "hash_keccak256"], &body, b"abc"),
        b"",
        10_000,
    );
    assert_eq!(
        r.status,
        Termination::HostError(HostStatus::MemoryFault.code())
    );
    assert!(r.output.is_empty());
}

#[test]
#[allow(clippy::too_many_lines)]
fn secp256k1_recover_and_p256_verify() {
    use k256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let expected = sk.verifying_key().to_encoded_point(false).as_bytes()[1..65].to_vec();
    let body = vec![
        li(Reg::A0, 0x1_0000),
        li(Reg::A1, 0x1_0020),
        li(Reg::A2, BUF),
        ecall(1),
        li(Reg::A0, BUF),
        li(Reg::A1, 64),
        ecall(0),
    ];
    let mut exec = executor();
    // Find messages whose signatures carry recovery id 0 and 1, and check both
    // the raw and the Ethereum-style (27/28) encodings of the id.
    let mut seen = [false, false];
    let mut msg = [0u8; 32];
    let mut ro = Vec::new();
    for nonce in 0u8..=255 {
        msg = keccak256(&[b"message".as_slice(), &[nonce]].concat());
        let (sig, rid) = sk.sign_prehash_recoverable(&msg).unwrap();
        let id = rid.to_byte();
        if seen[id as usize] {
            continue;
        }
        seen[id as usize] = true;
        for v in [id, id + 27] {
            let mut sig65 = sig.to_bytes().to_vec();
            sig65.push(v);
            ro = msg.to_vec();
            ro.extend_from_slice(&sig65);
            let r = run(
                &mut exec,
                &module(&["output_write", "secp256k1_recover"], &body, &ro),
                b"",
                10_000,
            );
            assert_eq!(r.status, Termination::Halt);
            assert_eq!(r.output, expected, "recovery id {id}, v {v}");
        }
        if seen == [true, true] {
            break;
        }
    }
    assert_eq!(seen, [true, true], "both recovery ids exercised");
    let _ = msg;
    // Bad recovery id and an unrecoverable signature report InvalidArgument.
    for (patch_at, value) in [(32 + 64, 9u8), (32, 0xFFu8)] {
        let mut bad = ro.clone();
        bad[patch_at] = value;
        if patch_at == 32 {
            bad[32..64].fill(0xFF);
        }
        let mut body = vec![
            li(Reg::A0, 0x1_0000),
            li(Reg::A1, 0x1_0020),
            li(Reg::A2, BUF),
            ecall(1),
        ];
        body.extend(report());
        let r = run(
            &mut exec,
            &module(&["output_write", "secp256k1_recover"], &body, &bad),
            b"",
            10_000,
        );
        assert_eq!(regs(&r).0, u64::from(HostStatus::InvalidArgument.code()));
    }
    // P-256: valid signature verifies, a flipped message bit does not, garbage key does not.
    let psk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
    let psig: p256::ecdsa::Signature = psk.sign_prehash(&msg).unwrap();
    let pk = psk.verifying_key().to_encoded_point(false).as_bytes()[1..65].to_vec();
    let mut ro = msg.to_vec();
    ro.extend_from_slice(&psig.to_bytes());
    ro.extend_from_slice(&pk);
    let mut body = vec![
        li(Reg::A0, 0x1_0000),
        li(Reg::A1, 0x1_0020),
        li(Reg::A2, 0x1_0060),
        ecall(1),
    ];
    body.extend(report());
    let r = run(
        &mut exec,
        &module(&["output_write", "p256_verify"], &body, &ro),
        b"",
        10_000,
    );
    assert_eq!(regs(&r).0, 0, "valid");
    let mut flipped = ro.clone();
    flipped[0] ^= 1;
    let r = run(
        &mut exec,
        &module(&["output_write", "p256_verify"], &body, &flipped),
        b"",
        10_000,
    );
    assert_eq!(regs(&r).0, 1, "invalid");
    let mut badkey = ro.clone();
    badkey[0x60..0x60 + 64].fill(0);
    let r = run(
        &mut exec,
        &module(&["output_write", "p256_verify"], &body, &badkey),
        b"",
        10_000,
    );
    assert_eq!(regs(&r).0, 1, "garbage key");
}

/// A callee that stores input[0] under key "c", outputs "ok", and traps if input[0] == 0xFF.
fn callee() -> Vec<u8> {
    let body = vec![
        li(Reg::A0, BUF),
        li(Reg::A1, 0),
        li(Reg::A2, 1),
        ecall(INPUT_READ),
        li(Reg::A0, 0x1_0000),
        li(Reg::A1, 1),
        li(Reg::A2, BUF),
        li(Reg::A3, 1),
        ecall(STORAGE_SET),
        li(Reg::A0, 0x1_0001),
        li(Reg::A1, 2),
        ecall(OUTPUT_WRITE),
        li(Reg::A0, BUF),
        ld(Reg::A1, Reg::A0, 0),
        Instruction::AluImm {
            op: solo_vm::isa::AluImmOp::Andi,
            rd: Reg::A1,
            rs1: Reg::A1,
            imm: 0xFF,
        },
        li(Reg::A2, 0xFF),
        // Falls through to block 1 (halt) unless the byte was 0xFF, then block 2 (trap).
        Instruction::Branch {
            cond: solo_vm::isa::Cond::Eq,
            rs1: Reg::A1,
            rs2: Reg::A2,
            block: 2,
        },
    ];
    let mut b = ModuleBuilder::new().rodata(b"cok");
    for i in imports() {
        b.import(i);
    }
    b.block(&body);
    b.block(&[Instruction::Halt]);
    b.block(&[Instruction::Trap]);
    b.export("main", 0).build()
}

/// A caller: invoke(hash at rodata 0, namespace at rodata 32, input byte at rodata 64, gas = a4 const, flags) then
/// report a0/a1 and copy the callee output after them.
fn caller(gas: i64, flags: i64, input_off: i64) -> Vec<Instruction> {
    let body = vec![
        li(Reg::A0, 0x1_0000),
        li(Reg::A1, 0x1_0020),
        li(Reg::A2, 0x1_0000 + input_off),
        li(Reg::A3, 1),
        li(Reg::A4, gas),
        li(Reg::A5, flags),
        ecall(INVOKE),
        li(Reg::A7, BUF + 0x100),
        sd(Reg::A7, Reg::A0, 0),
        sd(Reg::A7, Reg::A1, 8),
        ecall(INVOKE_OUT_LEN),
        sd(Reg::A7, Reg::A0, 16),
        li(Reg::A0, BUF + 0x118),
        li(Reg::A1, 0),
        li(Reg::A2, 8),
        ecall(INVOKE_OUT_READ),
        li(Reg::A0, BUF + 0x100),
        li(Reg::A1, 26),
        ecall(OUTPUT_WRITE),
    ];
    body
}

#[test]
#[allow(clippy::too_many_lines)]
fn invoke_semantics() {
    let mut exec = executor();
    let callee_hash = load(&mut exec, &callee(), Capability::Sandboxed);
    let callee_ns = [0xCC; 32];
    let mut ro = callee_hash.to_vec();
    ro.extend_from_slice(&callee_ns);
    ro.push(0x42); // input byte at 64: stores 0x42
    ro.push(0xFF); // input byte at 65: callee traps
    let key = crate::storage::namespaced(&callee_ns, b"c");

    // Successful nested call: status 0, gas used reported, output "ok" visible, storage committed.
    let r = run(
        &mut exec,
        &module(&imports(), &caller(50_000, 0, 64), &ro),
        b"",
        200_000,
    );
    assert_eq!(r.status, Termination::Halt);
    let (status, used) = regs(&r);
    assert_eq!(status, 0);
    assert!(used > 500 && used < 5_000, "{used}");
    assert_eq!(u64::from_le_bytes(r.output[16..24].try_into().unwrap()), 2);
    assert_eq!(&r.output[24..26], b"ok");
    assert_eq!(exec.state().get(&key), Some(vec![0x42]));
    assert!(
        r.gas_used < 200_000 - 40_000,
        "unused callee gas was refunded: {}",
        r.gas_used
    );

    // Callee trap: status CalleeTrapped, its storage write discarded.
    exec.state_mut().delete(&key);
    let r = run(
        &mut exec,
        &module(&imports(), &caller(50_000, 0, 65), &ro),
        b"",
        200_000,
    );
    assert_eq!(regs(&r).0, u64::from(HostStatus::CalleeTrapped.code()));
    assert_eq!(exec.state().get(&key), None);

    // Static call: the callee's storage_set is a violation reported to the caller.
    let r = run(
        &mut exec,
        &module(&imports(), &caller(50_000, 2, 64), &ro),
        b"",
        200_000,
    );
    assert_eq!(regs(&r).0, u64::from(HostStatus::StaticViolation.code()));
    assert_eq!(exec.state().get(&key), None);

    // Callee out of gas: CalleeTrapped, and all of its limit is consumed.
    let r = run(
        &mut exec,
        &module(&imports(), &caller(100, 0, 64), &ro),
        b"",
        200_000,
    );
    let (status, used) = regs(&r);
    assert_eq!(status, u64::from(HostStatus::CalleeTrapped.code()));
    assert_eq!(used, 100);

    // Unknown code hash: NotFound.
    let mut unknown = ro.clone();
    unknown[0] ^= 1;
    let r = run(
        &mut exec,
        &module(&imports(), &caller(50_000, 0, 64), &unknown),
        b"",
        200_000,
    );
    assert_eq!(regs(&r).0, u64::from(HostStatus::NotFound.code()));

    // Gas limit beyond i64: InvalidArgument. Caller lacking the gas to lend: OutOfGas.
    let r = run(
        &mut exec,
        &module(&imports(), &caller(-1, 0, 64), &ro),
        b"",
        200_000,
    );
    assert_eq!(regs(&r).0, u64::from(HostStatus::InvalidArgument.code()));
    let r = run(
        &mut exec,
        &module(&imports(), &caller(50_000, 0, 64), &ro),
        b"",
        3_000,
    );
    assert_eq!(r.status, Termination::OutOfGas);

    // Depth limit.
    exec.set_max_depth(1);
    let r = run(
        &mut exec,
        &module(&imports(), &caller(50_000, 0, 64), &ro),
        b"",
        200_000,
    );
    assert_eq!(regs(&r).0, u64::from(HostStatus::DepthExceeded.code()));
    exec.set_max_depth(0);
    let r = run(
        &mut exec,
        &module(&imports(), &caller(50_000, 0, 64), &ro),
        b"",
        200_000,
    );
    assert_eq!(
        r.status,
        Termination::HostError(HostStatus::DepthExceeded.code())
    );
    assert_eq!(r.gas_used, 0);
    exec.set_max_depth(MAX_DEPTH);

    // Storage deletes inside a static frame are violations too.
    let bytes = module(
        &imports(),
        &[li(Reg::A0, 0x1_0000), li(Reg::A1, 2), ecall(STORAGE_DELETE)],
        &ro,
    );
    let hash = load(&mut exec, &bytes, Capability::Sandboxed);
    let r = exec.call(
        &hash,
        NS,
        b"",
        200_000,
        Capability::Sandboxed,
        Flags {
            privileged: false,
            static_call: true,
        },
    );
    assert_eq!(
        r.status,
        Termination::HostError(HostStatus::StaticViolation.code())
    );

    // A static caller may not make a non-static nested call.
    let bytes = module(&imports(), &caller(50_000, 0, 64), &ro);
    let hash = load(&mut exec, &bytes, Capability::Sandboxed);
    let r = exec.call(
        &hash,
        NS,
        b"",
        200_000,
        Capability::Sandboxed,
        Flags {
            privileged: false,
            static_call: true,
        },
    );
    assert_eq!(
        r.status,
        Termination::HostError(HostStatus::StaticViolation.code())
    );

    // Privileged flag is honoured only for privileged callers; a sandboxed caller's callee stays sandboxed
    // (its key is namespaced), a privileged caller's callee with the flag writes the bare key.
    let r = run(
        &mut exec,
        &module(&imports(), &caller(50_000, 1, 64), &ro),
        b"",
        200_000,
    );
    assert_eq!(regs(&r).0, 0);
    assert_eq!(exec.state().get(&key), Some(vec![0x42]));
    exec.state_mut().delete(&key);
    let bytes = module(&imports(), &caller(50_000, 1, 64), &ro);
    let hash = load(&mut exec, &bytes, Capability::Privileged);
    let r = exec.call(
        &hash,
        NS,
        b"",
        200_000,
        Capability::Privileged,
        Flags::default(),
    );
    assert_eq!(regs(&r).0, 0);
    assert_eq!(exec.state().get(b"c"), Some(vec![0x42]));
    assert_eq!(exec.state().get(&key), None);
}

#[test]
fn logs_metrics_and_call_errors() {
    let body = vec![
        li(Reg::A0, 3),
        li(Reg::A1, 0x1_0000),
        li(Reg::A2, 5),
        ecall(LOG),
        li(Reg::A0, 0x1_0000),
        li(Reg::A1, 5),
        li(Reg::A2, -7),
        li(Reg::A3, 1),
        ecall(METRIC),
    ];
    let mut exec = executor();
    let r = run(&mut exec, &module(&imports(), &body, b"hello"), b"", 10_000);
    assert_eq!(r.status, Termination::Halt);
    assert_eq!(exec.logs(), &[(3, b"hello".to_vec())]);
    let emitted = [("hello".to_owned(), -7, 1, Capability::Sandboxed)];
    assert_eq!(exec.metrics(), &emitted);
    assert_eq!(exec.take_metrics(), emitted.to_vec());
    assert!(exec.metrics().is_empty());
    // Unknown hash, unknown export, bad gas limit.
    let fail = |r: CallResult, s: HostStatus| {
        assert_eq!(r.status, Termination::HostError(s.code()));
        assert_eq!(r.gas_used, 0);
        assert!(r.output.is_empty());
    };
    fail(
        exec.call(
            &[1; 32],
            NS,
            b"",
            10,
            Capability::Sandboxed,
            Flags::default(),
        ),
        HostStatus::NotFound,
    );
    let bytes = module(&[], &[], &[]);
    let hash = load(&mut exec, &bytes, Capability::Sandboxed);
    fail(
        exec.call_export(
            &hash,
            "nope",
            NS,
            b"",
            10,
            Capability::Sandboxed,
            Flags::default(),
        ),
        HostStatus::NotFound,
    );
    fail(
        exec.call(&hash, NS, b"", -5, Capability::Sandboxed, Flags::default()),
        HostStatus::InvalidArgument,
    );
    let ok = exec.call(&hash, NS, b"", 10, Capability::Sandboxed, Flags::default());
    assert_eq!(ok.status, Termination::Halt);
    assert_eq!(exec.last_position(), Some((hash, 0, 0)));
    assert_eq!(ok.gas_used, 1);
    assert_eq!(ok.invoke_status(), HostStatus::Ok);
    assert!(ok.started);
    assert!(format!("{ok:?}").contains("Halt"));
    let not_started = CallResult {
        status: Termination::HostError(9),
        output: vec![],
        gas_used: 0,
        started: false,
    };
    assert_eq!(not_started.invoke_status(), HostStatus::InvalidArgument);
}

#[test]
fn unknown_handle_is_unavailable() {
    let mut exec = executor();
    let layout = ModuleBuilder::new().layout;
    let mut mem = Memory::new(layout, &[], &[]);
    let mut regs = [0u64; Reg::COUNT];
    let mut gas = 100;
    let mut ctx = HostContext {
        regs: &mut regs,
        memory: &mut mem,
        gas: &mut gas,
    };
    assert_eq!(
        abi::dispatch(&mut exec, 99, &mut ctx),
        Err(Termination::HostError(HostStatus::Unavailable.code()))
    );
}

#[test]
fn hello_guest_through_the_executor() {
    let elf = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../solo-recompile/tests/fixtures/hello.elf"
    ))
    .unwrap();
    let input = solo_recompile::Input::load(&elf).unwrap();
    let bytes = solo_recompile::recompile(&input, &solo_recompile::Options::default()).unwrap();
    let mut exec = executor();
    let hash = load(&mut exec, &bytes, Capability::Sandboxed);
    let r = exec.call(
        &hash,
        NS,
        b"",
        1_000_000,
        Capability::Sandboxed,
        Flags::default(),
    );
    assert_eq!(r.status, Termination::Halt);
    assert_eq!(r.output, keccak256(b"hello, solo"));
    assert!(r.gas_used > 100);
}

/// An extension serving `ext_double` (handle 100): a0 = 2 * a0, writing a marker key.
struct Doubler;

impl crate::executor::Extension<MemStorage> for Doubler {
    fn resolve(&self, name: &str, capability: Capability) -> Option<u32> {
        (name == "ext_double" && capability == Capability::Privileged).then_some(100)
    }

    fn call(
        &mut self,
        handle: u32,
        ctx: &mut HostContext<'_>,
        state: &mut crate::storage::Overlay<MemStorage>,
    ) -> Result<(), Termination> {
        assert_eq!(handle, 100);
        ctx.charge(1)?;
        let v = ctx.arg(Reg::A0);
        ctx.set(Reg::A0, v * 2);
        state.set(b"doubled", &v.to_le_bytes());
        Ok(())
    }
}

#[test]
fn extensions_serve_high_handles() {
    let mut exec = executor();
    // Without an extension the import does not resolve and a high handle is unavailable.
    assert!(
        exec.load(&module(&["ext_double"], &[], &[]), Capability::Privileged)
            .is_err()
    );
    let layout = ModuleBuilder::new().layout;
    let mut mem = Memory::new(layout, &[], &[]);
    let mut register_file = [0u64; Reg::COUNT];
    let mut gas = 100;
    let mut ctx = HostContext {
        regs: &mut register_file,
        memory: &mut mem,
        gas: &mut gas,
    };
    assert_eq!(
        solo_vm::host::Host::call(&mut exec, 100, &mut ctx),
        Err(Termination::HostError(HostStatus::Unavailable.code()))
    );
    assert!(exec.extension_mut().is_none());
    exec.set_extension(Box::new(Doubler));
    assert!(exec.extension_mut().is_some());
    assert!((exec.resolver())("ext_double", Capability::Privileged));
    assert!(!(exec.resolver())("ext_double", Capability::Sandboxed));
    assert!((exec.resolver())("abi_version", Capability::Sandboxed));
    let mut body = vec![li(Reg::A0, 21), ecall(1)];
    body.extend(report());
    let bytes = module(&["output_write", "ext_double"], &body, &[]);
    assert!(
        exec.load(&bytes, Capability::Sandboxed).is_err(),
        "privileged-only import"
    );
    let hash = exec.load(&bytes, Capability::Privileged).unwrap();
    assert_eq!(
        exec.load(&bytes, Capability::Privileged).unwrap(),
        hash,
        "second load is a no-op"
    );
    let r = exec.call(
        &hash,
        NS,
        b"",
        1_000,
        Capability::Privileged,
        Flags::default(),
    );
    assert_eq!(regs(&r).0, 42);
    assert_eq!(
        exec.state().get(b"doubled"),
        Some(21u64.to_le_bytes().to_vec())
    );
    assert_eq!(exec.cache_mut().cost_table(), CostTable::V1);
}
