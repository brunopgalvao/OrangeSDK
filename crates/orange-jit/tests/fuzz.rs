//! Seeded fuzzing of the native backend against the reference interpreter
//! (spec 07 §4.1), alongside the property test of `differential.rs`.
//!
//! Three harnesses, each from a fixed seed (see `orange-fuzz` for the long
//! mode): random modules from the builder compared on both backends; the
//! same modules rerun with the gas limit at every point around exhaustion,
//! so each backend runs out of gas at the same instruction; and the byte
//! encodings of those modules mutated, parsed, and when the parser accepts
//! them run on both backends, re-encoded and parsed again.

#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::many_single_char_names
)]

mod support;

use orange_fuzz::Rng;
use orange_jit::Compiled;
use orange_vm::builder::ModuleBuilder;
use orange_vm::gas::CostTable;
use orange_vm::host::{Capability, Host};
use orange_vm::isa::{AluImmOp, AluOp, Cond, Instruction, LoadWidth, Reg, StoreWidth};
use orange_vm::module::{Module, Program, SECTION_CODE, SECTION_JUMP_TABLE, SECTION_LAYOUT};
use support::{IMPORTS, Outcome, TestHost, VARIANTS, interp, native};

const ALU: [AluOp; 28] = [
    AluOp::Add,
    AluOp::Sub,
    AluOp::And,
    AluOp::Or,
    AluOp::Xor,
    AluOp::Sll,
    AluOp::Srl,
    AluOp::Sra,
    AluOp::Slt,
    AluOp::Sltu,
    AluOp::Mul,
    AluOp::Mulh,
    AluOp::Mulhsu,
    AluOp::Mulhu,
    AluOp::Div,
    AluOp::Divu,
    AluOp::Rem,
    AluOp::Remu,
    AluOp::Addw,
    AluOp::Subw,
    AluOp::Sllw,
    AluOp::Srlw,
    AluOp::Sraw,
    AluOp::Mulw,
    AluOp::Divw,
    AluOp::Divuw,
    AluOp::Remw,
    AluOp::Remuw,
];

const ALU_IMM: [AluImmOp; 13] = [
    AluImmOp::Addi,
    AluImmOp::Andi,
    AluImmOp::Ori,
    AluImmOp::Xori,
    AluImmOp::Slti,
    AluImmOp::Sltiu,
    AluImmOp::Slli,
    AluImmOp::Srli,
    AluImmOp::Srai,
    AluImmOp::Addiw,
    AluImmOp::Slliw,
    AluImmOp::Srliw,
    AluImmOp::Sraiw,
];

const LOADS: [LoadWidth; 7] = [
    LoadWidth::B,
    LoadWidth::Bu,
    LoadWidth::H,
    LoadWidth::Hu,
    LoadWidth::W,
    LoadWidth::Wu,
    LoadWidth::D,
];

const STORES: [StoreWidth; 4] = [StoreWidth::B, StoreWidth::H, StoreWidth::W, StoreWidth::D];

const CONDS: [Cond; 6] = [Cond::Eq, Cond::Ne, Cond::Lt, Cond::Ge, Cond::Ltu, Cond::Geu];

/// Rodata, data and bss sizes that end every region mid-page.
const RO: &[u8] = &[0x5A; 29];
const DATA: &[u8] = &[0x80, 0x7F, 0x01, 0xFE, 0x00, 0x33, 0x44];
const BSS: u32 = 21;

/// Addresses at and around every region boundary of the layout of [`base`].
const ANCHORS: &[u64] = &[
    0,
    0x1_0000,
    0x1_0000 + 29 - 8,
    0x1_0000 + 29,
    0x2_0000,
    0x2_0000 + 28 - 4,
    0x2_0000 + 28,
    0x3_0000,
    0x3_0000 + 4096 - 8,
    0x3_0000 + 4096,
    0x3_0000 + 8192,
    0xFFFD_E000 - 1,
    0xFFFD_E000,
    0xFFFD_FFF8,
    0xFFFE_0000,
    0xFFFF_FFFF,
    0x1_0000_0000,
];

const POOL: &[u8] = &[0, 1, 2, 3, 5, 7, 9, 10, 11, 12, 13, 17, 20, 26, 30, 31];

fn reg(r: &mut Rng) -> Reg {
    Reg::new(*r.pick(POOL)).unwrap()
}

fn nonzero(r: &mut Rng) -> Reg {
    Reg::new(*r.pick(&POOL[1..])).unwrap()
}

fn imm(r: &mut Rng) -> i64 {
    match r.below(4) {
        0 => r.below(64) as i64 - 32,
        1 => *r.pick(ANCHORS) as i64,
        _ => r.edgy() as i64,
    }
}

fn address(r: &mut Rng) -> i64 {
    (*r.pick(ANCHORS) as i64).wrapping_add(r.below(17) as i64 - 8)
}

/// The first `Li` of a two-instruction access so `R[rs1] + off` is an address.
fn aimed(r: &mut Rng, base: Reg) -> (Instruction, i64) {
    let off = r.below(33) as i64 - 16;
    let li = Instruction::Li {
        rd: base,
        imm: address(r).wrapping_sub(off),
    };
    (li, off)
}

fn body(r: &mut Rng, out: &mut Vec<Instruction>) {
    let imports = IMPORTS.len() as u64;
    match r.below(12) {
        0 => out.push(Instruction::Li {
            rd: reg(r),
            imm: imm(r),
        }),
        1 | 2 => {
            let op = *r.pick(&ALU_IMM);
            let v = imm(r);
            let imm = op.shift_limit().map_or(v, |l| v.rem_euclid(l + 1));
            out.push(Instruction::AluImm {
                op,
                rd: reg(r),
                rs1: reg(r),
                imm,
            });
        }
        3..=5 => out.push(Instruction::Alu {
            op: *r.pick(&ALU),
            rd: reg(r),
            rs1: reg(r),
            rs2: reg(r),
        }),
        6 => {
            let rs1 = nonzero(r);
            let (li, off) = aimed(r, rs1);
            out.push(li);
            out.push(Instruction::Load {
                width: *r.pick(&LOADS),
                rd: reg(r),
                rs1,
                off,
            });
        }
        7 => {
            let rs1 = nonzero(r);
            let (li, off) = aimed(r, rs1);
            out.push(li);
            out.push(Instruction::Store {
                width: *r.pick(&STORES),
                rs1,
                rs2: reg(r),
                off,
            });
        }
        8 => out.push(Instruction::Ecall {
            import: r.below(imports) as u32,
        }),
        9 => {
            let rs1 = nonzero(r);
            out.push(Instruction::Li {
                rd: rs1,
                imm: *r.pick(&[0, 1, 7, 4096, 4097, 0x2_0000, 0x10_0000, -1]),
            });
            out.push(Instruction::Sbrk { rd: reg(r), rs1 });
        }
        _ => {
            let (dst, src, len) = (nonzero(r), nonzero(r), nonzero(r));
            out.push(Instruction::Li {
                rd: dst,
                imm: address(r),
            });
            out.push(Instruction::Li {
                rd: src,
                imm: address(r),
            });
            out.push(Instruction::Li {
                rd: len,
                imm: *r.pick(&[0, 1, 8, 31, 64, 4096, 5000]),
            });
            if r.chance(1, 2) {
                out.push(Instruction::Memcopy { dst, src, len });
            } else {
                out.push(Instruction::Memfill { dst, val: src, len });
            }
        }
    }
}

/// A slot address in a module of `n` blocks where block `b` has slot `b + 1`.
fn slot_address(r: &mut Rng, n: u64) -> i64 {
    match r.below(6) {
        0..=2 => 8 * (r.below(n) as i64 + 1),
        3 => 8 * (n as i64 + 1),
        4 => 8 * (r.below(n) as i64 + 1) + r.below(7) as i64 + 1,
        _ => r.edgy() as i64,
    }
}

fn terminator(r: &mut Rng, cur: u64, n: u64, out: &mut Vec<Instruction>) {
    let last = cur + 1 == n;
    let cont = (cur + 2) as u32;
    let choice = r.below(if last { 4 } else { 9 });
    match choice {
        0 => out.push(Instruction::Halt),
        1 => out.push(Instruction::Trap),
        2 => out.push(Instruction::Jump {
            block: r.below(n) as u32,
        }),
        3 => {
            let rs1 = nonzero(r);
            let off = r.below(5) as i64 - 2;
            out.push(Instruction::Li {
                rd: rs1,
                imm: slot_address(r, n).wrapping_sub(off),
            });
            out.push(Instruction::JumpIndirect { rs1, off });
        }
        4 => {}
        5 | 6 => out.push(Instruction::Branch {
            cond: *r.pick(&CONDS),
            rs1: reg(r),
            rs2: reg(r),
            block: r.below(n) as u32,
        }),
        7 => out.push(Instruction::Call {
            rd: reg(r),
            block: r.below(n) as u32,
            slot: cont,
        }),
        _ => {
            let rs1 = nonzero(r);
            let off = r.below(5) as i64 - 2;
            out.push(Instruction::Li {
                rd: rs1,
                imm: slot_address(r, n).wrapping_sub(off),
            });
            out.push(Instruction::CallIndirect {
                rd: reg(r),
                rs1,
                off,
                slot: cont,
            });
        }
    }
}

/// A random valid module of up to 10 blocks, exporting `entry`.
fn module(r: &mut Rng) -> ModuleBuilder {
    let mut b = ModuleBuilder::new().rodata(RO).data(DATA);
    b.layout.bss_size = BSS;
    b.layout.stack_base = 0xFFFD_E000;
    for name in IMPORTS {
        b.import(name);
    }
    let n = 1 + r.below(10);
    for i in 0..n {
        b.slot(i as u32);
    }
    b.jump_table.push(None);
    for cur in 0..n {
        let mut code = Vec::new();
        for _ in 0..r.below(9) {
            body(r, &mut code);
        }
        terminator(r, cur, n, &mut code);
        if code.is_empty() {
            code.push(Instruction::Li {
                rd: Reg::ZERO,
                imm: 0,
            });
        }
        b.block(&code);
    }
    b.export("entry", r.below(n) as u32)
}

fn args(r: &mut Rng) -> Vec<u64> {
    (0..6)
        .map(|_| {
            if r.chance(1, 2) {
                *r.pick(ANCHORS)
            } else {
                r.edgy()
            }
        })
        .collect()
}

/// Parses `bytes` against the test host's imports without panicking.
fn parse(bytes: &[u8]) -> Option<Module> {
    let host = TestHost::default();
    Module::parse(bytes, &|n| {
        host.resolve(n, Capability::Privileged).is_some()
    })
    .ok()
}

/// Both backends, every register variant, on one entry: the same outcome.
fn agree(p: &Program, compiled: &[Compiled], entry: &str, args: &[u64], gas: i64) -> Outcome {
    let expected = interp(p, entry, args, gas);
    for (c, o) in compiled.iter().zip(VARIANTS) {
        assert_eq!(native(c, entry, args, gas), expected, "{o:?} gas {gas}");
    }
    expected
}

fn compile_all(p: &Program) -> Vec<Compiled> {
    VARIANTS
        .iter()
        .map(|o| Compiled::with_options(p, *o).expect("a valid program compiles"))
        .collect()
}

/// The builder that re-encodes a parsed module.
fn rebuild(m: &Module) -> ModuleBuilder {
    let mut b = ModuleBuilder::new();
    b.layout = m.layout;
    b.rodata.clone_from(&m.rodata);
    b.data.clone_from(&m.data);
    b.imports.clone_from(&m.imports);
    b.exports.clone_from(&m.exports);
    b.jump_table.clone_from(&m.jump_table);
    b.blocks.clone_from(&m.blocks);
    b.debug.clone_from(&m.debug);
    b
}

#[test]
fn random_modules_agree_on_both_backends() {
    orange_fuzz::run("jit-modules", 150, |r| {
        let p = Program::new(parse(&module(r).build()).unwrap(), CostTable::V1);
        let compiled = compile_all(&p);
        for _ in 0..3 {
            let gas = *r.pick(&[0, 1, 50, 300, 2_000, 1_000_000]);
            agree(&p, &compiled, "entry", &args(r), gas);
        }
    });
}

#[test]
fn gas_runs_out_at_the_same_instruction_on_both_backends() {
    orange_fuzz::run("jit-gas-edges", 60, |r| {
        let p = Program::new(parse(&module(r).build()).unwrap(), CostTable::V1);
        let compiled = compile_all(&p);
        let a = args(r);
        let full = agree(&p, &compiled, "entry", &a, 100_000);
        let used = 100_000 - full.gas.max(0);
        // Every limit from a little below what the run used to just above
        // it, plus a spread of points through the run.
        let mut limits: Vec<i64> = (used - 12..=used + 2).filter(|g| *g >= 0).collect();
        limits.extend((0..8).map(|_| r.below(used as u64 + 1) as i64));
        for gas in limits {
            agree(&p, &compiled, "entry", &a, gas);
        }
    });
}

#[test]
fn mutated_module_bytes_parse_cleanly_and_agree_when_accepted() {
    let mut accepted = 0u32;
    orange_fuzz::run("jit-mutated-bytes", 1_000, |r| {
        let mut b = module(r);
        // Half the time edit only one section's payload, so the section
        // framing survives and the edit reaches that section's own checks.
        let mutated = if r.chance(1, 2) {
            let (id, payload) = match r.below(3) {
                0 => (SECTION_CODE, b.code_bytes()),
                1 => (SECTION_JUMP_TABLE, b.jump_table_bytes()),
                _ => (SECTION_LAYOUT, b.layout_bytes()),
            };
            let mut edited = payload.clone();
            let at = r.index(edited.len());
            edited[at] = if r.chance(1, 2) {
                r.u64() as u8
            } else {
                edited[at] ^ (1 << r.below(8))
            };
            b.raw_overrides.insert(id, edited);
            b.build()
        } else {
            r.mutate(&b.build())
        };
        let Some(m) = parse(&mutated) else { return };
        accepted += 1;
        // An accepted module re-encodes to one that parses to itself.
        assert_eq!(parse(&rebuild(&m).build()).as_ref(), Some(&m));
        // A valid layout may ask for a stack of up to 2 GiB (spec 01 §9);
        // zeroing and digesting that is slow, and checks nothing new.
        if m.layout.stack_top - m.layout.stack_base > 1 << 20 {
            return;
        }
        let p = Program::new(m, CostTable::V1);
        let compiled = compile_all(&p);
        let exports: Vec<String> = p.module.exports.iter().map(|(n, _)| n.clone()).collect();
        for name in exports {
            let host = TestHost::default();
            let i =
                orange_vm::interp::Instance::new(&p, &host, Capability::Privileged, &name, &[], 10);
            let j = orange_jit::Instance::new(
                &compiled[0],
                &host,
                Capability::Privileged,
                &name,
                &[],
                10,
            );
            assert_eq!(i.is_ok(), j.is_ok());
            if i.is_ok() {
                agree(&p, &compiled, &name, &args(r), 5_000);
            }
        }
    });
    // The mutations must leave a fair share of modules valid, or the run
    // compares nothing.
    assert!(accepted > 100, "only {accepted} mutated modules parsed");
}

#[test]
fn random_bytes_never_panic_the_parser() {
    orange_fuzz::run("jit-random-bytes", 2_000, |r| {
        let len = r.index(200);
        let mut bytes = r.bytes(len);
        if r.chance(1, 2) && len >= 8 {
            // A valid header, so the parse gets past the magic.
            bytes[..8].copy_from_slice(&ModuleBuilder::new().header);
        }
        let _ = parse(&bytes);
    });
}
