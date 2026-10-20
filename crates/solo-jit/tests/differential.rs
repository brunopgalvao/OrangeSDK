//! The native backend against the reference interpreter (spec 07 §4).
//!
//! Two kinds of test: a property test that generates random valid modules
//! (instruction mixes, loops, calls, indirect jumps to good and bad slots,
//! loads and stores around every region boundary, host calls, gas limits
//! that run out anywhere) and compares every observable result; and
//! deterministic tables that put every instruction through its edge values
//! with every kind of operand register, so that each lowering path is
//! exercised on every run whatever the random seed.

#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]

mod support;

use proptest::prelude::*;
use solo_jit::{Compiled, Options};
use solo_vm::builder::ModuleBuilder;
use solo_vm::isa::{AluImmOp, AluOp, Cond, Instruction, LoadWidth, Reg, StoreWidth};
use solo_vm::module::Program;
use solo_vm::status::Termination;
use support::{IMPORTS, Outcome, VARIANTS, interp, native, program, same, same_b};

fn r(i: u8) -> Reg {
    Reg::new(i).unwrap()
}

const A0: Reg = Reg::A0;
const A1: Reg = Reg::A1;
const A2: Reg = Reg::A2;
const A3: Reg = Reg::A3;
const A4: Reg = Reg::A4;
const A5: Reg = Reg::A5;

/// Rodata, data and bss sizes that leave every region end mid-page.
const RO: &[u8] = &[0x81; 37];
const DATA: &[u8] = &[
    0x7F, 0x01, 0xFF, 0x80, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
];
const BSS: u32 = 13;

/// A builder with the layout every generated module uses: rodata at
/// `0x1_0000`, data and bss at `0x2_0000`, heap at `0x3_0000` (1 MiB max),
/// stack `0xFFFD_E000..0xFFFE_0000` (8 KiB), and every test import.
fn base() -> ModuleBuilder {
    let mut b = ModuleBuilder::new().rodata(RO).data(DATA);
    b.layout.bss_size = BSS;
    b.layout.stack_base = 0xFFFD_E000;
    for name in IMPORTS {
        b.import(name);
    }
    b
}

/// Addresses at and around every region boundary.
const ANCHORS: &[u64] = &[
    0,
    0xFFFF,
    0x1_0000,
    0x1_0000 + 37 - 8,
    0x1_0000 + 37 - 1,
    0x1_0000 + 37,
    0x2_0000,
    0x2_0000 + 24 - 8,
    0x2_0000 + 24 - 3,
    0x2_0000 + 24,
    0x3_0000,
    0x3_0000 + 4096 - 4,
    0x3_0000 + 4096,
    0xFFFD_DFFF,
    0xFFFD_E000,
    0xFFFD_FFF8,
    0xFFFD_FFFC,
    0xFFFE_0000,
    0xFFFF_0000,
    0xFFFF_FFFF,
    0x1_0002_0000,
    0xFFFF_FFFF_FFFD_FFF0,
];

const EDGES: &[i64] = &[
    0,
    1,
    -1,
    2,
    31,
    32,
    63,
    64,
    0xFFF,
    0x1000,
    -0xFFF,
    -0x1000,
    0xFFFF,
    0x1_0000,
    i32::MAX as i64,
    i32::MIN as i64,
    0xFFFF_FFFF,
    0x1_0000_0000,
    i64::MAX,
    i64::MIN,
    0x1234_5678_9ABC_DEF0,
    -0x1234_5678_9ABC_DEF0,
];

const POOL: &[u8] = &[0, 1, 2, 5, 6, 8, 10, 11, 12, 13, 14, 15, 18, 27, 28, 31];

fn reg() -> impl Strategy<Value = Reg> {
    prop::sample::select(POOL).prop_map(r)
}

fn nonzero_reg() -> impl Strategy<Value = Reg> {
    prop::sample::select(&POOL[1..]).prop_map(r)
}

fn imm() -> impl Strategy<Value = i64> {
    prop_oneof![
        3 => -20i64..20,
        3 => prop::sample::select(EDGES),
        2 => any::<i64>(),
        2 => prop::sample::select(ANCHORS).prop_map(|a| a as i64),
    ]
}

fn address() -> impl Strategy<Value = i64> {
    (prop::sample::select(ANCHORS), -9i64..9).prop_map(|(a, d)| (a as i64).wrapping_add(d))
}

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

/// An immediate valid for `op` (shift amounts are range-checked at load).
fn fit(op: AluImmOp, imm: i64) -> i64 {
    op.shift_limit().map_or(imm, |l| imm.rem_euclid(l + 1))
}

/// One body item: a few instructions that never end a block.
fn body_item() -> impl Strategy<Value = Vec<Instruction>> {
    let imports = u32::try_from(IMPORTS.len()).unwrap();
    prop_oneof![
        3 => (reg(), imm()).prop_map(|(rd, imm)| vec![Instruction::Li { rd, imm }]),
        5 => (prop::sample::select(ALU_IMM.to_vec()), reg(), reg(), imm()).prop_map(
            |(op, rd, rs1, imm)| vec![Instruction::AluImm { op, rd, rs1, imm: fit(op, imm) }]
        ),
        7 => (prop::sample::select(ALU.to_vec()), reg(), reg(), reg())
            .prop_map(|(op, rd, rs1, rs2)| vec![Instruction::Alu { op, rd, rs1, rs2 }]),
        4 => (prop::sample::select(LOADS.to_vec()), reg(), nonzero_reg(), address(), -9i64..9).prop_map(
            |(width, rd, rs1, a, off)| vec![
                Instruction::Li { rd: rs1, imm: a.wrapping_sub(off) },
                Instruction::Load { width, rd, rs1, off },
            ]
        ),
        1 => (prop::sample::select(LOADS.to_vec()), reg(), reg(), imm())
            .prop_map(|(width, rd, rs1, off)| vec![Instruction::Load { width, rd, rs1, off }]),
        4 => (prop::sample::select(STORES.to_vec()), nonzero_reg(), reg(), address(), -9i64..9).prop_map(
            |(width, rs1, rs2, a, off)| vec![
                Instruction::Li { rd: rs1, imm: a.wrapping_sub(off) },
                Instruction::Store { width, rs1, rs2, off },
            ]
        ),
        2 => (0..imports).prop_map(|import| vec![Instruction::Ecall { import }]),
        1 => (reg(), nonzero_reg(), prop::sample::select(vec![0i64, 1, 4096, 5000, 0x10_0000, -1]))
            .prop_map(|(rd, rs1, n)| vec![
                Instruction::Li { rd: rs1, imm: n },
                Instruction::Sbrk { rd, rs1 },
            ]),
        1 => (nonzero_reg(), nonzero_reg(), nonzero_reg(), address(), address(), 0i64..80).prop_map(
            |(dst, src, len, d, s, n)| vec![
                Instruction::Li { rd: dst, imm: d },
                Instruction::Li { rd: src, imm: s },
                Instruction::Li { rd: len, imm: n },
                Instruction::Memcopy { dst, src, len },
            ]
        ),
        1 => (nonzero_reg(), reg(), nonzero_reg(), address(), 0i64..80).prop_map(
            |(dst, val, len, d, n)| vec![
                Instruction::Li { rd: dst, imm: d },
                Instruction::Li { rd: len, imm: n },
                Instruction::Memfill { dst, val, len },
            ]
        ),
    ]
}

/// A slot address for an indirect jump in a module of `n` blocks, where the
/// slot of block `b` is `b + 1` and slot `n + 1` is empty.
fn slot_address(n: usize) -> impl Strategy<Value = i64> {
    let n = n as i64;
    prop_oneof![
        4 => (0..n).prop_map(|b| 8 * (b + 1)),
        1 => Just(8 * (n + 1)),
        1 => Just(8 * (n + 2)),
        1 => Just(0),
        1 => (0..n, 1i64..8).prop_map(|(b, m)| 8 * (b + 1) + m),
        1 => any::<i64>(),
    ]
}

/// The end of block `cur` of `n`. Only the last block is forbidden to fall
/// through; calls need a following block for their continuation.
fn terminator(cur: usize, n: usize) -> impl Strategy<Value = Vec<Instruction>> {
    let last = cur + 1 == n;
    let nb = u32::try_from(n).unwrap();
    let cont = u32::try_from(cur + 2).unwrap();
    let target = 0..nb;
    let mut options: Vec<(u32, BoxedStrategy<Vec<Instruction>>)> = vec![
        (2, Just(vec![Instruction::Halt]).boxed()),
        (1, Just(vec![Instruction::Trap]).boxed()),
        (
            2,
            target
                .clone()
                .prop_map(|block| vec![Instruction::Jump { block }])
                .boxed(),
        ),
        (
            2,
            (nonzero_reg(), slot_address(n), -2i64..3)
                .prop_map(|(rs1, a, off)| {
                    vec![
                        Instruction::Li {
                            rd: rs1,
                            imm: a.wrapping_sub(off),
                        },
                        Instruction::JumpIndirect { rs1, off },
                    ]
                })
                .boxed(),
        ),
    ];
    if !last {
        options.push((2, Just(vec![]).boxed()));
        options.push((
            4,
            (
                prop::sample::select(CONDS.to_vec()),
                reg(),
                reg(),
                target.clone(),
            )
                .prop_map(|(cond, rs1, rs2, block)| {
                    vec![Instruction::Branch {
                        cond,
                        rs1,
                        rs2,
                        block,
                    }]
                })
                .boxed(),
        ));
        options.push((
            2,
            (reg(), target)
                .prop_map(move |(rd, block)| {
                    vec![Instruction::Call {
                        rd,
                        block,
                        slot: cont,
                    }]
                })
                .boxed(),
        ));
        options.push((
            2,
            (reg(), nonzero_reg(), slot_address(n), -2i64..3)
                .prop_map(move |(rd, rs1, a, off)| {
                    vec![
                        Instruction::Li {
                            rd: rs1,
                            imm: a.wrapping_sub(off),
                        },
                        Instruction::CallIndirect {
                            rd,
                            rs1,
                            off,
                            slot: cont,
                        },
                    ]
                })
                .boxed(),
        ));
    }
    prop::strategy::Union::new_weighted(options)
}

fn block(cur: usize, n: usize) -> impl Strategy<Value = Vec<Instruction>> {
    (prop::collection::vec(body_item(), 0..7), terminator(cur, n)).prop_map(|(body, end)| {
        let mut v: Vec<Instruction> = body.into_iter().flatten().collect();
        v.extend(end);
        v
    })
}

#[derive(Debug, Clone)]
struct Case {
    blocks: Vec<Vec<Instruction>>,
    entry: u32,
    args: Vec<u64>,
    gas: i64,
}

impl Case {
    fn builder(&self) -> ModuleBuilder {
        let mut b = base();
        let n = u32::try_from(self.blocks.len()).unwrap();
        for i in 0..n {
            b.slot(i);
        }
        b.jump_table.push(None);
        let mut b = b.export("main", 0).export("entry", self.entry);
        for code in &self.blocks {
            // A generated block may be empty (fall-through only); give it one
            // instruction so the layout stays one block per item.
            if code.is_empty() {
                b.block(&[Instruction::Li {
                    rd: Reg::ZERO,
                    imm: 0,
                }]);
            } else {
                b.block(code);
            }
        }
        b
    }
}

fn case() -> impl Strategy<Value = Case> {
    (1usize..7)
        .prop_flat_map(|n| {
            (
                (0..n).map(|i| block(i, n)).collect::<Vec<_>>(),
                0..u32::try_from(n).unwrap(),
                prop::collection::vec(prop_oneof![any::<u64>(), prop::sample::select(ANCHORS)], 6),
                prop_oneof![0i64..400, 400i64..4000, Just(1_000_000)],
            )
        })
        .prop_map(|(blocks, entry, args, gas)| Case {
            blocks,
            entry,
            args,
            gas,
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 400, ..ProptestConfig::default() })]

    #[test]
    fn random_modules_agree(case in case()) {
        let p = program(&case.builder());
        let expected = interp(&p, "entry", &case.args, case.gas);
        for options in VARIANTS {
            let c = Compiled::with_options(&p, options).unwrap();
            prop_assert_eq!(&native(&c, "entry", &case.args, case.gas), &expected, "{:?}", options);
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic tables.

const VALUES: &[(u64, u64)] = &[
    (0, 0),
    (1, u64::MAX),
    (7, 0),
    (u64::MAX - 6, 2),
    (1 << 63, u64::MAX),
    (1 << 63, 1),
    (0x8000_0000, 0xFFFF_FFFF),
    (0xFFFF_FFFF_8000_0000, 0xFFFF_FFFF_FFFF_FFFF),
    (u64::MAX, u64::MAX),
    (0x1234_5678_9ABC_DEF0, 37),
    (5, 64 + 3),
    (i64::MAX as u64, 2),
    (1 << 32, (1 << 32) + 1),
    (0xFFFF_FFF9, 2),
    (0x8000_0000, 0),
];

/// Compiles every variant once and runs each `args` on all of them.
fn same_all(p: &Program, cases: &[Vec<u64>]) {
    let compiled: Vec<Compiled> = VARIANTS
        .iter()
        .map(|o| Compiled::with_options(p, *o).unwrap())
        .collect();
    for args in cases {
        let expected = interp(p, "main", args, 1000);
        for (c, o) in compiled.iter().zip(VARIANTS) {
            assert_eq!(
                native(c, "main", args, 1000),
                expected,
                "{o:?} {args:x?}\n{:?}",
                p.module.blocks
            );
        }
    }
}

/// Copies `a0` into `rs1` and `a1` into `rs2` (when they are other
/// registers), then runs `ins`.
fn with_sources(rs1: Reg, rs2: Reg, ins: Instruction) -> ModuleBuilder {
    let mut code = Vec::new();
    for (dst, src) in [(rs1, A0), (rs2, A1)] {
        if dst != Reg::ZERO && dst != src && dst != A0 && dst != A1 {
            code.push(Instruction::AluImm {
                op: AluImmOp::Addi,
                rd: dst,
                rs1: src,
                imm: 0,
            });
        }
    }
    code.push(ins);
    code.push(Instruction::Halt);
    let mut b = base();
    b.block(&code);
    b.export("main", 0)
}

/// `(rd, rs1, rs2)` shapes: distinct, aliased destination, both sources the
/// same, register 0 in each position, and registers rarely mapped.
fn shapes() -> Vec<(Reg, Reg, Reg)> {
    vec![
        (A2, A0, A1),
        (A0, A0, A1),
        (A1, A0, A1),
        (A2, A0, A0),
        (Reg::ZERO, A0, A1),
        (A2, Reg::ZERO, A1),
        (A2, A0, Reg::ZERO),
        (r(31), r(30), r(29)),
    ]
}

fn value_args() -> Vec<Vec<u64>> {
    VALUES.iter().map(|&(a, b)| vec![a, b]).collect()
}

#[test]
fn register_register_operations() {
    for op in ALU {
        for (rd, rs1, rs2) in shapes() {
            let b = with_sources(rs1, rs2, Instruction::Alu { op, rd, rs1, rs2 });
            same_all(&program(&b), &value_args());
        }
    }
}

#[test]
fn register_immediate_operations() {
    for op in ALU_IMM {
        for &imm in EDGES {
            for (rd, rs1, _) in shapes() {
                let imm = fit(op, imm);
                let b = with_sources(rs1, A1, Instruction::AluImm { op, rd, rs1, imm });
                same_all(&program(&b), &value_args()[..6]);
            }
        }
    }
}

#[test]
fn constants() {
    let mut values: Vec<i64> = EDGES.to_vec();
    values.extend([
        0xFFFF_0000_FFFF_0005u64 as i64,
        0x0001_0000_0000_0002,
        0xFFFF_FFFF_FFFF_1234u64 as i64,
        0x0000_FFFF_0000_0000,
    ]);
    for imm in values {
        for rd in [A0, Reg::ZERO, r(31)] {
            let mut b = base();
            b.block(&[Instruction::Li { rd, imm }, Instruction::Halt]);
            same_b(&b.export("main", 0), &[], 100);
        }
    }
}

#[test]
fn loads_and_stores_at_every_boundary() {
    let mut offsets: Vec<i64> = vec![0, 1, -1, 7, -8, 0xFFF, -0xFFF, 0x1000, -0x1000];
    offsets.extend([0x7FFF_FFFF, -0x8000_0000, 0x1_0000_0000]);
    let mut b = base();
    let mut code = Vec::new();
    for width in LOADS {
        for rd in [A2, Reg::ZERO, r(31)] {
            code.push(Instruction::Load {
                width,
                rd,
                rs1: A0,
                off: 0,
            });
        }
    }
    code.push(Instruction::Halt);
    b.block(&code);
    let loads = program(&b.export("main", 0));
    let mut b = base();
    let mut code = Vec::new();
    for width in STORES {
        for rs2 in [A1, Reg::ZERO, r(31)] {
            code.push(Instruction::Store {
                width,
                rs1: A0,
                rs2,
                off: 0,
            });
        }
    }
    code.push(Instruction::Halt);
    b.block(&code);
    let stores = program(&b.export("main", 0));
    let mut cases = Vec::new();
    for &a in ANCHORS {
        for d in -9i64..9 {
            cases.push(vec![a.wrapping_add(d as u64), 0x8877_6655_4433_2211]);
        }
    }
    same_all(&loads, &cases);
    same_all(&stores, &cases);
    // Every offset form, with a register base and with register 0.
    for off in offsets {
        for rs1 in [A0, Reg::ZERO, r(31)] {
            for width in [LoadWidth::D, LoadWidth::B] {
                let b = with_sources(
                    rs1,
                    A1,
                    Instruction::Load {
                        width,
                        rd: A2,
                        rs1,
                        off,
                    },
                );
                let p = program(&b);
                let base = 0x2_0004i64.wrapping_sub(off) as u64;
                same_all(
                    &p,
                    &[vec![base], vec![0xFFFD_FFF8u64.wrapping_sub(off as u64)]],
                );
            }
            let b = with_sources(
                rs1,
                A1,
                Instruction::Store {
                    width: StoreWidth::W,
                    rs1,
                    rs2: A1,
                    off,
                },
            );
            same_all(
                &program(&b),
                &[vec![0xFFFD_E100u64.wrapping_sub(off as u64), 0xABCD]],
            );
        }
    }
}

/// Block 0 branches on `cond` to block 2, else falls into block 1.
#[test]
fn branches_forward_and_backward() {
    for cond in CONDS {
        for (rs1, rs2) in [(A0, A1), (A0, Reg::ZERO), (Reg::ZERO, A1), (r(31), r(30))] {
            let mut b = base();
            let mut code = Vec::new();
            for (dst, src) in [(r(31), A0), (r(30), A1)] {
                code.push(Instruction::AluImm {
                    op: AluImmOp::Addi,
                    rd: dst,
                    rs1: src,
                    imm: 0,
                });
            }
            code.push(Instruction::Branch {
                cond,
                rs1,
                rs2,
                block: 2,
            });
            b.block(&code);
            b.block(&[Instruction::Li { rd: A2, imm: 1 }, Instruction::Halt]);
            b.block(&[Instruction::Li { rd: A2, imm: 2 }, Instruction::Halt]);
            same_all(&program(&b.export("main", 0)), &value_args());
        }
        // A loop: count a0 down by a1 while `cond` holds against a2.
        let mut b = base();
        b.block(&[Instruction::Li { rd: A2, imm: 0 }]);
        b.block(&[
            Instruction::Alu {
                op: AluOp::Sub,
                rd: A0,
                rs1: A0,
                rs2: A1,
            },
            Instruction::AluImm {
                op: AluImmOp::Addi,
                rd: r(5),
                rs1: r(5),
                imm: 1,
            },
            Instruction::Branch {
                cond,
                rs1: A0,
                rs2: A2,
                block: 1,
            },
        ]);
        b.block(&[Instruction::Halt]);
        let p = program(&b.export("main", 0));
        same_all(
            &p,
            &[vec![10, 1], vec![10, 3], vec![u64::MAX, 1], vec![0, 0]],
        );
    }
}

#[test]
fn calls_and_indirect_jumps() {
    // call f; f adds 10 and returns through the link register.
    for link in [Reg::RA, r(31), Reg::ZERO] {
        let mut b = base();
        let cont = b.slot(1);
        let f = b.slot(2);
        b.block(&[Instruction::Call {
            rd: link,
            block: 2,
            slot: cont,
        }]);
        b.block(&[Instruction::Halt]);
        b.block(&[
            Instruction::AluImm {
                op: AluImmOp::Addi,
                rd: A0,
                rs1: A0,
                imm: 10,
            },
            Instruction::JumpIndirect { rs1: link, off: 0 },
        ]);
        same_b(&b.clone().export("main", 0), &[5], 100);
        // call_indirect through a pointer in the link register itself, a
        // pointer in another register, and with the link discarded.
        for (rd, rs1) in [(link, link), (A3, A4), (Reg::ZERO, A4), (r(31), r(31))] {
            let mut b = b.clone();
            b.blocks[0] = vec![
                Instruction::Li {
                    rd: rs1,
                    imm: 8 * i64::from(f) + 4,
                },
                Instruction::CallIndirect {
                    rd,
                    rs1,
                    off: -4,
                    slot: cont,
                },
            ];
            b.blocks[2][1] = Instruction::JumpIndirect { rs1: rd, off: 0 };
            same_b(&b.export("main", 0), &[5], 100);
        }
    }
    // Every kind of bad slot address, through each base kind.
    for bad in [0i64, 4, 8 * 3, 8 * 50, 1 << 40, -8] {
        for rs1 in [A0, r(31), Reg::ZERO] {
            let mut b = base();
            b.slot(1);
            b.jump_table.push(None);
            b.block(&[
                Instruction::Li { rd: rs1, imm: bad },
                Instruction::JumpIndirect { rs1, off: 0 },
            ]);
            b.block(&[Instruction::Halt]);
            same_b(&b.export("main", 0), &[], 100);
        }
    }
    // An address with high bits set still names its slot (spec 01 §3.1).
    let mut b = base();
    let s = b.slot(1);
    b.block(&[
        Instruction::Li {
            rd: A0,
            imm: 8 * i64::from(s) + (1 << 40),
        },
        Instruction::JumpIndirect { rs1: A0, off: 0 },
    ]);
    b.block(&[Instruction::Halt]);
    assert_eq!(
        same_b(&b.export("main", 0), &[], 100).status,
        Termination::Halt
    );
}

#[test]
fn gas_runs_out_at_the_same_block_entry() {
    // A loop costing 3 per iteration, then a halt block costing 1.
    let mut b = base();
    b.block(&[
        Instruction::AluImm {
            op: AluImmOp::Addi,
            rd: A0,
            rs1: A0,
            imm: -1,
        },
        Instruction::Branch {
            cond: Cond::Ne,
            rs1: A0,
            rs2: Reg::ZERO,
            block: 0,
        },
    ]);
    b.block(&[Instruction::Halt]);
    let p = program(&b.export("main", 0));
    for gas in 0..20 {
        let o = same(&p, "main", &[4], gas);
        assert_eq!(o.status == Termination::Halt, gas >= 13);
    }
    // A block dearer than an immediate operand: 250 divisions cost 5000.
    let mut b = base();
    let mut code = vec![
        Instruction::Alu {
            op: AluOp::Div,
            rd: A0,
            rs1: A0,
            rs2: A1,
        };
        250
    ];
    code.push(Instruction::Halt);
    b.block(&code);
    let p = program(&b.export("main", 0));
    for gas in [0, 4999, 5000, 5001, 1_000_000] {
        same(&p, "main", &[1 << 40, 3], gas);
    }
}

#[test]
fn sites_sbrk_memcopy_memfill() {
    let mut b = base();
    b.block(&[
        Instruction::Sbrk {
            rd: A2,
            rs1: Reg::ZERO,
        },
        Instruction::Sbrk { rd: A3, rs1: A0 },
        Instruction::Sbrk {
            rd: Reg::ZERO,
            rs1: A0,
        },
        Instruction::Sbrk { rd: r(31), rs1: A1 },
        Instruction::Store {
            width: StoreWidth::D,
            rs1: A3,
            rs2: A3,
            off: 0,
        },
        Instruction::Load {
            width: LoadWidth::D,
            rd: A4,
            rs1: A3,
            off: 0,
        },
        Instruction::Halt,
    ]);
    let p = program(&b.export("main", 0));
    for args in [[1u64, 0x20_0000], [4096, 1], [0x10_0000, 0], [5000, 4096]] {
        for gas in [10, 40, 300, 600, 1_000_000] {
            same(&p, "main", &args, gas);
        }
    }
    // memcopy and memfill: ok, overlapping, zero length anywhere, faults,
    // and dynamic charges that run out.
    let mut b = base();
    b.block(&[
        Instruction::Memcopy {
            dst: A0,
            src: A1,
            len: A2,
        },
        Instruction::Memfill {
            dst: A3,
            val: A4,
            len: A2,
        },
        Instruction::Memcopy {
            dst: r(31),
            src: A1,
            len: Reg::ZERO,
        },
        Instruction::Halt,
    ]);
    let p = program(&b.export("main", 0));
    let cases: &[[u64; 5]] = &[
        [0xFFFD_E000, 0x1_0000, 37, 0x2_0000, 0x1AB],
        [0xFFFD_E010, 0xFFFD_E000, 33, 0xFFFD_E001, 7],
        [0, 0xFFFF_FFFF, 0, 0, 0],
        [0x1_0000, 0x2_0000, 1, 0x2_0000, 0],
        [0x2_0000, 0x3_0000, 1, 0x2_0000, 0],
        [0x2_0000, 0x1_0000, 30, 0x1_0000, 0],
        [0xFFFD_E000, 0x1_0000, 0x10_0000, 0x2_0000, 0],
    ];
    for args in cases {
        for gas in [5, 33, 34, 35, 36, 1_000_000] {
            same(&p, "main", args, gas);
        }
    }
}

#[test]
fn host_calls_through_the_same_trait() {
    // One block per import; each is entered by its own export.
    let mut b = base();
    for i in 0..IMPORTS.len() {
        b.block(&[
            Instruction::Li { rd: r(31), imm: 77 },
            Instruction::Ecall {
                import: u32::try_from(i).unwrap(),
            },
            Instruction::Load {
                width: LoadWidth::D,
                rd: A3,
                rs1: Reg::SP,
                off: -8,
            },
            Instruction::Alu {
                op: AluOp::Add,
                rd: A4,
                rs1: r(31),
                rs2: A0,
            },
            Instruction::Sbrk { rd: A5, rs1: A2 },
            Instruction::Halt,
        ]);
    }
    for (i, name) in IMPORTS.iter().enumerate() {
        b = b.export(name, u32::try_from(i).unwrap());
    }
    let p = program(&b);
    for name in IMPORTS {
        for args in [
            [0xFFFD_E000u64, 0x0102_0304_0506_0708, 0x1_0000, 0, 0, 0],
            [0x1_0000, 5, 0xFFFF_FFFF, 0, 0, 0],
            [0x7, 0x1_0000, 0x2_0000, 1, 2, 3],
            [0x1_0000_0000, 6, 0x3_0000, 0, 0, 0],
        ] {
            for gas in [11, 18, 30, 1_000_000] {
                same(&p, name, &args, gas);
            }
        }
    }
}

#[test]
fn a_host_that_drains_gas_and_returns_success_saturates() {
    // `drain` leaves the counter at i64::MIN + 3 and returns Ok; the next
    // block entry must saturate at i64::MIN, not wrap (spec 01 §5).
    let mut b = base();
    let drain = u32::try_from(IMPORTS.iter().position(|n| *n == "drain").unwrap()).unwrap();
    b.block(&[
        Instruction::Ecall { import: drain },
        Instruction::Li { rd: A0, imm: 1 },
    ]);
    // Block 1 costs 1 + 3 + 1 = 5 > 3, so the subtraction overflows.
    b.block(&[
        Instruction::Li { rd: A1, imm: 2 },
        Instruction::Alu {
            op: AluOp::Mul,
            rd: A1,
            rs1: A1,
            rs2: A1,
        },
        Instruction::Halt,
    ]);
    let o = same_b(&b.clone().export("main", 0), &[], 100);
    assert_eq!(o.status, Termination::OutOfGas);
    assert_eq!(o.gas, i64::MIN);
    assert_eq!(o.position, (1, 0));
    assert_eq!(o.regs[10], 1);
    // Without overflow the counter keeps its exact negative value.
    b.blocks[1].remove(1);
    let o = same_b(&b.export("main", 0), &[], 100);
    assert_eq!(o.status, Termination::OutOfGas);
    assert_eq!(o.gas, i64::MIN + 1);
}

#[test]
fn outcomes_compare_everything() {
    let mut b = base();
    b.block(&[Instruction::Halt]);
    let o: Outcome = same_b(&b.export("main", 0), &[], 10);
    assert_eq!(o.position, (0, 0));
    assert_eq!(o.gas, 9);
    assert!(o.log.is_empty());
    assert_eq!(VARIANTS[2], Options::default());
}
