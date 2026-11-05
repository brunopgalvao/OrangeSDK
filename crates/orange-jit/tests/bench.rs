//! Timings of the native backend against the interpreter. Ignored by
//! default; run with
//!
//! ```sh
//! cargo test --release -p orange-jit --test bench -- --ignored --nocapture
//! ```
//!
//! Both backends must agree on every result before a timing is printed.

#![allow(clippy::cast_precision_loss, clippy::many_single_char_names)]

use std::time::{Duration, Instant};

use orange_jit::Compiled;
use orange_vm::builder::ModuleBuilder;
use orange_vm::gas::CostTable;
use orange_vm::host::{Capability, NoHost};
use orange_vm::isa::{AluImmOp, AluOp, Cond, Instruction, LoadWidth, Reg, StoreWidth};
use orange_vm::module::{Module, Program};
use orange_vm::status::Termination;

fn r(i: u8) -> Reg {
    Reg::new(i).unwrap()
}

/// A hash-mixing loop over a 256-entry table on the stack: per iteration a
/// load, a store, a multiply, shifts, xors and adds, a remainder every
/// iteration and a loop branch. `a0` is the iteration count; `a0` returns
/// the mixed state.
fn mixer() -> Program {
    let (n, x, i, t, p, sp) = (Reg::A0, r(5), r(6), r(7), r(28), Reg::SP);
    let alu = |op, rd, rs1, rs2| Instruction::Alu { op, rd, rs1, rs2 };
    let imm = |op, rd, rs1, imm| Instruction::AluImm { op, rd, rs1, imm };
    let mut b = ModuleBuilder::new();
    b.block(&[
        Instruction::Li {
            rd: x,
            imm: 0x1E37_79B9_7F4A_7C15,
        },
        Instruction::Li { rd: i, imm: 0 },
        imm(AluImmOp::Addi, sp, sp, -2048),
    ]);
    b.block(&[
        imm(AluImmOp::Andi, p, i, 255),
        imm(AluImmOp::Slli, p, p, 3),
        alu(AluOp::Add, p, p, sp),
        Instruction::Load {
            width: LoadWidth::D,
            rd: t,
            rs1: p,
            off: 0,
        },
        alu(AluOp::Xor, x, x, t),
        Instruction::Li {
            rd: t,
            imm: 0x3F58_476D_1CE4_E5B9,
        },
        alu(AluOp::Mul, x, x, t),
        imm(AluImmOp::Srli, t, x, 31),
        alu(AluOp::Xor, x, x, t),
        alu(AluOp::Add, x, x, i),
        Instruction::Store {
            width: StoreWidth::D,
            rs1: p,
            rs2: x,
            off: 0,
        },
        imm(AluImmOp::Ori, t, i, 1),
        alu(AluOp::Remu, t, x, t),
        alu(AluOp::Add, x, x, t),
        imm(AluImmOp::Addi, i, i, 1),
        Instruction::Branch {
            cond: Cond::Ltu,
            rs1: i,
            rs2: n,
            block: 1,
        },
    ]);
    b.block(&[imm(AluImmOp::Addi, Reg::A0, x, 0), Instruction::Halt]);
    let m = Module::parse(&b.export("main", 0).build(), &|_| false).unwrap();
    Program::new(m, CostTable::V1)
}

fn best_of(runs: usize, mut f: impl FnMut() -> (Termination, u64)) -> (Duration, u64) {
    let mut best = Duration::MAX;
    let mut out = 0;
    for _ in 0..runs {
        let start = Instant::now();
        let (t, v) = f();
        best = best.min(start.elapsed());
        assert_eq!(t, Termination::Halt);
        out = v;
    }
    (best, out)
}

#[test]
#[ignore = "timing; run explicitly in release mode"]
fn mixer_native_vs_interpreter() {
    let program = mixer();
    let iterations = 2_000_000u64;
    let start = Instant::now();
    let compiled = Compiled::new(&program).unwrap();
    let compile = start.elapsed();
    let gas = 1 << 40;
    let (it, iv) = best_of(3, || {
        let mut i = orange_vm::interp::Instance::new(
            &program,
            &NoHost,
            Capability::Sandboxed,
            "main",
            &[iterations],
            gas,
        )
        .unwrap();
        (i.run(&mut NoHost), i.reg(Reg::A0))
    });
    let (nt, nv) = best_of(5, || {
        let mut i = orange_jit::Instance::new(
            &compiled,
            &NoHost,
            Capability::Sandboxed,
            "main",
            &[iterations],
            gas,
        )
        .unwrap();
        (i.run(&mut NoHost), i.reg(Reg::A0))
    });
    assert_eq!(nv, iv);
    let instructions = iterations * 16;
    println!(
        "mixer: {iterations} iterations, {instructions} instructions\n  interpreter {:>10.1} ms  {:>7.1} M instr/s\n  native      {:>10.1} ms  {:>7.1} M instr/s\n  speedup {:.1}x, compile {:.3} ms, code {} bytes",
        it.as_secs_f64() * 1e3,
        instructions as f64 / it.as_secs_f64() / 1e6,
        nt.as_secs_f64() * 1e3,
        instructions as f64 / nt.as_secs_f64() / 1e6,
        it.as_secs_f64() / nt.as_secs_f64(),
        compile.as_secs_f64() * 1e3,
        compiled.code_size(),
    );
}
