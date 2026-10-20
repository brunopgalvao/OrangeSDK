//! The public interface: compile errors, instance errors, accessors, reuse
//! of compiled code across instances and threads, and long branches.

#![allow(clippy::cast_possible_wrap)]

mod support;

use solo_jit::{CompileError, Compiled, Instance, MAX_BLOCK_COST, Options, SUPPORTED};
use solo_vm::builder::ModuleBuilder;
use solo_vm::gas::MAX_GAS_LIMIT;
use solo_vm::host::Capability;
use solo_vm::interp::InstanceError;
use solo_vm::isa::{AluImmOp, Cond, Instruction, LoadWidth, Reg, StoreWidth};
use solo_vm::module::ValidationError;
use solo_vm::status::Termination;
use support::{TestHost, program, same};

fn halting() -> ModuleBuilder {
    let mut b = ModuleBuilder::new();
    b.import("add");
    b.import("priv");
    b.block(&[Instruction::Halt]);
    b.export("main", 0)
}

#[test]
fn this_target_is_supported() {
    const { assert!(SUPPORTED) };
}

#[test]
fn compile_errors() {
    let p = program(&halting());
    let c = Compiled::new(&p).unwrap();
    assert!(c.code_size() >= 4096);
    assert!(format!("{c:?}").contains("Compiled"));

    let mut bad = p.clone();
    bad.module.blocks[0] = vec![Instruction::Li {
        rd: Reg::A0,
        imm: 1,
    }];
    assert_eq!(
        Compiled::new(&bad).err(),
        Some(CompileError::Invalid(
            ValidationError::FinalBlockFallsThrough
        ))
    );
    let mut bad = p.clone();
    bad.block_costs.push(1);
    assert_eq!(Compiled::new(&bad).err(), Some(CompileError::Costs));
    let mut bad = p.clone();
    bad.block_costs[0] = MAX_BLOCK_COST + 1;
    assert_eq!(Compiled::new(&bad).err(), Some(CompileError::Costs));
    let mut dear = p.clone();
    dear.block_costs[0] = MAX_BLOCK_COST;
    assert!(Compiled::new(&dear).is_ok());
    let small = Options {
        code_limit: 64,
        ..Options::default()
    };
    assert_eq!(
        Compiled::with_options(&p, small).err(),
        Some(CompileError::TooLarge)
    );
    for e in [
        CompileError::Unsupported,
        CompileError::Memory,
        CompileError::TooLarge,
    ] {
        assert_eq!(e, e);
        assert!(!format!("{e:?}").is_empty());
    }
}

#[test]
fn instance_errors_match_the_interpreter() {
    let p = program(&halting());
    let c = Compiled::new(&p).unwrap();
    let host = TestHost::default();
    let cases: [(&str, Capability, i64, InstanceError); 4] = [
        ("main", Capability::Privileged, -1, InstanceError::GasLimit),
        (
            "main",
            Capability::Privileged,
            MAX_GAS_LIMIT + 1,
            InstanceError::GasLimit,
        ),
        (
            "nope",
            Capability::Privileged,
            10,
            InstanceError::NoSuchExport,
        ),
        (
            "main",
            Capability::Sandboxed,
            10,
            InstanceError::UnresolvedImport(1),
        ),
    ];
    for (entry, cap, gas, err) in cases {
        assert_eq!(
            Instance::new(&c, &host, cap, entry, &[], gas).err(),
            Some(err)
        );
        assert_eq!(
            solo_vm::interp::Instance::new(&p, &host, cap, entry, &[], gas).err(),
            Some(err)
        );
    }
}

#[test]
fn accessors_memory_edits_and_reruns() {
    // Loads a word the host wrote into fresh heap before the run.
    let mut b = ModuleBuilder::new();
    b.block(&[
        Instruction::Li {
            rd: Reg::A1,
            imm: 0x3_0000,
        },
        Instruction::Load {
            width: LoadWidth::D,
            rd: Reg::A0,
            rs1: Reg::A1,
            off: 8,
        },
        Instruction::Store {
            width: StoreWidth::B,
            rs1: Reg::A1,
            rs2: Reg::A1,
            off: 0,
        },
        Instruction::Halt,
    ]);
    let p = program(&b.export("main", 0));
    let c = Compiled::new(&p).unwrap();
    let mut host = TestHost::default();
    let mut inst = Instance::new(&c, &host, Capability::Sandboxed, "main", &[7, 8], 100).unwrap();
    assert_eq!(inst.reg(Reg::A0), 7);
    assert_eq!(inst.regs()[11], 8);
    assert_eq!(inst.position(), (0, 0));
    assert_eq!(inst.memory().heap_size(), 0);
    inst.memory_mut().sbrk(1).unwrap();
    inst.memory_mut()
        .write(0x3_0008, &0x1122_3344_5566_7788u64.to_le_bytes())
        .unwrap();
    assert_eq!(inst.run(&mut host), Termination::Halt);
    assert_eq!(inst.reg(Reg::A0), 0x1122_3344_5566_7788);
    assert_eq!(inst.memory().read(0x3_0000, 1).unwrap(), &[0]);
    assert_eq!(inst.position(), (0, 3));
    let gas = inst.gas();
    // A finished instance stays finished.
    assert_eq!(inst.run(&mut host), Termination::Halt);
    assert_eq!(inst.gas(), gas);
    assert!(format!("{inst:?}").contains("Instance"));
    // Without the host's heap the same load faults, at the same position
    // as on the interpreter.
    let mut inst = Instance::new(&c, &host, Capability::Sandboxed, "main", &[], 100).unwrap();
    assert_eq!(inst.run(&mut host), Termination::MemoryFault);
    assert_eq!(inst.position(), (0, 1));
}

#[test]
fn compiled_code_is_shared_across_threads() {
    let mut b = ModuleBuilder::new();
    b.block(&[
        Instruction::AluImm {
            op: AluImmOp::Addi,
            rd: Reg::A0,
            rs1: Reg::A0,
            imm: -1,
        },
        Instruction::Branch {
            cond: Cond::Ne,
            rs1: Reg::A0,
            rs2: Reg::ZERO,
            block: 0,
        },
    ]);
    b.block(&[Instruction::Halt]);
    let p = program(&b.export("main", 0));
    let c = Compiled::new(&p).unwrap();
    std::thread::scope(|s| {
        for n in 1..5u64 {
            let c = &c;
            s.spawn(move || {
                let mut host = TestHost::default();
                let mut inst = Instance::new(
                    c,
                    &host,
                    Capability::Sandboxed,
                    "main",
                    &[n * 1000],
                    1 << 40,
                )
                .unwrap();
                assert_eq!(inst.run(&mut host), Termination::Halt);
                assert_eq!(inst.gas(), (1 << 40) - 3 * 1000 * n as i64 - 1);
            });
        }
    });
}

#[test]
fn branches_across_more_than_a_mebibyte() {
    // Block 1 is over a mebibyte of native code and loops back to itself,
    // which is beyond a conditional branch's reach on AArch64.
    let mut b = ModuleBuilder::new();
    b.block(&[Instruction::Li {
        rd: Reg::A0,
        imm: 0,
    }]);
    let mut body = vec![
        Instruction::AluImm {
            op: AluImmOp::Addi,
            rd: Reg::A0,
            rs1: Reg::A0,
            imm: 1,
        };
        300_000
    ];
    body.push(Instruction::Branch {
        cond: Cond::Ne,
        rs1: Reg::A0,
        rs2: Reg::A1,
        block: 1,
    });
    b.block(&body);
    b.block(&[Instruction::Branch {
        cond: Cond::Eq,
        rs1: Reg::A0,
        rs2: Reg::A1,
        block: 4,
    }]);
    b.block(&[Instruction::Trap]);
    b.block(&[Instruction::Halt]);
    let p = program(&b.export("main", 0));
    let o = same(&p, "main", &[0, 600_000], 10_000_000);
    assert_eq!(o.status, Termination::Halt);
    assert_eq!(o.regs[10], 600_000);
}
