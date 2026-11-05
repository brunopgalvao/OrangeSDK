//! Shared by the differential tests: a deterministic host, runners for both
//! backends, and the comparison of everything spec 07 §4 compares.

#![allow(
    dead_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]

use orange_jit::{Compiled, Options};
use orange_vm::builder::ModuleBuilder;
use orange_vm::gas::CostTable;
use orange_vm::host::{Capability, Host, HostContext};
use orange_vm::interp;
use orange_vm::isa::Reg;
use orange_vm::memory::Memory;
use orange_vm::module::{Module, Program};
use orange_vm::status::Termination;

/// Host functions the generated modules may import.
pub const IMPORTS: [&str; 8] = [
    "add", "mem", "fail", "burn", "clobber", "grow", "drain", "priv",
];

/// A host whose every function is deterministic and which records every
/// call, so two backends must make the same calls with the same arguments.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TestHost {
    pub log: Vec<(u32, [u64; 6])>,
}

impl Host for TestHost {
    fn resolve(&self, name: &str, capability: Capability) -> Option<u32> {
        let i = IMPORTS.iter().position(|n| *n == name)?;
        let handle = u32::try_from(i).ok()? + 1;
        (handle != 8 || capability == Capability::Privileged).then_some(handle)
    }

    fn call(&mut self, handle: u32, ctx: &mut HostContext<'_>) -> Result<(), Termination> {
        let args = [
            ctx.arg(Reg::A0),
            ctx.arg(Reg::A1),
            ctx.arg(Reg::A2),
            ctx.arg(Reg::A3),
            ctx.arg(Reg::A4),
            ctx.arg(Reg::A5),
        ];
        self.log.push((handle, args));
        match handle {
            1 => {
                ctx.charge(7)?;
                let v = args[0].wrapping_add(args[1]);
                ctx.set(Reg::A0, v);
                ctx.set(Reg::A1, v ^ 0x5555);
            }
            2 => {
                ctx.memory
                    .write(ctx.arg32(Reg::A0), &args[1].to_le_bytes())
                    .map_err(|_| Termination::MemoryFault)?;
                let v = ctx
                    .memory
                    .read_uint(ctx.arg32(Reg::A2), 4)
                    .map_err(|_| Termination::HostError(6))?;
                ctx.set(Reg::A0, v);
            }
            3 => return Err(Termination::HostError(u32::from(args[0] as u8))),
            4 => ctx.charge(args[0] & 0xFFFF)?,
            5 => {
                ctx.regs[0] = 1234;
                for (i, r) in ctx.regs.iter_mut().enumerate().skip(1) {
                    *r = r.rotate_left(i as u32) ^ i as u64;
                }
            }
            6 => {
                let end = ctx.memory.sbrk(4096).map_or(0, |(end, _)| end);
                ctx.set(Reg::A0, u64::from(end));
            }
            7 => *ctx.gas = i64::MIN + 3,
            _ => ctx.set(Reg::A1, 8),
        }
        Ok(())
    }
}

/// Everything a run produces that two conforming backends must agree on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: Termination,
    pub regs: [u64; 32],
    pub gas: i64,
    pub position: (u32, usize),
    pub heap_size: u32,
    /// A digest of each region's bytes: rodata, data and bss, heap, stack.
    pub memory: [u64; 4],
    pub log: Vec<(u32, [u64; 6])>,
}

fn hash(bytes: &[u8]) -> u64 {
    use std::hash::Hasher;
    let mut h = std::hash::DefaultHasher::new();
    h.write(bytes);
    h.finish()
}

/// Digests of every region.
pub fn digest(m: &Memory) -> [u64; 4] {
    let l = *m.layout();
    let rw = u32::try_from(l.rw_size()).unwrap();
    [
        hash(m.read(l.ro_base, l.ro_size).unwrap()),
        hash(m.read(l.rw_base, rw).unwrap()),
        hash(m.read(l.heap_base, m.heap_size()).unwrap()),
        hash(m.read(l.stack_base, l.stack_top - l.stack_base).unwrap()),
    ]
}

/// Parses builder output into a program, resolving imports against [`TestHost`].
pub fn program(b: &ModuleBuilder) -> Program {
    let host = TestHost::default();
    let m = Module::parse(&b.build(), &|n| {
        host.resolve(n, Capability::Privileged).is_some()
    })
    .expect("generated module is valid");
    Program::new(m, CostTable::V1)
}

/// Runs on the reference interpreter.
pub fn interp(p: &Program, entry: &str, args: &[u64], gas: i64) -> Outcome {
    let mut host = TestHost::default();
    let mut inst = interp::Instance::new(p, &host, Capability::Privileged, entry, args, gas)
        .expect("instance");
    let status = inst.run(&mut host);
    Outcome {
        status,
        regs: *inst.regs(),
        gas: inst.gas(),
        position: inst.position(),
        heap_size: inst.memory().heap_size(),
        memory: digest(inst.memory()),
        log: host.log,
    }
}

/// Runs on the native backend.
pub fn native(c: &Compiled, entry: &str, args: &[u64], gas: i64) -> Outcome {
    let mut host = TestHost::default();
    let mut inst = orange_jit::Instance::new(c, &host, Capability::Privileged, entry, args, gas)
        .expect("instance");
    let status = inst.run(&mut host);
    Outcome {
        status,
        regs: *inst.regs(),
        gas: inst.gas(),
        position: inst.position(),
        heap_size: inst.memory().heap_size(),
        memory: digest(inst.memory()),
        log: host.log,
    }
}

/// Register settings every comparison runs under: all spilled, a few in
/// host registers, and as many as the target offers.
pub const VARIANTS: [Options; 3] = [
    Options {
        host_registers: 0,
        code_limit: usize::MAX,
    },
    Options {
        host_registers: 3,
        code_limit: usize::MAX,
    },
    Options {
        host_registers: usize::MAX,
        code_limit: usize::MAX,
    },
];

/// Asserts that every register variant of the native backend agrees with
/// the interpreter on `p` and returns the interpreter's outcome.
pub fn same(p: &Program, entry: &str, args: &[u64], gas: i64) -> Outcome {
    let expected = interp(p, entry, args, gas);
    for options in VARIANTS {
        let c = Compiled::with_options(p, options).expect("compiles");
        let got = native(&c, entry, args, gas);
        assert_eq!(got, expected, "{options:?}\n{:#?}", p.module.blocks);
    }
    expected
}

/// [`same`] for a builder, entering at `main`.
pub fn same_b(b: &ModuleBuilder, args: &[u64], gas: i64) -> Outcome {
    same(&program(b), "main", args, gas)
}
