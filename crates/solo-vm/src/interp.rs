//! The reference interpreter (spec 01, 02, 04).
//!
//! Deliberately simple: one instruction at a time, no caching, no tricks.
//! Every other backend must agree with this one on every program.

// The interpreter is bit-level arithmetic by nature: sign and width changes
// are the semantics, not accidents, so the cast lints are silenced here only.
#![allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation
)]

use alloc::vec::Vec;

use crate::gas::{MAX_GAS_LIMIT, bulk_cost, sbrk_cost};
use crate::host::{Capability, Host, HostContext};
use crate::isa::{AluImmOp, AluOp, Cond, Instruction, LoadWidth, Reg, StoreWidth};
use crate::memory::Memory;
use crate::module::Program;
use crate::status::Termination;

/// Why an instance could not be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceError {
    /// The host does not provide an import under this capability set.
    UnresolvedImport(u32),
    /// The gas limit is negative or above [`MAX_GAS_LIMIT`] (spec 04 §4).
    GasLimit,
    /// The entry export does not exist.
    NoSuchExport,
}

/// Where the next instruction comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// Continue with the next instruction of the block.
    Next,
    /// Enter `block`.
    Jump(u32),
    /// Stop with this status.
    End(Termination),
}

/// One running (or finished) instance of a program.
pub struct Instance<'p> {
    program: &'p Program,
    regs: [u64; 16],
    memory: Memory,
    gas: i64,
    imports: Vec<u32>,
    block: u32,
    index: usize,
    steps: u64,
}

const fn addr(v: u64) -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    let a = v as u32;
    a
}

const fn sx32(v: u64) -> u64 {
    #[allow(clippy::cast_possible_truncation)]
    let w = v as u32;
    w as i32 as i64 as u64
}

#[allow(clippy::cast_possible_truncation)]
const fn low32(v: u64) -> u32 {
    v as u32
}

impl<'p> Instance<'p> {
    /// Creates an instance positioned at the export `entry`, with `args` in
    /// `a0`–`a5` (missing arguments are 0), `sp` at `stack_top`, and the gas
    /// counter at `gas_limit` (spec 01 §2, §3.3, 04 §4).
    ///
    /// # Errors
    /// See [`InstanceError`].
    pub fn new(
        program: &'p Program,
        host: &dyn Host,
        capability: Capability,
        entry: &str,
        args: &[u64],
        gas_limit: i64,
    ) -> Result<Instance<'p>, InstanceError> {
        if !(0..=MAX_GAS_LIMIT).contains(&gas_limit) {
            return Err(InstanceError::GasLimit);
        }
        let module = &program.module;
        let block = module.export(entry).ok_or(InstanceError::NoSuchExport)?;
        let mut imports = Vec::with_capacity(module.imports.len());
        for (i, name) in module.imports.iter().enumerate() {
            let handle = host.resolve(name, capability).ok_or_else(|| {
                InstanceError::UnresolvedImport(u32::try_from(i).unwrap_or(u32::MAX))
            })?;
            imports.push(handle);
        }
        let mut regs = [0u64; 16];
        for (i, a) in args.iter().take(6).enumerate() {
            regs[Reg::A0.index() + i] = *a;
        }
        regs[Reg::SP.index()] = u64::from(module.layout.stack_top);
        Ok(Instance {
            program,
            regs,
            memory: Memory::new(module.layout, &module.rodata, &module.data),
            gas: gas_limit,
            imports,
            block,
            index: 0,
            steps: 0,
        })
    }

    /// The registers.
    #[must_use]
    pub const fn regs(&self) -> &[u64; 16] {
        &self.regs
    }

    /// One register.
    #[must_use]
    pub const fn reg(&self, r: Reg) -> u64 {
        self.regs[r.index()]
    }

    /// Remaining gas; negative after `OutOfGas`.
    #[must_use]
    pub const fn gas(&self) -> i64 {
        self.gas
    }

    /// The memory.
    #[must_use]
    pub const fn memory(&self) -> &Memory {
        &self.memory
    }

    /// Mutable access to memory, for hosts preparing input or reading output.
    pub const fn memory_mut(&mut self) -> &mut Memory {
        &mut self.memory
    }

    /// Instructions executed so far.
    #[must_use]
    pub const fn steps(&self) -> u64 {
        self.steps
    }

    /// Runs to termination.
    pub fn run(&mut self, host: &mut dyn Host) -> Termination {
        self.run_with_step_limit(host, u64::MAX)
    }

    /// Runs until termination or until `limit` instructions have executed in
    /// this call, in which case the result is `StepLimit` and the instance can
    /// be resumed. Only for debugging and simulation hosts (spec 01 §6).
    pub fn run_with_step_limit(&mut self, host: &mut dyn Host, limit: u64) -> Termination {
        let mut budget = limit;
        loop {
            if self.index == 0 {
                let cost = self.program.block_costs[self.block as usize];
                if let Err(t) = self.charge(cost) {
                    return t;
                }
            }
            if budget == 0 {
                return Termination::StepLimit;
            }
            budget -= 1;
            self.steps += 1;
            let block = &self.program.module.blocks[self.block as usize];
            let ins = block[self.index];
            let flow = self.execute(ins, host);
            match flow {
                Flow::Next => {
                    self.index += 1;
                    if self.index == block.len() {
                        self.block += 1;
                        self.index = 0;
                    }
                }
                Flow::Jump(target) => {
                    self.block = target;
                    self.index = 0;
                }
                Flow::End(t) => return t,
            }
        }
    }

    fn charge(&mut self, cost: u64) -> Result<(), Termination> {
        let cost = i64::try_from(cost).unwrap_or(i64::MAX);
        self.gas = self.gas.saturating_sub(cost);
        if self.gas < 0 {
            Err(Termination::OutOfGas)
        } else {
            Ok(())
        }
    }

    fn set(&mut self, r: Reg, v: u64) {
        if r != Reg::ZERO {
            self.regs[r.index()] = v;
        }
    }

    fn execute(&mut self, ins: Instruction, host: &mut dyn Host) -> Flow {
        match ins {
            Instruction::Trap => Flow::End(Termination::Trap),
            Instruction::Halt => Flow::End(Termination::Halt),
            Instruction::Ecall { import } => self.ecall(import, host),
            Instruction::Sbrk { rd, rs1 } => self.sbrk(rd, rs1),
            Instruction::Memcopy { dst, src, len } => self.memcopy(dst, src, len),
            Instruction::Memfill { dst, val, len } => self.memfill(dst, val, len),
            Instruction::Li { rd, imm } => {
                #[allow(clippy::cast_sign_loss)]
                self.set(rd, imm as u64);
                Flow::Next
            }
            Instruction::AluImm { op, rd, rs1, imm } => {
                let v = alu_imm(op, self.reg(rs1), imm);
                self.set(rd, v);
                Flow::Next
            }
            Instruction::Alu { op, rd, rs1, rs2 } => {
                let v = alu(op, self.reg(rs1), self.reg(rs2));
                self.set(rd, v);
                Flow::Next
            }
            Instruction::Load {
                width,
                rd,
                rs1,
                off,
            } => self.load(width, rd, rs1, off),
            Instruction::Store {
                width,
                rs1,
                rs2,
                off,
            } => self.store(width, rs1, rs2, off),
            Instruction::Jump { block } => Flow::Jump(block),
            Instruction::Call { rd, block, slot } => {
                self.set(rd, 8 * u64::from(slot));
                Flow::Jump(block)
            }
            Instruction::JumpIndirect { rs1, off } => self.indirect(self.reg(rs1), off),
            Instruction::CallIndirect { rd, rs1, off, slot } => {
                let target = self.reg(rs1);
                self.set(rd, 8 * u64::from(slot));
                self.indirect(target, off)
            }
            Instruction::Branch {
                cond,
                rs1,
                rs2,
                block,
            } => {
                if branch(cond, self.reg(rs1), self.reg(rs2)) {
                    Flow::Jump(block)
                } else {
                    Flow::Next
                }
            }
        }
    }

    fn ecall(&mut self, import: u32, host: &mut dyn Host) -> Flow {
        let handle = self.imports[import as usize];
        let mut ctx = HostContext {
            regs: &mut self.regs,
            memory: &mut self.memory,
            gas: &mut self.gas,
        };
        match host.call(handle, &mut ctx) {
            Ok(()) => {
                self.regs[Reg::ZERO.index()] = 0;
                Flow::Next
            }
            Err(t) => Flow::End(t),
        }
    }

    fn sbrk(&mut self, rd: Reg, rs1: Reg) -> Flow {
        let bytes = addr(self.reg(rs1));
        match self.memory.sbrk_pages(bytes) {
            Some(pages) => {
                if let Err(t) = self.charge(sbrk_cost(pages)) {
                    return Flow::End(t);
                }
                let (old_end, _) = self.memory.sbrk(bytes).expect("checked by sbrk_pages");
                self.set(rd, u64::from(old_end));
            }
            None => self.set(rd, 0),
        }
        Flow::Next
    }

    fn charge_bulk(&mut self, len: Reg) -> Result<u32, Termination> {
        let n = addr(self.reg(len));
        self.charge(bulk_cost(n))?;
        Ok(n)
    }

    fn memcopy(&mut self, dst: Reg, src: Reg, len: Reg) -> Flow {
        let n = match self.charge_bulk(len) {
            Ok(n) => n,
            Err(t) => return Flow::End(t),
        };
        match self
            .memory
            .copy(addr(self.reg(dst)), addr(self.reg(src)), n)
        {
            Ok(()) => Flow::Next,
            Err(_) => Flow::End(Termination::MemoryFault),
        }
    }

    fn memfill(&mut self, dst: Reg, val: Reg, len: Reg) -> Flow {
        let n = match self.charge_bulk(len) {
            Ok(n) => n,
            Err(t) => return Flow::End(t),
        };
        match self
            .memory
            .fill(addr(self.reg(dst)), self.reg(val) as u8, n)
        {
            Ok(()) => Flow::Next,
            Err(_) => Flow::End(Termination::MemoryFault),
        }
    }

    fn load(&mut self, width: LoadWidth, rd: Reg, rs1: Reg, off: i64) -> Flow {
        #[allow(clippy::cast_sign_loss)]
        let a = addr(self.reg(rs1).wrapping_add(off as u64));
        let Ok(raw) = self.memory.read_uint(a, width.bytes()) else {
            return Flow::End(Termination::MemoryFault);
        };
        let v = match width {
            LoadWidth::B => i64::from(raw as u8 as i8) as u64,
            LoadWidth::H => i64::from(raw as u16 as i16) as u64,
            LoadWidth::W => sx32(raw),
            LoadWidth::Bu | LoadWidth::Hu | LoadWidth::Wu | LoadWidth::D => raw,
        };
        self.set(rd, v);
        Flow::Next
    }

    fn store(&mut self, width: StoreWidth, rs1: Reg, rs2: Reg, off: i64) -> Flow {
        #[allow(clippy::cast_sign_loss)]
        let a = addr(self.reg(rs1).wrapping_add(off as u64));
        match self.memory.write_uint(a, width.bytes(), self.reg(rs2)) {
            Ok(()) => Flow::Next,
            Err(_) => Flow::End(Termination::MemoryFault),
        }
    }

    fn indirect(&self, base: u64, off: i64) -> Flow {
        #[allow(clippy::cast_sign_loss)]
        let v = addr(base.wrapping_add(off as u64));
        if v == 0 || !v.is_multiple_of(8) {
            return Flow::End(Termination::InvalidJump);
        }
        match self.program.module.jump_table.get((v / 8) as usize) {
            Some(Some(block)) => Flow::Jump(*block),
            _ => Flow::End(Termination::InvalidJump),
        }
    }
}

#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation
)]
fn alu_imm(op: AluImmOp, a: u64, imm: i64) -> u64 {
    let i = imm as u64;
    match op {
        AluImmOp::Addi => a.wrapping_add(i),
        AluImmOp::Andi => a & i,
        AluImmOp::Ori => a | i,
        AluImmOp::Xori => a ^ i,
        AluImmOp::Slti => u64::from((a as i64) < imm),
        AluImmOp::Sltiu => u64::from(a < i),
        AluImmOp::Slli => a << (imm & 63),
        AluImmOp::Srli => a >> (imm & 63),
        AluImmOp::Srai => ((a as i64) >> (imm & 63)) as u64,
        AluImmOp::Addiw => sx32(a.wrapping_add(i)),
        AluImmOp::Slliw => sx32(a << (imm & 31)),
        AluImmOp::Srliw => sx32(u64::from(low32(a) >> (imm & 31))),
        AluImmOp::Sraiw => i64::from((low32(a) as i32) >> (imm & 31)) as u64,
    }
}

#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation
)]
fn alu(op: AluOp, a: u64, b: u64) -> u64 {
    let (sa, sb) = (a as i64, b as i64);
    let (wa, wb) = (low32(a), low32(b));
    let (swa, swb) = (wa as i32, wb as i32);
    match op {
        AluOp::Add => a.wrapping_add(b),
        AluOp::Sub => a.wrapping_sub(b),
        AluOp::And => a & b,
        AluOp::Or => a | b,
        AluOp::Xor => a ^ b,
        AluOp::Sll => a << (b & 63),
        AluOp::Srl => a >> (b & 63),
        AluOp::Sra => (sa >> (b & 63)) as u64,
        AluOp::Slt => u64::from(sa < sb),
        AluOp::Sltu => u64::from(a < b),
        AluOp::Mul => a.wrapping_mul(b),
        AluOp::Mulh => ((i128::from(sa) * i128::from(sb)) >> 64) as u64,
        AluOp::Mulhsu => ((i128::from(sa) * i128::from(b)) >> 64) as u64,
        AluOp::Mulhu => ((u128::from(a) * u128::from(b)) >> 64) as u64,
        AluOp::Div => div_signed(sa, sb) as u64,
        AluOp::Divu => div_unsigned(a, b),
        AluOp::Rem => rem_signed(sa, sb) as u64,
        AluOp::Remu => rem_unsigned(a, b),
        AluOp::Addw => sx32(a.wrapping_add(b)),
        AluOp::Subw => sx32(a.wrapping_sub(b)),
        AluOp::Sllw => sx32(a << (b & 31)),
        AluOp::Srlw => sx32(u64::from(wa >> (b & 31))),
        AluOp::Sraw => i64::from(swa >> (b & 31)) as u64,
        AluOp::Mulw => sx32(a.wrapping_mul(b)),
        AluOp::Divw => i64::from(div_signed_32(swa, swb)) as u64,
        AluOp::Divuw => sx32(u64::from(div_unsigned_32(wa, wb))),
        AluOp::Remw => i64::from(rem_signed_32(swa, swb)) as u64,
        AluOp::Remuw => sx32(u64::from(rem_unsigned_32(wa, wb))),
    }
}

const fn div_signed(a: i64, b: i64) -> i64 {
    if b == 0 { -1 } else { a.wrapping_div(b) }
}

const fn rem_signed(a: i64, b: i64) -> i64 {
    if b == 0 { a } else { a.wrapping_rem(b) }
}

fn div_unsigned(a: u64, b: u64) -> u64 {
    a.checked_div(b).unwrap_or(u64::MAX)
}

const fn rem_unsigned(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { a % b }
}

const fn div_signed_32(a: i32, b: i32) -> i32 {
    if b == 0 { -1 } else { a.wrapping_div(b) }
}

const fn rem_signed_32(a: i32, b: i32) -> i32 {
    if b == 0 { a } else { a.wrapping_rem(b) }
}

fn div_unsigned_32(a: u32, b: u32) -> u32 {
    a.checked_div(b).unwrap_or(u32::MAX)
}

const fn rem_unsigned_32(a: u32, b: u32) -> u32 {
    if b == 0 { a } else { a % b }
}

#[allow(clippy::cast_possible_wrap)]
fn branch(cond: Cond, a: u64, b: u64) -> bool {
    match cond {
        Cond::Eq => a == b,
        Cond::Ne => a != b,
        Cond::Lt => (a as i64) < (b as i64),
        Cond::Ge => (a as i64) >= (b as i64),
        Cond::Ltu => a < b,
        Cond::Geu => a >= b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::ModuleBuilder;
    use crate::gas::CostTable;
    use crate::module::Module;
    use alloc::vec;

    /// Resolves `ok`, `fail`, `oog`, `clobber_zero` for everyone and `priv`
    /// only under `Privileged`.
    #[derive(Default)]
    struct TestHost {
        calls: Vec<u32>,
    }

    impl Host for TestHost {
        fn resolve(&self, name: &str, capability: Capability) -> Option<u32> {
            match (name, capability) {
                ("ok", _) => Some(1),
                ("fail", _) => Some(2),
                ("oog", _) => Some(3),
                ("clobber_zero", _) => Some(4),
                ("priv", Capability::Privileged) => Some(5),
                _ => None,
            }
        }

        fn call(&mut self, handle: u32, ctx: &mut HostContext<'_>) -> Result<(), Termination> {
            self.calls.push(handle);
            match handle {
                1 => {
                    ctx.charge(5)?;
                    let a0 = ctx.arg(Reg::A0);
                    ctx.set(Reg::A0, a0 + 1);
                    ctx.set(Reg::A1, 0xBEEF);
                    ctx.memory
                        .write(0xFFFC_0000, &[0xAA])
                        .map_err(|_| Termination::MemoryFault)?;
                    Ok(())
                }
                2 => Err(Termination::HostError(7)),
                3 => ctx.charge(1_000_000),
                4 => {
                    ctx.regs[0] = 99;
                    Ok(())
                }
                _ => Ok(()),
            }
        }
    }

    impl From<crate::memory::MemoryFault> for Termination {
        fn from(_: crate::memory::MemoryFault) -> Termination {
            Termination::MemoryFault
        }
    }

    fn program(b: &ModuleBuilder) -> Program {
        let host = TestHost::default();
        let m = Module::parse(&b.build(), &|n| {
            host.resolve(n, Capability::Privileged).is_some()
        })
        .unwrap();
        Program::new(m, CostTable::V1)
    }

    fn run<'a>(p: &'a Program, args: &[u64], gas: i64) -> (Termination, Instance<'a>) {
        let mut host = TestHost::default();
        let mut inst = Instance::new(p, &host, Capability::Sandboxed, "main", args, gas).unwrap();
        let t = inst.run(&mut host);
        (t, inst)
    }

    fn r(i: u8) -> Reg {
        Reg::new(i).unwrap()
    }

    const A0: Reg = Reg::A0;
    const A1: Reg = Reg::A1;
    const A2: Reg = Reg::A2;
    const A3: Reg = Reg::A3;
    const A4: Reg = Reg::A4;
    const A5: Reg = Reg::A5;

    fn single(ins: &[Instruction]) -> ModuleBuilder {
        let mut b = ModuleBuilder::new();
        let mut body = ins.to_vec();
        body.push(Instruction::Halt);
        b.block(&body);
        b.export("main", 0)
    }

    #[test]
    fn instance_errors_and_setup() {
        let p = program(&single(&[]));
        let host = TestHost::default();
        assert_eq!(
            Instance::new(&p, &host, Capability::Sandboxed, "nope", &[], 10).err(),
            Some(InstanceError::NoSuchExport)
        );
        assert_eq!(
            Instance::new(&p, &host, Capability::Sandboxed, "main", &[], -1).err(),
            Some(InstanceError::GasLimit)
        );
        assert_eq!(
            Instance::new(
                &p,
                &host,
                Capability::Sandboxed,
                "main",
                &[],
                MAX_GAS_LIMIT + 1
            )
            .err(),
            Some(InstanceError::GasLimit)
        );
        let mut b = ModuleBuilder::new();
        b.import("ok");
        let i = b.import("priv");
        b.block(&[Instruction::Ecall { import: i }, Instruction::Halt]);
        let b = b.export("main", 0);
        let p = program(&b);
        assert_eq!(
            Instance::new(&p, &host, Capability::Sandboxed, "main", &[], 10).err(),
            Some(InstanceError::UnresolvedImport(1))
        );
        assert!(Instance::new(&p, &host, Capability::Privileged, "main", &[], 10).is_ok());

        let p = program(&single(&[]));
        let (t, inst) = run(&p, &[1, 2, 3, 4, 5, 6, 7], 10);
        assert_eq!(t, Termination::Halt);
        assert_eq!(&inst.regs()[10..16], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(inst.reg(Reg::SP), 0xFFFE_0000);
        assert_eq!(inst.reg(Reg::RA), 0);
        assert_eq!(inst.gas(), 9);
        assert_eq!(inst.steps(), 1);
        assert_eq!(inst.memory().heap_size(), 0);
        assert_eq!(alloc::format!("{:?}", InstanceError::GasLimit), "GasLimit");
        assert_eq!(Flow::Next, Flow::Next);
        assert!(alloc::format!("{:?}", Flow::Jump(1)).contains("Jump"));
    }

    fn unop(op: AluImmOp, a: u64, imm: i64) -> u64 {
        #[allow(clippy::cast_possible_wrap)]
        let p = program(&single(&[
            Instruction::Li {
                rd: A0,
                imm: a as i64,
            },
            Instruction::AluImm {
                op,
                rd: A1,
                rs1: A0,
                imm,
            },
        ]));
        let (t, inst) = run(&p, &[], 100);
        assert_eq!(t, Termination::Halt);
        inst.reg(A1)
    }

    #[test]
    fn register_immediate_semantics() {
        use AluImmOp::*;
        let neg1 = u64::MAX;
        assert_eq!(unop(Addi, 5, -7), neg1 - 1);
        assert_eq!(unop(Addi, u64::MAX, 1), 0);
        assert_eq!(unop(Andi, 0xFF, -16), 0xF0);
        assert_eq!(unop(Ori, 0x0F, 0x30), 0x3F);
        assert_eq!(unop(Xori, 0xFF, -1), !0xFFu64);
        assert_eq!(unop(Slti, neg1, 0), 1);
        assert_eq!(unop(Slti, 0, -1), 0);
        assert_eq!(unop(Sltiu, 0, -1), 1); // imm sign-extended then unsigned
        assert_eq!(unop(Sltiu, neg1, -1), 0);
        assert_eq!(unop(Slli, 1, 63), 1 << 63);
        assert_eq!(unop(Srli, neg1, 63), 1);
        assert_eq!(unop(Srai, 1 << 63, 63), neg1);
        assert_eq!(unop(Srai, 0x7FFF_FFFF_FFFF_FFFF, 1), 0x3FFF_FFFF_FFFF_FFFF);
        assert_eq!(unop(Addiw, 0x7FFF_FFFF, 1), 0xFFFF_FFFF_8000_0000);
        assert_eq!(unop(Addiw, 0x1_0000_0000, 5), 5);
        assert_eq!(unop(Slliw, 1, 31), 0xFFFF_FFFF_8000_0000);
        assert_eq!(unop(Srliw, 0xFFFF_FFFF_8000_0000, 31), 1);
        assert_eq!(unop(Srliw, 0x8000_0000, 0), 0xFFFF_FFFF_8000_0000);
        assert_eq!(unop(Sraiw, 0x8000_0000, 31), neg1);
        assert_eq!(unop(Sraiw, 0x0000_0001_4000_0000, 1), 0x2000_0000);
    }

    fn binop(op: AluOp, a: u64, b: u64) -> u64 {
        #[allow(clippy::cast_possible_wrap)]
        let p = program(&single(&[
            Instruction::Li {
                rd: A0,
                imm: a as i64,
            },
            Instruction::Li {
                rd: A1,
                imm: b as i64,
            },
            Instruction::Alu {
                op,
                rd: A2,
                rs1: A0,
                rs2: A1,
            },
        ]));
        let (t, inst) = run(&p, &[], 100);
        assert_eq!(t, Termination::Halt);
        inst.reg(A2)
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn register_register_semantics() {
        use AluOp::*;
        let neg1 = u64::MAX;
        let min = 1u64 << 63;
        assert_eq!(binop(Add, 1, neg1), 0);
        assert_eq!(binop(Sub, 0, 1), neg1);
        assert_eq!(binop(And, 0xF0F0, 0xFF00), 0xF000);
        assert_eq!(binop(Or, 0xF0F0, 0x0F0F), 0xFFFF);
        assert_eq!(binop(Xor, 0xFFFF, 0x0F0F), 0xF0F0);
        assert_eq!(binop(Sll, 1, 64 + 3), 8); // only low 6 bits
        assert_eq!(binop(Srl, min, 63), 1);
        assert_eq!(binop(Sra, min, 63), neg1);
        assert_eq!(binop(Slt, neg1, 0), 1);
        assert_eq!(binop(Slt, 0, neg1), 0);
        assert_eq!(binop(Sltu, 0, neg1), 1);
        assert_eq!(binop(Mul, 1 << 32, 1 << 32), 0);
        assert_eq!(binop(Mul, neg1, neg1), 1);
        assert_eq!(binop(Mulh, neg1, neg1), 0); // (-1)*(-1) = 1, high = 0
        assert_eq!(binop(Mulh, min, 2), neg1); // -2^64 >> 64 = -1
        assert_eq!(binop(Mulhsu, neg1, 2), neg1); // -1 * 2 = -2, high = -1
        assert_eq!(binop(Mulhsu, 2, neg1), 1); // 2 * (2^64-1), high = 1
        assert_eq!(binop(Mulhu, neg1, neg1), neg1 - 1);
        // Division rules (02 §6.1).
        assert_eq!(binop(Div, 7, 0), neg1);
        assert_eq!(binop(Divu, 7, 0), neg1);
        assert_eq!(binop(Rem, 7, 0), 7);
        assert_eq!(binop(Remu, 7, 0), 7);
        assert_eq!(binop(Div, min, neg1), min);
        assert_eq!(binop(Rem, min, neg1), 0);
        assert_eq!(binop(Div, neg1 - 6, 2), neg1 - 2); // -7 / 2 = -3
        assert_eq!(binop(Rem, neg1 - 6, 2), neg1); // -7 % 2 = -1
        assert_eq!(binop(Divu, neg1, 2), 0x7FFF_FFFF_FFFF_FFFF);
        assert_eq!(binop(Remu, neg1, 2), 1);
        // W forms.
        assert_eq!(binop(Addw, 0xFFFF_FFFF, 1), 0);
        assert_eq!(binop(Addw, 0x7FFF_FFFF, 1), 0xFFFF_FFFF_8000_0000);
        assert_eq!(binop(Subw, 0, 1), neg1);
        assert_eq!(binop(Sllw, 1, 32 + 4), 16);
        assert_eq!(binop(Srlw, 0xFFFF_FFFF_8000_0000, 31), 1);
        assert_eq!(binop(Sraw, 0x8000_0000, 31), neg1);
        assert_eq!(binop(Mulw, 0x1_0000, 0x1_0000), 0);
        assert_eq!(binop(Mulw, 0xFFFF_FFFF, 0xFFFF_FFFF), 1);
        assert_eq!(binop(Divw, 7, 0), neg1);
        assert_eq!(binop(Divw, 0x8000_0000, 0xFFFF_FFFF), 0xFFFF_FFFF_8000_0000);
        assert_eq!(binop(Divw, 0xFFFF_FFF9, 2), neg1 - 2); // -7 / 2
        assert_eq!(binop(Divuw, 0xFFFF_FFFF, 2), 0x7FFF_FFFF);
        assert_eq!(binop(Divuw, 7, 0), neg1); // 2^32-1 sign-extended
        assert_eq!(binop(Remw, 0xFFFF_FFF9, 2), neg1);
        assert_eq!(binop(Remw, 0x8000_0000, 0xFFFF_FFFF), 0);
        assert_eq!(binop(Remw, 7, 0), 7);
        assert_eq!(binop(Remuw, 0xFFFF_FFFF, 2), 1);
        assert_eq!(binop(Remuw, 0x8000_0000, 0), 0xFFFF_FFFF_8000_0000);
    }

    #[test]
    fn register_zero_reads_zero_and_discards_writes() {
        let mut b = ModuleBuilder::new();
        b.slot(1);
        b.block(&[
            Instruction::Li {
                rd: Reg::ZERO,
                imm: 5,
            },
            Instruction::Alu {
                op: AluOp::Add,
                rd: Reg::ZERO,
                rs1: A0,
                rs2: A0,
            },
            Instruction::AluImm {
                op: AluImmOp::Addi,
                rd: A1,
                rs1: Reg::ZERO,
                imm: 3,
            },
            Instruction::Sbrk {
                rd: Reg::ZERO,
                rs1: Reg::ZERO,
            },
            Instruction::Call {
                rd: Reg::ZERO,
                block: 1,
                slot: 1,
            },
        ]);
        b.block(&[Instruction::Halt]);
        let p = program(&b.export("main", 0));
        let (t, inst) = run(&p, &[7], 100);
        assert_eq!(t, Termination::Halt);
        assert_eq!(inst.reg(Reg::ZERO), 0);
        assert_eq!(inst.reg(A1), 3);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn loads_and_stores() {
        let data: Vec<u8> = vec![
            0x80, 0x01, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x80, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let b = single(&[
            Instruction::Li {
                rd: A0,
                imm: 0x2_0008,
            },
            Instruction::Load {
                width: LoadWidth::B,
                rd: r(5),
                rs1: A0,
                off: -8,
            },
            Instruction::Load {
                width: LoadWidth::Bu,
                rd: r(6),
                rs1: A0,
                off: -8,
            },
            Instruction::Load {
                width: LoadWidth::H,
                rd: r(7),
                rs1: A0,
                off: -6,
            },
            Instruction::Load {
                width: LoadWidth::Hu,
                rd: r(8),
                rs1: A0,
                off: -6,
            },
            Instruction::Load {
                width: LoadWidth::W,
                rd: r(9),
                rs1: A0,
                off: -4,
            },
            Instruction::Load {
                width: LoadWidth::Wu,
                rd: r(11),
                rs1: A0,
                off: -4,
            },
            Instruction::Load {
                width: LoadWidth::D,
                rd: r(12),
                rs1: A0,
                off: 0,
            },
            // Stores into the stack, then reload.
            Instruction::Li {
                rd: A3,
                imm: 0xFFFC_0010,
            },
            Instruction::Store {
                width: StoreWidth::D,
                rs1: A3,
                rs2: r(12),
                off: 0,
            },
            Instruction::Store {
                width: StoreWidth::B,
                rs1: A3,
                rs2: r(5),
                off: 8,
            },
            Instruction::Store {
                width: StoreWidth::H,
                rs1: A3,
                rs2: r(7),
                off: 9,
            }, // misaligned
            Instruction::Store {
                width: StoreWidth::W,
                rs1: A3,
                rs2: r(9),
                off: 11,
            },
            Instruction::Load {
                width: LoadWidth::D,
                rd: r(14),
                rs1: A3,
                off: 0,
            },
            Instruction::Load {
                width: LoadWidth::Bu,
                rd: r(15),
                rs1: A3,
                off: 8,
            },
        ])
        .data(&data);
        let p = program(&b);
        let (t, inst) = run(&p, &[], 1000);
        assert_eq!(t, Termination::Halt);
        assert_eq!(inst.reg(r(5)), 0xFFFF_FFFF_FFFF_FF80);
        assert_eq!(inst.reg(r(6)), 0x80);
        assert_eq!(inst.reg(r(7)), 0x7FFF);
        assert_eq!(inst.reg(r(8)), 0x7FFF);
        assert_eq!(inst.reg(r(9)), 0xFFFF_FFFF_8000_0000);
        assert_eq!(inst.reg(r(11)), 0x8000_0000);
        assert_eq!(inst.reg(r(12)), 0x8877_6655_4433_2211);
        assert_eq!(inst.reg(r(14)), 0x8877_6655_4433_2211);
        assert_eq!(inst.reg(r(15)), 0x80);
        assert_eq!(
            inst.memory().read(0xFFFC_0019, 6).unwrap(),
            &[0xFF, 0x7F, 0x00, 0x00, 0x00, 0x80]
        );
        // The effective address is the low 32 bits of the computed value.
        let p = program(
            &single(&[
                Instruction::Li {
                    rd: A0,
                    imm: 0x1_0000_0002_0000,
                },
                Instruction::Load {
                    width: LoadWidth::Bu,
                    rd: A1,
                    rs1: A0,
                    off: 0,
                },
            ])
            .data(&[0x42]),
        );
        let (t, inst) = run(&p, &[], 100);
        assert_eq!(t, Termination::Halt);
        assert_eq!(inst.reg(A1), 0x42);
        // Faults.
        for width in LoadWidth::ALL_FOR_TEST {
            let p = program(&single(&[Instruction::Load {
                width,
                rd: A1,
                rs1: Reg::ZERO,
                off: 0x100,
            }]));
            let (t, inst) = run(&p, &[], 100);
            assert_eq!(t, Termination::MemoryFault);
            assert_eq!(inst.reg(A1), 0);
        }
        for width in StoreWidth::ALL_FOR_TEST {
            let p = program(
                &single(&[Instruction::Store {
                    width,
                    rs1: Reg::ZERO,
                    rs2: A0,
                    off: 0x1_0000,
                }])
                .rodata(&[0; 8]),
            );
            let (t, _) = run(&p, &[1], 100);
            assert_eq!(t, Termination::MemoryFault);
        }
    }

    #[test]
    fn branches_jumps_and_fallthrough() {
        for (cond, a, b, taken) in [
            (Cond::Eq, 1, 1, true),
            (Cond::Eq, 1, 2, false),
            (Cond::Ne, 1, 2, true),
            (Cond::Ne, 2, 2, false),
            (Cond::Lt, u64::MAX, 0, true),
            (Cond::Lt, 0, u64::MAX, false),
            (Cond::Ge, 0, u64::MAX, true),
            (Cond::Ge, u64::MAX, 0, false),
            (Cond::Ltu, 0, u64::MAX, true),
            (Cond::Ltu, u64::MAX, 0, false),
            (Cond::Geu, u64::MAX, 0, true),
            (Cond::Geu, 0, 1, false),
        ] {
            let mut m = ModuleBuilder::new();
            m.block(&[Instruction::Branch {
                cond,
                rs1: A0,
                rs2: A1,
                block: 2,
            }]);
            m.block(&[Instruction::Li { rd: A2, imm: 1 }, Instruction::Halt]); // fallthrough target
            m.block(&[Instruction::Li { rd: A2, imm: 2 }, Instruction::Halt]);
            let p = program(&m.export("main", 0));
            let (t, inst) = run(&p, &[a, b], 100);
            assert_eq!(t, Termination::Halt);
            assert_eq!(inst.reg(A2), if taken { 2 } else { 1 }, "{cond:?} {a} {b}");
        }
        // Fallthrough from a block ending in a plain instruction, and jump.
        let mut m = ModuleBuilder::new();
        m.block(&[Instruction::Li { rd: A0, imm: 1 }]);
        m.block(&[
            Instruction::AluImm {
                op: AluImmOp::Addi,
                rd: A0,
                rs1: A0,
                imm: 1,
            },
            Instruction::Jump { block: 3 },
        ]);
        m.block(&[Instruction::Trap]);
        m.block(&[Instruction::Halt]);
        let p = program(&m.export("main", 0));
        let (t, inst) = run(&p, &[], 100);
        assert_eq!(t, Termination::Halt);
        assert_eq!(inst.reg(A0), 2);
        assert_eq!(inst.gas(), 100 - 1 - 3 - 1);
        // Trap.
        let mut m = ModuleBuilder::new();
        m.block(&[Instruction::Trap]);
        let p = program(&m.export("main", 0));
        assert_eq!(run(&p, &[], 10).0, Termination::Trap);
    }

    #[test]
    fn calls_and_indirect_jumps() {
        // main: call f (block 2) with continuation block 1; block 1 halts.
        // f: a0 += 10; ret.
        let mut m = ModuleBuilder::new();
        let cont = m.slot(1);
        m.block(&[Instruction::Call {
            rd: Reg::RA,
            block: 2,
            slot: cont,
        }]);
        m.block(&[Instruction::Halt]);
        m.block(&[
            Instruction::AluImm {
                op: AluImmOp::Addi,
                rd: A0,
                rs1: A0,
                imm: 10,
            },
            Instruction::JumpIndirect {
                rs1: Reg::RA,
                off: 0,
            },
        ]);
        let p = program(&m.export("main", 0));
        let (t, inst) = run(&p, &[5], 100);
        assert_eq!(t, Termination::Halt);
        assert_eq!(inst.reg(A0), 15);
        assert_eq!(inst.reg(Reg::RA), 8 * u64::from(cont));

        // call_indirect through a function pointer held in the link register
        // itself: the target is read before rd is written.
        let mut m = ModuleBuilder::new();
        let cont = m.slot(1);
        let fptr = m.slot(2);
        m.block(&[
            Instruction::Li {
                rd: Reg::RA,
                imm: 8 * i64::from(fptr),
            },
            Instruction::CallIndirect {
                rd: Reg::RA,
                rs1: Reg::RA,
                off: 0,
                slot: cont,
            },
        ]);
        m.block(&[Instruction::Halt]);
        m.block(&[
            Instruction::Li { rd: A0, imm: 77 },
            Instruction::JumpIndirect {
                rs1: Reg::RA,
                off: 0,
            },
        ]);
        let p = program(&m.export("main", 0));
        let (t, inst) = run(&p, &[], 100);
        assert_eq!(t, Termination::Halt);
        assert_eq!(inst.reg(A0), 77);

        // Offsets apply, and the high 32 bits are ignored.
        let mut m = ModuleBuilder::new();
        let s = m.slot(1);
        m.block(&[
            Instruction::Li {
                rd: A0,
                imm: (8 * i64::from(s)) + 4 + (1 << 40),
            },
            Instruction::JumpIndirect { rs1: A0, off: -4 },
        ]);
        m.block(&[Instruction::Halt]);
        let p = program(&m.export("main", 0));
        assert_eq!(run(&p, &[], 100).0, Termination::Halt);

        // Invalid targets: zero, misaligned, beyond the table, empty slot.
        for bad in [0i64, 4, 8 * 50, 8 * 2] {
            let mut m = ModuleBuilder::new();
            m.slot(1);
            m.jump_table.push(None); // slot 2 empty
            m.block(&[
                Instruction::Li { rd: A0, imm: bad },
                Instruction::JumpIndirect { rs1: A0, off: 0 },
            ]);
            m.block(&[Instruction::Halt]);
            let p = program(&m.export("main", 0));
            assert_eq!(run(&p, &[], 100).0, Termination::InvalidJump, "{bad}");
        }
    }

    #[test]
    fn gas_is_charged_at_block_entry_and_per_iteration() {
        // Block 0: li; branch (cost 1 + 2 = 3). Loop a0 times through block 0.
        // Block 1: halt (cost 1).
        let mut m = ModuleBuilder::new();
        m.block(&[
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
        m.block(&[Instruction::Halt]);
        let p = program(&m.export("main", 0));
        let (t, inst) = run(&p, &[4], 100);
        assert_eq!(t, Termination::Halt);
        assert_eq!(inst.gas(), 100 - 4 * 3 - 1);
        assert_eq!(inst.steps(), 9);
        // Exactly enough.
        let (t, inst) = run(&p, &[4], 13);
        assert_eq!(t, Termination::Halt);
        assert_eq!(inst.gas(), 0);
        // One short: out of gas at the entry to the halt block, nothing of it executed.
        let (t, inst) = run(&p, &[4], 12);
        assert_eq!(t, Termination::OutOfGas);
        assert_eq!(inst.gas(), -1);
        assert_eq!(inst.steps(), 8);
        // Zero gas: out of gas before the first instruction; registers untouched.
        let (t, inst) = run(&p, &[4], 0);
        assert_eq!(t, Termination::OutOfGas);
        assert_eq!(inst.reg(A0), 4);
        assert_eq!(inst.gas(), -3);
    }

    #[test]
    fn sbrk_semantics_and_dynamic_gas() {
        let p = program(&single(&[
            Instruction::Sbrk {
                rd: A1,
                rs1: Reg::ZERO,
            }, // 0 bytes: current end, no charge
            Instruction::Li { rd: A0, imm: 1 },
            Instruction::Sbrk { rd: A2, rs1: A0 }, // one page
            Instruction::Li {
                rd: A0,
                imm: 0x10_0000,
            },
            Instruction::Sbrk { rd: A3, rs1: A0 }, // exceeds heap_max (1 MiB total): 0, no charge
            Instruction::Li {
                rd: A0,
                imm: 0x3_0000,
            },
            Instruction::Store {
                width: StoreWidth::B,
                rs1: A0,
                rs2: A0,
                off: 0xFFF,
            },
        ]));
        let (t, inst) = run(&p, &[], 10_000);
        assert_eq!(t, Termination::Halt);
        assert_eq!(inst.reg(A1), 0x3_0000);
        assert_eq!(inst.reg(A2), 0x3_0000);
        assert_eq!(inst.reg(A3), 0);
        assert_eq!(inst.memory().heap_size(), 4096);
        // Static: 10 + 1 + 10 + 1 + 10 + 1 + 3 + 1 = 37, dynamic: 256.
        assert_eq!(inst.gas(), 10_000 - 37 - 256);
        // Dynamic charge fails: static 37 fits, the page does not.
        let (t, inst) = run(&p, &[], 37 + 255);
        assert_eq!(t, Termination::OutOfGas);
        assert_eq!(inst.memory().heap_size(), 0);
        assert_eq!(inst.reg(A2), 0);
    }

    #[test]
    fn bulk_memory_semantics_and_dynamic_gas() {
        let rodata: Vec<u8> = (1u8..=64).collect();
        let b = single(&[
            Instruction::Li {
                rd: A0,
                imm: 0xFFFC_0000,
            },
            Instruction::Li {
                rd: A1,
                imm: 0x1_0000,
            },
            Instruction::Li { rd: A2, imm: 33 },
            Instruction::Memcopy {
                dst: A0,
                src: A1,
                len: A2,
            },
            Instruction::Li {
                rd: A3,
                imm: 0xFFFC_0010,
            },
            Instruction::Memcopy {
                dst: A3,
                src: A0,
                len: A2,
            }, // overlapping
            Instruction::Li { rd: A4, imm: 0x1FF },
            Instruction::Li { rd: A5, imm: 4 },
            Instruction::Memfill {
                dst: A0,
                val: A4,
                len: A5,
            },
        ])
        .rodata(&rodata);
        let p = program(&b);
        let (t, inst) = run(&p, &[], 10_000);
        assert_eq!(t, Termination::Halt);
        assert_eq!(inst.memory().read(0xFFFC_0000, 4).unwrap(), &[0xFF; 4]);
        assert_eq!(inst.memory().read(0xFFFC_0010, 33).unwrap(), &rodata[..33]);
        // Static: 1*7 + 10 + 10 + 10 + 1(halt) = 38; dynamic: 2 + 2 + 1 = 5.
        assert_eq!(inst.gas(), 10_000 - 37 - 5);
        // Dynamic charge fails before any copy.
        let (t, inst) = run(&p, &[], 37 + 1);
        assert_eq!(t, Termination::OutOfGas);
        assert_eq!(inst.memory().read(0xFFFC_0000, 1).unwrap(), &[0]);
        // Faulting copy and fill still charge the dynamic cost.
        let p = program(&single(&[
            Instruction::Li { rd: A1, imm: 0x100 },
            Instruction::Memcopy {
                dst: A1,
                src: A1,
                len: A1,
            },
        ]));
        let (t, inst) = run(&p, &[], 1000);
        assert_eq!(t, Termination::MemoryFault);
        assert_eq!(inst.gas(), 1000 - 1 - 10 - 1 - 8);
        let p = program(&single(&[
            Instruction::Li { rd: A1, imm: 0x100 },
            Instruction::Memfill {
                dst: A1,
                val: A1,
                len: A1,
            },
        ]));
        let (t, inst) = run(&p, &[], 1000);
        assert_eq!(t, Termination::MemoryFault);
        assert_eq!(inst.gas(), 1000 - 1 - 10 - 1 - 8);
    }

    #[test]
    fn host_calls() {
        let mut b = ModuleBuilder::new();
        let ok = b.import("ok");
        let fail = b.import("fail");
        let oog = b.import("oog");
        let clobber = b.import("clobber_zero");
        b.block(&[Instruction::Ecall { import: ok }, Instruction::Halt]);
        b.block(&[Instruction::Ecall { import: fail }, Instruction::Halt]);
        b.block(&[Instruction::Ecall { import: oog }, Instruction::Halt]);
        b.block(&[Instruction::Ecall { import: clobber }, Instruction::Halt]);
        let b = b
            .export("main", 0)
            .export("f", 1)
            .export("g", 2)
            .export("z", 3);
        let p = program(&b);
        let mut host = TestHost::default();
        let mut inst = Instance::new(&p, &host, Capability::Sandboxed, "main", &[41], 100).unwrap();
        assert_eq!(inst.run(&mut host), Termination::Halt);
        assert_eq!(inst.reg(A0), 42);
        assert_eq!(inst.reg(A1), 0xBEEF);
        assert_eq!(inst.gas(), 100 - 11 - 5);
        assert_eq!(inst.memory().read(0xFFFC_0000, 1).unwrap(), &[0xAA]);
        assert_eq!(host.calls, vec![1]);
        let mut inst = Instance::new(&p, &host, Capability::Sandboxed, "f", &[], 100).unwrap();
        assert_eq!(inst.run(&mut host), Termination::HostError(7));
        let mut inst = Instance::new(&p, &host, Capability::Sandboxed, "g", &[], 100).unwrap();
        assert_eq!(inst.run(&mut host), Termination::OutOfGas);
        assert!(inst.gas() < 0);
        let mut inst = Instance::new(&p, &host, Capability::Sandboxed, "z", &[], 100).unwrap();
        assert_eq!(inst.run(&mut host), Termination::Halt);
        assert_eq!(inst.reg(Reg::ZERO), 0);
    }

    #[test]
    fn step_limit_and_resume() {
        let p = program(&single(&[
            Instruction::Li { rd: A0, imm: 1 },
            Instruction::Li { rd: A1, imm: 2 },
            Instruction::Li { rd: A2, imm: 3 },
        ]));
        let mut host = TestHost::default();
        let mut inst = Instance::new(&p, &host, Capability::Sandboxed, "main", &[], 100).unwrap();
        assert_eq!(
            inst.run_with_step_limit(&mut host, 2),
            Termination::StepLimit
        );
        assert_eq!(inst.steps(), 2);
        assert_eq!(inst.reg(A1), 2);
        assert_eq!(inst.reg(A2), 0);
        inst.memory_mut().write(0xFFFC_0000, &[1]).unwrap();
        assert_eq!(
            inst.run_with_step_limit(&mut host, 0),
            Termination::StepLimit
        );
        assert_eq!(inst.run(&mut host), Termination::Halt);
        assert_eq!(inst.steps(), 4);
        assert_eq!(inst.reg(A2), 3);
        assert_eq!(inst.gas(), 100 - 4);
    }
}
