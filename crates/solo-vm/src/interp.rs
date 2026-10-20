//! The reference interpreter (spec 01, 02, 04).
//!
//! Deliberately simple: one instruction at a time, no caching, no tricks.
//! Every other backend must agree with this one on every program.

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
            Instruction::Memcopy { dst, src, len } => self.bulk(dst, Some(src), None, len),
            Instruction::Memfill { dst, val, len } => self.bulk(dst, None, Some(val), len),
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

    fn bulk(&mut self, dst: Reg, src: Option<Reg>, val: Option<Reg>, len: Reg) -> Flow {
        let n = addr(self.reg(len));
        if let Err(t) = self.charge(bulk_cost(n)) {
            return Flow::End(t);
        }
        let d = addr(self.reg(dst));
        let result = match (src, val) {
            (Some(s), _) => self.memory.copy(d, addr(self.reg(s)), n),
            (None, Some(v)) => {
                #[allow(clippy::cast_possible_truncation)]
                let byte = self.reg(v) as u8;
                self.memory.fill(d, byte, n)
            }
            (None, None) => unreachable!("bulk is called with a source or a value"),
        };
        match result {
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
            LoadWidth::B => (raw as u8 as i8 as i64) as u64,
            LoadWidth::H => (raw as u16 as i16 as i64) as u64,
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
        if v == 0 || v % 8 != 0 {
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
        AluImmOp::Sraiw => ((low32(a) as i32) >> (imm & 31)) as i64 as u64,
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
        AluOp::Sraw => (swa >> (b & 31)) as i64 as u64,
        AluOp::Mulw => sx32(a.wrapping_mul(b)),
        AluOp::Divw => div_signed_32(swa, swb) as i64 as u64,
        AluOp::Divuw => sx32(u64::from(div_unsigned_32(wa, wb))),
        AluOp::Remw => rem_signed_32(swa, swb) as i64 as u64,
        AluOp::Remuw => sx32(u64::from(rem_unsigned_32(wa, wb))),
    }
}

const fn div_signed(a: i64, b: i64) -> i64 {
    if b == 0 { -1 } else { a.wrapping_div(b) }
}

const fn rem_signed(a: i64, b: i64) -> i64 {
    if b == 0 { a } else { a.wrapping_rem(b) }
}

const fn div_unsigned(a: u64, b: u64) -> u64 {
    if b == 0 { u64::MAX } else { a / b }
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

const fn div_unsigned_32(a: u32, b: u32) -> u32 {
    if b == 0 { u32::MAX } else { a / b }
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
