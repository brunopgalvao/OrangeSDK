//! Instruction set: operands, encoding, and decoding (spec 02).
//!
//! Semantics live in the interpreter; this module is the single place that
//! knows how an instruction is laid out in bytes. Every instruction has exactly
//! one encoding, so `decode(encode(i)) == i` and `encode(decode(b)) == b` for
//! every valid `b`.

use alloc::vec::Vec;

use crate::leb128::{LebError, read_sleb, read_uleb, write_sleb, write_uleb};

/// A register index in `0..16` (spec 01 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Reg(u8);

impl Reg {
    /// `zero`, always reads 0.
    pub const ZERO: Reg = Reg(0);
    /// Return address.
    pub const RA: Reg = Reg(1);
    /// Stack pointer.
    pub const SP: Reg = Reg(2);
    /// First argument / return register.
    pub const A0: Reg = Reg(10);
    /// Second argument / return register.
    pub const A1: Reg = Reg(11);
    /// Third argument register.
    pub const A2: Reg = Reg(12);
    /// Fourth argument register.
    pub const A3: Reg = Reg(13);
    /// Fifth argument register.
    pub const A4: Reg = Reg(14);
    /// Sixth argument register.
    pub const A5: Reg = Reg(15);

    /// Builds a register from its index, or `None` if out of range.
    #[must_use]
    pub const fn new(index: u8) -> Option<Reg> {
        if index < 16 { Some(Reg(index)) } else { None }
    }

    /// The register's index.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    const fn from_nibble(n: u8) -> Reg {
        Reg(n & 0x0F)
    }
}

/// Register–immediate operations (spec 02 §5, excluding `li`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AluImmOp {
    /// `addi`
    Addi,
    /// `andi`
    Andi,
    /// `ori`
    Ori,
    /// `xori`
    Xori,
    /// `slti`
    Slti,
    /// `sltiu`
    Sltiu,
    /// `slli`
    Slli,
    /// `srli`
    Srli,
    /// `srai`
    Srai,
    /// `addiw`
    Addiw,
    /// `slliw`
    Slliw,
    /// `srliw`
    Srliw,
    /// `sraiw`
    Sraiw,
}

impl AluImmOp {
    const ALL: [AluImmOp; 13] = [
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

    /// The opcode byte (spec 02 §5).
    #[must_use]
    pub const fn opcode(self) -> u8 {
        0x11 + self as u8
    }

    const fn from_opcode(op: u8) -> Option<AluImmOp> {
        if op >= 0x11 && op <= 0x1D {
            Some(Self::ALL[(op - 0x11) as usize])
        } else {
            None
        }
    }

    /// The valid range of the immediate for shift forms, or `None` if unrestricted.
    #[must_use]
    pub const fn shift_limit(self) -> Option<i64> {
        match self {
            AluImmOp::Slli | AluImmOp::Srli | AluImmOp::Srai => Some(63),
            AluImmOp::Slliw | AluImmOp::Srliw | AluImmOp::Sraiw => Some(31),
            _ => None,
        }
    }
}

/// Register–register operations (spec 02 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum AluOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Sll,
    Srl,
    Sra,
    Slt,
    Sltu,
    Mul,
    Mulh,
    Mulhsu,
    Mulhu,
    Div,
    Divu,
    Rem,
    Remu,
    Addw,
    Subw,
    Sllw,
    Srlw,
    Sraw,
    Mulw,
    Divw,
    Divuw,
    Remw,
    Remuw,
}

impl AluOp {
    const ALL: [AluOp; 28] = [
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

    /// The opcode byte (spec 02 §6).
    #[must_use]
    pub const fn opcode(self) -> u8 {
        0x20 + self as u8
    }

    const fn from_opcode(op: u8) -> Option<AluOp> {
        if op >= 0x20 && op <= 0x3B {
            Some(Self::ALL[(op - 0x20) as usize])
        } else {
            None
        }
    }
}

/// Load widths and extensions (spec 02 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum LoadWidth {
    B,
    Bu,
    H,
    Hu,
    W,
    Wu,
    D,
}

impl LoadWidth {
    /// Every load width, for exhaustive tests.
    #[cfg(test)]
    pub(crate) const ALL_FOR_TEST: [LoadWidth; 7] = Self::ALL;
    const ALL: [LoadWidth; 7] = [
        LoadWidth::B,
        LoadWidth::Bu,
        LoadWidth::H,
        LoadWidth::Hu,
        LoadWidth::W,
        LoadWidth::Wu,
        LoadWidth::D,
    ];

    /// The opcode byte (spec 02 §7).
    #[must_use]
    pub const fn opcode(self) -> u8 {
        0x40 + self as u8
    }

    const fn from_opcode(op: u8) -> Option<LoadWidth> {
        if op >= 0x40 && op <= 0x46 {
            Some(Self::ALL[(op - 0x40) as usize])
        } else {
            None
        }
    }

    /// Bytes accessed.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        match self {
            LoadWidth::B | LoadWidth::Bu => 1,
            LoadWidth::H | LoadWidth::Hu => 2,
            LoadWidth::W | LoadWidth::Wu => 4,
            LoadWidth::D => 8,
        }
    }
}

/// Store widths (spec 02 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum StoreWidth {
    B,
    H,
    W,
    D,
}

impl StoreWidth {
    /// Every store width, for exhaustive tests.
    #[cfg(test)]
    pub(crate) const ALL_FOR_TEST: [StoreWidth; 4] = Self::ALL;
    const ALL: [StoreWidth; 4] = [StoreWidth::B, StoreWidth::H, StoreWidth::W, StoreWidth::D];

    /// The opcode byte (spec 02 §8).
    #[must_use]
    pub const fn opcode(self) -> u8 {
        0x48 + self as u8
    }

    const fn from_opcode(op: u8) -> Option<StoreWidth> {
        if op >= 0x48 && op <= 0x4B {
            Some(Self::ALL[(op - 0x48) as usize])
        } else {
            None
        }
    }

    /// Bytes accessed.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        match self {
            StoreWidth::B => 1,
            StoreWidth::H => 2,
            StoreWidth::W => 4,
            StoreWidth::D => 8,
        }
    }
}

/// Branch conditions (spec 02 §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum Cond {
    Eq,
    Ne,
    Lt,
    Ge,
    Ltu,
    Geu,
}

impl Cond {
    const ALL: [Cond; 6] = [Cond::Eq, Cond::Ne, Cond::Lt, Cond::Ge, Cond::Ltu, Cond::Geu];

    /// The opcode byte (spec 02 §9).
    #[must_use]
    pub const fn opcode(self) -> u8 {
        0x58 + self as u8
    }

    const fn from_opcode(op: u8) -> Option<Cond> {
        if op >= 0x58 && op <= 0x5D {
            Some(Self::ALL[(op - 0x58) as usize])
        } else {
            None
        }
    }
}

/// Opcodes of the instructions that are not members of an operation family.
pub mod opcode {
    /// `trap`
    pub const TRAP: u8 = 0x00;
    /// `halt`
    pub const HALT: u8 = 0x01;
    /// `ecall`
    pub const ECALL: u8 = 0x02;
    /// `sbrk`
    pub const SBRK: u8 = 0x03;
    /// `memcopy`
    pub const MEMCOPY: u8 = 0x04;
    /// `memfill`
    pub const MEMFILL: u8 = 0x05;
    /// `li`
    pub const LI: u8 = 0x10;
    /// `jump`
    pub const JUMP: u8 = 0x50;
    /// `call`
    pub const CALL: u8 = 0x51;
    /// `jump_indirect`
    pub const JUMP_INDIRECT: u8 = 0x52;
    /// `call_indirect`
    pub const CALL_INDIRECT: u8 = 0x53;
    /// First opcode of the reserved extension range (spec 02 §11).
    pub const EXTENSION_BASE: u8 = 0xC0;
}

/// A decoded instruction (spec 02).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Instruction {
    /// Terminate with `Trap`.
    Trap,
    /// Terminate with `Halt`.
    Halt,
    /// Call host function `import`.
    Ecall {
        /// Index into the module's import table.
        import: u32,
    },
    /// Grow the heap by `R[rs1]` bytes; `R[rd]` gets the old end or 0.
    Sbrk {
        /// Destination.
        rd: Reg,
        /// Byte count source.
        rs1: Reg,
    },
    /// Copy `R[len]` bytes from `R[src]` to `R[dst]`.
    Memcopy {
        /// Destination address register.
        dst: Reg,
        /// Source address register.
        src: Reg,
        /// Length register.
        len: Reg,
    },
    /// Fill `R[len]` bytes at `R[dst]` with the low byte of `R[val]`.
    Memfill {
        /// Destination address register.
        dst: Reg,
        /// Value register.
        val: Reg,
        /// Length register.
        len: Reg,
    },
    /// `R[rd] = imm`.
    Li {
        /// Destination.
        rd: Reg,
        /// The constant.
        imm: i64,
    },
    /// Register–immediate operation.
    AluImm {
        /// Operation.
        op: AluImmOp,
        /// Destination.
        rd: Reg,
        /// Source.
        rs1: Reg,
        /// Immediate.
        imm: i64,
    },
    /// Register–register operation.
    Alu {
        /// Operation.
        op: AluOp,
        /// Destination.
        rd: Reg,
        /// First source.
        rs1: Reg,
        /// Second source.
        rs2: Reg,
    },
    /// Load from `R[rs1] + off`.
    Load {
        /// Width and extension.
        width: LoadWidth,
        /// Destination.
        rd: Reg,
        /// Base.
        rs1: Reg,
        /// Offset.
        off: i64,
    },
    /// Store `R[rs2]` to `R[rs1] + off`.
    Store {
        /// Width.
        width: StoreWidth,
        /// Base.
        rs1: Reg,
        /// Value.
        rs2: Reg,
        /// Offset.
        off: i64,
    },
    /// Unconditional transfer to `block`.
    Jump {
        /// Target block index.
        block: u32,
    },
    /// `R[rd] = 8 × slot`, then transfer to `block`.
    Call {
        /// Link register.
        rd: Reg,
        /// Target block index.
        block: u32,
        /// Continuation slot.
        slot: u32,
    },
    /// Transfer through the jump table using `R[rs1] + off`.
    JumpIndirect {
        /// Address register.
        rs1: Reg,
        /// Offset.
        off: i64,
    },
    /// `R[rd] = 8 × slot`, then transfer through the jump table.
    CallIndirect {
        /// Link register.
        rd: Reg,
        /// Address register.
        rs1: Reg,
        /// Offset.
        off: i64,
        /// Continuation slot.
        slot: u32,
    },
    /// Conditional transfer to `block`, otherwise fall through.
    Branch {
        /// Condition.
        cond: Cond,
        /// First operand.
        rs1: Reg,
        /// Second operand.
        rs2: Reg,
        /// Target block index.
        block: u32,
    },
}

/// Why decoding failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeErrorKind {
    /// The byte string ended inside an instruction.
    Truncated,
    /// Not an opcode of this spec version.
    UnknownOpcode(u8),
    /// A single-register byte with its high nibble set.
    RegisterHighBits,
    /// A malformed LEB128 operand.
    Leb(LebError),
    /// A shift immediate outside its allowed range.
    ShiftOutOfRange,
}

/// A decoding failure at a byte offset within the decoded slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError {
    /// What went wrong.
    pub kind: DecodeErrorKind,
    /// Offset of the offending byte within the input slice.
    pub offset: usize,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn byte(&mut self) -> Result<u8, DecodeError> {
        let b = *self.bytes.get(self.pos).ok_or(DecodeError {
            kind: DecodeErrorKind::Truncated,
            offset: self.pos,
        })?;
        self.pos += 1;
        Ok(b)
    }

    fn reg_pair(&mut self) -> Result<(Reg, Reg), DecodeError> {
        let b = self.byte()?;
        Ok((Reg::from_nibble(b), Reg::from_nibble(b >> 4)))
    }

    fn reg_single(&mut self) -> Result<Reg, DecodeError> {
        let b = self.byte()?;
        if b & 0xF0 != 0 {
            return Err(DecodeError {
                kind: DecodeErrorKind::RegisterHighBits,
                offset: self.pos - 1,
            });
        }
        Ok(Reg::from_nibble(b))
    }

    fn uleb(&mut self) -> Result<u32, DecodeError> {
        let (v, n) = read_uleb(&self.bytes[self.pos..]).map_err(|e| self.leb_err(e))?;
        self.pos += n;
        Ok(v)
    }

    fn sleb(&mut self) -> Result<i64, DecodeError> {
        let (v, n) = read_sleb(&self.bytes[self.pos..]).map_err(|e| self.leb_err(e))?;
        self.pos += n;
        Ok(v)
    }

    fn leb_err(&self, e: LebError) -> DecodeError {
        let kind = match e {
            LebError::Truncated => DecodeErrorKind::Truncated,
            other => DecodeErrorKind::Leb(other),
        };
        DecodeError {
            kind,
            offset: self.pos,
        }
    }
}

impl Instruction {
    /// The opcode byte of this instruction (spec 02 §11).
    #[must_use]
    pub const fn opcode(&self) -> u8 {
        match self {
            Instruction::Trap => opcode::TRAP,
            Instruction::Halt => opcode::HALT,
            Instruction::Ecall { .. } => opcode::ECALL,
            Instruction::Sbrk { .. } => opcode::SBRK,
            Instruction::Memcopy { .. } => opcode::MEMCOPY,
            Instruction::Memfill { .. } => opcode::MEMFILL,
            Instruction::Li { .. } => opcode::LI,
            Instruction::AluImm { op, .. } => op.opcode(),
            Instruction::Alu { op, .. } => op.opcode(),
            Instruction::Load { width, .. } => width.opcode(),
            Instruction::Store { width, .. } => width.opcode(),
            Instruction::Jump { .. } => opcode::JUMP,
            Instruction::Call { .. } => opcode::CALL,
            Instruction::JumpIndirect { .. } => opcode::JUMP_INDIRECT,
            Instruction::CallIndirect { .. } => opcode::CALL_INDIRECT,
            Instruction::Branch { cond, .. } => cond.opcode(),
        }
    }

    /// Whether this instruction must be the last of its block (spec 02).
    #[must_use]
    pub const fn ends_block(&self) -> bool {
        matches!(
            self,
            Instruction::Trap
                | Instruction::Halt
                | Instruction::Jump { .. }
                | Instruction::Call { .. }
                | Instruction::JumpIndirect { .. }
                | Instruction::CallIndirect { .. }
                | Instruction::Branch { .. }
        )
    }

    /// Whether control may continue at the next block after this instruction
    /// (spec 02 §10). True for branches and for every non-terminating instruction.
    #[must_use]
    pub const fn falls_through(&self) -> bool {
        !matches!(
            self,
            Instruction::Trap
                | Instruction::Halt
                | Instruction::Jump { .. }
                | Instruction::Call { .. }
                | Instruction::JumpIndirect { .. }
                | Instruction::CallIndirect { .. }
        )
    }

    /// Appends the canonical encoding (spec 02 §2).
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.opcode());
        match *self {
            Instruction::Trap | Instruction::Halt => {}
            Instruction::Ecall { import } => write_uleb(import, out),
            Instruction::Sbrk { rd, rs1 } => out.push(pack(rd, rs1)),
            Instruction::Memcopy { dst, src, len } => {
                out.push(pack(dst, src));
                out.push(len.0);
            }
            Instruction::Memfill { dst, val, len } => {
                out.push(pack(dst, val));
                out.push(len.0);
            }
            Instruction::Li { rd, imm } => {
                out.push(rd.0);
                write_sleb(imm, out);
            }
            Instruction::AluImm { rd, rs1, imm, .. } => {
                out.push(pack(rd, rs1));
                write_sleb(imm, out);
            }
            Instruction::Alu { rd, rs1, rs2, .. } => {
                out.push(pack(rd, rs1));
                out.push(rs2.0);
            }
            Instruction::Load { rd, rs1, off, .. } => {
                out.push(pack(rd, rs1));
                write_sleb(off, out);
            }
            Instruction::Store { rs1, rs2, off, .. } => {
                out.push(pack(rs1, rs2));
                write_sleb(off, out);
            }
            Instruction::Jump { block } => write_uleb(block, out),
            Instruction::Call { rd, block, slot } => {
                out.push(rd.0);
                write_uleb(block, out);
                write_uleb(slot, out);
            }
            Instruction::JumpIndirect { rs1, off } => {
                out.push(rs1.0);
                write_sleb(off, out);
            }
            Instruction::CallIndirect { rd, rs1, off, slot } => {
                out.push(pack(rd, rs1));
                write_sleb(off, out);
                write_uleb(slot, out);
            }
            Instruction::Branch {
                rs1, rs2, block, ..
            } => {
                out.push(pack(rs1, rs2));
                write_uleb(block, out);
            }
        }
    }

    /// Decodes one instruction from the start of `bytes`, returning it and the
    /// number of bytes consumed.
    ///
    /// # Errors
    /// Any byte string that is not the canonical encoding of an instruction of
    /// this spec version (spec 02 §2, §11).
    pub fn decode(bytes: &[u8]) -> Result<(Instruction, usize), DecodeError> {
        let mut c = Cursor { bytes, pos: 0 };
        let op = c.byte()?;
        let ins = match op {
            opcode::TRAP => Instruction::Trap,
            opcode::HALT => Instruction::Halt,
            opcode::ECALL => Instruction::Ecall { import: c.uleb()? },
            opcode::SBRK => {
                let (rd, rs1) = c.reg_pair()?;
                Instruction::Sbrk { rd, rs1 }
            }
            opcode::MEMCOPY => {
                let (dst, src) = c.reg_pair()?;
                let len = c.reg_single()?;
                Instruction::Memcopy { dst, src, len }
            }
            opcode::MEMFILL => {
                let (dst, val) = c.reg_pair()?;
                let len = c.reg_single()?;
                Instruction::Memfill { dst, val, len }
            }
            opcode::LI => {
                let rd = c.reg_single()?;
                let imm = c.sleb()?;
                Instruction::Li { rd, imm }
            }
            opcode::JUMP => Instruction::Jump { block: c.uleb()? },
            opcode::CALL => {
                let rd = c.reg_single()?;
                let block = c.uleb()?;
                let slot = c.uleb()?;
                Instruction::Call { rd, block, slot }
            }
            opcode::JUMP_INDIRECT => {
                let rs1 = c.reg_single()?;
                let off = c.sleb()?;
                Instruction::JumpIndirect { rs1, off }
            }
            opcode::CALL_INDIRECT => {
                let (rd, rs1) = c.reg_pair()?;
                let off = c.sleb()?;
                let slot = c.uleb()?;
                Instruction::CallIndirect { rd, rs1, off, slot }
            }
            _ => Self::decode_family(op, &mut c)?,
        };
        Ok((ins, c.pos))
    }

    fn decode_family(op: u8, c: &mut Cursor<'_>) -> Result<Instruction, DecodeError> {
        if let Some(aop) = AluImmOp::from_opcode(op) {
            let (rd, rs1) = c.reg_pair()?;
            let imm_offset = c.pos;
            let imm = c.sleb()?;
            if let Some(limit) = aop.shift_limit()
                && !(0..=limit).contains(&imm)
            {
                return Err(DecodeError {
                    kind: DecodeErrorKind::ShiftOutOfRange,
                    offset: imm_offset,
                });
            }
            return Ok(Instruction::AluImm {
                op: aop,
                rd,
                rs1,
                imm,
            });
        }
        if let Some(aop) = AluOp::from_opcode(op) {
            let (rd, rs1) = c.reg_pair()?;
            let rs2 = c.reg_single()?;
            return Ok(Instruction::Alu {
                op: aop,
                rd,
                rs1,
                rs2,
            });
        }
        if let Some(width) = LoadWidth::from_opcode(op) {
            let (rd, rs1) = c.reg_pair()?;
            let off = c.sleb()?;
            return Ok(Instruction::Load {
                width,
                rd,
                rs1,
                off,
            });
        }
        if let Some(width) = StoreWidth::from_opcode(op) {
            let (rs1, rs2) = c.reg_pair()?;
            let off = c.sleb()?;
            return Ok(Instruction::Store {
                width,
                rs1,
                rs2,
                off,
            });
        }
        if let Some(cond) = Cond::from_opcode(op) {
            let (rs1, rs2) = c.reg_pair()?;
            let block = c.uleb()?;
            return Ok(Instruction::Branch {
                cond,
                rs1,
                rs2,
                block,
            });
        }
        Err(DecodeError {
            kind: DecodeErrorKind::UnknownOpcode(op),
            offset: 0,
        })
    }
}

const fn pack(low: Reg, high: Reg) -> u8 {
    low.0 | (high.0 << 4)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;

    fn r(i: u8) -> Reg {
        Reg::new(i).unwrap()
    }

    /// One instruction of every variant and family member, for exhaustive tests.
    pub(crate) fn every_instruction() -> Vec<Instruction> {
        let mut v = vec![
            Instruction::Trap,
            Instruction::Halt,
            Instruction::Ecall { import: 300 },
            Instruction::Sbrk {
                rd: r(10),
                rs1: r(11),
            },
            Instruction::Memcopy {
                dst: r(10),
                src: r(11),
                len: r(12),
            },
            Instruction::Memfill {
                dst: r(10),
                val: r(11),
                len: r(12),
            },
            Instruction::Li {
                rd: r(5),
                imm: -1_000_000,
            },
            Instruction::Jump { block: 7 },
            Instruction::Call {
                rd: r(1),
                block: 9,
                slot: 3,
            },
            Instruction::JumpIndirect { rs1: r(1), off: 0 },
            Instruction::CallIndirect {
                rd: r(1),
                rs1: r(6),
                off: -8,
                slot: 4,
            },
        ];
        for op in AluImmOp::ALL {
            let imm = if op.shift_limit().is_some() { 5 } else { -300 };
            v.push(Instruction::AluImm {
                op,
                rd: r(3),
                rs1: r(4),
                imm,
            });
        }
        for op in AluOp::ALL {
            v.push(Instruction::Alu {
                op,
                rd: r(3),
                rs1: r(4),
                rs2: r(5),
            });
        }
        for width in LoadWidth::ALL {
            v.push(Instruction::Load {
                width,
                rd: r(3),
                rs1: r(2),
                off: 16,
            });
        }
        for width in StoreWidth::ALL {
            v.push(Instruction::Store {
                width,
                rs1: r(2),
                rs2: r(3),
                off: -16,
            });
        }
        for cond in Cond::ALL {
            v.push(Instruction::Branch {
                cond,
                rs1: r(3),
                rs2: r(0),
                block: 2,
            });
        }
        v
    }

    #[test]
    fn registers() {
        assert_eq!(Reg::new(15), Some(Reg::A5));
        assert_eq!(Reg::new(16), None);
        assert_eq!(Reg::ZERO.index(), 0);
        assert_eq!(Reg::RA.index(), 1);
        assert_eq!(Reg::SP.index(), 2);
        assert_eq!(Reg::A0.index(), 10);
        assert_eq!(Reg::A1.index(), 11);
        assert_eq!(Reg::A2.index(), 12);
        assert_eq!(Reg::A3.index(), 13);
        assert_eq!(Reg::A4.index(), 14);
        assert!(Reg::A0 < Reg::A1);
    }

    #[test]
    fn opcode_map_matches_spec() {
        assert_eq!(AluImmOp::Addi.opcode(), 0x11);
        assert_eq!(AluImmOp::Sraiw.opcode(), 0x1D);
        assert_eq!(AluOp::Add.opcode(), 0x20);
        assert_eq!(AluOp::Remuw.opcode(), 0x3B);
        assert_eq!(LoadWidth::B.opcode(), 0x40);
        assert_eq!(LoadWidth::D.opcode(), 0x46);
        assert_eq!(StoreWidth::B.opcode(), 0x48);
        assert_eq!(StoreWidth::D.opcode(), 0x4B);
        assert_eq!(Cond::Eq.opcode(), 0x58);
        assert_eq!(Cond::Geu.opcode(), 0x5D);
        assert_eq!(LoadWidth::Hu.bytes(), 2);
        assert_eq!(LoadWidth::Wu.bytes(), 4);
        assert_eq!(LoadWidth::D.bytes(), 8);
        assert_eq!(LoadWidth::Bu.bytes(), 1);
        assert_eq!(StoreWidth::H.bytes(), 2);
        assert_eq!(StoreWidth::W.bytes(), 4);
        assert_eq!(StoreWidth::D.bytes(), 8);
        assert_eq!(StoreWidth::B.bytes(), 1);
        assert_eq!(AluImmOp::Slli.shift_limit(), Some(63));
        assert_eq!(AluImmOp::Sraiw.shift_limit(), Some(31));
        assert_eq!(AluImmOp::Xori.shift_limit(), None);
    }

    #[test]
    fn every_instruction_roundtrips_and_is_unique() {
        let all = every_instruction();
        let mut seen = alloc::collections::BTreeSet::new();
        for ins in &all {
            let mut bytes = Vec::new();
            ins.encode(&mut bytes);
            assert_eq!(bytes[0], ins.opcode());
            let (back, n) = Instruction::decode(&bytes).unwrap();
            assert_eq!(&back, ins);
            assert_eq!(n, bytes.len());
            assert!(seen.insert(bytes.clone()), "duplicate encoding for {ins:?}");
            // Trailing bytes are not consumed.
            bytes.push(0xAA);
            assert_eq!(Instruction::decode(&bytes).unwrap().1, n);
        }
        assert_eq!(all.len(), 11 + 13 + 28 + 7 + 4 + 6);
    }

    #[test]
    fn block_ending_and_fallthrough_tables() {
        for ins in every_instruction() {
            let ends = ins.ends_block();
            let falls = ins.falls_through();
            match ins {
                Instruction::Branch { .. } => assert!(ends && falls),
                Instruction::Trap
                | Instruction::Halt
                | Instruction::Jump { .. }
                | Instruction::Call { .. }
                | Instruction::JumpIndirect { .. }
                | Instruction::CallIndirect { .. } => assert!(ends && !falls),
                _ => assert!(!ends && falls, "{ins:?}"),
            }
        }
    }

    #[test]
    fn decode_errors() {
        let err = |b: &[u8]| Instruction::decode(b).unwrap_err();
        assert_eq!(err(&[]).kind, DecodeErrorKind::Truncated);
        assert_eq!(err(&[opcode::SBRK]).kind, DecodeErrorKind::Truncated);
        assert_eq!(err(&[opcode::SBRK]).offset, 1);
        assert_eq!(err(&[0x06]).kind, DecodeErrorKind::UnknownOpcode(0x06));
        assert_eq!(err(&[0x47]).kind, DecodeErrorKind::UnknownOpcode(0x47));
        assert_eq!(err(&[0x5E]).kind, DecodeErrorKind::UnknownOpcode(0x5E));
        assert_eq!(err(&[0xC0]).kind, DecodeErrorKind::UnknownOpcode(0xC0));
        assert_eq!(err(&[0xFF]).kind, DecodeErrorKind::UnknownOpcode(0xFF));
        assert_eq!(
            err(&[opcode::LI, 0x10, 0x00]).kind,
            DecodeErrorKind::RegisterHighBits
        );
        assert_eq!(err(&[opcode::LI, 0x10, 0x00]).offset, 1);
        assert_eq!(
            err(&[AluOp::Add.opcode(), 0x21, 0xF3]).kind,
            DecodeErrorKind::RegisterHighBits
        );
        assert_eq!(
            err(&[opcode::MEMCOPY, 0x21, 0x13]).kind,
            DecodeErrorKind::RegisterHighBits
        );
        assert_eq!(
            err(&[opcode::MEMFILL, 0x21, 0x13]).kind,
            DecodeErrorKind::RegisterHighBits
        );
        // Non-canonical immediate.
        let e = err(&[AluImmOp::Addi.opcode(), 0x21, 0x80, 0x00]);
        assert_eq!(e.kind, DecodeErrorKind::Leb(LebError::NonCanonical));
        assert_eq!(e.offset, 2);
        // Overflowing block index.
        let e = err(&[opcode::JUMP, 0x80, 0x80, 0x80, 0x80, 0x10]);
        assert_eq!(e.kind, DecodeErrorKind::Leb(LebError::Overflow));
        // Truncated immediate.
        assert_eq!(
            err(&[opcode::LI, 0x05, 0x80]).kind,
            DecodeErrorKind::Truncated
        );
        // Shift out of range: slli 64, slliw 32, srai -1.
        assert_eq!(
            err(&[AluImmOp::Slli.opcode(), 0x21, 0xC0, 0x00]).kind,
            DecodeErrorKind::ShiftOutOfRange
        );
        assert_eq!(
            err(&[AluImmOp::Slliw.opcode(), 0x21, 0x20]).kind,
            DecodeErrorKind::ShiftOutOfRange
        );
        assert_eq!(
            err(&[AluImmOp::Srai.opcode(), 0x21, 0x7F]).kind,
            DecodeErrorKind::ShiftOutOfRange
        );
        assert_eq!(err(&[AluImmOp::Srai.opcode(), 0x21, 0x7F]).offset, 2);
        // Boundary shifts decode.
        assert!(Instruction::decode(&[AluImmOp::Slli.opcode(), 0x21, 0x3F]).is_ok());
        assert!(Instruction::decode(&[AluImmOp::Sraiw.opcode(), 0x21, 0x1F]).is_ok());
    }

    fn reg_strategy() -> impl Strategy<Value = Reg> {
        (0u8..16).prop_map(|i| Reg::new(i).unwrap())
    }

    fn instruction_strategy() -> impl Strategy<Value = Instruction> {
        let reg = reg_strategy;
        prop_oneof![
            Just(Instruction::Trap),
            Just(Instruction::Halt),
            any::<u32>().prop_map(|import| Instruction::Ecall { import }),
            (reg(), reg()).prop_map(|(rd, rs1)| Instruction::Sbrk { rd, rs1 }),
            (reg(), reg(), reg()).prop_map(|(dst, src, len)| Instruction::Memcopy {
                dst,
                src,
                len
            }),
            (reg(), reg(), reg()).prop_map(|(dst, val, len)| Instruction::Memfill {
                dst,
                val,
                len
            }),
            (reg(), any::<i64>()).prop_map(|(rd, imm)| Instruction::Li { rd, imm }),
            (0usize..13, reg(), reg(), any::<i64>()).prop_map(|(i, rd, rs1, imm)| {
                let op = AluImmOp::ALL[i];
                let imm = match op.shift_limit() {
                    Some(l) => imm.rem_euclid(l + 1),
                    None => imm,
                };
                Instruction::AluImm { op, rd, rs1, imm }
            }),
            (0usize..28, reg(), reg(), reg()).prop_map(|(i, rd, rs1, rs2)| Instruction::Alu {
                op: AluOp::ALL[i],
                rd,
                rs1,
                rs2
            }),
            (0usize..7, reg(), reg(), any::<i64>()).prop_map(|(i, rd, rs1, off)| {
                Instruction::Load {
                    width: LoadWidth::ALL[i],
                    rd,
                    rs1,
                    off,
                }
            }),
            (0usize..4, reg(), reg(), any::<i64>()).prop_map(|(i, rs1, rs2, off)| {
                Instruction::Store {
                    width: StoreWidth::ALL[i],
                    rs1,
                    rs2,
                    off,
                }
            }),
            any::<u32>().prop_map(|block| Instruction::Jump { block }),
            (reg(), any::<u32>(), any::<u32>()).prop_map(|(rd, block, slot)| Instruction::Call {
                rd,
                block,
                slot
            }),
            (reg(), any::<i64>()).prop_map(|(rs1, off)| Instruction::JumpIndirect { rs1, off }),
            (reg(), reg(), any::<i64>(), any::<u32>())
                .prop_map(|(rd, rs1, off, slot)| Instruction::CallIndirect { rd, rs1, off, slot }),
            (0usize..6, reg(), reg(), any::<u32>()).prop_map(|(i, rs1, rs2, block)| {
                Instruction::Branch {
                    cond: Cond::ALL[i],
                    rs1,
                    rs2,
                    block,
                }
            }),
        ]
    }

    proptest! {
        #[test]
        fn random_instructions_roundtrip(ins in instruction_strategy()) {
            let mut bytes = Vec::new();
            ins.encode(&mut bytes);
            let (back, n) = Instruction::decode(&bytes).unwrap();
            prop_assert_eq!(back, ins);
            prop_assert_eq!(n, bytes.len());
        }
    }
}
