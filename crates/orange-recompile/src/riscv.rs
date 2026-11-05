//! RV64IMAC instruction decoding for the recompiler's input (spec 03 §8).
//!
//! Compressed (C) instructions are expanded to their 32-bit equivalents, since
//! the precompiled `core` for `riscv64imac` uses them. Floating point, CSR
//! access other than the canonical `unimp`, and privileged instructions are
//! reported as unsupported.

use orange_vm::isa::{AluImmOp, AluOp, Cond, LoadWidth, Reg, StoreWidth};

/// Atomic memory operations (A extension), lowered by the recompiler to plain
/// load, operation, store (spec 02 §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum AmoOp {
    Swap,
    Add,
    Xor,
    And,
    Or,
    Min,
    Max,
    Minu,
    Maxu,
}

/// Width of an atomic operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmoWidth {
    /// 32-bit, result sign-extended.
    W,
    /// 64-bit.
    D,
}

/// A decoded RV64IMA instruction, with compressed forms already expanded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Rv {
    /// `lui rd, imm` with `imm` already shifted (`imm << 12`, sign-extended).
    Lui { rd: Reg, imm: i64 },
    /// `auipc rd, imm` with `imm` already shifted.
    Auipc { rd: Reg, imm: i64 },
    /// `jal rd, offset`.
    Jal { rd: Reg, offset: i64 },
    /// `jalr rd, rs1, offset`.
    Jalr { rd: Reg, rs1: Reg, offset: i64 },
    /// Conditional branch by `offset`.
    Branch {
        cond: Cond,
        rs1: Reg,
        rs2: Reg,
        offset: i64,
    },
    /// Load.
    Load {
        width: LoadWidth,
        rd: Reg,
        rs1: Reg,
        offset: i64,
    },
    /// Store.
    Store {
        width: StoreWidth,
        rs1: Reg,
        rs2: Reg,
        offset: i64,
    },
    /// Register–immediate operation.
    OpImm {
        op: AluImmOp,
        rd: Reg,
        rs1: Reg,
        imm: i64,
    },
    /// Register–register operation.
    Op {
        op: AluOp,
        rd: Reg,
        rs1: Reg,
        rs2: Reg,
    },
    /// `fence` or `fence.i`; deleted by the recompiler.
    Fence,
    /// `ecall`; not used by Orange guests (host calls are symbol calls).
    Ecall,
    /// `ebreak`; becomes `trap`.
    Ebreak,
    /// The canonical illegal instruction `unimp` or an all-zero word; becomes `trap`.
    Unimp,
    /// `lr.{w,d} rd, (rs1)`.
    Lr { width: AmoWidth, rd: Reg, rs1: Reg },
    /// `sc.{w,d} rd, rs2, (rs1)`.
    Sc {
        width: AmoWidth,
        rd: Reg,
        rs1: Reg,
        rs2: Reg,
    },
    /// `amo<op>.{w,d} rd, rs2, (rs1)`.
    Amo {
        op: AmoOp,
        width: AmoWidth,
        rd: Reg,
        rs1: Reg,
        rs2: Reg,
    },
}

/// An instruction word the recompiler does not accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsupported(pub u32);

fn reg(bits: u32) -> Reg {
    #[allow(clippy::cast_possible_truncation)]
    Reg::new((bits & 0x1F) as u8).expect("five bits")
}

fn sext(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    #[allow(clippy::cast_possible_wrap)]
    (((i64::from(value)) << shift) >> shift)
}

fn imm_i(w: u32) -> i64 {
    sext(w >> 20, 12)
}

fn imm_s(w: u32) -> i64 {
    sext(((w >> 25) << 5) | ((w >> 7) & 0x1F), 12)
}

fn imm_b(w: u32) -> i64 {
    let v = (((w >> 31) & 1) << 12)
        | (((w >> 7) & 1) << 11)
        | (((w >> 25) & 0x3F) << 5)
        | (((w >> 8) & 0xF) << 1);
    sext(v, 13)
}

fn imm_u(w: u32) -> i64 {
    sext(w & 0xFFFF_F000, 32)
}

fn imm_j(w: u32) -> i64 {
    let v = (((w >> 31) & 1) << 20)
        | (((w >> 12) & 0xFF) << 12)
        | (((w >> 20) & 1) << 11)
        | (((w >> 21) & 0x3FF) << 1);
    sext(v, 21)
}

/// Decodes one 32-bit instruction word.
///
/// # Errors
/// [`Unsupported`] for anything outside RV64IMA plus `fence`, `ecall`,
/// `ebreak`, and `unimp`.
#[allow(clippy::too_many_lines)]
pub fn decode(w: u32) -> Result<Rv, Unsupported> {
    if w == 0 || w == 0xC000_1073 {
        return Ok(Rv::Unimp);
    }
    let opcode = w & 0x7F;
    let rd = reg(w >> 7);
    let rs1 = reg(w >> 15);
    let rs2 = reg(w >> 20);
    let funct3 = (w >> 12) & 7;
    let funct7 = w >> 25;
    let unsupported = Err(Unsupported(w));
    let ins = match opcode {
        0x37 => Rv::Lui { rd, imm: imm_u(w) },
        0x17 => Rv::Auipc { rd, imm: imm_u(w) },
        0x6F => Rv::Jal {
            rd,
            offset: imm_j(w),
        },
        0x67 if funct3 == 0 => Rv::Jalr {
            rd,
            rs1,
            offset: imm_i(w),
        },
        0x63 => {
            let cond = match funct3 {
                0 => Cond::Eq,
                1 => Cond::Ne,
                4 => Cond::Lt,
                5 => Cond::Ge,
                6 => Cond::Ltu,
                7 => Cond::Geu,
                _ => return unsupported,
            };
            Rv::Branch {
                cond,
                rs1,
                rs2,
                offset: imm_b(w),
            }
        }
        0x03 => {
            let width = match funct3 {
                0 => LoadWidth::B,
                1 => LoadWidth::H,
                2 => LoadWidth::W,
                3 => LoadWidth::D,
                4 => LoadWidth::Bu,
                5 => LoadWidth::Hu,
                6 => LoadWidth::Wu,
                _ => return unsupported,
            };
            Rv::Load {
                width,
                rd,
                rs1,
                offset: imm_i(w),
            }
        }
        0x23 => {
            let width = match funct3 {
                0 => StoreWidth::B,
                1 => StoreWidth::H,
                2 => StoreWidth::W,
                3 => StoreWidth::D,
                _ => return unsupported,
            };
            Rv::Store {
                width,
                rs1,
                rs2,
                offset: imm_s(w),
            }
        }
        0x13 => {
            let shamt = i64::from((w >> 20) & 0x3F);
            let funct6 = w >> 26;
            let (op, imm) = match (funct3, funct6) {
                (0, _) => (AluImmOp::Addi, imm_i(w)),
                (1, 0) => (AluImmOp::Slli, shamt),
                (2, _) => (AluImmOp::Slti, imm_i(w)),
                (3, _) => (AluImmOp::Sltiu, imm_i(w)),
                (4, _) => (AluImmOp::Xori, imm_i(w)),
                (5, 0) => (AluImmOp::Srli, shamt),
                (5, 0x10) => (AluImmOp::Srai, shamt),
                (6, _) => (AluImmOp::Ori, imm_i(w)),
                (7, _) => (AluImmOp::Andi, imm_i(w)),
                _ => return unsupported,
            };
            Rv::OpImm { op, rd, rs1, imm }
        }
        0x1B => {
            let shamt = i64::from((w >> 20) & 0x1F);
            let (op, imm) = match (funct3, funct7) {
                (0, _) => (AluImmOp::Addiw, imm_i(w)),
                (1, 0) => (AluImmOp::Slliw, shamt),
                (5, 0) => (AluImmOp::Srliw, shamt),
                (5, 0x20) => (AluImmOp::Sraiw, shamt),
                _ => return unsupported,
            };
            Rv::OpImm { op, rd, rs1, imm }
        }
        0x33 => {
            let op = match (funct7, funct3) {
                (0, 0) => AluOp::Add,
                (0x20, 0) => AluOp::Sub,
                (0, 1) => AluOp::Sll,
                (0, 2) => AluOp::Slt,
                (0, 3) => AluOp::Sltu,
                (0, 4) => AluOp::Xor,
                (0, 5) => AluOp::Srl,
                (0x20, 5) => AluOp::Sra,
                (0, 6) => AluOp::Or,
                (0, 7) => AluOp::And,
                (1, 0) => AluOp::Mul,
                (1, 1) => AluOp::Mulh,
                (1, 2) => AluOp::Mulhsu,
                (1, 3) => AluOp::Mulhu,
                (1, 4) => AluOp::Div,
                (1, 5) => AluOp::Divu,
                (1, 6) => AluOp::Rem,
                (1, 7) => AluOp::Remu,
                _ => return unsupported,
            };
            Rv::Op { op, rd, rs1, rs2 }
        }
        0x3B => {
            let op = match (funct7, funct3) {
                (0, 0) => AluOp::Addw,
                (0x20, 0) => AluOp::Subw,
                (0, 1) => AluOp::Sllw,
                (0, 5) => AluOp::Srlw,
                (0x20, 5) => AluOp::Sraw,
                (1, 0) => AluOp::Mulw,
                (1, 4) => AluOp::Divw,
                (1, 5) => AluOp::Divuw,
                (1, 6) => AluOp::Remw,
                (1, 7) => AluOp::Remuw,
                _ => return unsupported,
            };
            Rv::Op { op, rd, rs1, rs2 }
        }
        0x0F if funct3 <= 1 => Rv::Fence,
        0x73 if funct3 == 0 && rd == Reg::ZERO && rs1 == Reg::ZERO => match w >> 20 {
            0 => Rv::Ecall,
            1 => Rv::Ebreak,
            _ => return unsupported,
        },
        0x2F => {
            let width = match funct3 {
                2 => AmoWidth::W,
                3 => AmoWidth::D,
                _ => return unsupported,
            };
            match funct7 >> 2 {
                0x02 if rs2 == Reg::ZERO => Rv::Lr { width, rd, rs1 },
                0x03 => Rv::Sc {
                    width,
                    rd,
                    rs1,
                    rs2,
                },
                funct5 => {
                    let op = match funct5 {
                        0x01 => AmoOp::Swap,
                        0x00 => AmoOp::Add,
                        0x04 => AmoOp::Xor,
                        0x0C => AmoOp::And,
                        0x08 => AmoOp::Or,
                        0x10 => AmoOp::Min,
                        0x14 => AmoOp::Max,
                        0x18 => AmoOp::Minu,
                        0x1C => AmoOp::Maxu,
                        _ => return unsupported,
                    };
                    Rv::Amo {
                        op,
                        width,
                        rd,
                        rs1,
                        rs2,
                    }
                }
            }
        }
        _ => return unsupported,
    };
    Ok(ins)
}

fn creg(bits: u16) -> Reg {
    #[allow(clippy::cast_possible_truncation)]
    Reg::new(8 + (bits & 7) as u8).expect("compressed registers are x8 to x15")
}

fn full(bits: u16) -> Reg {
    #[allow(clippy::cast_possible_truncation)]
    Reg::new((bits & 0x1F) as u8).expect("five bits")
}

const fn bit(h: u16, i: u32) -> u32 {
    ((h >> i) & 1) as u32
}

const fn bits(h: u16, hi: u32, lo: u32) -> u32 {
    ((h >> lo) as u32) & ((1 << (hi - lo + 1)) - 1)
}

/// Decodes one 16-bit compressed instruction into its 32-bit equivalent.
///
/// # Errors
/// [`Unsupported`] for reserved encodings, floating-point forms, and hints
/// that have no RV64 meaning. The error carries the halfword zero-extended.
#[allow(clippy::too_many_lines)]
pub fn decode_compressed(h: u16) -> Result<Rv, Unsupported> {
    let unsupported = Err(Unsupported(u32::from(h)));
    if h == 0 {
        return Ok(Rv::Unimp);
    }
    let op = h & 3;
    let funct3 = bits(h, 15, 13);
    let rd_full = full(h >> 7);
    let rs2_full = full(h >> 2);
    let rdp = creg(h >> 7);
    let rs2p = creg(h >> 2);
    let ins = match (op, funct3) {
        (0, 0) => {
            let uimm = (bits(h, 12, 11) << 4)
                | (bits(h, 10, 7) << 6)
                | (bit(h, 6) << 2)
                | (bit(h, 5) << 3);
            if uimm == 0 {
                return unsupported;
            }
            Rv::OpImm {
                op: AluImmOp::Addi,
                rd: rs2p,
                rs1: Reg::SP,
                imm: i64::from(uimm),
            }
        }
        (0, 2) => {
            let uimm = (bits(h, 12, 10) << 3) | (bit(h, 6) << 2) | (bit(h, 5) << 6);
            Rv::Load {
                width: LoadWidth::W,
                rd: rs2p,
                rs1: rdp,
                offset: i64::from(uimm),
            }
        }
        (0, 3) => {
            let uimm = (bits(h, 12, 10) << 3) | (bits(h, 6, 5) << 6);
            Rv::Load {
                width: LoadWidth::D,
                rd: rs2p,
                rs1: rdp,
                offset: i64::from(uimm),
            }
        }
        (0, 6) => {
            let uimm = (bits(h, 12, 10) << 3) | (bit(h, 6) << 2) | (bit(h, 5) << 6);
            Rv::Store {
                width: StoreWidth::W,
                rs1: rdp,
                rs2: rs2p,
                offset: i64::from(uimm),
            }
        }
        (0, 7) => {
            let uimm = (bits(h, 12, 10) << 3) | (bits(h, 6, 5) << 6);
            Rv::Store {
                width: StoreWidth::D,
                rs1: rdp,
                rs2: rs2p,
                offset: i64::from(uimm),
            }
        }
        (1, 0) => {
            let imm = sext((bit(h, 12) << 5) | bits(h, 6, 2), 6);
            Rv::OpImm {
                op: AluImmOp::Addi,
                rd: rd_full,
                rs1: rd_full,
                imm,
            }
        }
        (1, 1) => {
            if rd_full == Reg::ZERO {
                return unsupported;
            }
            let imm = sext((bit(h, 12) << 5) | bits(h, 6, 2), 6);
            Rv::OpImm {
                op: AluImmOp::Addiw,
                rd: rd_full,
                rs1: rd_full,
                imm,
            }
        }
        (1, 2) => {
            let imm = sext((bit(h, 12) << 5) | bits(h, 6, 2), 6);
            Rv::OpImm {
                op: AluImmOp::Addi,
                rd: rd_full,
                rs1: Reg::ZERO,
                imm,
            }
        }
        (1, 3) => {
            if rd_full == Reg::SP {
                let imm = sext(
                    (bit(h, 12) << 9)
                        | (bit(h, 6) << 4)
                        | (bit(h, 5) << 6)
                        | (bits(h, 4, 3) << 7)
                        | (bit(h, 2) << 5),
                    10,
                );
                if imm == 0 {
                    return unsupported;
                }
                Rv::OpImm {
                    op: AluImmOp::Addi,
                    rd: Reg::SP,
                    rs1: Reg::SP,
                    imm,
                }
            } else {
                let imm = sext((bit(h, 12) << 17) | (bits(h, 6, 2) << 12), 18);
                if imm == 0 || rd_full == Reg::ZERO {
                    return unsupported;
                }
                Rv::Lui { rd: rd_full, imm }
            }
        }
        (1, 4) => {
            let shamt = i64::from((bit(h, 12) << 5) | bits(h, 6, 2));
            match bits(h, 11, 10) {
                0 => Rv::OpImm {
                    op: AluImmOp::Srli,
                    rd: rdp,
                    rs1: rdp,
                    imm: shamt,
                },
                1 => Rv::OpImm {
                    op: AluImmOp::Srai,
                    rd: rdp,
                    rs1: rdp,
                    imm: shamt,
                },
                2 => Rv::OpImm {
                    op: AluImmOp::Andi,
                    rd: rdp,
                    rs1: rdp,
                    imm: sext((bit(h, 12) << 5) | bits(h, 6, 2), 6),
                },
                _ => {
                    let op = match (bit(h, 12), bits(h, 6, 5)) {
                        (0, 0) => AluOp::Sub,
                        (0, 1) => AluOp::Xor,
                        (0, 2) => AluOp::Or,
                        (0, 3) => AluOp::And,
                        (1, 0) => AluOp::Subw,
                        (1, 1) => AluOp::Addw,
                        _ => return unsupported,
                    };
                    Rv::Op {
                        op,
                        rd: rdp,
                        rs1: rdp,
                        rs2: rs2p,
                    }
                }
            }
        }
        (1, 5) => {
            let imm = sext(
                (bit(h, 12) << 11)
                    | (bit(h, 11) << 4)
                    | (bits(h, 10, 9) << 8)
                    | (bit(h, 8) << 10)
                    | (bit(h, 7) << 6)
                    | (bit(h, 6) << 7)
                    | (bits(h, 5, 3) << 1)
                    | (bit(h, 2) << 5),
                12,
            );
            Rv::Jal {
                rd: Reg::ZERO,
                offset: imm,
            }
        }
        (1, 6 | 7) => {
            let imm = sext(
                (bit(h, 12) << 8)
                    | (bits(h, 11, 10) << 3)
                    | (bits(h, 6, 5) << 6)
                    | (bits(h, 4, 3) << 1)
                    | (bit(h, 2) << 5),
                9,
            );
            let cond = if funct3 == 6 { Cond::Eq } else { Cond::Ne };
            Rv::Branch {
                cond,
                rs1: rdp,
                rs2: Reg::ZERO,
                offset: imm,
            }
        }
        (2, 0) => {
            let shamt = i64::from((bit(h, 12) << 5) | bits(h, 6, 2));
            Rv::OpImm {
                op: AluImmOp::Slli,
                rd: rd_full,
                rs1: rd_full,
                imm: shamt,
            }
        }
        (2, 2) => {
            if rd_full == Reg::ZERO {
                return unsupported;
            }
            let uimm = (bit(h, 12) << 5) | (bits(h, 6, 4) << 2) | (bits(h, 3, 2) << 6);
            Rv::Load {
                width: LoadWidth::W,
                rd: rd_full,
                rs1: Reg::SP,
                offset: i64::from(uimm),
            }
        }
        (2, 3) => {
            if rd_full == Reg::ZERO {
                return unsupported;
            }
            let uimm = (bit(h, 12) << 5) | (bits(h, 6, 5) << 3) | (bits(h, 4, 2) << 6);
            Rv::Load {
                width: LoadWidth::D,
                rd: rd_full,
                rs1: Reg::SP,
                offset: i64::from(uimm),
            }
        }
        (2, 4) => match (bit(h, 12), rd_full == Reg::ZERO, rs2_full == Reg::ZERO) {
            (0, false, true) => Rv::Jalr {
                rd: Reg::ZERO,
                rs1: rd_full,
                offset: 0,
            },
            (0, _, false) => Rv::Op {
                op: AluOp::Add,
                rd: rd_full,
                rs1: Reg::ZERO,
                rs2: rs2_full,
            },
            (1, true, true) => Rv::Ebreak,
            (1, false, true) => Rv::Jalr {
                rd: Reg::RA,
                rs1: rd_full,
                offset: 0,
            },
            (1, _, false) => Rv::Op {
                op: AluOp::Add,
                rd: rd_full,
                rs1: rd_full,
                rs2: rs2_full,
            },
            _ => return unsupported,
        },
        (2, 6) => {
            let uimm = (bits(h, 12, 9) << 2) | (bits(h, 8, 7) << 6);
            Rv::Store {
                width: StoreWidth::W,
                rs1: Reg::SP,
                rs2: rs2_full,
                offset: i64::from(uimm),
            }
        }
        (2, 7) => {
            let uimm = (bits(h, 12, 10) << 3) | (bits(h, 9, 7) << 6);
            Rv::Store {
                width: StoreWidth::D,
                rs1: Reg::SP,
                rs2: rs2_full,
                offset: i64::from(uimm),
            }
        }
        _ => return unsupported,
    };
    Ok(ins)
}

/// Decodes the instruction at `offset` in `code`, returning it and its length
/// in bytes (2 or 4).
///
/// # Errors
/// [`Unsupported`] for an unknown encoding, or `Unsupported(0)` if the bytes
/// run out.
pub fn decode_at(code: &[u8], offset: usize) -> Result<(Rv, usize), Unsupported> {
    let lo = *code.get(offset).ok_or(Unsupported(0))?;
    if lo & 3 == 3 {
        let bytes = code.get(offset..offset + 4).ok_or(Unsupported(0))?;
        let w = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Ok((decode(w)?, 4))
    } else {
        let bytes = code.get(offset..offset + 2).ok_or(Unsupported(0))?;
        let h = u16::from_le_bytes([bytes[0], bytes[1]]);
        Ok((decode_compressed(h)?, 2))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn r(i: u8) -> Reg {
        Reg::new(i).unwrap()
    }

    // Encoders for building test words.
    pub(crate) fn enc_r(opcode: u32, funct3: u32, funct7: u32, rd: u8, rs1: u8, rs2: u8) -> u32 {
        opcode
            | (u32::from(rd) << 7)
            | (funct3 << 12)
            | (u32::from(rs1) << 15)
            | (u32::from(rs2) << 20)
            | (funct7 << 25)
    }
    pub(crate) fn enc_i(opcode: u32, funct3: u32, rd: u8, rs1: u8, imm: i32) -> u32 {
        #[allow(clippy::cast_sign_loss)]
        let imm = (imm as u32) & 0xFFF;
        opcode | (u32::from(rd) << 7) | (funct3 << 12) | (u32::from(rs1) << 15) | (imm << 20)
    }
    pub(crate) fn enc_s(opcode: u32, funct3: u32, rs1: u8, rs2: u8, imm: i32) -> u32 {
        #[allow(clippy::cast_sign_loss)]
        let imm = (imm as u32) & 0xFFF;
        opcode
            | ((imm & 0x1F) << 7)
            | (funct3 << 12)
            | (u32::from(rs1) << 15)
            | (u32::from(rs2) << 20)
            | ((imm >> 5) << 25)
    }
    pub(crate) fn enc_b(funct3: u32, rs1: u8, rs2: u8, imm: i32) -> u32 {
        #[allow(clippy::cast_sign_loss)]
        let imm = (imm as u32) & 0x1FFF;
        0x63 | (((imm >> 11) & 1) << 7)
            | (((imm >> 1) & 0xF) << 8)
            | (funct3 << 12)
            | (u32::from(rs1) << 15)
            | (u32::from(rs2) << 20)
            | (((imm >> 5) & 0x3F) << 25)
            | (((imm >> 12) & 1) << 31)
    }
    pub(crate) fn enc_u(opcode: u32, rd: u8, imm: i32) -> u32 {
        #[allow(clippy::cast_sign_loss)]
        let imm = imm as u32;
        opcode | (u32::from(rd) << 7) | (imm & 0xFFFF_F000)
    }
    pub(crate) fn enc_j(rd: u8, imm: i32) -> u32 {
        #[allow(clippy::cast_sign_loss)]
        let imm = (imm as u32) & 0x1F_FFFF;
        0x6F | (u32::from(rd) << 7)
            | (((imm >> 12) & 0xFF) << 12)
            | (((imm >> 11) & 1) << 20)
            | (((imm >> 1) & 0x3FF) << 21)
            | (((imm >> 20) & 1) << 31)
    }

    #[test]
    fn words_from_the_hello_binary() {
        // addi sp, sp, -48
        assert_eq!(
            decode(0xFD01_0113),
            Ok(Rv::OpImm {
                op: AluImmOp::Addi,
                rd: Reg::SP,
                rs1: Reg::SP,
                imm: -48
            })
        );
        // sd ra, 40(sp)
        assert_eq!(
            decode(0x0211_3423),
            Ok(Rv::Store {
                width: StoreWidth::D,
                rs1: Reg::SP,
                rs2: Reg::RA,
                offset: 40
            })
        );
        // auipc a0, 0xfffd0 ; the shifted immediate
        assert_eq!(
            decode(0xFFFD_0517),
            Ok(Rv::Auipc {
                rd: Reg::A0,
                imm: -0x30000
            })
        );
        // jalr ra, 0(ra)
        assert_eq!(
            decode(0x0000_80E7),
            Ok(Rv::Jalr {
                rd: Reg::RA,
                rs1: Reg::RA,
                offset: 0
            })
        );
        // ret = jalr zero, 0(ra)
        assert_eq!(
            decode(0x0000_8067),
            Ok(Rv::Jalr {
                rd: Reg::ZERO,
                rs1: Reg::RA,
                offset: 0
            })
        );
        assert_eq!(decode(0xC000_1073), Ok(Rv::Unimp));
        assert_eq!(decode(0), Ok(Rv::Unimp));
        assert_eq!(decode(0x0000_0073), Ok(Rv::Ecall));
        assert_eq!(decode(0x0010_0073), Ok(Rv::Ebreak));
        assert_eq!(decode(0x0FF0_000F), Ok(Rv::Fence));
        assert_eq!(decode(0x0000_100F), Ok(Rv::Fence));
    }

    #[test]
    fn immediates_sign_extend() {
        assert_eq!(
            decode(enc_u(0x37, 5, -4096)),
            Ok(Rv::Lui {
                rd: r(5),
                imm: -4096
            })
        );
        assert_eq!(
            decode(enc_u(0x37, 5, 0x7FFF_F000)),
            Ok(Rv::Lui {
                rd: r(5),
                imm: 0x7FFF_F000
            })
        );
        assert_eq!(
            decode(enc_j(1, -2)),
            Ok(Rv::Jal {
                rd: Reg::RA,
                offset: -2
            })
        );
        assert_eq!(
            decode(enc_j(0, 0xF_FFFE)),
            Ok(Rv::Jal {
                rd: Reg::ZERO,
                offset: 0xF_FFFE
            })
        );
        assert_eq!(
            decode(enc_j(0, -0x10_0000)),
            Ok(Rv::Jal {
                rd: Reg::ZERO,
                offset: -0x10_0000
            })
        );
        assert_eq!(
            decode(enc_b(0, 1, 2, -4096)),
            Ok(Rv::Branch {
                cond: Cond::Eq,
                rs1: r(1),
                rs2: r(2),
                offset: -4096
            })
        );
        assert_eq!(
            decode(enc_b(1, 1, 2, 4094)),
            Ok(Rv::Branch {
                cond: Cond::Ne,
                rs1: r(1),
                rs2: r(2),
                offset: 4094
            })
        );
        assert_eq!(
            decode(enc_i(0x03, 0, 3, 4, -2048)),
            Ok(Rv::Load {
                width: LoadWidth::B,
                rd: r(3),
                rs1: r(4),
                offset: -2048
            })
        );
        assert_eq!(
            decode(enc_s(0x23, 3, 4, 5, 2047)),
            Ok(Rv::Store {
                width: StoreWidth::D,
                rs1: r(4),
                rs2: r(5),
                offset: 2047
            })
        );
        assert_eq!(
            decode(enc_s(0x23, 0, 4, 5, -1)),
            Ok(Rv::Store {
                width: StoreWidth::B,
                rs1: r(4),
                rs2: r(5),
                offset: -1
            })
        );
    }

    #[test]
    fn every_branch_load_store() {
        for (f3, cond) in [
            (0, Cond::Eq),
            (1, Cond::Ne),
            (4, Cond::Lt),
            (5, Cond::Ge),
            (6, Cond::Ltu),
            (7, Cond::Geu),
        ] {
            assert_eq!(
                decode(enc_b(f3, 1, 2, 8)),
                Ok(Rv::Branch {
                    cond,
                    rs1: r(1),
                    rs2: r(2),
                    offset: 8
                })
            );
        }
        for f3 in [2, 3] {
            assert_eq!(
                decode(enc_b(f3, 1, 2, 8)),
                Err(Unsupported(enc_b(f3, 1, 2, 8)))
            );
        }
        for (f3, width) in [
            (0, LoadWidth::B),
            (1, LoadWidth::H),
            (2, LoadWidth::W),
            (3, LoadWidth::D),
            (4, LoadWidth::Bu),
            (5, LoadWidth::Hu),
            (6, LoadWidth::Wu),
        ] {
            assert_eq!(
                decode(enc_i(0x03, f3, 1, 2, 4)),
                Ok(Rv::Load {
                    width,
                    rd: r(1),
                    rs1: r(2),
                    offset: 4
                })
            );
        }
        assert!(decode(enc_i(0x03, 7, 1, 2, 4)).is_err());
        for (f3, width) in [
            (0, StoreWidth::B),
            (1, StoreWidth::H),
            (2, StoreWidth::W),
            (3, StoreWidth::D),
        ] {
            assert_eq!(
                decode(enc_s(0x23, f3, 1, 2, 4)),
                Ok(Rv::Store {
                    width,
                    rs1: r(1),
                    rs2: r(2),
                    offset: 4
                })
            );
        }
        assert!(decode(enc_s(0x23, 4, 1, 2, 4)).is_err());
    }

    #[test]
    fn op_imm_forms() {
        let cases = [
            (0, 0, AluImmOp::Addi, -5),
            (2, 0, AluImmOp::Slti, 7),
            (3, 0, AluImmOp::Sltiu, 7),
            (4, 0, AluImmOp::Xori, -1),
            (6, 0, AluImmOp::Ori, 1),
            (7, 0, AluImmOp::Andi, 0xF),
        ];
        for (f3, _, op, imm) in cases {
            assert_eq!(
                decode(enc_i(0x13, f3, 1, 2, imm)),
                Ok(Rv::OpImm {
                    op,
                    rd: r(1),
                    rs1: r(2),
                    imm: i64::from(imm)
                })
            );
        }
        // Shifts: 6-bit shamt for 64-bit, funct6 selects arithmetic.
        assert_eq!(
            decode(enc_i(0x13, 1, 1, 2, 63)),
            Ok(Rv::OpImm {
                op: AluImmOp::Slli,
                rd: r(1),
                rs1: r(2),
                imm: 63
            })
        );
        assert_eq!(
            decode(enc_i(0x13, 5, 1, 2, 63)),
            Ok(Rv::OpImm {
                op: AluImmOp::Srli,
                rd: r(1),
                rs1: r(2),
                imm: 63
            })
        );
        assert_eq!(
            decode(enc_i(0x13, 5, 1, 2, 0x400 | 63)),
            Ok(Rv::OpImm {
                op: AluImmOp::Srai,
                rd: r(1),
                rs1: r(2),
                imm: 63
            })
        );
        assert!(decode(enc_i(0x13, 1, 1, 2, 0x400)).is_err());
        assert!(decode(enc_i(0x13, 5, 1, 2, 0x200)).is_err());
        // 32-bit forms: 5-bit shamt, funct7 selects arithmetic.
        assert_eq!(
            decode(enc_i(0x1B, 0, 1, 2, -3)),
            Ok(Rv::OpImm {
                op: AluImmOp::Addiw,
                rd: r(1),
                rs1: r(2),
                imm: -3
            })
        );
        assert_eq!(
            decode(enc_i(0x1B, 1, 1, 2, 31)),
            Ok(Rv::OpImm {
                op: AluImmOp::Slliw,
                rd: r(1),
                rs1: r(2),
                imm: 31
            })
        );
        assert_eq!(
            decode(enc_i(0x1B, 5, 1, 2, 31)),
            Ok(Rv::OpImm {
                op: AluImmOp::Srliw,
                rd: r(1),
                rs1: r(2),
                imm: 31
            })
        );
        assert_eq!(
            decode(enc_i(0x1B, 5, 1, 2, 0x400 | 31)),
            Ok(Rv::OpImm {
                op: AluImmOp::Sraiw,
                rd: r(1),
                rs1: r(2),
                imm: 31
            })
        );
        assert!(decode(enc_i(0x1B, 1, 1, 2, 0x20)).is_err());
        assert!(decode(enc_i(0x1B, 2, 1, 2, 0)).is_err());
        assert!(decode(enc_i(0x1B, 5, 1, 2, 0x100)).is_err());
    }

    #[test]
    fn op_forms() {
        let base = [
            (0, 0, AluOp::Add),
            (0x20, 0, AluOp::Sub),
            (0, 1, AluOp::Sll),
            (0, 2, AluOp::Slt),
            (0, 3, AluOp::Sltu),
            (0, 4, AluOp::Xor),
            (0, 5, AluOp::Srl),
            (0x20, 5, AluOp::Sra),
            (0, 6, AluOp::Or),
            (0, 7, AluOp::And),
            (1, 0, AluOp::Mul),
            (1, 1, AluOp::Mulh),
            (1, 2, AluOp::Mulhsu),
            (1, 3, AluOp::Mulhu),
            (1, 4, AluOp::Div),
            (1, 5, AluOp::Divu),
            (1, 6, AluOp::Rem),
            (1, 7, AluOp::Remu),
        ];
        for (f7, f3, op) in base {
            assert_eq!(
                decode(enc_r(0x33, f3, f7, 1, 2, 3)),
                Ok(Rv::Op {
                    op,
                    rd: r(1),
                    rs1: r(2),
                    rs2: r(3)
                })
            );
        }
        assert!(decode(enc_r(0x33, 1, 0x20, 1, 2, 3)).is_err());
        let word = [
            (0, 0, AluOp::Addw),
            (0x20, 0, AluOp::Subw),
            (0, 1, AluOp::Sllw),
            (0, 5, AluOp::Srlw),
            (0x20, 5, AluOp::Sraw),
            (1, 0, AluOp::Mulw),
            (1, 4, AluOp::Divw),
            (1, 5, AluOp::Divuw),
            (1, 6, AluOp::Remw),
            (1, 7, AluOp::Remuw),
        ];
        for (f7, f3, op) in word {
            assert_eq!(
                decode(enc_r(0x3B, f3, f7, 1, 2, 3)),
                Ok(Rv::Op {
                    op,
                    rd: r(1),
                    rs1: r(2),
                    rs2: r(3)
                })
            );
        }
        assert!(decode(enc_r(0x3B, 2, 0, 1, 2, 3)).is_err());
    }

    #[test]
    fn atomics() {
        let amo = |funct5: u32, f3: u32, rs2: u8| enc_r(0x2F, f3, funct5 << 2, 1, 2, rs2);
        assert_eq!(
            decode(amo(0x02, 2, 0)),
            Ok(Rv::Lr {
                width: AmoWidth::W,
                rd: r(1),
                rs1: r(2)
            })
        );
        assert_eq!(
            decode(amo(0x02, 3, 0)),
            Ok(Rv::Lr {
                width: AmoWidth::D,
                rd: r(1),
                rs1: r(2)
            })
        );
        assert!(decode(amo(0x02, 3, 3)).is_err()); // lr with rs2 set
        assert_eq!(
            decode(amo(0x03, 3, 3)),
            Ok(Rv::Sc {
                width: AmoWidth::D,
                rd: r(1),
                rs1: r(2),
                rs2: r(3)
            })
        );
        for (f5, op) in [
            (0x01, AmoOp::Swap),
            (0x00, AmoOp::Add),
            (0x04, AmoOp::Xor),
            (0x0C, AmoOp::And),
            (0x08, AmoOp::Or),
            (0x10, AmoOp::Min),
            (0x14, AmoOp::Max),
            (0x18, AmoOp::Minu),
            (0x1C, AmoOp::Maxu),
        ] {
            assert_eq!(
                decode(amo(f5, 2, 3)),
                Ok(Rv::Amo {
                    op,
                    width: AmoWidth::W,
                    rd: r(1),
                    rs1: r(2),
                    rs2: r(3)
                })
            );
        }
        assert!(decode(amo(0x05, 2, 3)).is_err());
        assert!(decode(amo(0x00, 1, 3)).is_err()); // bad width
    }

    #[test]
    fn unsupported_words() {
        for w in [
            0x0000_0007,             // flw
            0x0000_0053,             // fadd.s
            0x0020_0073,             // uret / privileged
            0x0000_1073,             // csrrw
            0x0000_2073,             // csrrs
            0x0000_1067,             // jalr with funct3 1
            0x0000_200F,             // fence with funct3 2
            0x0000_0003 | (7 << 12), // ld with bad width
            0xFFFF_FFFF,
            0x0000_0013 | (1 << 12) | (1 << 26), // slli with funct6 set
        ] {
            assert_eq!(decode(w), Err(Unsupported(w)), "{w:#x}");
        }
        assert_eq!(format!("{:?}", Unsupported(1)), "Unsupported(1)");
        assert_eq!(format!("{:?}", AmoOp::Swap), "Swap");
        assert_eq!(format!("{:?}", AmoWidth::W), "W");
    }

    #[test]
    fn compressed_words_from_the_hello_binary() {
        let addi = |rd, rs1, imm| Rv::OpImm {
            op: AluImmOp::Addi,
            rd,
            rs1,
            imm,
        };
        assert_eq!(decode_compressed(0x7139), Ok(addi(Reg::SP, Reg::SP, -0x40))); // c.addi16sp
        assert_eq!(decode_compressed(0x1141), Ok(addi(Reg::SP, Reg::SP, -0x10)));
        assert_eq!(decode_compressed(0x6121), Ok(addi(Reg::SP, Reg::SP, 0x40)));
        assert_eq!(
            decode_compressed(0xFC06),
            Ok(Rv::Store {
                width: StoreWidth::D,
                rs1: Reg::SP,
                rs2: Reg::RA,
                offset: 0x38
            })
        );
        assert_eq!(
            decode_compressed(0xE406),
            Ok(Rv::Store {
                width: StoreWidth::D,
                rs1: Reg::SP,
                rs2: Reg::RA,
                offset: 8
            })
        );
        assert_eq!(
            decode_compressed(0xE002),
            Ok(Rv::Store {
                width: StoreWidth::D,
                rs1: Reg::SP,
                rs2: Reg::ZERO,
                offset: 0
            })
        );
        assert_eq!(
            decode_compressed(0x892E),
            Ok(Rv::Op {
                op: AluOp::Add,
                rd: r(18),
                rs1: Reg::ZERO,
                rs2: Reg::A1
            })
        ); // mv s2, a1
        assert_eq!(
            decode_compressed(0x860A),
            Ok(Rv::Op {
                op: AluOp::Add,
                rd: Reg::A2,
                rs1: Reg::ZERO,
                rs2: Reg::SP
            })
        );
        assert_eq!(decode_compressed(0x45AD), Ok(addi(Reg::A1, Reg::ZERO, 0xB))); // c.li
        assert_eq!(decode_compressed(0x0505), Ok(addi(Reg::A0, Reg::A0, 1)));
        assert_eq!(
            decode_compressed(0x70E2),
            Ok(Rv::Load {
                width: LoadWidth::D,
                rd: Reg::RA,
                rs1: Reg::SP,
                offset: 0x38
            })
        );
        assert_eq!(
            decode_compressed(0x8082),
            Ok(Rv::Jalr {
                rd: Reg::ZERO,
                rs1: Reg::RA,
                offset: 0
            })
        ); // ret
        assert_eq!(decode_compressed(0x0000), Ok(Rv::Unimp));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn compressed_forms_by_hand() {
        // c.addi4spn a0, sp, 8: CIW uimm=8 -> bits[5]=1 (nzuimm[3]).
        assert_eq!(
            decode_compressed(0x0028),
            Ok(Rv::OpImm {
                op: AluImmOp::Addi,
                rd: Reg::A0,
                rs1: Reg::SP,
                imm: 8
            })
        );
        assert_eq!(decode_compressed(0x0008), Err(Unsupported(0x0008))); // zero immediate
        // c.lw a0, 4(a1): funct3 010, uimm[2]=inst[6] -> 0x4188 | ...
        assert_eq!(
            decode_compressed(0x41C8),
            Ok(Rv::Load {
                width: LoadWidth::W,
                rd: Reg::A0,
                rs1: Reg::A1,
                offset: 4
            })
        );
        // c.ld a0, 8(a1)
        assert_eq!(
            decode_compressed(0x6588),
            Ok(Rv::Load {
                width: LoadWidth::D,
                rd: Reg::A0,
                rs1: Reg::A1,
                offset: 8
            })
        );
        // c.sw a0, 4(a1) and c.sd a0, 8(a1)
        assert_eq!(
            decode_compressed(0xC1C8),
            Ok(Rv::Store {
                width: StoreWidth::W,
                rs1: Reg::A1,
                rs2: Reg::A0,
                offset: 4
            })
        );
        assert_eq!(
            decode_compressed(0xE588),
            Ok(Rv::Store {
                width: StoreWidth::D,
                rs1: Reg::A1,
                rs2: Reg::A0,
                offset: 8
            })
        );
        // c.addiw a0, -1 ; c.addiw x0 reserved
        assert_eq!(
            decode_compressed(0x357D),
            Ok(Rv::OpImm {
                op: AluImmOp::Addiw,
                rd: Reg::A0,
                rs1: Reg::A0,
                imm: -1
            })
        );
        assert_eq!(decode_compressed(0x207D), Err(Unsupported(0x207D)));
        // c.lui a0, 0x1000 ; c.lui with zero imm reserved ; c.lui x0 reserved
        assert_eq!(
            decode_compressed(0x6505),
            Ok(Rv::Lui {
                rd: Reg::A0,
                imm: 0x1000
            })
        );
        assert_eq!(decode_compressed(0x6501), Err(Unsupported(0x6501)));
        assert_eq!(decode_compressed(0x6005), Err(Unsupported(0x6005)));
        // c.addi16sp with zero immediate is reserved.
        assert_eq!(decode_compressed(0x6101), Err(Unsupported(0x6101)));
        // c.srli a0, 1 ; c.srai a0, 1 ; c.andi a0, -1
        assert_eq!(
            decode_compressed(0x8105),
            Ok(Rv::OpImm {
                op: AluImmOp::Srli,
                rd: Reg::A0,
                rs1: Reg::A0,
                imm: 1
            })
        );
        assert_eq!(
            decode_compressed(0x8505),
            Ok(Rv::OpImm {
                op: AluImmOp::Srai,
                rd: Reg::A0,
                rs1: Reg::A0,
                imm: 1
            })
        );
        assert_eq!(
            decode_compressed(0x997D),
            Ok(Rv::OpImm {
                op: AluImmOp::Andi,
                rd: Reg::A0,
                rs1: Reg::A0,
                imm: -1
            })
        );
        // c.sub/xor/or/and a0, a1 and c.subw/addw
        assert_eq!(
            decode_compressed(0x8D0D),
            Ok(Rv::Op {
                op: AluOp::Sub,
                rd: Reg::A0,
                rs1: Reg::A0,
                rs2: Reg::A1
            })
        );
        assert_eq!(
            decode_compressed(0x8D2D),
            Ok(Rv::Op {
                op: AluOp::Xor,
                rd: Reg::A0,
                rs1: Reg::A0,
                rs2: Reg::A1
            })
        );
        assert_eq!(
            decode_compressed(0x8D4D),
            Ok(Rv::Op {
                op: AluOp::Or,
                rd: Reg::A0,
                rs1: Reg::A0,
                rs2: Reg::A1
            })
        );
        assert_eq!(
            decode_compressed(0x8D6D),
            Ok(Rv::Op {
                op: AluOp::And,
                rd: Reg::A0,
                rs1: Reg::A0,
                rs2: Reg::A1
            })
        );
        assert_eq!(
            decode_compressed(0x9D0D),
            Ok(Rv::Op {
                op: AluOp::Subw,
                rd: Reg::A0,
                rs1: Reg::A0,
                rs2: Reg::A1
            })
        );
        assert_eq!(
            decode_compressed(0x9D2D),
            Ok(Rv::Op {
                op: AluOp::Addw,
                rd: Reg::A0,
                rs1: Reg::A0,
                rs2: Reg::A1
            })
        );
        assert_eq!(decode_compressed(0x9D4D), Err(Unsupported(0x9D4D)));
        // c.j +2 ; c.j -2
        assert_eq!(
            decode_compressed(0xA009),
            Ok(Rv::Jal {
                rd: Reg::ZERO,
                offset: 2
            })
        );
        assert_eq!(
            decode_compressed(0xBFFD),
            Ok(Rv::Jal {
                rd: Reg::ZERO,
                offset: -2
            })
        );
        // c.beqz a0, +8 ; c.bnez a0, -2
        assert_eq!(
            decode_compressed(0xC501),
            Ok(Rv::Branch {
                cond: Cond::Eq,
                rs1: Reg::A0,
                rs2: Reg::ZERO,
                offset: 8
            })
        );
        assert_eq!(
            decode_compressed(0xFD7D),
            Ok(Rv::Branch {
                cond: Cond::Ne,
                rs1: Reg::A0,
                rs2: Reg::ZERO,
                offset: -2
            })
        );
        // c.slli a0, 32
        assert_eq!(
            decode_compressed(0x1502),
            Ok(Rv::OpImm {
                op: AluImmOp::Slli,
                rd: Reg::A0,
                rs1: Reg::A0,
                imm: 32
            })
        );
        // c.lwsp a0, 4 ; c.ldsp a0, 8 ; x0 destinations reserved
        assert_eq!(
            decode_compressed(0x4512),
            Ok(Rv::Load {
                width: LoadWidth::W,
                rd: Reg::A0,
                rs1: Reg::SP,
                offset: 4
            })
        );
        assert_eq!(
            decode_compressed(0x6522),
            Ok(Rv::Load {
                width: LoadWidth::D,
                rd: Reg::A0,
                rs1: Reg::SP,
                offset: 8
            })
        );
        assert_eq!(decode_compressed(0x4012), Err(Unsupported(0x4012)));
        assert_eq!(decode_compressed(0x6022), Err(Unsupported(0x6022)));
        // c.jr a0 ; c.jalr a0 ; c.ebreak ; c.add a0, a1 ; c.mv x0 reserved-ish forms
        assert_eq!(
            decode_compressed(0x8502),
            Ok(Rv::Jalr {
                rd: Reg::ZERO,
                rs1: Reg::A0,
                offset: 0
            })
        );
        assert_eq!(
            decode_compressed(0x9502),
            Ok(Rv::Jalr {
                rd: Reg::RA,
                rs1: Reg::A0,
                offset: 0
            })
        );
        assert_eq!(decode_compressed(0x9002), Ok(Rv::Ebreak));
        assert_eq!(
            decode_compressed(0x952E),
            Ok(Rv::Op {
                op: AluOp::Add,
                rd: Reg::A0,
                rs1: Reg::A0,
                rs2: Reg::A1
            })
        );
        assert_eq!(decode_compressed(0x8002), Err(Unsupported(0x8002))); // c.jr x0
        // c.swsp a0, 4 ; c.sdsp a0, 8
        assert_eq!(
            decode_compressed(0xC22A),
            Ok(Rv::Store {
                width: StoreWidth::W,
                rs1: Reg::SP,
                rs2: Reg::A0,
                offset: 4
            })
        );
        assert_eq!(
            decode_compressed(0xE42A),
            Ok(Rv::Store {
                width: StoreWidth::D,
                rs1: Reg::SP,
                rs2: Reg::A0,
                offset: 8
            })
        );
        // Floating point and reserved quadrant-0 forms.
        for h in [0x2000u16, 0xA000, 0x2002, 0xA002, 0x8000, 0x9C41] {
            assert_eq!(
                decode_compressed(h),
                Err(Unsupported(u32::from(h))),
                "{h:#x}"
            );
        }
    }

    #[test]
    fn decode_at_picks_the_width() {
        let code = [0x82, 0x80, 0x13, 0x01, 0x01, 0xFD, 0x01];
        assert_eq!(
            decode_at(&code, 0),
            Ok((
                Rv::Jalr {
                    rd: Reg::ZERO,
                    rs1: Reg::RA,
                    offset: 0
                },
                2
            ))
        );
        assert_eq!(
            decode_at(&code, 2),
            Ok((
                Rv::OpImm {
                    op: AluImmOp::Addi,
                    rd: Reg::SP,
                    rs1: Reg::SP,
                    imm: -48
                },
                4
            ))
        );
        assert_eq!(decode_at(&code, 6), Err(Unsupported(0)));
        assert_eq!(decode_at(&code, 7), Err(Unsupported(0)));
        assert_eq!(decode_at(&[0x03], 0), Err(Unsupported(0)));
    }
}
