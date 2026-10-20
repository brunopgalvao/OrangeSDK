//! Gas: the instruction cost table and dynamic charges (spec 04).

use crate::isa::{AluOp, Instruction};

/// A version of the instruction cost table (spec 04 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostTable {
    version: u32,
}

/// Minimum static cost of a block (spec 04 §2).
pub const BLOCK_MIN_COST: u64 = 1;
/// Dynamic cost per 4096-byte page added by `sbrk` (spec 04 §3.1).
pub const SBRK_PAGE_COST: u64 = 256;
/// Dynamic cost per started 32-byte unit of `memcopy` and `memfill` (spec 04 §3.2).
pub const BULK_UNIT_COST: u64 = 1;
/// Largest gas limit a host may set (spec 04 §4).
pub const MAX_GAS_LIMIT: i64 = 1 << 62;

impl CostTable {
    /// Cost table version 1 (spec 04 Table 2.1, provisional).
    pub const V1: CostTable = CostTable { version: 1 };

    /// The table version.
    #[must_use]
    pub const fn version(self) -> u32 {
        self.version
    }

    /// Static cost of one instruction.
    #[must_use]
    pub const fn static_cost(self, ins: &Instruction) -> u64 {
        match ins {
            Instruction::Li { .. }
            | Instruction::AluImm { .. }
            | Instruction::Halt
            | Instruction::Trap => 1,
            Instruction::Alu { op, .. } => match op {
                AluOp::Mul | AluOp::Mulw => 3,
                AluOp::Mulh | AluOp::Mulhsu | AluOp::Mulhu => 4,
                AluOp::Div
                | AluOp::Divu
                | AluOp::Rem
                | AluOp::Remu
                | AluOp::Divw
                | AluOp::Divuw
                | AluOp::Remw
                | AluOp::Remuw => 20,
                _ => 1,
            },
            Instruction::Load { .. } | Instruction::Store { .. } => 3,
            Instruction::Jump { .. } | Instruction::Call { .. } | Instruction::Branch { .. } => 2,
            Instruction::JumpIndirect { .. } | Instruction::CallIndirect { .. } => 4,
            Instruction::Ecall { .. }
            | Instruction::Sbrk { .. }
            | Instruction::Memcopy { .. }
            | Instruction::Memfill { .. } => 10,
        }
    }

    /// Static cost of a block: the sum of its instructions, at least
    /// [`BLOCK_MIN_COST`], or `None` if the sum does not fit a signed 64-bit
    /// integer (spec 03 §7.6).
    #[must_use]
    pub fn block_cost(self, instructions: &[Instruction]) -> Option<u64> {
        let mut total: u64 = 0;
        for ins in instructions {
            total = total.checked_add(self.static_cost(ins))?;
        }
        i64::try_from(total)
            .ok()
            .map(|fits| fits.unsigned_abs().max(BLOCK_MIN_COST))
    }
}

/// Dynamic cost of growing the heap by `pages` pages (spec 04 §3.1).
#[must_use]
pub const fn sbrk_cost(pages: u32) -> u64 {
    pages as u64 * SBRK_PAGE_COST
}

/// Dynamic cost of a bulk memory operation over `len` bytes (spec 04 §3.2).
#[must_use]
pub const fn bulk_cost(len: u32) -> u64 {
    (len as u64).div_ceil(32) * BULK_UNIT_COST
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::{AluImmOp, Cond, LoadWidth, Reg, StoreWidth, tests::every_instruction};

    #[test]
    fn table_v1_rows_are_pinned() {
        let t = CostTable::V1;
        assert_eq!(t.version(), 1);
        for ins in every_instruction() {
            let expected = match ins {
                Instruction::Li { .. }
                | Instruction::AluImm { .. }
                | Instruction::Halt
                | Instruction::Trap => 1,
                Instruction::Alu { op, .. } => match op {
                    AluOp::Mul | AluOp::Mulw => 3,
                    AluOp::Mulh | AluOp::Mulhsu | AluOp::Mulhu => 4,
                    AluOp::Div
                    | AluOp::Divu
                    | AluOp::Rem
                    | AluOp::Remu
                    | AluOp::Divw
                    | AluOp::Divuw
                    | AluOp::Remw
                    | AluOp::Remuw => 20,
                    _ => 1,
                },
                Instruction::Load { .. } | Instruction::Store { .. } => 3,
                Instruction::Jump { .. }
                | Instruction::Call { .. }
                | Instruction::Branch { .. } => 2,
                Instruction::JumpIndirect { .. } | Instruction::CallIndirect { .. } => 4,
                Instruction::Ecall { .. }
                | Instruction::Sbrk { .. }
                | Instruction::Memcopy { .. }
                | Instruction::Memfill { .. } => 10,
            };
            assert_eq!(t.static_cost(&ins), expected, "{ins:?}");
        }
    }

    #[test]
    fn worked_example_from_spec() {
        let r = |i| Reg::new(i).unwrap();
        let block = [
            Instruction::AluImm {
                op: AluImmOp::Addi,
                rd: r(10),
                rs1: r(10),
                imm: 1,
            },
            Instruction::Load {
                width: LoadWidth::D,
                rd: r(11),
                rs1: r(10),
                off: 0,
            },
            Instruction::Alu {
                op: AluOp::Add,
                rd: r(12),
                rs1: r(11),
                rs2: r(12),
            },
            Instruction::Branch {
                cond: Cond::Ne,
                rs1: r(10),
                rs2: r(13),
                block: 0,
            },
        ];
        assert_eq!(CostTable::V1.block_cost(&block), Some(7));
        assert_eq!(bulk_cost(1000), 32);
        let _ = StoreWidth::D;
    }

    #[test]
    fn block_cost_minimum_and_overflow() {
        assert_eq!(CostTable::V1.block_cost(&[]), Some(BLOCK_MIN_COST));
        // Overflow is unreachable through a valid module (16 MiB code), so it is
        // exercised through the arithmetic directly.
        let many = alloc::vec![Instruction::Alu { op: AluOp::Div, rd: Reg::ZERO, rs1: Reg::ZERO, rs2: Reg::ZERO }; 4];
        assert_eq!(CostTable::V1.block_cost(&many), Some(80));
        assert!(i64::try_from(CostTable::V1.block_cost(&many).unwrap()).is_ok());
    }

    #[test]
    fn dynamic_costs() {
        assert_eq!(sbrk_cost(0), 0);
        assert_eq!(sbrk_cost(1), 256);
        assert_eq!(sbrk_cost(3), 768);
        assert_eq!(bulk_cost(0), 0);
        assert_eq!(bulk_cost(1), 1);
        assert_eq!(bulk_cost(32), 1);
        assert_eq!(bulk_cost(33), 2);
        assert_eq!(bulk_cost(u32::MAX), 134_217_728);
        assert_eq!(MAX_GAS_LIMIT, 4_611_686_018_427_387_904);
    }
}
