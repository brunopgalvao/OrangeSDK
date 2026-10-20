//! Which guest registers live in host registers.
//!
//! A host has fewer free registers than the guest's thirty-one writable
//! ones (spec 01 §2), so the compiler counts how often each guest register
//! appears in the program and gives host registers to the most used. The
//! rest stay in [`crate::ctx::Ctx::regs`] and are loaded and stored around
//! each use. The choice only affects speed, never results.

use solo_vm::isa::{Instruction, Reg};
use solo_vm::module::Program;

/// The guest-to-host register assignment for one compiled program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegMap {
    host: [Option<u8>; Reg::COUNT],
}

impl RegMap {
    /// Assigns `hosts`, in order, to the guest registers the program uses
    /// most, ties broken by the lower register index. Register 0 is never
    /// assigned; registers the program never names are left in memory.
    pub(crate) fn choose(program: &Program, hosts: &[u8]) -> RegMap {
        let mut uses = [0u64; Reg::COUNT];
        for ins in program.module.blocks.iter().flatten() {
            for r in operands(ins) {
                uses[r.index()] += 1;
            }
        }
        uses[0] = 0;
        let mut order: Vec<usize> = (1..Reg::COUNT).filter(|&g| uses[g] > 0).collect();
        order.sort_by_key(|&g| (core::cmp::Reverse(uses[g]), g));
        let mut host = [None; Reg::COUNT];
        for (&g, &h) in order.iter().zip(hosts) {
            host[g] = Some(h);
        }
        RegMap { host }
    }

    /// The host register holding guest register `r`, if any.
    pub(crate) fn host(&self, r: Reg) -> Option<u8> {
        self.host[r.index()]
    }

    /// Every assigned pair, in guest register order.
    pub(crate) fn pairs(&self) -> Vec<(Reg, u8)> {
        self.host
            .iter()
            .enumerate()
            .filter_map(|(g, h)| Some((Reg::new(u8::try_from(g).ok()?)?, (*h)?)))
            .collect()
    }
}

/// The registers an instruction names, padded with register 0.
fn operands(ins: &Instruction) -> [Reg; 3] {
    let z = Reg::ZERO;
    match *ins {
        Instruction::Trap
        | Instruction::Halt
        | Instruction::Ecall { .. }
        | Instruction::Jump { .. } => [z, z, z],
        Instruction::Li { rd, .. } | Instruction::Call { rd, .. } => [rd, z, z],
        Instruction::Sbrk { rd, rs1 }
        | Instruction::AluImm { rd, rs1, .. }
        | Instruction::Load { rd, rs1, .. }
        | Instruction::CallIndirect { rd, rs1, .. } => [rd, rs1, z],
        Instruction::JumpIndirect { rs1, .. } => [rs1, z, z],
        Instruction::Memcopy { dst, src, len } => [dst, src, len],
        Instruction::Memfill { dst, val, len } => [dst, val, len],
        Instruction::Alu { rd, rs1, rs2, .. } => [rd, rs1, rs2],
        Instruction::Store { rs1, rs2, .. } | Instruction::Branch { rs1, rs2, .. } => {
            [rs1, rs2, z]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solo_vm::builder::ModuleBuilder;
    use solo_vm::gas::CostTable;
    use solo_vm::isa::{AluOp, Cond, LoadWidth};
    use solo_vm::module::Module;

    fn r(i: u8) -> Reg {
        Reg::new(i).unwrap()
    }

    #[test]
    fn most_used_registers_win_and_ties_go_to_lower_indices() {
        let mut b = ModuleBuilder::new();
        b.block(&[
            Instruction::Alu {
                op: AluOp::Add,
                rd: r(7),
                rs1: r(7),
                rs2: r(5),
            },
            Instruction::Load {
                width: LoadWidth::D,
                rd: r(9),
                rs1: r(7),
                off: 0,
            },
            Instruction::Li { rd: r(6), imm: 1 },
            Instruction::Alu {
                op: AluOp::Add,
                rd: Reg::ZERO,
                rs1: Reg::ZERO,
                rs2: Reg::ZERO,
            },
            Instruction::Branch {
                cond: Cond::Eq,
                rs1: r(5),
                rs2: r(5),
                block: 0,
            },
        ]);
        b.block(&[Instruction::Halt]);
        let m = Module::parse(&b.build(), &|_| true).unwrap();
        let p = Program::new(m, CostTable::V1);
        let map = RegMap::choose(&p, &[20, 21, 22]);
        // r7: 3 uses, r5: 3 uses, r9 and r6: 1 use each.
        assert_eq!(map.host(r(5)), Some(20));
        assert_eq!(map.host(r(7)), Some(21));
        assert_eq!(map.host(r(6)), Some(22));
        assert_eq!(map.host(r(9)), None);
        assert_eq!(map.host(Reg::ZERO), None);
        assert_eq!(map.pairs(), vec![(r(5), 20), (r(6), 22), (r(7), 21)]);
        assert_eq!(RegMap::choose(&p, &[]).pairs(), vec![]);
        assert!(format!("{map:?}").contains("RegMap"));
        assert_eq!(map.clone(), map);
    }

    #[test]
    fn every_instruction_names_its_registers() {
        let (a, b, c) = (r(1), r(2), r(3));
        let z = Reg::ZERO;
        let cases = [
            (Instruction::Sbrk { rd: a, rs1: b }, [a, b, z]),
            (
                Instruction::Memcopy {
                    dst: a,
                    src: b,
                    len: c,
                },
                [a, b, c],
            ),
            (
                Instruction::Memfill {
                    dst: a,
                    val: b,
                    len: c,
                },
                [a, b, c],
            ),
            (
                Instruction::Call {
                    rd: a,
                    block: 0,
                    slot: 1,
                },
                [a, z, z],
            ),
            (Instruction::JumpIndirect { rs1: b, off: 0 }, [b, z, z]),
            (
                Instruction::CallIndirect {
                    rd: a,
                    rs1: b,
                    off: 0,
                    slot: 1,
                },
                [a, b, z],
            ),
            (Instruction::Ecall { import: 0 }, [z, z, z]),
            (Instruction::Jump { block: 0 }, [z, z, z]),
            (Instruction::Trap, [z, z, z]),
        ];
        for (ins, regs) in cases {
            assert_eq!(operands(&ins), regs, "{ins:?}");
        }
    }
}
