//! The translation pipeline from a loaded ELF to a Solo module (spec 03 §8).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use solo_vm::builder::ModuleBuilder;
use solo_vm::isa::{AluOp, Instruction, LoadWidth, Reg, StoreWidth};
use solo_vm::memory::PAGE;
use solo_vm::module::{Module, ValidationError};

use crate::elf::{Input, Reloc, reloc};
use crate::riscv::{AmoOp, AmoWidth, Rv, decode_at};

/// Layout parameters not determined by the ELF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Maximum heap size in bytes; page-aligned.
    pub heap_max: u32,
    /// Stack size in bytes; page-aligned.
    pub stack_size: u32,
    /// Initial `sp`; page-aligned, at most `0xFFFF_0000`.
    pub stack_top: u32,
    /// Emit a debug section mapping every block index to the address of its
    /// first instruction in the input ELF (see [`debug_map`]).
    pub debug_map: bool,
}

/// Default maximum heap: 1 GiB (spec 03 §8 rule 10). Kernels are recompiled
/// with the defaults, and one Osaka transaction (2^24 gas, EIP-7825) can keep
/// close to 200 MiB live in the EVM; the heaviest execution-spec state test
/// needs 192 MiB (spec 07 §4.2). The heap grows only as `sbrk` asks, at
/// 256 gas a page, so the bound costs nothing until it is used.
pub const HEAP_MAX: u32 = 1 << 30;

impl Default for Options {
    fn default() -> Self {
        Options {
            heap_max: HEAP_MAX,
            stack_size: 1 << 20,
            stack_top: 0xFFFF_0000,
            debug_map: false,
        }
    }
}

/// Decodes a debug section written with `Options::debug_map`: a list of
/// little-endian `u64` addresses, one per block in order.
///
/// # Panics
/// Never; each chunk is exactly 8 bytes.
#[must_use]
pub fn debug_map(section: &[u8]) -> Vec<u64> {
    section
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().expect("8 bytes")))
        .collect()
}

/// Why an ELF could not be recompiled. Addresses are guest code addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum RecompileError {
    /// An instruction word the recompiler does not accept.
    Unsupported { address: u64, word: u32 },
    /// An `auipc` with no relocation describing its target.
    UnpairedAuipc { address: u64 },
    /// A call-pair `auipc` not followed by the matching `jalr`.
    BrokenCallPair { address: u64 },
    /// A control-flow target that is not an instruction boundary.
    TargetNotInstruction { address: u64 },
    /// An atomic form the lowering does not handle (min/max, or aliasing registers).
    UnsupportedAtomic { address: u64 },
    /// A relocation type the recompiler does not understand.
    UnknownReloc { address: u64, r_type: u32 },
    /// A data relocation outside its section.
    DataRelocOutOfRange { address: u64 },
    /// No `solo_export_*` symbol.
    NoExports,
    /// The produced module failed validation; a recompiler bug.
    Validation(ValidationError),
}

impl fmt::Display for RecompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecompileError::Unsupported { address, word } => {
                write!(f, "unsupported instruction {word:#010x} at {address:#x}")
            }
            RecompileError::UnpairedAuipc { address } => {
                write!(f, "auipc without relocation at {address:#x}")
            }
            RecompileError::BrokenCallPair { address } => {
                write!(f, "call pair without jalr at {address:#x}")
            }
            RecompileError::TargetNotInstruction { address } => {
                write!(f, "control-flow target {address:#x} is not an instruction")
            }
            RecompileError::UnsupportedAtomic { address } => {
                write!(f, "unsupported atomic at {address:#x}")
            }
            RecompileError::UnknownReloc { address, r_type } => {
                write!(f, "unknown relocation type {r_type} at {address:#x}")
            }
            RecompileError::DataRelocOutOfRange { address } => {
                write!(f, "data relocation outside its section at {address:#x}")
            }
            RecompileError::NoExports => write!(f, "no solo_export_* symbol"),
            RecompileError::Validation(e) => write!(f, "produced module failed validation: {e:?}"),
        }
    }
}

impl std::error::Error for RecompileError {}

/// Prefix of host-call stub symbols.
pub const IMPORT_PREFIX: &str = "__solo_import_";
/// Prefix of export entry symbols.
pub const EXPORT_PREFIX: &str = "solo_export_";
/// Scratch register used by the atomic lowering (spec 01 §2: `tp` is unused by guests).
const SCRATCH: Reg = Reg::new(4).expect("tp");

#[derive(Debug, Clone, PartialEq, Eq)]
enum Stub {
    Import(String),
    Halt,
    Trap,
    Sbrk,
}

struct Decoded {
    address: u64,
    rv: Rv,
    len: usize,
}

/// Per-instruction facts derived from relocations.
#[derive(Default)]
struct Facts {
    /// `auipc` address → absolute target and whether it is code.
    hi: HashMap<u64, (u64, bool)>,
    /// `auipc` address of a call pair → target.
    call_pair: HashMap<u64, u64>,
    /// `lui` address → absolute code target.
    lui_code: HashMap<u64, u64>,
}

struct Ctx<'a> {
    input: &'a Input,
    insns: Vec<Decoded>,
    index_of: HashMap<u64, usize>,
    facts: Facts,
    stubs: HashMap<u64, Stub>,
    imports: Vec<String>,
    starts: BTreeSet<u64>,
    slots: BTreeMap<u64, u32>,
    block_of: HashMap<u64, u32>,
}

const fn is_call(rd: Reg) -> bool {
    !matches!(rd, Reg::ZERO)
}

fn decode_text(input: &Input) -> Result<(Vec<Decoded>, HashMap<u64, usize>), RecompileError> {
    let mut insns = Vec::new();
    let mut index_of = HashMap::new();
    let mut offset = 0usize;
    while offset < input.text.bytes.len() {
        let address = input.text.address + offset as u64;
        let (rv, len) = decode_at(&input.text.bytes, offset)
            .map_err(|u| RecompileError::Unsupported { address, word: u.0 })?;
        index_of.insert(address, insns.len());
        insns.push(Decoded { address, rv, len });
        offset += len;
    }
    Ok((insns, index_of))
}

impl<'a> Ctx<'a> {
    fn new(input: &'a Input) -> Result<Ctx<'a>, RecompileError> {
        let (insns, index_of) = decode_text(input)?;
        let mut ctx = Ctx {
            input,
            insns,
            index_of,
            facts: Facts::default(),
            stubs: HashMap::new(),
            imports: Vec::new(),
            starts: BTreeSet::new(),
            slots: BTreeMap::new(),
            block_of: HashMap::new(),
        };
        ctx.collect_stubs();
        ctx.collect_facts()?;
        ctx.collect_local_pairs();
        ctx.collect_imports();
        ctx.collect_starts()?;
        ctx.assign_slots();
        Ok(ctx)
    }

    fn collect_stubs(&mut self) {
        for sym in &self.input.symbols {
            if !sym.in_text {
                continue;
            }
            let stub = if let Some(name) = sym.name.strip_prefix(IMPORT_PREFIX) {
                Stub::Import(name.to_owned())
            } else if sym.name == "__solo_halt" {
                Stub::Halt
            } else if sym.name == "__solo_trap" {
                Stub::Trap
            } else if sym.name == "__solo_sbrk" {
                Stub::Sbrk
            } else {
                continue;
            };
            self.stubs.insert(sym.value, stub);
        }
    }

    /// Imports are numbered in order of first call site, so the table holds
    /// only host functions the program uses.
    fn collect_imports(&mut self) {
        let mut targets: Vec<u64> = Vec::new();
        for d in &self.insns {
            match d.rv {
                Rv::Jal { offset, .. } => targets.push(d.address.wrapping_add_signed(offset)),
                Rv::Auipc { .. } => {
                    if let Some(t) = self.facts.call_pair.get(&d.address) {
                        targets.push(*t);
                    }
                }
                _ => {}
            }
        }
        for t in targets {
            if let Some(Stub::Import(name)) = self.stubs.get(&t)
                && !self.imports.contains(name)
            {
                self.imports.push(name.clone());
            }
        }
    }

    fn import_index(&self, name: &str) -> u32 {
        let i = self
            .imports
            .iter()
            .position(|n| n == name)
            .expect("imports collected before translation");
        u32::try_from(i).expect("import count fits u32")
    }

    fn reloc_address(&self, r: &Reloc) -> u64 {
        self.input.text.address + r.offset
    }

    fn collect_facts(&mut self) -> Result<(), RecompileError> {
        for r in &self.input.text_relocs {
            let address = self.reloc_address(r);
            let target = r.symbol.value.wrapping_add_signed(r.addend);
            match r.r_type {
                reloc::R_RISCV_CALL | reloc::R_RISCV_CALL_PLT => {
                    let next = self.index_of.get(&address).map(|i| i + 1);
                    let ok = next.and_then(|i| self.insns.get(i)).is_some_and(|d| {
                        matches!((&self.insns[self.index_of[&address]].rv, &d.rv),
                            (Rv::Auipc { rd, .. }, Rv::Jalr { rs1, .. }) if rd == rs1)
                    });
                    if !ok {
                        return Err(RecompileError::BrokenCallPair { address });
                    }
                    self.facts.call_pair.insert(address, target);
                }
                reloc::R_RISCV_PCREL_HI20 => {
                    self.facts.hi.insert(address, (target, r.symbol.in_text));
                }
                reloc::R_RISCV_HI20 if r.symbol.in_text => {
                    self.facts.lui_code.insert(address, target);
                }
                reloc::R_RISCV_PCREL_LO12_I
                | reloc::R_RISCV_PCREL_LO12_S
                | reloc::R_RISCV_HI20
                | reloc::R_RISCV_LO12_I
                | reloc::R_RISCV_LO12_S
                | reloc::R_RISCV_BRANCH
                | reloc::R_RISCV_JAL
                | reloc::R_RISCV_RVC_BRANCH
                | reloc::R_RISCV_RVC_JUMP => {}
                r_type => return Err(RecompileError::UnknownReloc { address, r_type }),
            }
        }
        Ok(())
    }

    /// The assembler resolves pc-relative references to targets in the same
    /// section without emitting relocations, so an `auipc` may arrive with no
    /// fact attached. Its meaning is still fixed by the instruction that
    /// consumes it: a `jalr` makes it a call pair, an `addi` makes it a code
    /// pointer. Both targets must land in the text section.
    fn collect_local_pairs(&mut self) {
        let text_start = self.input.text.address;
        let text_end = text_start + self.input.text.bytes.len() as u64;
        for i in 0..self.insns.len() {
            let Rv::Auipc { rd, imm } = self.insns[i].rv else {
                continue;
            };
            let a = self.insns[i].address;
            if self.facts.call_pair.contains_key(&a) || self.facts.hi.contains_key(&a) {
                continue;
            }
            let Some(next) = self.insns.get(i + 1) else {
                continue;
            };
            let pc_value = a.wrapping_add_signed(imm);
            if let Rv::Jalr { rs1, offset, .. } = next.rv
                && rs1 == rd
            {
                let target = pc_value.wrapping_add_signed(offset);
                if (text_start..text_end).contains(&target) {
                    self.facts.call_pair.insert(a, target);
                }
                continue;
            }
            if let Some(lo) = self.sole_low_part(i, rd) {
                let target = pc_value.wrapping_add_signed(lo);
                if (text_start..text_end).contains(&target) {
                    self.facts.hi.insert(a, (target, true));
                }
            }
        }
    }

    /// The low offset of a relocation-less `auipc rd` at `i`, if every read of
    /// `rd` before it is overwritten (within straight-line code) is an
    /// `addi _, rd, lo` with the same `lo`. The `auipc` is then rewritten so
    /// that each such `addi` yields the code slot of the target.
    fn sole_low_part(&self, i: usize, rd: Reg) -> Option<i64> {
        let mut lo_seen = None;
        for d in self.insns.iter().skip(i + 1).take(LOCAL_PAIR_WINDOW) {
            let (dest, sources, control) = registers(&d.rv);
            if sources.contains(&Some(rd)) {
                match d.rv {
                    Rv::OpImm {
                        op: solo_vm::isa::AluImmOp::Addi,
                        rs1,
                        imm,
                        ..
                    } if rs1 == rd && lo_seen.is_none_or(|l| l == imm) => lo_seen = Some(imm),
                    _ => return None,
                }
            }
            if control || dest == Some(rd) {
                break;
            }
        }
        lo_seen
    }

    fn require_instruction(&self, address: u64) -> Result<(), RecompileError> {
        if self.index_of.contains_key(&address) {
            Ok(())
        } else {
            Err(RecompileError::TargetNotInstruction { address })
        }
    }

    fn code_pointer_targets(&self) -> Vec<u64> {
        let mut targets: Vec<u64> = self
            .input
            .rodata_relocs
            .iter()
            .chain(&self.input.data_relocs)
            .filter(|r| {
                r.symbol.in_text && matches!(r.r_type, reloc::R_RISCV_64 | reloc::R_RISCV_32)
            })
            .map(|r| r.symbol.value.wrapping_add_signed(r.addend))
            .collect();
        targets.extend(
            self.facts
                .hi
                .iter()
                .filter(|(a, (_, code))| *code && !self.facts.call_pair.contains_key(*a))
                .map(|(_, (t, _))| *t),
        );
        targets.extend(self.facts.lui_code.values().copied());
        targets
    }

    fn collect_starts(&mut self) -> Result<(), RecompileError> {
        let mut starts = BTreeSet::new();
        starts.insert(self.input.text.address);
        for sym in &self.input.symbols {
            if sym.in_text && sym.is_function {
                starts.insert(sym.value);
            }
        }
        for t in self.code_pointer_targets() {
            starts.insert(t);
        }
        let mut skip_next = false;
        for (i, d) in self.insns.iter().enumerate() {
            if skip_next {
                skip_next = false;
                continue;
            }
            let next = d.address + d.len as u64;
            match d.rv {
                Rv::Jal { offset, .. } => {
                    let t = d.address.wrapping_add_signed(offset);
                    if !self.stubs.contains_key(&t) {
                        starts.insert(t);
                    }
                    starts.insert(next);
                }
                Rv::Branch { offset, .. } => {
                    starts.insert(d.address.wrapping_add_signed(offset));
                    starts.insert(next);
                }
                Rv::Jalr { .. } | Rv::Ebreak | Rv::Unimp | Rv::Ecall => {
                    starts.insert(next);
                }
                Rv::Auipc { .. } if self.facts.call_pair.contains_key(&d.address) => {
                    let after = self.insns[i + 1].address + self.insns[i + 1].len as u64;
                    starts.insert(after);
                    skip_next = true;
                }
                _ => {}
            }
        }
        let end = self.input.text.address + self.input.text.bytes.len() as u64;
        starts.remove(&end);
        for s in &starts {
            self.require_instruction(*s)?;
        }
        self.starts = starts;
        Ok(())
    }

    fn assign_slots(&mut self) {
        let mut wanted: BTreeSet<u64> = self.code_pointer_targets().into_iter().collect();
        let mut skip_next = false;
        for (i, d) in self.insns.iter().enumerate() {
            if skip_next {
                skip_next = false;
                continue;
            }
            match d.rv {
                Rv::Jal { rd, offset } if is_call(rd) => {
                    let t = d.address.wrapping_add_signed(offset);
                    if !self.stubs.contains_key(&t) {
                        wanted.insert(d.address + d.len as u64);
                    }
                }
                Rv::Jalr { rd, .. } if is_call(rd) => {
                    wanted.insert(d.address + d.len as u64);
                }
                Rv::Auipc { .. } if self.facts.call_pair.contains_key(&d.address) => {
                    let t = self.facts.call_pair[&d.address];
                    let jalr = &self.insns[i + 1];
                    if let Rv::Jalr { rd, .. } = jalr.rv
                        && is_call(rd)
                        && !self.stubs.contains_key(&t)
                    {
                        wanted.insert(jalr.address + jalr.len as u64);
                    }
                    skip_next = true;
                }
                _ => {}
            }
        }
        let end = self.input.text.address + self.input.text.bytes.len() as u64;
        wanted.remove(&end);
        for (i, a) in wanted.into_iter().enumerate() {
            self.slots
                .insert(a, u32::try_from(i + 1).expect("slot count fits u32"));
        }
    }

    fn block(&self, address: u64) -> Result<u32, RecompileError> {
        self.block_of
            .get(&address)
            .copied()
            .ok_or(RecompileError::TargetNotInstruction { address })
    }

    fn slot_address(&self, address: u64) -> Result<i64, RecompileError> {
        let slot = self
            .slots
            .get(&address)
            .ok_or(RecompileError::TargetNotInstruction { address })?;
        Ok(8 * i64::from(*slot))
    }

    fn continuation(&self, after: u64) -> Result<u32, RecompileError> {
        self.slots
            .get(&after)
            .copied()
            .ok_or(RecompileError::TargetNotInstruction { address: after })
    }

    /// A direct transfer to `target` from an instruction whose link register is `rd`.
    ///
    /// A call to a stub becomes the stub's instruction in place, and execution
    /// continues with the caller's next instruction. A *tail call* to a stub
    /// (`rd` is `zero`) must still return to the caller's caller, so it gets an
    /// explicit `ret` after the instruction; the halt and trap stubs never return.
    fn direct(&self, rd: Reg, target: u64, after: u64) -> Result<Vec<Instruction>, RecompileError> {
        let ret = Instruction::JumpIndirect {
            rs1: Reg::RA,
            off: 0,
        };
        Ok(match self.stubs.get(&target) {
            Some(Stub::Import(name)) => {
                let ecall = Instruction::Ecall {
                    import: self.import_index(name),
                };
                if is_call(rd) {
                    vec![ecall]
                } else {
                    vec![ecall, ret]
                }
            }
            Some(Stub::Sbrk) => {
                let sbrk = Instruction::Sbrk {
                    rd: Reg::A0,
                    rs1: Reg::A0,
                };
                if is_call(rd) {
                    vec![sbrk]
                } else {
                    vec![sbrk, ret]
                }
            }
            Some(Stub::Halt) => vec![Instruction::Halt],
            Some(Stub::Trap) => vec![Instruction::Trap],
            None if is_call(rd) => vec![Instruction::Call {
                rd,
                block: self.block(target)?,
                slot: self.continuation(after)?,
            }],
            None => vec![Instruction::Jump {
                block: self.block(target)?,
            }],
        })
    }

    #[allow(clippy::cast_possible_wrap)]
    fn translate_lui(&self, a: u64, rd: Reg, imm: i64) -> Result<Instruction, RecompileError> {
        Ok(match self.facts.lui_code.get(&a) {
            Some(t) => {
                let lo = (*t as i64).wrapping_sub(imm);
                Instruction::Li {
                    rd,
                    imm: self.slot_address(*t)?.wrapping_sub(lo),
                }
            }
            None => Instruction::Li { rd, imm },
        })
    }

    /// Translates an `auipc`. Returns the instructions and whether the
    /// following `jalr` was consumed as the second half of a call pair.
    #[allow(clippy::cast_possible_wrap)]
    fn translate_auipc(
        &self,
        i: usize,
        rd: Reg,
        imm: i64,
    ) -> Result<(Vec<Instruction>, bool), RecompileError> {
        let a = self.insns[i].address;
        if let Some(t) = self.facts.call_pair.get(&a) {
            let jalr = &self.insns[i + 1];
            #[rustfmt::skip]
            let Rv::Jalr { rd: link, .. } = jalr.rv else { unreachable!("checked in collect_facts") };
            return Ok((self.direct(link, *t, jalr.address + jalr.len as u64)?, true));
        }
        let (t, code) = *self
            .facts
            .hi
            .get(&a)
            .ok_or(RecompileError::UnpairedAuipc { address: a })?;
        let pc_value = (a as i64).wrapping_add(imm);
        let ins = if code && !self.stubs.contains_key(&t) {
            let lo = (t as i64).wrapping_sub(pc_value);
            Instruction::Li {
                rd,
                imm: self.slot_address(t)?.wrapping_sub(lo),
            }
        } else {
            Instruction::Li { rd, imm: pc_value }
        };
        Ok((vec![ins], false))
    }

    #[allow(clippy::cast_possible_wrap)]
    fn translate_one(&self, i: usize) -> Result<(Vec<Instruction>, bool), RecompileError> {
        let d = &self.insns[i];
        let a = d.address;
        let next = a + d.len as u64;
        let out = match d.rv {
            Rv::Lui { rd, imm } => vec![self.translate_lui(a, rd, imm)?],
            Rv::Auipc { rd, imm } => return self.translate_auipc(i, rd, imm),
            Rv::Jal { rd, offset } => self.direct(rd, a.wrapping_add_signed(offset), next)?,
            Rv::Jalr { rd, rs1, offset } => {
                if is_call(rd) {
                    vec![Instruction::CallIndirect {
                        rd,
                        rs1,
                        off: offset,
                        slot: self.continuation(next)?,
                    }]
                } else {
                    vec![Instruction::JumpIndirect { rs1, off: offset }]
                }
            }
            Rv::Branch {
                cond,
                rs1,
                rs2,
                offset,
            } => vec![Instruction::Branch {
                cond,
                rs1,
                rs2,
                block: self.block(a.wrapping_add_signed(offset))?,
            }],
            Rv::Load {
                width,
                rd,
                rs1,
                offset,
            } => vec![Instruction::Load {
                width,
                rd,
                rs1,
                off: offset,
            }],
            Rv::Store {
                width,
                rs1,
                rs2,
                offset,
            } => vec![Instruction::Store {
                width,
                rs1,
                rs2,
                off: offset,
            }],
            Rv::OpImm { op, rd, rs1, imm } => vec![Instruction::AluImm { op, rd, rs1, imm }],
            Rv::Op { op, rd, rs1, rs2 } => vec![Instruction::Alu { op, rd, rs1, rs2 }],
            Rv::Fence => vec![],
            Rv::Ecall | Rv::Ebreak | Rv::Unimp => vec![Instruction::Trap],
            Rv::Lr { width, rd, rs1 } => vec![Instruction::Load {
                width: load_width(width),
                rd,
                rs1,
                off: 0,
            }],
            Rv::Sc {
                width,
                rd,
                rs1,
                rs2,
            } => vec![
                Instruction::Store {
                    width: store_width(width),
                    rs1,
                    rs2,
                    off: 0,
                },
                Instruction::Li { rd, imm: 0 },
            ],
            Rv::Amo {
                op,
                width,
                rd,
                rs1,
                rs2,
            } => lower_amo(op, width, rd, rs1, rs2)
                .ok_or(RecompileError::UnsupportedAtomic { address: a })?,
        };
        Ok((out, false))
    }

    fn translate_blocks(&mut self) -> Result<Vec<Vec<Instruction>>, RecompileError> {
        for (i, s) in self.starts.iter().enumerate() {
            self.block_of
                .insert(*s, u32::try_from(i).expect("block count fits u32"));
        }
        let mut blocks: Vec<Vec<Instruction>> = Vec::with_capacity(self.starts.len());
        let mut current: Vec<Instruction> = Vec::new();
        let mut skip_next = false;
        for i in 0..self.insns.len() {
            let address = self.insns[i].address;
            if i > 0 && self.starts.contains(&address) {
                blocks.push(std::mem::take(&mut current));
            }
            if skip_next {
                skip_next = false;
                continue;
            }
            let (out, consumed_next) = self.translate_one(i)?;
            skip_next = consumed_next;
            current.extend(out);
        }
        blocks.push(current);
        // Blocks must be non-empty; a block that translated to nothing (only
        // fences, or a consumed jalr) gets an explicit fallthrough-free form.
        for b in &mut blocks {
            if b.is_empty() {
                b.push(Instruction::AluImm {
                    op: solo_vm::isa::AluImmOp::Addi,
                    rd: Reg::ZERO,
                    rs1: Reg::ZERO,
                    imm: 0,
                });
            }
        }
        if blocks
            .last()
            .is_some_and(|b| b.last().is_some_and(Instruction::falls_through))
        {
            blocks.push(vec![Instruction::Trap]);
        }
        Ok(blocks)
    }
}

const fn load_width(w: AmoWidth) -> LoadWidth {
    match w {
        AmoWidth::W => LoadWidth::W,
        AmoWidth::D => LoadWidth::D,
    }
}

const fn store_width(w: AmoWidth) -> StoreWidth {
    match w {
        AmoWidth::W => StoreWidth::W,
        AmoWidth::D => StoreWidth::D,
    }
}

/// How far past a relocation-less `auipc` to look for its uses.
const LOCAL_PAIR_WINDOW: usize = 16;

/// The register an instruction writes, the registers it reads, and whether
/// it transfers control (ending the straight-line run).
fn registers(rv: &Rv) -> (Option<Reg>, [Option<Reg>; 2], bool) {
    match *rv {
        Rv::Lui { rd, .. } | Rv::Auipc { rd, .. } => (Some(rd), [None, None], false),
        Rv::Jal { rd, .. } => (Some(rd), [None, None], true),
        Rv::Jalr { rd, rs1, .. } => (Some(rd), [Some(rs1), None], true),
        Rv::Branch { rs1, rs2, .. } => (None, [Some(rs1), Some(rs2)], true),
        Rv::Load { rd, rs1, .. } | Rv::OpImm { rd, rs1, .. } | Rv::Lr { rd, rs1, .. } => {
            (Some(rd), [Some(rs1), None], false)
        }
        Rv::Store { rs1, rs2, .. } => (None, [Some(rs1), Some(rs2)], false),
        Rv::Op { rd, rs1, rs2, .. }
        | Rv::Sc { rd, rs1, rs2, .. }
        | Rv::Amo { rd, rs1, rs2, .. } => (Some(rd), [Some(rs1), Some(rs2)], false),
        Rv::Fence => (None, [None, None], false),
        Rv::Ecall | Rv::Ebreak | Rv::Unimp => (None, [None, None], true),
    }
}

/// `amo<op> rd, rs2, (rd)`: the address register is about to be overwritten
/// with the old value, so compute the new value in the scratch register and
/// recover the old one by inverting the operation. Only invertible operations
/// qualify.
fn lower_amo_into_address(
    alu: AluOp,
    width: AmoWidth,
    rd: Reg,
    rs1: Reg,
    rs2: Reg,
    load: Instruction,
) -> Option<Vec<Instruction>> {
    let inverse = match alu {
        AluOp::Add => AluOp::Sub,
        AluOp::Addw => AluOp::Subw,
        AluOp::Xor => AluOp::Xor,
        _ => return None,
    };
    if rd == rs2 {
        return None;
    }
    Some(vec![
        load,
        Instruction::Alu {
            op: alu,
            rd: SCRATCH,
            rs1: SCRATCH,
            rs2,
        },
        Instruction::Store {
            width: store_width(width),
            rs1,
            rs2: SCRATCH,
            off: 0,
        },
        Instruction::Alu {
            op: inverse,
            rd,
            rs1: SCRATCH,
            rs2,
        },
    ])
}

fn lower_amo(op: AmoOp, width: AmoWidth, rd: Reg, rs1: Reg, rs2: Reg) -> Option<Vec<Instruction>> {
    let load = Instruction::Load {
        width: load_width(width),
        rd: SCRATCH,
        rs1,
        off: 0,
    };
    if op == AmoOp::Swap {
        return Some(vec![
            load,
            Instruction::Store {
                width: store_width(width),
                rs1,
                rs2,
                off: 0,
            },
            Instruction::Alu {
                op: AluOp::Add,
                rd,
                rs1: SCRATCH,
                rs2: Reg::ZERO,
            },
        ]);
    }
    let alu = match (op, width) {
        (AmoOp::Add, AmoWidth::W) => AluOp::Addw,
        (AmoOp::Add, AmoWidth::D) => AluOp::Add,
        (AmoOp::Xor, _) => AluOp::Xor,
        (AmoOp::And, _) => AluOp::And,
        (AmoOp::Or, _) => AluOp::Or,
        _ => return None,
    };
    if rd == Reg::ZERO {
        return Some(vec![
            load,
            Instruction::Alu {
                op: alu,
                rd: SCRATCH,
                rs1: SCRATCH,
                rs2,
            },
            Instruction::Store {
                width: store_width(width),
                rs1,
                rs2: SCRATCH,
                off: 0,
            },
        ]);
    }
    if rd == rs1 {
        return lower_amo_into_address(alu, width, rd, rs1, rs2, load);
    }
    // `rd == rs2` is fine: the operation reads `rs2` before writing `rd`.
    Some(vec![
        load,
        Instruction::Alu {
            op: alu,
            rd,
            rs1: SCRATCH,
            rs2,
        },
        Instruction::Store {
            width: store_width(width),
            rs1,
            rs2: rd,
            off: 0,
        },
        Instruction::Alu {
            op: AluOp::Add,
            rd,
            rs1: SCRATCH,
            rs2: Reg::ZERO,
        },
    ])
}

fn page_up(v: u64) -> u64 {
    v.div_ceil(u64::from(PAGE)) * u64::from(PAGE)
}

fn patch_data(
    ctx: &Ctx<'_>,
    bytes: &mut [u8],
    relocs: &[Reloc],
    base: u64,
) -> Result<(), RecompileError> {
    for r in relocs {
        let address = base + r.offset;
        let width = match r.r_type {
            reloc::R_RISCV_64 => 8,
            reloc::R_RISCV_32 => 4,
            r_type => return Err(RecompileError::UnknownReloc { address, r_type }),
        };
        if !r.symbol.in_text {
            continue;
        }
        let target = r.symbol.value.wrapping_add_signed(r.addend);
        #[allow(clippy::cast_sign_loss)]
        let value = ctx.slot_address(target)? as u64;
        let off = usize::try_from(r.offset).unwrap_or(usize::MAX);
        let field = off
            .checked_add(width)
            .and_then(|end| bytes.get_mut(off..end))
            .ok_or(RecompileError::DataRelocOutOfRange { address })?;
        field.copy_from_slice(&value.to_le_bytes()[..width]);
    }
    Ok(())
}

/// Recompiles a loaded ELF into module bytes, validated before return.
///
/// # Errors
/// See [`RecompileError`].
#[allow(clippy::cast_possible_truncation)]
pub fn recompile(input: &Input, options: &Options) -> Result<Vec<u8>, RecompileError> {
    let mut ctx = Ctx::new(input)?;
    let blocks = ctx.translate_blocks()?;

    let mut rodata = input.rodata.bytes.clone();
    patch_data(
        &ctx,
        &mut rodata,
        &input.rodata_relocs,
        input.rodata.address,
    )?;
    let mut data = input.data.bytes.clone();
    patch_data(&ctx, &mut data, &input.data_relocs, input.data.address)?;

    let mut b = ModuleBuilder::new();
    let rodata_base = if input.rodata.size > 0 {
        input.rodata.address
    } else {
        0x1_0000
    };
    let rodata_end = rodata_base + rodata.len() as u64;
    let (data_base, bss_size) = match (input.data.size > 0, input.bss.size > 0) {
        (true, true) => (
            input.data.address,
            (input.bss.address + input.bss.size) - (input.data.address + data.len() as u64),
        ),
        (true, false) => (input.data.address, 0),
        (false, true) => (input.bss.address, input.bss.size),
        (false, false) => (page_up(rodata_end) + u64::from(PAGE), 0),
    };
    let data_end = data_base + data.len() as u64 + bss_size;
    b.layout.ro_base = rodata_base as u32;
    b.layout.ro_size = rodata.len() as u32;
    b.layout.rw_base = data_base as u32;
    b.layout.data_size = data.len() as u32;
    b.layout.bss_size = bss_size as u32;
    b.layout.heap_base = (page_up(data_end) + u64::from(PAGE)) as u32;
    b.layout.heap_max = options.heap_max;
    b.layout.stack_top = options.stack_top;
    b.layout.stack_base = options.stack_top - options.stack_size;
    b.rodata = rodata;
    b.data = data;
    b.imports.clone_from(&ctx.imports);
    b.jump_table = vec![None; ctx.slots.len() + 1];
    for (address, slot) in &ctx.slots {
        b.jump_table[*slot as usize] = Some(ctx.block(*address)?);
    }
    b.blocks = blocks;
    for sym in &input.symbols {
        if let Some(name) = sym.name.strip_prefix(EXPORT_PREFIX)
            && sym.in_text
        {
            b.exports.push((name.to_owned(), ctx.block(sym.value)?));
        }
    }
    if b.exports.is_empty() {
        return Err(RecompileError::NoExports);
    }
    if options.debug_map {
        let mut map = Vec::with_capacity(ctx.starts.len() * 8);
        for start in &ctx.starts {
            map.extend_from_slice(&start.to_le_bytes());
        }
        b.debug = Some(map);
    }
    let bytes = b.build();
    Module::parse(&bytes, &|_| true).map_err(RecompileError::Validation)?;
    Ok(bytes)
}

#[cfg(test)]
#[allow(clippy::cast_possible_wrap)]
mod tests {
    use super::*;
    use crate::elf::{Section, Symbol};
    use crate::riscv::tests::{enc_b, enc_i, enc_j, enc_r, enc_s, enc_u};
    use solo_vm::isa::{AluImmOp, Cond};

    const TEXT: u64 = 0x4000_0000;

    fn sym(name: &str, value: u64, in_text: bool) -> Symbol {
        Symbol {
            name: name.to_owned(),
            value,
            in_text,
            is_function: in_text,
        }
    }

    fn func(name: &str, offset: u64) -> Symbol {
        sym(name, TEXT + offset, true)
    }

    fn rel(offset: u64, r_type: u32, symbol: Symbol, addend: i64) -> Reloc {
        Reloc {
            offset,
            r_type,
            symbol,
            addend,
        }
    }

    fn text(words: &[u32]) -> Section {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        Section {
            address: TEXT,
            size: bytes.len() as u64,
            bytes,
        }
    }

    fn input(words: &[u32], mut symbols: Vec<Symbol>, text_relocs: Vec<Reloc>) -> Input {
        symbols.insert(0, func("solo_export_main", 0));
        Input {
            text: text(words),
            symbols,
            text_relocs,
            ..Input::default()
        }
    }

    fn module_of(input: &Input) -> Module {
        let bytes = recompile(input, &Options::default()).expect("recompiles");
        Module::parse(&bytes, &|_| true).expect("valid")
    }

    const RET: u32 = 0x0000_8067;
    const UNIMP: u32 = 0xC000_1073;
    const FENCE: u32 = 0x0FF0_000F;
    const EBREAK: u32 = 0x0010_0073;
    const ECALL: u32 = 0x0000_0073;

    fn jal(rd: u8, off: i32) -> u32 {
        enc_j(rd, off)
    }
    fn jalr(rd: u8, rs1: u8, off: i32) -> u32 {
        enc_i(0x67, 0, rd, rs1, off)
    }
    fn auipc(rd: u8, imm: i32) -> u32 {
        enc_u(0x17, rd, imm)
    }
    fn lui(rd: u8, imm: i32) -> u32 {
        enc_u(0x37, rd, imm)
    }
    fn addi(rd: u8, rs1: u8, imm: i32) -> u32 {
        enc_i(0x13, 0, rd, rs1, imm)
    }
    fn amo(funct5: u32, f3: u32, rd: u8, rs1: u8, rs2: u8) -> u32 {
        enc_r(0x2F, f3, funct5 << 2, rd, rs1, rs2)
    }
    fn r(i: u8) -> Reg {
        Reg::new(i).unwrap()
    }

    #[test]
    fn direct_calls_jumps_and_stubs() {
        // 0: call f (16) ; 4: call import stub (20) ; 8: jump halt stub (24)
        // 12: ret ; 16: f: ret ; 20: import stub ; 24: halt stub
        let words = [jal(1, 16), jal(1, 16), jal(0, 16), RET, RET, UNIMP, UNIMP];
        let inp = input(
            &words,
            vec![
                func("f", 16),
                func("__solo_import_output_write", 20),
                func("__solo_halt", 24),
            ],
            vec![],
        );
        let m = module_of(&inp);
        assert_eq!(m.imports, vec!["output_write".to_owned()]);
        assert_eq!(m.jump_table, vec![None, Some(1)]);
        assert_eq!(
            m.blocks[0],
            vec![Instruction::Call {
                rd: Reg::RA,
                block: 4,
                slot: 1
            }]
        );
        assert_eq!(m.blocks[1], vec![Instruction::Ecall { import: 0 }]);
        assert_eq!(m.blocks[2], vec![Instruction::Halt]);
        assert_eq!(
            m.blocks[3],
            vec![Instruction::JumpIndirect {
                rs1: Reg::RA,
                off: 0
            }]
        );
        assert_eq!(
            m.blocks[4],
            vec![Instruction::JumpIndirect {
                rs1: Reg::RA,
                off: 0
            }]
        );
        assert_eq!(m.blocks[5], vec![Instruction::Trap]);
        assert_eq!(m.blocks[6], vec![Instruction::Trap]);
        assert_eq!(m.export("main"), Some(0));
    }

    #[test]
    fn call_pairs_including_tail_calls_and_stubs() {
        // 0: auipc ra ; 4: jalr ra (call f@24) ; 8: auipc t1 ; 12: jalr zero (tail call f)
        // 16: auipc ra ; 20: jalr ra (call trap stub @28) ; 24: f: ret ; 28: trap stub
        let words = [
            auipc(1, 0),
            jalr(1, 1, 24),
            auipc(6, 0),
            jalr(0, 6, 16),
            auipc(1, 0),
            jalr(1, 1, 12),
            RET,
            UNIMP,
        ];
        let f = func("f", 24);
        let trap = func("__solo_trap", 28);
        let relocs = vec![
            rel(0, reloc::R_RISCV_CALL_PLT, f.clone(), 0),
            rel(8, reloc::R_RISCV_CALL, f.clone(), 0),
            rel(16, reloc::R_RISCV_CALL_PLT, trap.clone(), 0),
        ];
        let m = module_of(&input(&words, vec![f, trap], relocs));
        let f_block = m.export("main").map(|_| 3).unwrap();
        assert_eq!(
            m.blocks[0],
            vec![Instruction::Call {
                rd: Reg::RA,
                block: f_block,
                slot: 1
            }]
        );
        assert_eq!(m.blocks[1], vec![Instruction::Jump { block: f_block }]);
        assert_eq!(m.blocks[2], vec![Instruction::Trap]);
        assert_eq!(m.jump_table, vec![None, Some(1)]);
        assert!(m.imports.is_empty());
    }

    #[test]
    fn broken_call_pair_is_rejected() {
        let words = [auipc(1, 0), addi(1, 1, 8), RET];
        let f = func("f", 8);
        let inp = input(
            &words,
            vec![f.clone()],
            vec![rel(0, reloc::R_RISCV_CALL_PLT, f, 0)],
        );
        assert_eq!(
            recompile(&inp, &Options::default()),
            Err(RecompileError::BrokenCallPair { address: TEXT })
        );
        // A call pair at the very end of the text has no jalr either.
        let words = [RET, auipc(1, 0)];
        let f = func("f", 0);
        let inp = input(
            &words,
            vec![f.clone()],
            vec![rel(4, reloc::R_RISCV_CALL_PLT, f, 0)],
        );
        assert_eq!(
            recompile(&inp, &Options::default()),
            Err(RecompileError::BrokenCallPair { address: TEXT + 4 })
        );
    }

    #[test]
    fn pc_relative_constants_and_code_pointers() {
        // 0: auipc a0 (data) ; 4: addi a0, a0, lo ; 8: auipc a1 (code f) ; 12: addi a1, a1, lo
        // 16: lui a2 (code f, absolute) ; 20: addi a2, a2, lo ; 24: ret ; 28: f: ret
        let data_sym = sym("buffer", 0x1_2000, false);
        let f = func("f", 28);
        let words = [
            auipc(10, 0),
            addi(10, 10, 0),
            auipc(11, 0),
            addi(11, 11, 0),
            lui(12, 0x4000_0000u32 as i32),
            addi(12, 12, 28),
            RET,
            RET,
        ];
        let relocs = vec![
            rel(0, reloc::R_RISCV_PCREL_HI20, data_sym, 0),
            rel(
                4,
                reloc::R_RISCV_PCREL_LO12_I,
                sym(".Lpcrel_hi0", TEXT, true),
                0,
            ),
            rel(8, reloc::R_RISCV_PCREL_HI20, f.clone(), 0),
            rel(
                12,
                reloc::R_RISCV_PCREL_LO12_I,
                sym(".Lpcrel_hi1", TEXT + 8, true),
                0,
            ),
            rel(16, reloc::R_RISCV_HI20, f.clone(), 0),
            rel(20, reloc::R_RISCV_LO12_I, f.clone(), 0),
        ];
        let m = module_of(&input(&words, vec![f], relocs));
        // f is the only address-taken block: slot 1, slot address 8.
        assert_eq!(m.jump_table, vec![None, Some(1)]);
        let b0 = &m.blocks[0];
        assert_eq!(
            b0[0],
            Instruction::Li {
                rd: Reg::A0,
                imm: TEXT as i64
            }
        ); // pc + 0; addi adds nothing
        assert_eq!(
            b0[1],
            Instruction::AluImm {
                op: AluImmOp::Addi,
                rd: Reg::A0,
                rs1: Reg::A0,
                imm: 0
            }
        );
        // auipc a1 to code: li a1, slot(8) - lo where lo = f - (pc+0) = 20.
        assert_eq!(
            b0[2],
            Instruction::Li {
                rd: Reg::A1,
                imm: 8 - 20
            }
        );
        assert_eq!(
            b0[3],
            Instruction::AluImm {
                op: AluImmOp::Addi,
                rd: Reg::A1,
                rs1: Reg::A1,
                imm: 0
            }
        );
        // lui a2 to code: li a2, slot(8) - lo where lo = f - 0x4000_0000 = 28.
        assert_eq!(
            b0[4],
            Instruction::Li {
                rd: Reg::A2,
                imm: 8 - 28
            }
        );
        assert_eq!(
            b0[5],
            Instruction::AluImm {
                op: AluImmOp::Addi,
                rd: Reg::A2,
                rs1: Reg::A2,
                imm: 28
            }
        );
        assert_eq!(
            b0[6],
            Instruction::JumpIndirect {
                rs1: Reg::RA,
                off: 0
            }
        );
        // Plain lui with no relocation is a constant.
        let m = module_of(&input(&[lui(5, 0x1_2000), RET], vec![], vec![]));
        assert_eq!(
            m.blocks[0][0],
            Instruction::Li {
                rd: r(5),
                imm: 0x1_2000
            }
        );
    }

    #[test]
    fn unpaired_auipc_is_rejected() {
        let inp = input(&[auipc(10, 0), RET], vec![], vec![]);
        assert_eq!(
            recompile(&inp, &Options::default()),
            Err(RecompileError::UnpairedAuipc { address: TEXT })
        );
    }

    #[test]
    fn indirect_calls_and_jumps() {
        let words = [jalr(1, 10, 0), jalr(0, 10, 4), RET];
        let m = module_of(&input(&words, vec![], vec![]));
        assert_eq!(
            m.blocks[0],
            vec![Instruction::CallIndirect {
                rd: Reg::RA,
                rs1: Reg::A0,
                off: 0,
                slot: 1
            }]
        );
        assert_eq!(
            m.blocks[1],
            vec![Instruction::JumpIndirect {
                rs1: Reg::A0,
                off: 4
            }]
        );
        assert_eq!(m.jump_table, vec![None, Some(1)]);
    }

    #[test]
    fn branches_fallthrough_padding_and_final_trap() {
        // 0: beq zero, zero, +8 ; 4: fence ; 8: addi a0, a0, 1  (falls off the end)
        let words = [enc_b(0, 0, 0, 8), FENCE, addi(10, 10, 1)];
        let m = module_of(&input(&words, vec![], vec![]));
        assert_eq!(
            m.blocks[0],
            vec![Instruction::Branch {
                cond: Cond::Eq,
                rs1: Reg::ZERO,
                rs2: Reg::ZERO,
                block: 2
            }]
        );
        assert_eq!(
            m.blocks[1],
            vec![Instruction::AluImm {
                op: AluImmOp::Addi,
                rd: Reg::ZERO,
                rs1: Reg::ZERO,
                imm: 0
            }]
        );
        assert_eq!(
            m.blocks[2],
            vec![Instruction::AluImm {
                op: AluImmOp::Addi,
                rd: Reg::A0,
                rs1: Reg::A0,
                imm: 1
            }]
        );
        assert_eq!(m.blocks[3], vec![Instruction::Trap]);
        // ebreak, ecall and unimp each become a trap and end a block.
        let m = module_of(&input(&[EBREAK, ECALL, UNIMP, RET], vec![], vec![]));
        assert_eq!(m.blocks[0], vec![Instruction::Trap]);
        assert_eq!(m.blocks[1], vec![Instruction::Trap]);
        assert_eq!(m.blocks[2], vec![Instruction::Trap]);
        assert_eq!(
            m.blocks[3],
            vec![Instruction::JumpIndirect {
                rs1: Reg::RA,
                off: 0
            }]
        );
    }

    #[test]
    fn target_not_an_instruction() {
        let inp = input(&[enc_b(0, 0, 0, 2), RET], vec![], vec![]);
        assert_eq!(
            recompile(&inp, &Options::default()),
            Err(RecompileError::TargetNotInstruction { address: TEXT + 2 })
        );
    }

    #[test]
    fn unsupported_instruction() {
        let inp = input(&[0x0000_0007, RET], vec![], vec![]);
        assert_eq!(
            recompile(&inp, &Options::default()),
            Err(RecompileError::Unsupported {
                address: TEXT,
                word: 0x0000_0007
            })
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn atomics_lowering() {
        let d = 3;
        let w = 2;
        let words = [
            amo(0x02, d, 10, 11, 0),  // lr.d a0, (a1)
            amo(0x03, d, 10, 11, 12), // sc.d a0, a2, (a1)
            amo(0x01, d, 10, 11, 12), // amoswap.d a0, a2, (a1)
            amo(0x00, w, 0, 11, 12),  // amoadd.w zero, a2, (a1)
            amo(0x00, d, 10, 11, 12), // amoadd.d a0, a2, (a1)
            amo(0x04, d, 10, 11, 12), // amoxor.d
            amo(0x0C, w, 10, 11, 12), // amoand.w
            amo(0x08, d, 10, 11, 12), // amoor.d
            RET,
        ];
        let m = module_of(&input(&words, vec![], vec![]));
        let b = &m.blocks[0];
        let (a0, a1, a2, tp) = (Reg::A0, Reg::A1, Reg::A2, SCRATCH);
        let ld = |rd| Instruction::Load {
            width: LoadWidth::D,
            rd,
            rs1: a1,
            off: 0,
        };
        let lw = |rd| Instruction::Load {
            width: LoadWidth::W,
            rd,
            rs1: a1,
            off: 0,
        };
        let sd = |rs2| Instruction::Store {
            width: StoreWidth::D,
            rs1: a1,
            rs2,
            off: 0,
        };
        let sw = |rs2| Instruction::Store {
            width: StoreWidth::W,
            rs1: a1,
            rs2,
            off: 0,
        };
        let mv = |rd, rs| Instruction::Alu {
            op: AluOp::Add,
            rd,
            rs1: rs,
            rs2: Reg::ZERO,
        };
        let op = |op, rd, rs1, rs2| Instruction::Alu { op, rd, rs1, rs2 };
        let expected = vec![
            ld(a0),
            sd(a2),
            Instruction::Li { rd: a0, imm: 0 },
            ld(tp),
            sd(a2),
            mv(a0, tp),
            lw(tp),
            op(AluOp::Addw, tp, tp, a2),
            sw(tp),
            ld(tp),
            op(AluOp::Add, a0, tp, a2),
            sd(a0),
            mv(a0, tp),
            ld(tp),
            op(AluOp::Xor, a0, tp, a2),
            sd(a0),
            mv(a0, tp),
            lw(tp),
            op(AluOp::And, a0, tp, a2),
            sw(a0),
            mv(a0, tp),
            ld(tp),
            op(AluOp::Or, a0, tp, a2),
            sd(a0),
            mv(a0, tp),
            Instruction::JumpIndirect {
                rs1: Reg::RA,
                off: 0,
            },
        ];
        assert_eq!(b, &expected);
        // The destination aliasing the value or the address register.
        let aliased = [
            amo(0x00, d, 12, 11, 12), // amoadd.d a2, a2, (a1)
            amo(0x00, d, 11, 11, 12), // amoadd.d a1, a2, (a1)
            amo(0x00, w, 11, 11, 12), // amoadd.w a1, a2, (a1)
            amo(0x04, d, 11, 11, 12), // amoxor.d a1, a2, (a1)
            RET,
        ];
        let m = module_of(&input(&aliased, vec![], vec![]));
        let b = &m.blocks[0];
        let sw_tp = Instruction::Store {
            width: StoreWidth::W,
            rs1: a1,
            rs2: tp,
            off: 0,
        };
        assert_eq!(
            b[..4],
            [ld(tp), op(AluOp::Add, a2, tp, a2), sd(a2), mv(a2, tp)]
        );
        assert_eq!(
            b[4..8],
            [
                ld(tp),
                op(AluOp::Add, tp, tp, a2),
                sd(tp),
                op(AluOp::Sub, a1, tp, a2)
            ]
        );
        assert_eq!(
            b[8..12],
            [
                lw(tp),
                op(AluOp::Addw, tp, tp, a2),
                sw_tp,
                op(AluOp::Subw, a1, tp, a2)
            ]
        );
        assert_eq!(
            b[12..16],
            [
                ld(tp),
                op(AluOp::Xor, tp, tp, a2),
                sd(tp),
                op(AluOp::Xor, a1, tp, a2)
            ]
        );
        for bad in [
            amo(0x10, d, 10, 11, 12), // amomin
            amo(0x0C, d, 11, 11, 12), // amoand into the address register
            amo(0x00, d, 11, 11, 11), // everything aliased
        ] {
            let inp = input(&[bad, RET], vec![], vec![]);
            assert_eq!(
                recompile(&inp, &Options::default()),
                Err(RecompileError::UnsupportedAtomic { address: TEXT })
            );
        }
    }

    #[test]
    fn relocation_errors() {
        let f = func("f", 4);
        let inp = input(&[RET, RET], vec![f.clone()], vec![rel(0, 99, f.clone(), 0)]);
        assert_eq!(
            recompile(&inp, &Options::default()),
            Err(RecompileError::UnknownReloc {
                address: TEXT,
                r_type: 99
            })
        );
        let mut inp = input(&[RET, RET], vec![f.clone()], vec![]);
        inp.rodata = Section {
            address: 0x1_0000,
            bytes: vec![0; 16],
            size: 16,
        };
        inp.rodata_relocs = vec![rel(0, 5, f.clone(), 0)];
        assert_eq!(
            recompile(&inp, &Options::default()),
            Err(RecompileError::UnknownReloc {
                address: 0x1_0000,
                r_type: 5
            })
        );
        inp.rodata_relocs = vec![rel(12, reloc::R_RISCV_64, f, 0)];
        assert_eq!(
            recompile(&inp, &Options::default()),
            Err(RecompileError::DataRelocOutOfRange { address: 0x1_000C })
        );
    }

    #[test]
    fn code_pointers_in_data_are_rewritten() {
        let f = func("f", 4);
        let g = func("g", 8);
        let mut inp = input(&[RET, RET, RET], vec![f.clone(), g.clone()], vec![]);
        inp.rodata = Section {
            address: 0x1_0000,
            bytes: vec![0xAA; 12],
            size: 12,
        };
        inp.rodata_relocs = vec![
            rel(0, reloc::R_RISCV_64, f.clone(), 0),
            rel(8, reloc::R_RISCV_32, g.clone(), 0),
        ];
        inp.data = Section {
            address: 0x1_2000,
            bytes: vec![0xBB; 16],
            size: 16,
        };
        inp.data_relocs = vec![
            rel(0, reloc::R_RISCV_64, sym("buffer", 0x1_2000, false), 0),
            rel(8, reloc::R_RISCV_64, f, 0),
        ];
        let m = module_of(&inp);
        // f and g are slots 1 and 2 in address order.
        assert_eq!(m.jump_table, vec![None, Some(1), Some(2)]);
        assert_eq!(&m.rodata[..8], &8u64.to_le_bytes());
        assert_eq!(&m.rodata[8..12], &16u32.to_le_bytes());
        assert_eq!(&m.data[..8], &[0xBB; 8]); // data symbol left as linked
        assert_eq!(&m.data[8..16], &8u64.to_le_bytes());
        assert_eq!(m.layout.rw_base, 0x1_2000);
        assert_eq!(m.layout.data_size, 16);
        assert_eq!(m.layout.bss_size, 0);
    }

    #[test]
    fn layouts() {
        // Neither data nor bss.
        let m = module_of(&input(&[RET], vec![], vec![]));
        assert_eq!(m.layout.ro_base, 0x1_0000);
        assert_eq!(m.layout.ro_size, 0);
        assert_eq!(m.layout.rw_base, 0x1_1000);
        assert_eq!(m.layout.heap_base, 0x1_2000);
        assert_eq!(m.layout.heap_max, 1 << 30);
        assert_eq!(m.layout.stack_base, 0xFFEF_0000);
        assert_eq!(m.layout.stack_top, 0xFFFF_0000);
        // Data and bss with alignment padding between them.
        let mut inp = input(&[RET], vec![], vec![]);
        inp.data = Section {
            address: 0x1_2000,
            bytes: vec![1, 2, 3],
            size: 3,
        };
        inp.bss = Section {
            address: 0x1_2008,
            bytes: vec![],
            size: 100,
        };
        let m = module_of(&inp);
        assert_eq!(m.layout.rw_base, 0x1_2000);
        assert_eq!(m.layout.data_size, 3);
        assert_eq!(m.layout.bss_size, 105);
        assert_eq!(m.layout.heap_base, 0x1_4000);
        assert_eq!(Options::default().stack_size, 1 << 20);
    }

    #[test]
    fn exports_and_validation() {
        let mut inp = input(&[RET], vec![], vec![]);
        inp.symbols.clear();
        assert_eq!(
            recompile(&inp, &Options::default()),
            Err(RecompileError::NoExports)
        );
        let inp = input(&[RET], vec![], vec![]);
        let bad = Options {
            heap_max: 1,
            ..Options::default()
        };
        assert!(matches!(
            recompile(&inp, &bad),
            Err(RecompileError::Validation(_))
        ));
    }

    #[test]
    fn error_messages() {
        let cases = [
            (
                RecompileError::Unsupported {
                    address: 16,
                    word: 7,
                },
                "unsupported instruction 0x00000007 at 0x10",
            ),
            (
                RecompileError::UnpairedAuipc { address: 16 },
                "auipc without relocation at 0x10",
            ),
            (
                RecompileError::BrokenCallPair { address: 16 },
                "call pair without jalr at 0x10",
            ),
            (
                RecompileError::TargetNotInstruction { address: 16 },
                "control-flow target 0x10 is not an instruction",
            ),
            (
                RecompileError::UnsupportedAtomic { address: 16 },
                "unsupported atomic at 0x10",
            ),
            (
                RecompileError::UnknownReloc {
                    address: 16,
                    r_type: 9,
                },
                "unknown relocation type 9 at 0x10",
            ),
            (
                RecompileError::DataRelocOutOfRange { address: 16 },
                "data relocation outside its section at 0x10",
            ),
            (RecompileError::NoExports, "no solo_export_* symbol"),
        ];
        for (e, msg) in cases {
            assert_eq!(e.to_string(), msg);
        }
        assert!(
            RecompileError::Validation(ValidationError::BadMagic)
                .to_string()
                .contains("BadMagic")
        );
        let boxed: Box<dyn std::error::Error> = Box::new(RecompileError::NoExports);
        assert!(boxed.to_string().contains("export"));
    }

    #[test]
    fn plain_instructions_pass_through_and_bss_only_layout() {
        // lw a0, 4(a1) ; sd a2, 8(a3) ; addi a0, a0, 1 ; add a0, a0, a1 ; ret
        let words = [
            enc_i(0x03, 2, 10, 11, 4),
            enc_s(0x23, 3, 13, 12, 8),
            addi(10, 10, 1),
            enc_r(0x33, 0, 0, 10, 10, 11),
            RET,
        ];
        let mut inp = input(&words, vec![sym("buffer", 0x1_2000, false)], vec![]);
        inp.bss = Section {
            address: 0x1_2000,
            bytes: vec![],
            size: 64,
        };
        let m = module_of(&inp);
        assert_eq!(
            m.blocks[0],
            vec![
                Instruction::Load {
                    width: LoadWidth::W,
                    rd: Reg::A0,
                    rs1: Reg::A1,
                    off: 4
                },
                Instruction::Store {
                    width: StoreWidth::D,
                    rs1: Reg::A3,
                    rs2: Reg::A2,
                    off: 8
                },
                Instruction::AluImm {
                    op: AluImmOp::Addi,
                    rd: Reg::A0,
                    rs1: Reg::A0,
                    imm: 1
                },
                Instruction::Alu {
                    op: AluOp::Add,
                    rd: Reg::A0,
                    rs1: Reg::A0,
                    rs2: Reg::A1
                },
                Instruction::JumpIndirect {
                    rs1: Reg::RA,
                    off: 0
                },
            ]
        );
        assert_eq!(m.layout.rw_base, 0x1_2000);
        assert_eq!(m.layout.data_size, 0);
        assert_eq!(m.layout.bss_size, 64);
        assert!(m.imports.is_empty());
    }

    #[test]
    fn sbrk_stub_becomes_the_instruction() {
        // 0: call sbrk stub (8) ; 4: ret ; 8: stub
        let words = [jal(1, 8), RET, UNIMP];
        let m = module_of(&input(&words, vec![func("__solo_sbrk", 8)], vec![]));
        assert_eq!(
            m.blocks[0],
            vec![Instruction::Sbrk {
                rd: Reg::A0,
                rs1: Reg::A0
            }]
        );
        assert_eq!(
            m.blocks[1],
            vec![Instruction::JumpIndirect {
                rs1: Reg::RA,
                off: 0
            }]
        );
        assert!(m.imports.is_empty());
        assert_eq!(m.jump_table, vec![None]);
    }

    #[test]
    fn relocation_less_local_pairs() {
        // 0: auipc ra, 0 ; 4: jalr ra, 16(ra)  -> call f at 16, no relocation
        // 8: auipc a0, 0 ; 12: addi a0, a0, 8  -> address of f (16) as a code pointer
        // 16: f: ret
        let words = [
            auipc(1, 0),
            jalr(1, 1, 16),
            auipc(10, 0),
            addi(10, 10, 8),
            RET,
        ];
        let m = module_of(&input(&words, vec![func("f", 16)], vec![]));
        // Slots in address order: the call continuation at 8 is slot 1, f at 16 is slot 2.
        assert_eq!(m.jump_table, vec![None, Some(1), Some(2)]);
        assert_eq!(
            m.blocks[0],
            vec![Instruction::Call {
                rd: Reg::RA,
                block: 2,
                slot: 1
            }]
        );
        // li a0, slot_address(16) - lo(8) = 8, then addi adds 8 -> slot address 16.
        assert_eq!(
            m.blocks[1][0],
            Instruction::Li {
                rd: Reg::A0,
                imm: 8
            }
        );
        assert_eq!(
            m.blocks[1][1],
            Instruction::AluImm {
                op: AluImmOp::Addi,
                rd: Reg::A0,
                rs1: Reg::A0,
                imm: 8
            }
        );
        // A pair whose target falls outside the text is still unpaired.
        let words = [auipc(1, 0), jalr(1, 1, 0x100), RET];
        assert_eq!(
            recompile(&input(&words, vec![], vec![]), &Options::default()),
            Err(RecompileError::UnpairedAuipc { address: TEXT })
        );
        // An auipc followed by something else stays unpaired.
        let words = [auipc(5, 0), enc_b(0, 0, 0, 4), RET];
        assert_eq!(
            recompile(&input(&words, vec![], vec![]), &Options::default()),
            Err(RecompileError::UnpairedAuipc { address: TEXT })
        );
        // A trailing auipc with nothing after it is unpaired too.
        let words = [RET, auipc(5, 0)];
        assert_eq!(
            recompile(&input(&words, vec![], vec![]), &Options::default()),
            Err(RecompileError::UnpairedAuipc { address: TEXT + 4 })
        );
        // So is one whose register feeds anything but an addi.
        let words = [auipc(10, 0), enc_r(0x33, 0, 0, 11, 10, 10), RET];
        assert_eq!(
            recompile(&input(&words, vec![], vec![]), &Options::default()),
            Err(RecompileError::UnpairedAuipc { address: TEXT })
        );
        // Two addis must agree on the low part.
        let words = [auipc(10, 0), addi(11, 10, 8), addi(12, 10, 12), RET];
        assert_eq!(
            recompile(&input(&words, vec![], vec![]), &Options::default()),
            Err(RecompileError::UnpairedAuipc { address: TEXT })
        );
        // The scan stops after the window even without a branch or an overwrite: the
        // agreeing addis inside it pair the auipc, so the module builds.
        let mut words = vec![auipc(10, 0), addi(11, 10, 8), addi(12, 10, 8)];
        words.extend([addi(0, 0, 0); LOCAL_PAIR_WINDOW]);
        words.push(RET);
        assert!(recompile(&input(&words, vec![], vec![]), &Options::default()).is_ok());
    }

    #[test]
    fn register_use_of_every_instruction_kind() {
        // The straight-line scan behind relocation-less pairs needs, for every instruction,
        // the register it writes, the registers it reads, and whether it ends the run. Pinned
        // here rather than left to whatever patterns the guest fixtures happen to contain.
        let x = |i| Some(r(i));
        let cases = [
            (lui(5, 0x1000), (x(5), [None, None], false)),
            (auipc(5, 0x1000), (x(5), [None, None], false)),
            (jal(1, 8), (x(1), [None, None], true)),
            (jalr(1, 6, 0), (x(1), [x(6), None], true)),
            (enc_b(0, 6, 7, 8), (None, [x(6), x(7)], true)),
            (enc_i(0x03, 3, 5, 6, 0), (x(5), [x(6), None], false)),
            (addi(5, 6, 1), (x(5), [x(6), None], false)),
            (amo(0b00010, 3, 5, 6, 0), (x(5), [x(6), None], false)),
            (enc_s(0x23, 3, 6, 7, 0), (None, [x(6), x(7)], false)),
            (enc_r(0x33, 0, 0, 5, 6, 7), (x(5), [x(6), x(7)], false)),
            (amo(0b00011, 3, 5, 6, 7), (x(5), [x(6), x(7)], false)),
            (amo(0b00000, 3, 5, 6, 7), (x(5), [x(6), x(7)], false)),
            (FENCE, (None, [None, None], false)),
            (ECALL, (None, [None, None], true)),
            (EBREAK, (None, [None, None], true)),
            (UNIMP, (None, [None, None], true)),
        ];
        for (word, expected) in cases {
            let rv = crate::riscv::decode(word).unwrap();
            assert_eq!(registers(&rv), expected, "{word:#010x}");
        }
    }

    #[test]
    fn local_pair_scan_reads_every_instruction_kind() {
        // After a relocation-less `auipc a0`, the scan passes a lui, a store, an ALU
        // op, an atomic, a store-conditional and a fence that leave a0 alone, takes the
        // two addis that read it with the same offset, and stops at the jump: a1 and a2
        // become code pointers to the `ret` at 40.
        let words = [
            auipc(10, 0),
            lui(16, 1),
            enc_s(0x23, 2, 12, 11, 0),
            enc_r(0x33, 0, 0, 13, 14, 15),
            amo(0, 2, 13, 14, 15),
            amo(3, 2, 13, 14, 15),
            FENCE,
            addi(11, 10, 40),
            addi(12, 10, 40),
            jal(0, 4),
            RET,
        ];
        let m = module_of(&input(&words, vec![], vec![]));
        assert_eq!(m.jump_table, vec![None, Some(1)]);
        assert_eq!(
            m.blocks[0][0],
            Instruction::Li {
                rd: Reg::A0,
                imm: 8 - 40
            }
        );
        // A trap ends the straight-line run as a jump does.
        let words = [auipc(10, 0), addi(11, 10, 12), UNIMP, RET];
        let m = module_of(&input(&words, vec![], vec![]));
        assert_eq!(m.jump_table, vec![None, Some(1)]);
        // Any other read of a0 before it is overwritten leaves the auipc unpaired.
        let words = [auipc(10, 0), enc_r(0x33, 0, 0, 11, 10, 10), RET];
        assert_eq!(
            recompile(&input(&words, vec![], vec![]), &Options::default()),
            Err(RecompileError::UnpairedAuipc { address: TEXT })
        );
    }

    #[test]
    fn debug_map_lists_block_addresses() {
        let words = [enc_b(0, 0, 0, 8), addi(10, 10, 1), RET];
        let inp = input(&words, vec![], vec![]);
        let plain = recompile(&inp, &Options::default()).unwrap();
        assert!(Module::parse(&plain, &|_| true).unwrap().debug.is_none());
        let with_map = recompile(
            &inp,
            &Options {
                debug_map: true,
                ..Options::default()
            },
        )
        .unwrap();
        let module = Module::parse(&with_map, &|_| true).unwrap();
        let map = debug_map(&module.debug.expect("debug section"));
        assert_eq!(map, vec![TEXT, TEXT + 4, TEXT + 8]);
        assert_eq!(map.len(), module.blocks.len());
    }

    #[test]
    fn tail_calls_to_stubs_return() {
        // 0: j import stub (12) ; 4: j sbrk stub (16) ; 8: ret ; 12: import stub ; 16: sbrk stub
        let words = [jal(0, 12), jal(0, 12), RET, UNIMP, UNIMP];
        let syms = vec![
            func("__solo_import_output_write", 12),
            func("__solo_sbrk", 16),
        ];
        let m = module_of(&input(&words, syms, vec![]));
        let ret = Instruction::JumpIndirect {
            rs1: Reg::RA,
            off: 0,
        };
        assert_eq!(m.blocks[0], vec![Instruction::Ecall { import: 0 }, ret]);
        assert_eq!(
            m.blocks[1],
            vec![
                Instruction::Sbrk {
                    rd: Reg::A0,
                    rs1: Reg::A0
                },
                ret
            ]
        );
        assert_eq!(m.blocks[2], vec![ret]);
    }
}
