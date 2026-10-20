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
}

impl Default for Options {
    fn default() -> Self {
        Options {
            heap_max: 16 << 20,
            stack_size: 1 << 20,
            stack_top: 0xFFFF_0000,
        }
    }
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
    fn direct(&self, rd: Reg, target: u64, after: u64) -> Result<Vec<Instruction>, RecompileError> {
        Ok(match self.stubs.get(&target) {
            Some(Stub::Import(name)) => vec![Instruction::Ecall {
                import: self.import_index(name),
            }],
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
    fn translate_constant(&self, i: usize) -> Result<(Vec<Instruction>, bool), RecompileError> {
        let d = &self.insns[i];
        let a = d.address;
        let out = match d.rv {
            Rv::Lui { rd, imm } => match self.facts.lui_code.get(&a) {
                Some(t) => {
                    let lo = (*t as i64).wrapping_sub(imm);
                    vec![Instruction::Li {
                        rd,
                        imm: self.slot_address(*t)?.wrapping_sub(lo),
                    }]
                }
                None => vec![Instruction::Li { rd, imm }],
            },
            Rv::Auipc { rd, imm } => {
                if let Some(t) = self.facts.call_pair.get(&a) {
                    let jalr = &self.insns[i + 1];
                    let Rv::Jalr { rd: link, .. } = jalr.rv else {
                        unreachable!("checked in collect_facts")
                    };
                    return Ok((self.direct(link, *t, jalr.address + jalr.len as u64)?, true));
                }
                let (t, code) = *self
                    .facts
                    .hi
                    .get(&a)
                    .ok_or(RecompileError::UnpairedAuipc { address: a })?;
                let pc_value = (a as i64).wrapping_add(imm);
                if code && !self.stubs.contains_key(&t) {
                    let lo = (t as i64).wrapping_sub(pc_value);
                    vec![Instruction::Li {
                        rd,
                        imm: self.slot_address(t)?.wrapping_sub(lo),
                    }]
                } else {
                    vec![Instruction::Li { rd, imm: pc_value }]
                }
            }
            _ => unreachable!("only called for lui and auipc"),
        };
        Ok((out, false))
    }

    #[allow(clippy::cast_possible_wrap)]
    fn translate_one(&self, i: usize) -> Result<(Vec<Instruction>, bool), RecompileError> {
        let d = &self.insns[i];
        let a = d.address;
        let next = a + d.len as u64;
        let out = match d.rv {
            Rv::Lui { .. } | Rv::Auipc { .. } => return self.translate_constant(i),
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
    if rd == rs1 || rd == rs2 {
        return None;
    }
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
        let off = usize::try_from(r.offset)
            .map_err(|_| RecompileError::DataRelocOutOfRange { address })?;
        let field = bytes
            .get_mut(off..off + width)
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
    let bytes = b.build();
    Module::parse(&bytes, &|_| true).map_err(RecompileError::Validation)?;
    Ok(bytes)
}
