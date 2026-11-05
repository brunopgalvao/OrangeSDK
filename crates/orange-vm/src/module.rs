//! Module parsing and validation (spec 03).

use alloc::string::String;
use alloc::vec::Vec;

use crate::gas::CostTable;
use crate::isa::{DecodeError, Instruction};
use crate::leb128::{LebError, read_uleb};
use crate::memory::{LayoutError, MemoryLayout};

/// The header magic, ASCII `ORNG`.
pub const MAGIC: [u8; 4] = *b"ORNG";
/// Memory layout section id.
pub const SECTION_LAYOUT: u8 = 1;
/// Read-only data section id.
pub const SECTION_RODATA: u8 = 2;
/// Data section id.
pub const SECTION_DATA: u8 = 3;
/// Imports section id.
pub const SECTION_IMPORTS: u8 = 4;
/// Exports section id.
pub const SECTION_EXPORTS: u8 = 5;
/// Jump table section id.
pub const SECTION_JUMP_TABLE: u8 = 6;
/// Code section id.
pub const SECTION_CODE: u8 = 7;
/// Debug section id, ignored by consensus.
pub const SECTION_DEBUG: u8 = 0x7F;
/// Maximum code section payload and base module size (spec 01 §9).
pub const MAX_CODE_BYTES: usize = 16 << 20;
/// Maximum number of basic blocks (spec 01 §9).
pub const MAX_BLOCKS: u32 = 1 << 24;
/// Maximum jump-table slots (spec 01 §9).
pub const MAX_SLOTS: u32 = 1 << 20;
/// Maximum import or export name length.
pub const MAX_NAME_LEN: u32 = 64;

/// A validated module (spec 03), before cost computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    /// Memory layout.
    pub layout: MemoryLayout,
    /// Read-only data.
    pub rodata: Vec<u8>,
    /// Initialised data.
    pub data: Vec<u8>,
    /// Import names in table order.
    pub imports: Vec<String>,
    /// Exports as `(name, block)`.
    pub exports: Vec<(String, u32)>,
    /// Jump table; `None` is an empty slot.
    pub jump_table: Vec<Option<u32>>,
    /// Basic blocks.
    pub blocks: Vec<Vec<Instruction>>,
    /// Debug payload, if any.
    pub debug: Option<Vec<u8>>,
}

/// Why a module was rejected. Each variant names the rule in spec 03 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    /// Rule 1: bad magic.
    BadMagic,
    /// Rule 1: unsupported spec version.
    UnsupportedVersion,
    /// Rule 1: header flags not zero.
    FlagsNotZero,
    /// Rule 1: the module is shorter than a header.
    TruncatedHeader,
    /// Rule 2: section ids not strictly increasing.
    SectionOrder,
    /// Rule 2: an id outside the known set.
    UnknownSection(u8),
    /// Rule 2: a section length that is malformed or runs past the end.
    SectionLength,
    /// Rule 3: a required section is missing.
    MissingSection(u8),
    /// Rule 4: the module or its code is too large.
    TooLarge,
    /// Rule 5, 6, 8: memory layout violation.
    Layout(LayoutError),
    /// Rule 7: section 2 or 3 length disagrees with the layout.
    DataSizeMismatch,
    /// Rule 9: an import or export name is malformed.
    BadName,
    /// Rule 9: a duplicate import or export name.
    DuplicateName,
    /// Rule 9: an import the host does not provide for this capability set.
    UnresolvedImport,
    /// Rule 10: jump table shape.
    JumpTable,
    /// Rule 10: a slot names a block that does not exist.
    SlotBlockOutOfRange,
    /// Rule 11: block count out of range or an empty block.
    BlockCount,
    /// Rule 12: an instruction failed to decode, in the given block. A block
    /// whose bytes are not exactly consumed surfaces as a truncated decode.
    Decode(u32, DecodeError),
    /// Rule 13: a block-ending instruction that is not last.
    TerminatorNotLast,
    /// Rule 13: the final block falls through.
    FinalBlockFallsThrough,
    /// Rule 14: a block operand out of range.
    BlockOutOfRange,
    /// Rule 14: a slot operand naming an empty or absent slot.
    BadSlot,
    /// Rule 14: a call's continuation slot does not name the next block.
    CallSlotMismatch,
    /// Rule 15: an import operand out of range.
    ImportOutOfRange,
    /// Rule 16: an export block out of range.
    ExportBlockOutOfRange,
    /// A malformed LEB128 in a section body (rules 2, 5, 9–11).
    Leb(LebError),
    /// A section body shorter than its contents require.
    Truncated,
}

impl From<LebError> for ValidationError {
    fn from(e: LebError) -> Self {
        ValidationError::Leb(e)
    }
}

impl From<LayoutError> for ValidationError {
    fn from(e: LayoutError) -> Self {
        ValidationError::Layout(e)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn uleb(&mut self) -> Result<u32, ValidationError> {
        let (v, n) = read_uleb(&self.bytes[self.pos..])?;
        self.pos += n;
        Ok(v)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ValidationError> {
        let end = self.pos.checked_add(n).ok_or(ValidationError::Truncated)?;
        let s = self
            .bytes
            .get(self.pos..end)
            .ok_or(ValidationError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn u32_le(&mut self) -> Result<u32, ValidationError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn done(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

fn name_ok(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN as usize
        && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

fn read_name(r: &mut Reader<'_>) -> Result<String, ValidationError> {
    let len = r.uleb()?;
    let bytes = r.take(len as usize)?;
    if !name_ok(bytes) {
        return Err(ValidationError::BadName);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| ValidationError::BadName)
}

struct Sections<'a> {
    layout: Option<&'a [u8]>,
    rodata: &'a [u8],
    data: &'a [u8],
    imports: Option<&'a [u8]>,
    exports: Option<&'a [u8]>,
    jump_table: Option<&'a [u8]>,
    code: Option<&'a [u8]>,
    debug: Option<&'a [u8]>,
}

fn split_sections(bytes: &[u8]) -> Result<Sections<'_>, ValidationError> {
    let mut s = Sections {
        layout: None,
        rodata: &[],
        data: &[],
        imports: None,
        exports: None,
        jump_table: None,
        code: None,
        debug: None,
    };
    let mut r = Reader { bytes, pos: 8 };
    let mut last_id: Option<u8> = None;
    while !r.done() {
        let id = r.take(1)?[0];
        if let Some(prev) = last_id
            && id <= prev
        {
            return Err(ValidationError::SectionOrder);
        }
        last_id = Some(id);
        let len = r.uleb().map_err(|_| ValidationError::SectionLength)?;
        let payload = r
            .take(len as usize)
            .map_err(|_| ValidationError::SectionLength)?;
        match id {
            SECTION_LAYOUT => s.layout = Some(payload),
            SECTION_RODATA => s.rodata = payload,
            SECTION_DATA => s.data = payload,
            SECTION_IMPORTS => s.imports = Some(payload),
            SECTION_EXPORTS => s.exports = Some(payload),
            SECTION_JUMP_TABLE => s.jump_table = Some(payload),
            SECTION_CODE => s.code = Some(payload),
            SECTION_DEBUG => s.debug = Some(payload),
            other => return Err(ValidationError::UnknownSection(other)),
        }
    }
    Ok(s)
}

fn parse_header(bytes: &[u8]) -> Result<(), ValidationError> {
    if bytes.len() < 8 {
        return Err(ValidationError::TruncatedHeader);
    }
    if bytes[..4] != MAGIC {
        return Err(ValidationError::BadMagic);
    }
    if bytes[4] != crate::SPEC_VERSION.0 || bytes[5] > crate::SPEC_VERSION.1 {
        return Err(ValidationError::UnsupportedVersion);
    }
    if bytes[6] != 0 || bytes[7] != 0 {
        return Err(ValidationError::FlagsNotZero);
    }
    Ok(())
}

fn parse_layout(payload: &[u8]) -> Result<MemoryLayout, ValidationError> {
    let mut r = Reader {
        bytes: payload,
        pos: 0,
    };
    let mut v = [0u32; 9];
    for slot in &mut v {
        *slot = r.u32_le()?;
    }
    if !r.done() {
        return Err(ValidationError::SectionLength);
    }
    let layout = MemoryLayout {
        ro_base: v[0],
        ro_size: v[1],
        rw_base: v[2],
        data_size: v[3],
        bss_size: v[4],
        heap_base: v[5],
        heap_max: v[6],
        stack_base: v[7],
        stack_top: v[8],
    };
    layout.validate()?;
    Ok(layout)
}

fn parse_names(
    payload: Option<&[u8]>,
    with_block: bool,
) -> Result<Vec<(String, u32)>, ValidationError> {
    let Some(payload) = payload else {
        return Ok(Vec::new());
    };
    let mut r = Reader {
        bytes: payload,
        pos: 0,
    };
    let count = r.uleb()?;
    let mut out: Vec<(String, u32)> = Vec::new();
    for _ in 0..count {
        let name = read_name(&mut r)?;
        let block = if with_block { r.uleb()? } else { 0 };
        if out.iter().any(|(n, _)| *n == name) {
            return Err(ValidationError::DuplicateName);
        }
        out.push((name, block));
    }
    if !r.done() {
        return Err(ValidationError::SectionLength);
    }
    Ok(out)
}

fn parse_jump_table(payload: &[u8]) -> Result<Vec<Option<u32>>, ValidationError> {
    let mut r = Reader {
        bytes: payload,
        pos: 0,
    };
    let count = r.uleb()?;
    if count == 0 || count > MAX_SLOTS {
        return Err(ValidationError::JumpTable);
    }
    // Every slot takes at least one byte, so the bytes left bound the count
    // worth reserving: a count prefix alone must not reserve memory.
    let mut table = Vec::with_capacity((count as usize).min(payload.len() - r.pos));
    for _ in 0..count {
        let v = r.uleb()?;
        table.push(if v == 0 { None } else { Some(v - 1) });
    }
    if !r.done() {
        return Err(ValidationError::SectionLength);
    }
    if table[0].is_some() {
        return Err(ValidationError::JumpTable);
    }
    Ok(table)
}

fn parse_code(payload: &[u8]) -> Result<Vec<Vec<Instruction>>, ValidationError> {
    // The code payload cannot exceed MAX_CODE_BYTES here: the whole-module size
    // check in `Module::parse` already bounds it.
    let mut r = Reader {
        bytes: payload,
        pos: 0,
    };
    let count = r.uleb()?;
    if count == 0 || count > MAX_BLOCKS {
        return Err(ValidationError::BlockCount);
    }
    // Every block takes at least two bytes (a length and an instruction), so
    // the bytes left bound the count worth reserving: a count prefix alone,
    // up to 2^24 blocks of 24 bytes each, must not reserve 384 MiB.
    let mut blocks = Vec::with_capacity((count as usize).min((payload.len() - r.pos) / 2));
    for index in 0..count {
        let len = r.uleb()?;
        if len == 0 {
            return Err(ValidationError::BlockCount);
        }
        let body = r.take(len as usize)?;
        blocks.push(decode_block(index, body)?);
    }
    if !r.done() {
        return Err(ValidationError::SectionLength);
    }
    Ok(blocks)
}

fn decode_block(index: u32, body: &[u8]) -> Result<Vec<Instruction>, ValidationError> {
    let mut instructions = Vec::new();
    let mut pos = 0;
    while pos < body.len() {
        let (ins, n) = Instruction::decode(&body[pos..]).map_err(|mut e| {
            e.offset += pos;
            ValidationError::Decode(index, e)
        })?;
        pos += n;
        if ins.ends_block() && pos < body.len() {
            return Err(ValidationError::TerminatorNotLast);
        }
        instructions.push(ins);
    }
    debug_assert_eq!(pos, body.len(), "decode consumed exactly the block");
    Ok(instructions)
}

fn check_operands(module: &Module) -> Result<(), ValidationError> {
    let block_count =
        u32::try_from(module.blocks.len()).map_err(|_| ValidationError::BlockCount)?;
    let import_count =
        u32::try_from(module.imports.len()).map_err(|_| ValidationError::ImportOutOfRange)?;
    let slot_target = |slot: u32| module.jump_table.get(slot as usize).copied().flatten();
    for (i, block) in module.blocks.iter().enumerate() {
        let next = u32::try_from(i + 1).map_err(|_| ValidationError::BlockCount)?;
        for ins in block {
            let (target, continuation, import) = match *ins {
                Instruction::Jump { block } | Instruction::Branch { block, .. } => {
                    (Some(block), None, None)
                }
                Instruction::Call { block, slot, .. } => (Some(block), Some(slot), None),
                Instruction::CallIndirect { slot, .. } => (None, Some(slot), None),
                Instruction::Ecall { import } => (None, None, Some(import)),
                _ => (None, None, None),
            };
            if target.is_some_and(|b| b >= block_count) {
                return Err(ValidationError::BlockOutOfRange);
            }
            if let Some(slot) = continuation {
                match slot_target(slot) {
                    None => return Err(ValidationError::BadSlot),
                    Some(b) if b != next => return Err(ValidationError::CallSlotMismatch),
                    Some(_) => {}
                }
            }
            if import.is_some_and(|i| i >= import_count) {
                return Err(ValidationError::ImportOutOfRange);
            }
        }
    }
    let last = module.blocks.last().expect("block count checked");
    if last.last().is_none_or(Instruction::falls_through) {
        return Err(ValidationError::FinalBlockFallsThrough);
    }
    if module
        .exports
        .iter()
        .any(|(_, block)| *block >= block_count)
    {
        return Err(ValidationError::ExportBlockOutOfRange);
    }
    if module
        .jump_table
        .iter()
        .flatten()
        .any(|b| *b >= block_count)
    {
        return Err(ValidationError::SlotBlockOutOfRange);
    }
    Ok(())
}

impl Module {
    /// Parses and validates a module against every rule of spec 03 §7 except
    /// rule 17 (cost), which [`Program::new`] applies. `import_available`
    /// answers rule 9 for the host and capability set the module will run under.
    ///
    /// # Errors
    /// The first rule violated, as a [`ValidationError`].
    pub fn parse(
        bytes: &[u8],
        import_available: &dyn Fn(&str) -> bool,
    ) -> Result<Module, ValidationError> {
        parse_header(bytes)?;
        let sections = split_sections(bytes)?;
        let layout_bytes = sections
            .layout
            .ok_or(ValidationError::MissingSection(SECTION_LAYOUT))?;
        let jump_bytes = sections
            .jump_table
            .ok_or(ValidationError::MissingSection(SECTION_JUMP_TABLE))?;
        let code_bytes = sections
            .code
            .ok_or(ValidationError::MissingSection(SECTION_CODE))?;
        if bytes.len() > MAX_CODE_BYTES + sections.rodata.len() + sections.data.len() {
            return Err(ValidationError::TooLarge);
        }
        let layout = parse_layout(layout_bytes)?;
        if sections.rodata.len() != layout.ro_size as usize
            || sections.data.len() != layout.data_size as usize
        {
            return Err(ValidationError::DataSizeMismatch);
        }
        let imports: Vec<String> = parse_names(sections.imports, false)?
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        if imports.iter().any(|n| !import_available(n)) {
            return Err(ValidationError::UnresolvedImport);
        }
        let exports = parse_names(sections.exports, true)?;
        let jump_table = parse_jump_table(jump_bytes)?;
        let blocks = parse_code(code_bytes)?;
        let module = Module {
            layout,
            rodata: sections.rodata.to_vec(),
            data: sections.data.to_vec(),
            imports,
            exports,
            jump_table,
            blocks,
            debug: sections.debug.map(<[u8]>::to_vec),
        };
        check_operands(&module)?;
        Ok(module)
    }

    /// The block an export names, if present.
    #[must_use]
    pub fn export(&self, name: &str) -> Option<u32> {
        self.exports
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, b)| *b)
    }

    /// Re-checks a module held in memory against the rules of spec 03 §7
    /// that concern its content rather than its bytes: 5–8 (layout and data
    /// sizes), 9 (name shape and uniqueness, not host resolution), 10, 11,
    /// the shift ranges of 12, and 13–16. [`Module::parse`] already applies
    /// all of them; this is for modules assembled or edited in memory before
    /// a backend that relies on them, such as a native compiler, runs them.
    ///
    /// # Errors
    /// The first rule violated, as a [`ValidationError`].
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.layout.validate()?;
        if self.rodata.len() != self.layout.ro_size as usize
            || self.data.len() != self.layout.data_size as usize
        {
            return Err(ValidationError::DataSizeMismatch);
        }
        let names = self
            .imports
            .iter()
            .map(String::as_str)
            .chain(self.exports.iter().map(|(n, _)| n.as_str()));
        if names.clone().any(|n| !name_ok(n.as_bytes())) {
            return Err(ValidationError::BadName);
        }
        let unique = |list: &mut dyn Iterator<Item = &str>| {
            let mut seen = alloc::collections::BTreeSet::new();
            let mut all = true;
            for n in list {
                all &= seen.insert(n);
            }
            all
        };
        if !unique(&mut self.imports.iter().map(String::as_str))
            || !unique(&mut self.exports.iter().map(|(n, _)| n.as_str()))
        {
            return Err(ValidationError::DuplicateName);
        }
        if self.jump_table.is_empty()
            || self.jump_table.len() > MAX_SLOTS as usize
            || self.jump_table[0].is_some()
        {
            return Err(ValidationError::JumpTable);
        }
        if self.blocks.is_empty()
            || self.blocks.len() > MAX_BLOCKS as usize
            || self.blocks.iter().any(Vec::is_empty)
        {
            return Err(ValidationError::BlockCount);
        }
        for (index, block) in self.blocks.iter().enumerate() {
            let last = block.len() - 1;
            for (i, ins) in block.iter().enumerate() {
                if let Instruction::AluImm { op, imm, .. } = ins
                    && op
                        .shift_limit()
                        .is_some_and(|limit| !(0..=limit).contains(imm))
                {
                    let mut before = Vec::new();
                    for earlier in &block[..i] {
                        earlier.encode(&mut before);
                    }
                    let error = DecodeError {
                        kind: crate::isa::DecodeErrorKind::ShiftOutOfRange,
                        offset: before.len(),
                    };
                    let index = u32::try_from(index).unwrap_or(u32::MAX);
                    return Err(ValidationError::Decode(index, error));
                }
                if ins.ends_block() && i != last {
                    return Err(ValidationError::TerminatorNotLast);
                }
            }
        }
        check_operands(self)
    }
}

/// A validated module with its per-block static costs under one cost table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    /// The module.
    pub module: Module,
    /// Static cost of each block (spec 04 §2).
    pub block_costs: Vec<u64>,
    /// The table the costs were computed from.
    pub cost_table: CostTable,
}

impl Program {
    /// Records every block's static cost under `cost_table` (spec 04 §2).
    ///
    /// Rule 17 of spec 03 §7 (costs fit a signed 64-bit integer) holds for every
    /// module that passes the size limits: 16 MiB of code at the dearest cost
    /// per byte sums to well under 2^40, so no check is needed here.
    ///
    /// # Panics
    /// Never for a module produced by [`Module::parse`]; see above.
    #[must_use]
    pub fn new(module: Module, cost_table: CostTable) -> Program {
        let block_costs = module
            .blocks
            .iter()
            .map(|block| {
                cost_table
                    .block_cost(block)
                    .expect("rule 17 holds under the size limits")
            })
            .collect();
        Program {
            module,
            block_costs,
            cost_table,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::ModuleBuilder;
    use crate::isa::{AluImmOp, Cond, DecodeErrorKind, Reg};
    use alloc::string::ToString;
    use alloc::vec;

    fn any_import(_: &str) -> bool {
        true
    }

    fn valid() -> ModuleBuilder {
        let mut b = ModuleBuilder::new();
        b.block(&[Instruction::Halt]);
        b.export("main", 0)
    }

    fn parse(b: &ModuleBuilder) -> Result<Module, ValidationError> {
        Module::parse(&b.build(), &any_import)
    }

    fn reject(b: &ModuleBuilder, expected: ValidationError) {
        assert_eq!(parse(b), Err(expected));
    }

    #[test]
    fn minimal_module_parses() {
        let m = parse(&valid()).unwrap();
        assert_eq!(m.blocks, vec![vec![Instruction::Halt]]);
        assert_eq!(m.export("main"), Some(0));
        assert_eq!(m.export("other"), None);
        assert_eq!(m.jump_table, vec![None]);
        assert!(m.imports.is_empty());
        assert!(m.debug.is_none());
        let p = Program::new(m.clone(), CostTable::V1);
        assert_eq!(p.block_costs, vec![1]);
        assert_eq!(p.cost_table, CostTable::V1);
        assert_eq!(p.module, m);
    }

    #[test]
    fn full_module_roundtrips() {
        let mut b = ModuleBuilder::new().rodata(&[1, 2, 3]).data(&[4, 5]);
        b.layout.bss_size = 10;
        let imp = b.import("storage_get");
        let r = |i| Reg::new(i).unwrap();
        // Block 0 calls block 2 with continuation slot naming block 1.
        let s1 = b.slot(1);
        b.block(&[Instruction::Call {
            rd: Reg::RA,
            block: 2,
            slot: s1,
        }]);
        b.block(&[Instruction::Ecall { import: imp }, Instruction::Halt]);
        b.block(&[
            Instruction::AluImm {
                op: AluImmOp::Addi,
                rd: r(10),
                rs1: r(10),
                imm: 1,
            },
            Instruction::JumpIndirect {
                rs1: Reg::RA,
                off: 0,
            },
        ]);
        b.debug = Some(vec![0xDE, 0xAD]);
        let b = b.export("main", 0).export("helper", 2);
        let m = parse(&b).unwrap();
        assert_eq!(m.rodata, vec![1, 2, 3]);
        assert_eq!(m.data, vec![4, 5]);
        assert_eq!(m.layout.bss_size, 10);
        assert_eq!(m.imports, vec!["storage_get".to_string()]);
        assert_eq!(m.exports.len(), 2);
        assert_eq!(m.jump_table, vec![None, Some(1)]);
        assert_eq!(m.blocks.len(), 3);
        assert_eq!(m.debug, Some(vec![0xDE, 0xAD]));
        let p = Program::new(m, CostTable::V1);
        assert_eq!(p.block_costs, vec![2, 11, 5]);
    }

    #[test]
    fn header_rules() {
        let b = valid();
        let bytes = b.build();
        assert_eq!(
            Module::parse(&bytes[..7], &any_import),
            Err(ValidationError::TruncatedHeader)
        );
        let mut bad = b.clone();
        bad.header[0] = b'X';
        reject(&bad, ValidationError::BadMagic);
        let mut bad = b.clone();
        bad.header[4] = 1;
        reject(&bad, ValidationError::UnsupportedVersion);
        let mut bad = b.clone();
        bad.header[5] = 2;
        reject(&bad, ValidationError::UnsupportedVersion);
        let mut bad = b.clone();
        bad.header[7] = 1;
        reject(&bad, ValidationError::FlagsNotZero);
        let mut ok = b;
        ok.header[5] = 0; // an earlier minor is accepted
        assert!(parse(&ok).is_ok());
    }

    #[test]
    fn section_rules() {
        let mut bad = valid();
        bad.extra_sections.push((SECTION_LAYOUT, vec![]));
        reject(&bad, ValidationError::SectionOrder);
        let mut bad = valid();
        bad.extra_sections.push((SECTION_CODE, vec![]));
        reject(&bad, ValidationError::SectionOrder);
        let mut bad = valid();
        bad.extra_sections.push((9, vec![]));
        reject(&bad, ValidationError::UnknownSection(9));
        let mut bad = valid();
        bad.trailing = vec![SECTION_DEBUG, 0x05, 0x00];
        reject(&bad, ValidationError::SectionLength);
        let mut bad = valid();
        bad.trailing = vec![SECTION_DEBUG, 0x80, 0x00];
        reject(&bad, ValidationError::SectionLength);
        let mut bad = valid();
        bad.trailing = vec![SECTION_DEBUG];
        reject(&bad, ValidationError::SectionLength);
        for id in [SECTION_LAYOUT, SECTION_JUMP_TABLE, SECTION_CODE] {
            let mut bad = valid();
            bad.omit.insert(id);
            reject(&bad, ValidationError::MissingSection(id));
        }
    }

    #[test]
    fn size_limit() {
        let mut bad = valid();
        bad.raw_overrides
            .insert(SECTION_CODE, vec![0; MAX_CODE_BYTES + 1]);
        reject(&bad, ValidationError::TooLarge);
    }

    #[test]
    fn layout_rules() {
        let mut bad = valid();
        bad.layout.rw_base += 1;
        reject(&bad, ValidationError::Layout(LayoutError::Misaligned));
        let mut bad = valid();
        bad.raw_overrides.insert(SECTION_LAYOUT, vec![0; 35]);
        reject(&bad, ValidationError::Truncated);
        let mut bad = valid();
        bad.raw_overrides.insert(SECTION_LAYOUT, vec![0; 40]);
        reject(&bad, ValidationError::SectionLength);
        let mut bad = valid().rodata(&[1, 2]);
        bad.layout.ro_size = 3;
        reject(&bad, ValidationError::DataSizeMismatch);
        let mut bad = valid().data(&[1]);
        bad.layout.data_size = 0;
        reject(&bad, ValidationError::DataSizeMismatch);
    }

    #[test]
    fn name_rules() {
        for name in ["", "bad-name", "with space", "x".repeat(65).as_str()] {
            let mut bad = valid();
            bad.import(name);
            reject(&bad, ValidationError::BadName);
        }
        let mut ok = valid();
        ok.import("x".repeat(64).as_str());
        assert!(parse(&ok).is_ok());
        let mut bad = valid();
        bad.import("a");
        bad.import("a");
        reject(&bad, ValidationError::DuplicateName);
        let bad = valid().export("main", 0);
        reject(&bad, ValidationError::DuplicateName);
        let mut bad = valid();
        bad.import("missing");
        assert_eq!(
            Module::parse(&bad.build(), &|_| false),
            Err(ValidationError::UnresolvedImport)
        );
        // Malformed name tables.
        let mut bad = valid();
        bad.raw_overrides.insert(SECTION_IMPORTS, vec![0x80, 0x00]);
        reject(&bad, ValidationError::Leb(LebError::NonCanonical));
        let mut bad = valid();
        bad.raw_overrides
            .insert(SECTION_IMPORTS, vec![0x01, 0x05, b'a']);
        reject(&bad, ValidationError::Truncated);
        let mut bad = valid();
        bad.raw_overrides
            .insert(SECTION_IMPORTS, vec![0x01, 0x01, b'a', 0x00]);
        reject(&bad, ValidationError::SectionLength);
        let mut bad = valid();
        bad.raw_overrides
            .insert(SECTION_IMPORTS, vec![0x01, 0x01, 0xFF]);
        reject(&bad, ValidationError::BadName);
    }

    #[test]
    fn jump_table_rules() {
        let mut bad = valid();
        bad.jump_table = vec![];
        reject(&bad, ValidationError::JumpTable);
        let mut bad = valid();
        bad.jump_table = vec![Some(0)];
        reject(&bad, ValidationError::JumpTable);
        let mut bad = valid();
        bad.raw_overrides
            .insert(SECTION_JUMP_TABLE, vec![0x81, 0x80, 0x40]); // 2^20 + 1 slots
        reject(&bad, ValidationError::JumpTable);
        let mut bad = valid();
        bad.raw_overrides
            .insert(SECTION_JUMP_TABLE, vec![0x01, 0x00, 0x00]);
        reject(&bad, ValidationError::SectionLength);
        let mut bad = valid();
        bad.jump_table = vec![None, Some(5)];
        reject(&bad, ValidationError::SlotBlockOutOfRange);
    }

    #[test]
    fn code_rules() {
        let mut bad = valid();
        bad.blocks.clear();
        reject(&bad, ValidationError::BlockCount);
        let mut bad = valid();
        bad.raw_overrides
            .insert(SECTION_CODE, vec![0x81, 0x80, 0x80, 0x08, 0x01, 0x01]); // 2^24 + 1 blocks
        reject(&bad, ValidationError::BlockCount);
        let mut bad = valid();
        bad.blocks.push(vec![]);
        reject(&bad, ValidationError::BlockCount);
        let mut bad = valid();
        bad.raw_overrides
            .insert(SECTION_CODE, vec![0x01, 0x01, 0x06]);
        assert!(matches!(
            parse(&bad),
            Err(ValidationError::Decode(
                0,
                DecodeError {
                    kind: DecodeErrorKind::UnknownOpcode(0x06),
                    offset: 0
                }
            ))
        ));
        // A block whose declared length cuts an instruction: truncated decode at offset 1.
        let mut bad = valid();
        bad.raw_overrides
            .insert(SECTION_CODE, vec![0x01, 0x02, 0x10, 0x05]); // li a5 with no immediate
        assert!(matches!(
            parse(&bad),
            Err(ValidationError::Decode(
                0,
                DecodeError {
                    kind: DecodeErrorKind::Truncated,
                    offset: 2
                }
            ))
        ));
        let mut bad = valid();
        bad.raw_overrides
            .insert(SECTION_CODE, vec![0x01, 0x01, 0x01, 0x00]); // trailing byte after the block
        reject(&bad, ValidationError::SectionLength);
        let mut bad = valid();
        bad.raw_overrides
            .insert(SECTION_CODE, vec![0x01, 0x05, 0x01]); // block length past the end
        reject(&bad, ValidationError::Truncated);
        let mut bad = ModuleBuilder::new();
        bad.block(&[Instruction::Halt, Instruction::Halt]);
        reject(&bad, ValidationError::TerminatorNotLast);
        let mut bad = ModuleBuilder::new();
        bad.block(&[Instruction::Li {
            rd: Reg::A0,
            imm: 1,
        }]);
        reject(&bad, ValidationError::FinalBlockFallsThrough);
        let mut bad = ModuleBuilder::new();
        bad.block(&[Instruction::Branch {
            cond: Cond::Eq,
            rs1: Reg::ZERO,
            rs2: Reg::ZERO,
            block: 0,
        }]);
        reject(&bad, ValidationError::FinalBlockFallsThrough);
    }

    #[test]
    fn operand_rules() {
        let mut bad = ModuleBuilder::new();
        bad.block(&[Instruction::Jump { block: 5 }]);
        reject(&bad, ValidationError::BlockOutOfRange);
        let mut bad = ModuleBuilder::new();
        bad.block(&[Instruction::Branch {
            cond: Cond::Eq,
            rs1: Reg::ZERO,
            rs2: Reg::ZERO,
            block: 1,
        }]);
        bad.block(&[Instruction::Halt]);
        assert!(parse(&bad).is_ok());
        let mut bad = ModuleBuilder::new();
        bad.block(&[Instruction::Branch {
            cond: Cond::Eq,
            rs1: Reg::ZERO,
            rs2: Reg::ZERO,
            block: 2,
        }]);
        bad.block(&[Instruction::Halt]);
        reject(&bad, ValidationError::BlockOutOfRange);
        let mut bad = ModuleBuilder::new();
        bad.block(&[Instruction::Call {
            rd: Reg::RA,
            block: 9,
            slot: 0,
        }]);
        bad.block(&[Instruction::Halt]);
        reject(&bad, ValidationError::BlockOutOfRange);
        // Slot 0 is empty; slot 9 absent.
        for slot in [0, 9] {
            let mut bad = ModuleBuilder::new();
            bad.block(&[Instruction::Call {
                rd: Reg::RA,
                block: 1,
                slot,
            }]);
            bad.block(&[Instruction::Halt]);
            reject(&bad, ValidationError::BadSlot);
            let mut bad = ModuleBuilder::new();
            bad.block(&[Instruction::CallIndirect {
                rd: Reg::RA,
                rs1: Reg::A0,
                off: 0,
                slot,
            }]);
            bad.block(&[Instruction::Halt]);
            reject(&bad, ValidationError::BadSlot);
        }
        // Slot names the wrong block.
        let mut bad = ModuleBuilder::new();
        let s = bad.slot(0);
        bad.block(&[Instruction::Call {
            rd: Reg::RA,
            block: 1,
            slot: s,
        }]);
        bad.block(&[Instruction::Halt]);
        reject(&bad, ValidationError::CallSlotMismatch);
        let mut bad = ModuleBuilder::new();
        let s = bad.slot(0);
        bad.block(&[Instruction::CallIndirect {
            rd: Reg::RA,
            rs1: Reg::A0,
            off: 0,
            slot: s,
        }]);
        bad.block(&[Instruction::Halt]);
        reject(&bad, ValidationError::CallSlotMismatch);
        // Correct continuation passes for both call forms.
        let mut ok = ModuleBuilder::new();
        let s = ok.slot(1);
        ok.block(&[Instruction::CallIndirect {
            rd: Reg::RA,
            rs1: Reg::A0,
            off: 0,
            slot: s,
        }]);
        ok.block(&[Instruction::Halt]);
        assert!(parse(&ok).is_ok());
        let mut bad = ModuleBuilder::new();
        bad.block(&[Instruction::Ecall { import: 0 }, Instruction::Halt]);
        reject(&bad, ValidationError::ImportOutOfRange);
        let bad = valid().export("x", 3);
        reject(&bad, ValidationError::ExportBlockOutOfRange);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn validate_rechecks_modules_built_in_memory() {
        let mut b = ModuleBuilder::new().rodata(&[1]).data(&[2]);
        b.import("ok");
        let s = b.slot(1);
        b.block(&[Instruction::Call {
            rd: Reg::RA,
            block: 1,
            slot: s,
        }]);
        b.block(&[
            Instruction::AluImm {
                op: AluImmOp::Slli,
                rd: Reg::A0,
                rs1: Reg::A0,
                imm: 63,
            },
            Instruction::Ecall { import: 0 },
            Instruction::Halt,
        ]);
        let good = parse(&b.export("main", 0)).unwrap();
        assert_eq!(good.validate(), Ok(()));
        let check = |edit: &dyn Fn(&mut Module), expected: ValidationError| {
            let mut m = good.clone();
            edit(&mut m);
            assert_eq!(m.validate(), Err(expected));
        };
        check(
            &|m| m.layout.rw_base += 1,
            ValidationError::Layout(LayoutError::Misaligned),
        );
        check(&|m| m.rodata.push(0), ValidationError::DataSizeMismatch);
        check(&|m| m.data.clear(), ValidationError::DataSizeMismatch);
        check(
            &|m| m.imports[0] = "bad-name".to_string(),
            ValidationError::BadName,
        );
        check(
            &|m| m.exports[0].0 = String::new(),
            ValidationError::BadName,
        );
        check(
            &|m| m.imports.push("ok".to_string()),
            ValidationError::DuplicateName,
        );
        check(
            &|m| m.exports.push(("main".to_string(), 1)),
            ValidationError::DuplicateName,
        );
        check(&|m| m.jump_table.clear(), ValidationError::JumpTable);
        check(&|m| m.jump_table[0] = Some(0), ValidationError::JumpTable);
        check(
            &|m| m.jump_table.resize(MAX_SLOTS as usize + 1, None),
            ValidationError::JumpTable,
        );
        check(&|m| m.blocks.clear(), ValidationError::BlockCount);
        check(&|m| m.blocks.insert(1, vec![]), ValidationError::BlockCount);
        check(
            &|m| {
                m.blocks
                    .resize(MAX_BLOCKS as usize + 1, vec![Instruction::Halt]);
            },
            ValidationError::BlockCount,
        );
        check(
            &|m| {
                m.blocks[1][0] = Instruction::AluImm {
                    op: AluImmOp::Slliw,
                    rd: Reg::A0,
                    rs1: Reg::A0,
                    imm: 32,
                };
                m.blocks[1].insert(
                    0,
                    Instruction::Li {
                        rd: Reg::A1,
                        imm: 300,
                    },
                );
            },
            ValidationError::Decode(
                1,
                DecodeError {
                    kind: DecodeErrorKind::ShiftOutOfRange,
                    offset: 4,
                },
            ),
        );
        check(
            &|m| {
                m.blocks[1][0] = Instruction::AluImm {
                    op: AluImmOp::Srai,
                    rd: Reg::A0,
                    rs1: Reg::A0,
                    imm: -1,
                };
            },
            ValidationError::Decode(
                1,
                DecodeError {
                    kind: DecodeErrorKind::ShiftOutOfRange,
                    offset: 0,
                },
            ),
        );
        check(
            &|m| m.blocks[1].insert(0, Instruction::Trap),
            ValidationError::TerminatorNotLast,
        );
        check(
            &|m| m.blocks[1][1] = Instruction::Ecall { import: 7 },
            ValidationError::ImportOutOfRange,
        );
        check(
            &|m| {
                m.blocks[1].pop();
            },
            ValidationError::FinalBlockFallsThrough,
        );
    }

    #[test]
    fn error_conversions_and_debug() {
        assert_eq!(
            ValidationError::from(LebError::Overflow),
            ValidationError::Leb(LebError::Overflow)
        );
        assert_eq!(
            ValidationError::from(LayoutError::Order),
            ValidationError::Layout(LayoutError::Order)
        );
        assert!(alloc::format!("{:?}", ValidationError::BadMagic).contains("BadMagic"));
        let b = ModuleBuilder::default();
        assert_eq!(b.header[..4], MAGIC);
        assert!(alloc::format!("{b:?}").contains("ModuleBuilder"));
    }
}
