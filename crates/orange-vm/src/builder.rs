//! Assembles module byte strings (spec 03). Used by tests, the conformance
//! suite, and the recompiler. The builder does not validate; it writes exactly
//! what it is told so that invalid modules can be constructed on purpose.

#![allow(clippy::missing_panics_doc)] // sizes beyond u32 are programming errors in test tooling

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use crate::isa::Instruction;
use crate::leb128::write_uleb;
use crate::memory::MemoryLayout;
use crate::module::{
    MAGIC, SECTION_CODE, SECTION_DATA, SECTION_DEBUG, SECTION_EXPORTS, SECTION_IMPORTS,
    SECTION_JUMP_TABLE, SECTION_LAYOUT, SECTION_RODATA,
};

/// Builds module bytes field by field.
#[derive(Debug, Clone)]
pub struct ModuleBuilder {
    /// Header bytes; defaults to magic, version 0.1, flags 0.
    pub header: [u8; 8],
    /// Memory layout section values.
    pub layout: MemoryLayout,
    /// Read-only data.
    pub rodata: Vec<u8>,
    /// Initialised data.
    pub data: Vec<u8>,
    /// Import names in table order.
    pub imports: Vec<String>,
    /// Exports as `(name, block)`.
    pub exports: Vec<(String, u32)>,
    /// Jump table; `None` is an empty slot. Slot 0 should be `None`.
    pub jump_table: Vec<Option<u32>>,
    /// Basic blocks as instruction lists.
    pub blocks: Vec<Vec<Instruction>>,
    /// Optional debug section payload.
    pub debug: Option<Vec<u8>>,
    /// Section ids to leave out even if they have content.
    pub omit: BTreeSet<u8>,
    /// Raw payloads that replace the generated payload of a section id.
    pub raw_overrides: BTreeMap<u8, Vec<u8>>,
    /// Extra raw sections appended after the regular ones, in the order given.
    pub extra_sections: Vec<(u8, Vec<u8>)>,
    /// Bytes appended after the last section.
    pub trailing: Vec<u8>,
}

impl Default for ModuleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleBuilder {
    /// A builder with a small valid layout and no content.
    #[must_use]
    pub fn new() -> ModuleBuilder {
        let mut header = [0u8; 8];
        header[..4].copy_from_slice(&MAGIC);
        header[4] = crate::SPEC_VERSION.0;
        header[5] = crate::SPEC_VERSION.1;
        ModuleBuilder {
            header,
            layout: MemoryLayout {
                ro_base: 0x1_0000,
                ro_size: 0,
                rw_base: 0x2_0000,
                data_size: 0,
                bss_size: 0,
                heap_base: 0x3_0000,
                heap_max: 0x10_0000,
                stack_base: 0xFFFC_0000,
                stack_top: 0xFFFE_0000,
            },
            rodata: Vec::new(),
            data: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            jump_table: alloc::vec![None],
            blocks: Vec::new(),
            debug: None,
            omit: BTreeSet::new(),
            raw_overrides: BTreeMap::new(),
            extra_sections: Vec::new(),
            trailing: Vec::new(),
        }
    }

    /// Sets read-only data and `ro_size` together.
    #[must_use]
    pub fn rodata(mut self, bytes: &[u8]) -> Self {
        self.rodata = bytes.to_vec();
        self.layout.ro_size = u32::try_from(bytes.len()).expect("rodata fits u32");
        self
    }

    /// Sets initialised data and `data_size` together.
    #[must_use]
    pub fn data(mut self, bytes: &[u8]) -> Self {
        self.data = bytes.to_vec();
        self.layout.data_size = u32::try_from(bytes.len()).expect("data fits u32");
        self
    }

    /// Adds an import and returns its index.
    pub fn import(&mut self, name: &str) -> u32 {
        self.imports.push(String::from(name));
        u32::try_from(self.imports.len() - 1).expect("import count fits u32")
    }

    /// Adds an export.
    #[must_use]
    pub fn export(mut self, name: &str, block: u32) -> Self {
        self.exports.push((String::from(name), block));
        self
    }

    /// Adds a jump-table slot for `block` and returns the slot index.
    pub fn slot(&mut self, block: u32) -> u32 {
        self.jump_table.push(Some(block));
        u32::try_from(self.jump_table.len() - 1).expect("slot count fits u32")
    }

    /// Appends a block and returns its index.
    pub fn block(&mut self, instructions: &[Instruction]) -> u32 {
        self.blocks.push(instructions.to_vec());
        u32::try_from(self.blocks.len() - 1).expect("block count fits u32")
    }

    fn section(out: &mut Vec<u8>, id: u8, payload: &[u8]) {
        out.push(id);
        write_uleb(u32::try_from(payload.len()).expect("section fits u32"), out);
        out.extend_from_slice(payload);
    }

    fn names(entries: &[(String, Option<u32>)]) -> Vec<u8> {
        let mut p = Vec::new();
        write_uleb(
            u32::try_from(entries.len()).expect("count fits u32"),
            &mut p,
        );
        for (name, block) in entries {
            write_uleb(u32::try_from(name.len()).expect("name fits u32"), &mut p);
            p.extend_from_slice(name.as_bytes());
            if let Some(b) = block {
                write_uleb(*b, &mut p);
            }
        }
        p
    }

    /// The layout section payload.
    #[must_use]
    pub fn layout_bytes(&self) -> Vec<u8> {
        let l = &self.layout;
        let mut p = Vec::with_capacity(36);
        for v in [
            l.ro_base,
            l.ro_size,
            l.rw_base,
            l.data_size,
            l.bss_size,
            l.heap_base,
            l.heap_max,
            l.stack_base,
            l.stack_top,
        ] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        p
    }

    /// The jump-table section payload.
    #[must_use]
    pub fn jump_table_bytes(&self) -> Vec<u8> {
        let mut p = Vec::new();
        write_uleb(
            u32::try_from(self.jump_table.len()).expect("slots fit u32"),
            &mut p,
        );
        for slot in &self.jump_table {
            write_uleb(slot.map_or(0, |b| b + 1), &mut p);
        }
        p
    }

    /// The code section payload.
    #[must_use]
    pub fn code_bytes(&self) -> Vec<u8> {
        let mut p = Vec::new();
        write_uleb(
            u32::try_from(self.blocks.len()).expect("blocks fit u32"),
            &mut p,
        );
        for block in &self.blocks {
            let mut body = Vec::new();
            for ins in block {
                ins.encode(&mut body);
            }
            write_uleb(u32::try_from(body.len()).expect("block fits u32"), &mut p);
            p.extend_from_slice(&body);
        }
        p
    }

    /// Produces the module bytes.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.header);
        let imports: Vec<(String, Option<u32>)> =
            self.imports.iter().map(|n| (n.clone(), None)).collect();
        let exports: Vec<(String, Option<u32>)> = self
            .exports
            .iter()
            .map(|(n, b)| (n.clone(), Some(*b)))
            .collect();
        let regular: [(u8, Option<Vec<u8>>); 8] = [
            (SECTION_LAYOUT, Some(self.layout_bytes())),
            (
                SECTION_RODATA,
                (!self.rodata.is_empty()).then(|| self.rodata.clone()),
            ),
            (
                SECTION_DATA,
                (!self.data.is_empty()).then(|| self.data.clone()),
            ),
            (
                SECTION_IMPORTS,
                (!imports.is_empty()).then(|| Self::names(&imports)),
            ),
            (
                SECTION_EXPORTS,
                (!exports.is_empty()).then(|| Self::names(&exports)),
            ),
            (SECTION_JUMP_TABLE, Some(self.jump_table_bytes())),
            (SECTION_CODE, Some(self.code_bytes())),
            (SECTION_DEBUG, self.debug.clone()),
        ];
        for (id, payload) in regular {
            if self.omit.contains(&id) {
                continue;
            }
            if let Some(raw) = self.raw_overrides.get(&id) {
                Self::section(&mut out, id, raw);
            } else if let Some(payload) = payload {
                Self::section(&mut out, id, &payload);
            }
        }
        for (id, payload) in &self.extra_sections {
            Self::section(&mut out, *id, payload);
        }
        out.extend_from_slice(&self.trailing);
        out
    }
}
