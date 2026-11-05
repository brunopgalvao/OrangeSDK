//! Reads the parts of a linked RV64 ELF the recompiler needs: section bytes
//! and addresses, symbols, and the relocations kept by `--emit-relocs`.

use std::collections::HashMap;

use object::read::elf::{ElfFile64, FileHeader};
use object::{
    Endianness, Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget,
    SectionIndex,
};

/// Relocation types used by the recompiler (ELF `R_RISCV_*`).
#[allow(missing_docs)]
pub mod reloc {
    pub const R_RISCV_32: u32 = 1;
    pub const R_RISCV_64: u32 = 2;
    pub const R_RISCV_BRANCH: u32 = 16;
    pub const R_RISCV_JAL: u32 = 17;
    pub const R_RISCV_CALL: u32 = 18;
    pub const R_RISCV_CALL_PLT: u32 = 19;
    pub const R_RISCV_PCREL_HI20: u32 = 23;
    pub const R_RISCV_PCREL_LO12_I: u32 = 24;
    pub const R_RISCV_PCREL_LO12_S: u32 = 25;
    pub const R_RISCV_HI20: u32 = 26;
    pub const R_RISCV_LO12_I: u32 = 27;
    pub const R_RISCV_LO12_S: u32 = 28;
    pub const R_RISCV_RVC_BRANCH: u32 = 44;
    pub const R_RISCV_RVC_JUMP: u32 = 45;
    pub const R_RISCV_RELAX: u32 = 51;
}

/// A loaded section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Section {
    /// Virtual address.
    pub address: u64,
    /// Bytes; empty for `.bss`.
    pub bytes: Vec<u8>,
    /// Size in memory (for `.bss`, larger than `bytes`).
    pub size: u64,
}

/// A symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Name as in the symbol table.
    pub name: String,
    /// Value (address for defined symbols).
    pub value: u64,
    /// Whether the symbol is defined in `.text`.
    pub in_text: bool,
    /// Whether it is a function symbol.
    pub is_function: bool,
}

/// A relocation against one of the loaded sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reloc {
    /// Offset of the relocated field from the section start.
    pub offset: u64,
    /// `R_RISCV_*` type.
    pub r_type: u32,
    /// The symbol the relocation refers to.
    pub symbol: Symbol,
    /// Addend.
    pub addend: i64,
}

/// Everything the recompiler consumes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Input {
    /// `.text`.
    pub text: Section,
    /// `.rodata`, if present.
    pub rodata: Section,
    /// `.data`, if present.
    pub data: Section,
    /// `.bss`, if present.
    pub bss: Section,
    /// All symbols with a name.
    pub symbols: Vec<Symbol>,
    /// Relocations against `.text`, sorted by offset.
    pub text_relocs: Vec<Reloc>,
    /// Relocations against `.rodata`, sorted by offset.
    pub rodata_relocs: Vec<Reloc>,
    /// Relocations against `.data`, sorted by offset.
    pub data_relocs: Vec<Reloc>,
}

/// Why an ELF could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfError {
    /// Not a readable 64-bit little-endian RISC-V ELF.
    Parse(String),
    /// A required section is missing or unreadable.
    Section(&'static str),
    /// A relocation refers to a symbol the loader cannot resolve.
    Relocation(u64),
}

impl std::fmt::Display for ElfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ElfError::Parse(m) => write!(f, "cannot parse ELF: {m}"),
            ElfError::Section(n) => write!(f, "missing or unreadable section {n}"),
            ElfError::Relocation(o) => write!(f, "unresolvable relocation at offset {o:#x}"),
        }
    }
}

impl std::error::Error for ElfError {}

type Elf<'a> = ElfFile64<'a, Endianness>;

fn load_section(file: &Elf<'_>, name: &'static str, loaded: bool) -> Result<Section, ElfError> {
    let Some(section) = file.section_by_name(name) else {
        return Ok(Section::default());
    };
    let bytes = if loaded {
        section
            .data()
            .map_err(|_| ElfError::Section(name))?
            .to_vec()
    } else {
        Vec::new()
    };
    Ok(Section {
        address: section.address(),
        bytes,
        size: section.size(),
    })
}

fn symbol_table(file: &Elf<'_>, text_index: Option<SectionIndex>) -> HashMap<usize, Symbol> {
    let mut map = HashMap::new();
    for sym in file.symbols() {
        let name = sym.name().unwrap_or_default();
        map.insert(
            sym.index().0,
            Symbol {
                name: name.to_owned(),
                value: sym.address(),
                in_text: sym.section_index() == text_index && text_index.is_some(),
                is_function: sym.kind() == object::SymbolKind::Text,
            },
        );
    }
    map
}

fn relocations(
    file: &Elf<'_>,
    name: &str,
    symbols: &HashMap<usize, Symbol>,
) -> Result<Vec<Reloc>, ElfError> {
    let Some(section) = file.section_by_name(name) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (r_offset, r) in section.relocations() {
        // For executables the ELF `r_offset` is a virtual address; the loader
        // keeps section-relative offsets.
        let offset = r_offset
            .checked_sub(section.address())
            .ok_or(ElfError::Relocation(r_offset))?;
        // An ELF file only ever yields ELF relocation flags.
        #[rustfmt::skip]
        let RelocationFlags::Elf { r_type } = r.flags() else { unreachable!() };
        let r_type = r_type.0;
        if r_type == reloc::R_RISCV_RELAX {
            continue;
        }
        let RelocationTarget::Symbol(index) = r.target() else {
            return Err(ElfError::Relocation(r_offset));
        };
        let symbol = symbols
            .get(&index.0)
            .cloned()
            .ok_or(ElfError::Relocation(r_offset))?;
        out.push(Reloc {
            offset,
            r_type,
            symbol,
            addend: r.addend(),
        });
    }
    out.sort_by_key(|r| r.offset);
    Ok(out)
}

impl Input {
    /// Loads an ELF image.
    ///
    /// # Errors
    /// See [`ElfError`].
    pub fn load(bytes: &[u8]) -> Result<Input, ElfError> {
        let file: Elf<'_> = ElfFile64::parse(bytes).map_err(|e| ElfError::Parse(e.to_string()))?;
        if file.elf_header().e_machine(file.endian()) != object::elf::EM_RISCV {
            return Err(ElfError::Parse("not a RISC-V ELF".to_owned()));
        }
        let text_section = file
            .section_by_name(".text")
            .ok_or(ElfError::Section(".text"))?;
        let text_index = Some(text_section.index());
        let symbols = symbol_table(&file, text_index);
        Ok(Input {
            text: load_section(&file, ".text", true)?,
            rodata: load_section(&file, ".rodata", true)?,
            data: load_section(&file, ".data", true)?,
            bss: load_section(&file, ".bss", false)?,
            text_relocs: relocations(&file, ".text", &symbols)?,
            rodata_relocs: relocations(&file, ".rodata", &symbols)?,
            data_relocs: relocations(&file, ".data", &symbols)?,
            symbols: {
                let mut v: Vec<Symbol> = symbols.into_values().collect();
                v.sort_by(|a, b| (a.value, &a.name).cmp(&(b.value, &b.name)));
                v
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO: &[u8] = include_bytes!("../tests/fixtures/hello.elf");

    #[test]
    fn loads_the_hello_fixture() {
        let input = Input::load(HELLO).unwrap();
        assert_eq!(input.text.address, 0x4000_0000);
        assert!(input.text.bytes.len() > 0x100);
        assert_eq!(input.rodata.address, 0x1_0000);
        assert_eq!(input.rodata.bytes, b"hello, orange");
        assert_eq!(input.data.size, 0);
        assert_eq!(input.bss.address, 0x1_2000);
        // COUNTER plus the allocator state: two words and 28 free-list heads.
        assert_eq!(input.bss.size, 8 + 16 + 28 * 8);
        assert!(
            input
                .symbols
                .iter()
                .any(|s| s.name == "orange_export_main" && s.in_text && s.is_function)
        );
        assert!(
            input
                .symbols
                .iter()
                .any(|s| s.name == "__orange_import_hash_keccak256")
        );
        let call = input
            .text_relocs
            .iter()
            .find(|r| {
                r.r_type == reloc::R_RISCV_CALL_PLT
                    && r.symbol.name == "__orange_import_hash_keccak256"
            })
            .unwrap();
        assert_eq!(call.addend, 0);
        assert!(call.offset % 2 == 0 && call.offset < input.text.bytes.len() as u64);
        assert!(
            input
                .text_relocs
                .iter()
                .any(|r| r.r_type == reloc::R_RISCV_PCREL_HI20)
        );
        assert!(
            input
                .text_relocs
                .iter()
                .any(|r| r.r_type == reloc::R_RISCV_PCREL_LO12_I)
        );
        assert!(
            input
                .text_relocs
                .windows(2)
                .all(|w| w[0].offset <= w[1].offset)
        );
        assert!(input.rodata_relocs.is_empty());
        assert!(
            !input
                .text_relocs
                .iter()
                .any(|r| r.r_type == reloc::R_RISCV_RELAX)
        );
    }

    #[test]
    fn rejects_garbage_and_other_machines() {
        assert!(matches!(
            Input::load(b"not an elf"),
            Err(ElfError::Parse(_))
        ));
        let mut x86 = HELLO.to_vec();
        x86[18] = 0x3E; // e_machine = EM_X86_64
        x86[19] = 0;
        assert_eq!(
            Input::load(&x86),
            Err(ElfError::Parse("not a RISC-V ELF".to_owned()))
        );
        assert_eq!(
            ElfError::Section(".text").to_string(),
            "missing or unreadable section .text"
        );
        assert_eq!(
            ElfError::Relocation(16).to_string(),
            "unresolvable relocation at offset 0x10"
        );
        assert!(
            ElfError::Parse("x".to_owned())
                .to_string()
                .contains("cannot parse")
        );
        let e: Box<dyn std::error::Error> = Box::new(ElfError::Section(".text"));
        assert!(e.to_string().contains(".text"));
    }

    fn rela_text_range() -> std::ops::Range<usize> {
        let file: Elf<'_> = ElfFile64::parse(HELLO).unwrap();
        let (start, len) = file
            .section_by_name(".rela.text")
            .unwrap()
            .file_range()
            .unwrap();
        let start = usize::try_from(start).unwrap();
        start..start + usize::try_from(len).unwrap()
    }

    #[test]
    fn relocation_with_unknown_or_absent_symbol() {
        let range = rela_text_range();
        // Entry layout: r_offset u64, r_info u64 (symbol << 32 | type), r_addend i64.
        let info_at = range.start + 8;
        let mut bytes = HELLO.to_vec();
        let info = u64::from_le_bytes(bytes[info_at..info_at + 8].try_into().unwrap());
        let r_offset = u64::from_le_bytes(bytes[range.start..range.start + 8].try_into().unwrap());
        // Symbol index far beyond the table.
        let bad = (0xFFFF_u64 << 32) | (info & 0xFFFF_FFFF);
        bytes[info_at..info_at + 8].copy_from_slice(&bad.to_le_bytes());
        assert_eq!(Input::load(&bytes), Err(ElfError::Relocation(r_offset)));
        // Symbol index zero: an absolute relocation with no symbol.
        let absolute = info & 0xFFFF_FFFF;
        bytes[info_at..info_at + 8].copy_from_slice(&absolute.to_le_bytes());
        assert_eq!(Input::load(&bytes), Err(ElfError::Relocation(r_offset)));
        // A relaxation marker is skipped, leaving one relocation fewer.
        let mut bytes = HELLO.to_vec();
        let relax = (info & !0xFFFF_FFFF) | u64::from(reloc::R_RISCV_RELAX);
        bytes[info_at..info_at + 8].copy_from_slice(&relax.to_le_bytes());
        let baseline = Input::load(HELLO).unwrap().text_relocs.len();
        assert_eq!(Input::load(&bytes).unwrap().text_relocs.len(), baseline - 1);
        // A relocation offset below the section start.
        let mut bytes = HELLO.to_vec();
        bytes[range.start..range.start + 8].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(Input::load(&bytes), Err(ElfError::Relocation(1)));
    }

    #[test]
    fn unreadable_section_data() {
        // Stretch .rodata's size past the end of the file so its data cannot be read.
        let file: Elf<'_> = ElfFile64::parse(HELLO).unwrap();
        let index = file.section_by_name(".rodata").unwrap().index().0;
        let shoff = usize::try_from(file.elf_header().e_shoff(file.endian())).unwrap();
        let size_at = shoff + index * 64 + 32;
        let mut bytes = HELLO.to_vec();
        bytes[size_at..size_at + 8].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes());
        assert_eq!(Input::load(&bytes), Err(ElfError::Section(".rodata")));
    }

    #[test]
    fn missing_text_section() {
        // Rename .text in the section header string table so it cannot be found.
        let mut bytes = HELLO.to_vec();
        let pos = bytes.windows(6).position(|w| w == b".text\0").unwrap();
        bytes[pos + 1] = b'x';
        assert_eq!(Input::load(&bytes), Err(ElfError::Section(".text")));
    }
}
