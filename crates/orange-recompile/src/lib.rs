//! ELF to OrangeSDK module recompiler (spec 03 §8).
//!
//! Pipeline: [`elf::Input::load`] reads the sections, symbols and relocations
//! of a linked RV64 ELF; [`translate::recompile`] decodes the code, discovers
//! basic blocks, rewrites every code-address constant to a jump-table slot
//! address, replaces calls to host-call stubs with `ecall`, and emits a
//! validated module.

#![forbid(unsafe_code)]

pub mod elf;
pub mod riscv;
pub mod translate;

pub use elf::Input;
pub use translate::{HEAP_MAX, Options, RecompileError, recompile};
