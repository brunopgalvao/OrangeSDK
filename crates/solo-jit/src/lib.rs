//! Native code backend for the Solo VM.
//!
//! [`Compiled::new`] translates a validated [`Program`] ahead of time into
//! machine code for the host (AArch64 on Apple silicon, x86-64 on Unix);
//! [`Instance`] runs it in-process with the same interface as the reference
//! interpreter's [`solo_vm::interp::Instance`]. Results are bit-exact with
//! the interpreter: registers, memory, gas remaining, the termination status
//! and the program position it reports, for every program. The
//! differential tests in `tests/` hold the two backends to that (spec 07 §4).
//!
//! How the generated code keeps the interpreter's semantics:
//!
//! - **Gas** is charged at every block entry with one subtract and a signed
//!   compare, so the out-of-gas point is the same block (spec 01 §5, 04 §2).
//! - **Memory** accesses go through a shared range check per width that
//!   finds the one region an address can be in and checks the whole access
//!   against its exact extent, so faults happen at the same byte boundary as
//!   in the interpreter, before anything is written (spec 01 §3.2).
//! - **Host calls, `sbrk`, `memcopy` and `memfill`** leave native code: the
//!   Rust side performs them exactly as the interpreter does, through the
//!   same [`Host`](solo_vm::host::Host) trait, then native code resumes after
//!   the instruction. Nested instances and panics therefore never cross
//!   native frames.
//! - **Every exit** is a call whose return address names the instruction,
//!   which gives the exact position for every termination.
//!
//! On other targets [`Compiled::new`] returns [`CompileError::Unsupported`]
//! and callers keep using the interpreter.

#![deny(clippy::undocumented_unsafe_blocks)]

mod code;
mod ctx;
mod instance;

#[cfg(any(
    all(target_arch = "aarch64", target_os = "macos"),
    all(target_arch = "x86_64", unix)
))]
mod exec;
#[cfg(any(
    all(target_arch = "aarch64", target_os = "macos"),
    all(target_arch = "x86_64", unix)
))]
mod regmap;

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
mod arm64;
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
use arm64 as arch;
#[cfg(all(target_arch = "x86_64", unix))]
mod x64;
#[cfg(all(target_arch = "x86_64", unix))]
use x64 as arch;

#[cfg(not(any(
    all(target_arch = "aarch64", target_os = "macos"),
    all(target_arch = "x86_64", unix)
)))]
mod exec {
    //! No native backend for this target: nothing compiles, so no code
    //! mapping, and therefore no instance, can exist.

    use crate::ctx::Ctx;
    use crate::instance::Resume;
    use solo_vm::memory::Memory;

    /// An uninhabited stand-in for executable memory.
    #[derive(Debug)]
    pub(crate) enum ExecMem {}

    impl ExecMem {
        pub(crate) fn base(&self) -> *const u8 {
            match *self {}
        }

        pub(crate) fn len(&self) -> usize {
            match *self {}
        }
    }

    pub(crate) fn run(compiled: &crate::Compiled, _: &mut Ctx, _: &mut Memory, _: Resume) -> u32 {
        match compiled.exec {}
    }
}

use solo_vm::memory::MemoryLayout;
use solo_vm::module::{Program, ValidationError};

pub use instance::Instance;

use code::{Code, Exit, Site};

/// Whether this target has a native backend.
pub const SUPPORTED: bool = cfg!(any(
    all(target_arch = "aarch64", target_os = "macos"),
    all(target_arch = "x86_64", unix)
));

/// The largest block cost the backends accept. A block of valid code costs
/// far less: 16 MiB of code (spec 01 §9) at the dearest instruction of
/// table version 1 sums to under 2^29.
pub const MAX_BLOCK_COST: u64 = (1 << 31) - 1;

/// Compilation settings. The defaults are what production wants; the knobs
/// exist to exercise every code path in tests and to bound resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// At most this many guest registers live in host registers (the target
    /// may offer fewer); the rest stay in memory. 0 keeps every guest
    /// register in memory.
    pub host_registers: usize,
    /// Reject programs whose native code would exceed this many bytes (the
    /// target's branch range is a further limit).
    pub code_limit: usize,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            host_registers: usize::MAX,
            code_limit: usize::MAX,
        }
    }
}

/// Why a program could not be compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompileError {
    /// This target has no native backend.
    Unsupported,
    /// The program breaks a rule of spec 03 §7 (see [`solo_vm::module::Module::validate`]).
    Invalid(ValidationError),
    /// The block costs do not match the blocks, or one exceeds [`MAX_BLOCK_COST`].
    Costs,
    /// The native code would exceed [`Options::code_limit`] or the target's
    /// branch range.
    TooLarge,
    /// The operating system refused executable memory.
    Memory,
}

/// A program translated to native code, ready to instantiate any number of
/// times. Immutable, so it can be shared across threads.
#[derive(Debug)]
pub struct Compiled {
    exec: exec::ExecMem,
    /// Native offset of each block.
    blocks: Vec<u32>,
    /// One absolute code address per jump-table slot, 0 for an empty slot.
    jump_table: Vec<u64>,
    exits: Vec<Exit>,
    sites: Vec<(u32, Site)>,
    layout: MemoryLayout,
    rodata: Vec<u8>,
    data: Vec<u8>,
    imports: Vec<String>,
    exports: Vec<(String, u32)>,
}

impl Compiled {
    /// Compiles `program` with default [`Options`].
    ///
    /// # Errors
    /// See [`CompileError`].
    pub fn new(program: &Program) -> Result<Compiled, CompileError> {
        Compiled::with_options(program, Options::default())
    }

    /// Compiles `program`.
    ///
    /// # Errors
    /// See [`CompileError`].
    pub fn with_options(program: &Program, options: Options) -> Result<Compiled, CompileError> {
        check(program)?;
        let (code, exec) = compile(program, options)?;
        let module = &program.module;
        let base = exec.base().addr() as u64;
        let jump_table = module
            .jump_table
            .iter()
            .map(|slot| slot.map_or(0, |b| base + u64::from(code.blocks[b as usize])))
            .collect();
        Ok(Compiled {
            exec,
            blocks: code.blocks,
            jump_table,
            exits: code.exits,
            sites: code.sites,
            layout: module.layout,
            rodata: module.rodata.clone(),
            data: module.data.clone(),
            imports: module.imports.clone(),
            exports: module.exports.clone(),
        })
    }

    /// Bytes of executable memory the native code occupies.
    #[must_use]
    pub fn code_size(&self) -> usize {
        self.exec.len()
    }

    /// The exit site whose call returns to `ret`.
    fn exit(&self, ret: u32) -> Exit {
        self.exits[self.exits.partition_point(|e| e.ret < ret)]
    }

    /// The index of the resumable site whose call returns to `ret`.
    fn site(&self, ret: u32) -> usize {
        self.sites.partition_point(|s| s.0 < ret)
    }
}

/// The rules native code relies on: a valid module (every branch target,
/// slot and import in range, no fall-through off the last block) and one
/// representable cost per block.
fn check(program: &Program) -> Result<(), CompileError> {
    program.module.validate().map_err(CompileError::Invalid)?;
    if program.block_costs.len() != program.module.blocks.len()
        || program.block_costs.iter().any(|&c| c > MAX_BLOCK_COST)
    {
        return Err(CompileError::Costs);
    }
    Ok(())
}

/// Generates and maps the code for a checked program.
#[cfg(any(
    all(target_arch = "aarch64", target_os = "macos"),
    all(target_arch = "x86_64", unix)
))]
fn compile(program: &Program, options: Options) -> Result<(Code, exec::ExecMem), CompileError> {
    let hosts = &arch::HOST_REGS[..options.host_registers.min(arch::HOST_REGS.len())];
    let map = regmap::RegMap::choose(program, hosts);
    let code = code::drive(arch::Native::new(map), program);
    if code.bytes.len() > options.code_limit.min(arch::CODE_LIMIT) {
        return Err(CompileError::TooLarge);
    }
    let exec = exec::ExecMem::new(&code.bytes)?;
    Ok((code, exec))
}

#[cfg(not(any(
    all(target_arch = "aarch64", target_os = "macos"),
    all(target_arch = "x86_64", unix)
)))]
fn compile(_: &Program, _: Options) -> Result<(Code, exec::ExecMem), CompileError> {
    Err(CompileError::Unsupported)
}
