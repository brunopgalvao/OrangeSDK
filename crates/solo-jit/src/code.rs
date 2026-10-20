//! What a native backend produces, and the driver that walks a program's
//! blocks in layout order on behalf of an architecture's emitter.
//!
//! Every way out of native code is a call to a shared exit routine, so the
//! return address of that call identifies the instruction that left: the
//! driver records it for each exit site together with the block and index
//! of the instruction. That gives the exact program position (the same one
//! the interpreter reports) for every termination, and for the four
//! instructions the Rust side performs (`ecall`, `sbrk`, `memcopy`,
//! `memfill`) the return address is also where native code resumes.

use solo_vm::isa::{Instruction, Reg};
use solo_vm::module::Program;

/// One exit site: the return address offset of its exit call and the
/// position of the instruction (or block entry) that owns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Exit {
    pub(crate) ret: u32,
    pub(crate) block: u32,
    pub(crate) index: u32,
}

/// An instruction native code hands to the Rust side and then resumes after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Site {
    Ecall(u32),
    Sbrk { rd: Reg, rs1: Reg },
    Memcopy { dst: Reg, src: Reg, len: Reg },
    Memfill { dst: Reg, val: Reg, len: Reg },
}

impl Site {
    /// The site an instruction becomes, if it is one the Rust side performs.
    pub(crate) fn of(ins: &Instruction) -> Option<Site> {
        match *ins {
            Instruction::Ecall { import } => Some(Site::Ecall(import)),
            Instruction::Sbrk { rd, rs1 } => Some(Site::Sbrk { rd, rs1 }),
            Instruction::Memcopy { dst, src, len } => Some(Site::Memcopy { dst, src, len }),
            Instruction::Memfill { dst, val, len } => Some(Site::Memfill { dst, val, len }),
            _ => None,
        }
    }
}

/// Position-independent native code for a whole program.
#[derive(Debug)]
pub(crate) struct Code {
    pub(crate) bytes: Vec<u8>,
    /// Offset of each block's first instruction.
    pub(crate) blocks: Vec<u32>,
    /// Exit sites, sorted by return offset.
    pub(crate) exits: Vec<Exit>,
    /// Resumable sites, sorted by return offset.
    pub(crate) sites: Vec<(u32, Site)>,
}

/// What an architecture provides to the driver. The emitter places its
/// runtime (entry trampoline, exit routines, memory checks) before the first
/// block, so every call from a block to the runtime is a backward call.
pub(crate) trait Emitter {
    /// The current code offset.
    fn here(&self) -> u32;
    /// Emits a block's entry charge of `cost` and returns the return offset
    /// of its out-of-gas exit call.
    fn charge(&mut self, cost: u32) -> u32;
    /// Emits one instruction of `block`; returns the return offset of its
    /// exit call if it has one.
    fn lower(&mut self, ins: &Instruction, block: u32) -> Option<u32>;
    /// Resolves branches to blocks and returns the code.
    fn finish(self, blocks: &[u32]) -> Vec<u8>;
}

/// Lowers every block of `program` in layout order. Costs must already be
/// known to fit (see `check` in the crate root). Stops with `None` as soon
/// as the code passes `limit` bytes, so an oversized program costs at most
/// `limit` plus one block of work and memory before it is rejected.
pub(crate) fn drive(mut e: impl Emitter, program: &Program, limit: usize) -> Option<Code> {
    let n = program.module.blocks.len();
    let mut blocks = Vec::with_capacity(n);
    let mut exits = Vec::new();
    let mut sites = Vec::new();
    for (b, (block, cost)) in program
        .module
        .blocks
        .iter()
        .zip(&program.block_costs)
        .enumerate()
    {
        let b = u32::try_from(b).unwrap_or(u32::MAX);
        blocks.push(e.here());
        let cost = u32::try_from(*cost).unwrap_or(u32::MAX);
        let ret = e.charge(cost);
        exits.push(Exit {
            ret,
            block: b,
            index: 0,
        });
        for (i, ins) in block.iter().enumerate() {
            if let Some(ret) = e.lower(ins, b) {
                let index = u32::try_from(i).unwrap_or(u32::MAX);
                exits.push(Exit {
                    ret,
                    block: b,
                    index,
                });
                if let Some(site) = Site::of(ins) {
                    sites.push((ret, site));
                }
            }
        }
        if e.here() as usize > limit {
            return None;
        }
    }
    let bytes = e.finish(&blocks);
    Some(Code {
        bytes,
        blocks,
        exits,
        sites,
    })
}
