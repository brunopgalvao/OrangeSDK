//! The block of state native code and the Rust side share while an instance
//! runs. Native code addresses it through one host register; every field it
//! touches is named here by its byte offset, so the layout is fixed by
//! `#[repr(C)]` and checked by the offset constants below.

use core::mem::offset_of;

use orange_vm::isa::Reg;

/// One mapped region as native code checks it: an access of `n` bytes at
/// guest address `a` is inside when `base <= a` and `a + n <= end`, and then
/// lives at host address `bias + a` (wrapping).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Region {
    pub(crate) base: u64,
    pub(crate) end: u64,
    pub(crate) bias: u64,
}

/// Regions in the order native code searches them: from the highest base
/// down, so the first region whose base is at or below an address is the
/// only one that can contain it (spec 01 §3.2 fixes the order of regions).
pub(crate) const STACK: usize = 0;
pub(crate) const HEAP: usize = 1;
pub(crate) const RW: usize = 2;
pub(crate) const RO: usize = 3;

/// Shared state of a running instance.
#[repr(C)]
#[derive(Debug, Default)]
pub(crate) struct Ctx {
    /// Guest registers. Registers native code keeps in host registers are
    /// written back here on every exit and reloaded on every entry.
    pub(crate) regs: [u64; Reg::COUNT],
    /// The gas counter, likewise kept in a host register while running.
    pub(crate) gas: i64,
    /// Why native code returned: one of the `EXIT_*` codes.
    pub(crate) exit_kind: u64,
    /// The return address of the call that left native code. It names the
    /// exit site, and for a resumable site it is where execution continues.
    pub(crate) exit_pc: u64,
    /// The native jump table: one absolute code address per slot, 0 if empty.
    pub(crate) jump_table: u64,
    /// Number of slots in the native jump table.
    pub(crate) jump_slots: u64,
    /// The four regions, indexed by [`STACK`], [`HEAP`], [`RW`], [`RO`].
    pub(crate) regions: [Region; 4],
}

/// Offset of guest register `r` in [`Ctx`].
pub(crate) const fn reg(r: Reg) -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    let off = (offset_of!(Ctx, regs) + 8 * r.index()) as u32;
    off
}

#[allow(clippy::cast_possible_truncation)]
mod offsets {
    use super::{Ctx, Region, offset_of};

    pub(crate) const GAS: u32 = offset_of!(Ctx, gas) as u32;
    pub(crate) const EXIT_KIND: u32 = offset_of!(Ctx, exit_kind) as u32;
    pub(crate) const EXIT_PC: u32 = offset_of!(Ctx, exit_pc) as u32;
    pub(crate) const JUMP_TABLE: u32 = offset_of!(Ctx, jump_table) as u32;
    pub(crate) const JUMP_SLOTS: u32 = offset_of!(Ctx, jump_slots) as u32;
    const REGIONS: u32 = offset_of!(Ctx, regions) as u32;
    const SIZE: u32 = size_of::<Region>() as u32;

    /// Offset of the `base` field of region `i`.
    pub(crate) const fn base(i: usize) -> u32 {
        REGIONS + SIZE * i as u32 + offset_of!(Region, base) as u32
    }

    /// Offset of the `end` field of region `i`.
    pub(crate) const fn end(i: usize) -> u32 {
        REGIONS + SIZE * i as u32 + offset_of!(Region, end) as u32
    }

    /// Offset of the `bias` field of region `i`.
    pub(crate) const fn bias(i: usize) -> u32 {
        REGIONS + SIZE * i as u32 + offset_of!(Region, bias) as u32
    }
}

pub(crate) use offsets::*;

/// Native code executed `halt`.
pub(crate) const EXIT_HALT: u64 = 0;
/// Native code executed `trap`.
pub(crate) const EXIT_TRAP: u64 = 1;
/// A load or store fell outside every region it may touch.
pub(crate) const EXIT_FAULT: u64 = 2;
/// An indirect jump named an invalid slot.
pub(crate) const EXIT_INVALID_JUMP: u64 = 3;
/// A block entry charge left the counter negative.
pub(crate) const EXIT_OUT_OF_GAS: u64 = 4;
/// A resumable site: an instruction the Rust side performs (`ecall`,
/// `sbrk`, `memcopy`, `memfill`) before native code continues.
pub(crate) const EXIT_SITE: u64 = 5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_what_native_code_assumes() {
        assert_eq!(reg(Reg::ZERO), 0);
        assert_eq!(reg(Reg::A0), 80);
        assert_eq!(GAS, 256);
        assert_eq!(EXIT_KIND, 264);
        assert_eq!(EXIT_PC, 272);
        assert_eq!(JUMP_TABLE, 280);
        assert_eq!(JUMP_SLOTS, 288);
        assert_eq!((base(STACK), end(STACK), bias(STACK)), (296, 304, 312));
        assert_eq!(base(HEAP), 320);
        assert_eq!(base(RW), 344);
        assert_eq!((base(RO), bias(RO)), (368, 384));
        assert_eq!(size_of::<Ctx>(), 392);
        let ctx = Ctx::default();
        assert_eq!(ctx.regions[RO], Region::default());
        assert!(format!("{ctx:?}").contains("exit_pc"));
        assert_eq!(
            [
                EXIT_HALT,
                EXIT_TRAP,
                EXIT_FAULT,
                EXIT_INVALID_JUMP,
                EXIT_OUT_OF_GAS,
                EXIT_SITE
            ],
            [0, 1, 2, 3, 4, 5]
        );
    }
}
