//! Executable memory and the one call into native code. This module and the
//! architecture emitters are the only places that know native code exists;
//! every `unsafe` block of the crate is here.
//!
//! Invariants the blocks below rely on:
//!
//! - **Code.** The bytes mapped are exactly what an emitter produced for a
//!   program that passed `check` (crate root): every block ends in a transfer
//!   or falls into the next block, every branch target is a block start,
//!   every call targets the runtime emitted before the first block, and the
//!   whole buffer is below the architecture's branch range.
//! - **Memory.** Native code dereferences only (a) the [`Ctx`] passed to
//!   [`ExecMem::enter`], at the fixed offsets of `crate::ctx`; (b) guest
//!   memory, through a region's `bias` after checking the access against that
//!   region's `base` and `end`, which the caller derives from the live
//!   backing slices of the instance's `Memory`; (c) the native jump table,
//!   after checking the slot against `jump_slots`; (d) its own stack frame.
//! - **Control.** Native code never calls back into Rust and never unwinds;
//!   it leaves only by returning from the entry trampoline with every
//!   callee-saved register restored.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::ptr::NonNull;

use orange_vm::memory::Memory;

use crate::ctx::{Ctx, HEAP, RO, RW, Region, STACK};
use crate::instance::Resume;
use crate::{CompileError, Compiled};

/// A private, read-and-execute mapping holding one program's native code.
#[derive(Debug)]
pub(crate) struct ExecMem {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: the mapping is written once in `new` and never again; afterwards it
// is immutable executable memory, which any thread may run concurrently.
unsafe impl Send for ExecMem {}
// SAFETY: as above; shared references only ever read or execute it.
unsafe impl Sync for ExecMem {}

impl ExecMem {
    /// Maps `code` as executable memory.
    pub(crate) fn new(code: &[u8]) -> Result<ExecMem, CompileError> {
        let page = 1usize << 14;
        let len = code.len().div_ceil(page).max(1) * page;
        let mem = ExecMem::map(len)?;
        mem.fill(code)?;
        Ok(mem)
    }

    /// Reserves `len` bytes of fresh anonymous memory.
    fn map(len: usize) -> Result<ExecMem, CompileError> {
        // SAFETY: an anonymous private mapping at an address of the kernel's
        // choosing aliases nothing; failure is reported as `MAP_FAILED`.
        let p = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                PROTECTION,
                libc::MAP_PRIVATE | libc::MAP_ANON | MAP_FLAGS,
                -1,
                0,
            )
        };
        let ptr = (p != libc::MAP_FAILED)
            .then_some(p)
            .and_then(|p| NonNull::new(p.cast::<u8>()))
            .ok_or(CompileError::Memory)?;
        Ok(ExecMem { ptr, len })
    }

    /// The start of the code.
    pub(crate) fn base(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    /// Bytes mapped (a whole number of pages).
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Runs native code from `target` until it exits, with the trampoline at
    /// offset 0 of the mapping.
    ///
    /// # Safety
    /// The mapping must hold code from `crate::compile` for the program the
    /// context belongs to, `target` must be a block start or a resume address
    /// that code recorded, and `ctx` must hold region and jump-table fields
    /// refreshed from live data (module invariants above).
    pub(crate) unsafe fn enter(&self, ctx: &mut Ctx, target: *const u8) {
        // SAFETY: offset 0 of the mapping is the entry trampoline, which has
        // exactly the `Entry` signature (see the architecture module).
        let entry: crate::arch::Entry = unsafe { core::mem::transmute(self.base()) };
        // SAFETY: the caller upholds the invariants of this module; the
        // trampoline returns normally with callee-saved registers restored.
        unsafe { entry(ctx, target) };
    }
}

/// One region of `memory` as native code checks it.
fn region(base: u32, bytes: *const u8, len: usize) -> Region {
    let base = u64::from(base);
    Region {
        base,
        end: base + len as u64,
        bias: (bytes.expose_provenance() as u64).wrapping_sub(base),
    }
}

/// Enters `compiled` at `at` with the guest state in `ctx` and `memory`, and
/// returns the code offset of the exit site once native code leaves.
///
/// The region and jump-table fields of `ctx` are derived here, immediately
/// before entering, from the live backing slices of `memory` and from the
/// tables of `compiled`, and `at` can only name a block start or a recorded
/// resume point, which together establish the invariants of this module.
pub(crate) fn run(compiled: &Compiled, ctx: &mut Ctx, memory: &mut Memory, at: Resume) -> u32 {
    let r = memory.regions_mut();
    ctx.regions[STACK] = region(r.stack.0, r.stack.1.as_mut_ptr(), r.stack.1.len());
    ctx.regions[HEAP] = region(r.heap.0, r.heap.1.as_mut_ptr(), r.heap.1.len());
    ctx.regions[RW] = region(r.rw.0, r.rw.1.as_mut_ptr(), r.rw.1.len());
    ctx.regions[RO] = region(r.ro.0, r.ro.1.as_ptr(), r.ro.1.len());
    ctx.jump_table = compiled.jump_table.as_ptr().expose_provenance() as u64;
    ctx.jump_slots = compiled.jump_table.len() as u64;
    let offset = match at {
        Resume::Block(b) => compiled.blocks[b as usize],
        Resume::Site(i) => compiled.sites[i].0,
    };
    let base = compiled.exec.base();
    // SAFETY: see above; `offset` is inside the mapping because it came
    // from the code's own block and site tables.
    unsafe { compiled.exec.enter(ctx, base.add(offset as usize)) };
    let ret = ctx.exit_pc.wrapping_sub(base.addr() as u64);
    u32::try_from(ret).unwrap_or(u32::MAX)
}

impl Drop for ExecMem {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`len` describe a mapping this value owns; nothing can
        // run it after drop because every `Instance` borrows its `Compiled`.
        unsafe { libc::munmap(self.ptr.as_ptr().cast::<c_void>(), self.len) };
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
mod platform {
    //! Apple silicon: `MAP_JIT` pages are writable or executable per thread,
    //! switched with `pthread_jit_write_protect_np`, and the instruction cache
    //! must be invalidated after writing.

    use super::{CompileError, ExecMem, c_void};

    pub(super) const PROTECTION: i32 = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
    pub(super) const MAP_FLAGS: i32 = libc::MAP_JIT;

    unsafe extern "C" {
        fn sys_icache_invalidate(start: *mut c_void, len: usize);
    }

    impl ExecMem {
        /// Copies `code` in and makes it visible to instruction fetch. Never
        /// fails here; the signature matches the other platforms.
        #[allow(clippy::unnecessary_wraps)]
        pub(super) fn fill(&self, code: &[u8]) -> Result<(), CompileError> {
            // SAFETY: switches this thread's view of every MAP_JIT page to
            // writable; no code from this mapping runs on this thread yet.
            unsafe { libc::pthread_jit_write_protect_np(0) };
            // SAFETY: the mapping is `len >= code.len()` bytes, fresh, and
            // disjoint from `code`.
            unsafe {
                core::ptr::copy_nonoverlapping(code.as_ptr(), self.ptr.as_ptr(), code.len());
            }
            // SAFETY: back to executable for this thread.
            unsafe { libc::pthread_jit_write_protect_np(1) };
            // SAFETY: the range is inside the mapping just written.
            unsafe { sys_icache_invalidate(self.ptr.as_ptr().cast(), self.len) };
            Ok(())
        }
    }
}

#[cfg(all(target_arch = "x86_64", unix))]
mod platform {
    //! x86-64: map writable, copy, then switch the pages to read and execute.
    //! The instruction cache is coherent with data writes.

    use super::{CompileError, ExecMem};

    pub(super) const PROTECTION: i32 = libc::PROT_READ | libc::PROT_WRITE;
    pub(super) const MAP_FLAGS: i32 = 0;

    impl ExecMem {
        /// Copies `code` in and makes the mapping read-and-execute.
        pub(super) fn fill(&self, code: &[u8]) -> Result<(), CompileError> {
            // SAFETY: the mapping is `len >= code.len()` bytes, fresh, writable
            // and disjoint from `code`.
            unsafe {
                core::ptr::copy_nonoverlapping(code.as_ptr(), self.ptr.as_ptr(), code.len());
            }
            // SAFETY: changes the protection of exactly the mapping we own.
            let rc = unsafe {
                libc::mprotect(
                    self.ptr.as_ptr().cast(),
                    self.len,
                    libc::PROT_READ | libc::PROT_EXEC,
                )
            };
            (rc == 0).then_some(()).ok_or(CompileError::Memory)
        }
    }
}

use platform::{MAP_FLAGS, PROTECTION};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_failure_is_an_error() {
        assert_eq!(
            ExecMem::map(usize::MAX & !0xFFFF).err(),
            Some(CompileError::Memory)
        );
        let m = ExecMem::new(&[0xC3; 10]).unwrap();
        assert_eq!(m.len(), 1 << 14);
        assert!(format!("{m:?}").contains("ExecMem"));
    }
}
