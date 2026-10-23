//! The guest allocator over the VM heap (spec 01 §3.2, 02 §4 `sbrk`).
//!
//! Blocks come in power-of-two size classes from 16 bytes to 2 GiB. A freed
//! block goes onto its class's free list and the next allocation of that
//! class takes it back; only when the list is empty is a new block carved
//! from the end of the heap, which grows by `sbrk`. Memory therefore stays
//! bounded by what is live at once (at most twice it, per class) rather than
//! by everything ever allocated. That matters to the kernel: the EVM drops
//! call inputs, return data and call frames as fast as gas lets it create
//! them. A transaction looping over the identity precompile finishes in a
//! 16 MiB heap with this allocator; one that never took memory back needs
//! more than 128 MiB for it (`crates/solo-conformance/tests/heap.rs`, which
//! also checks the rules above from inside the guest). The price is the
//! rounding: a block takes up to twice its size, and a class's blocks stay in
//! that class for the instance's life, so a 24 KiB code copy holds 32 KiB.
//!
//! An allocation the heap cannot satisfy returns null, which `alloc` turns
//! into a handled allocation error: the instance traps.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

const PAGE: usize = 4096;
/// log2 of the smallest block: room for the free-list link, 16-byte aligned.
const MIN_SHIFT: u32 = 4;
/// log2 of the largest block, the most a heap can hold (spec 03 §7.2 rule 8).
const MAX_SHIFT: u32 = 31;
const CLASSES: usize = (MAX_SHIFT - MIN_SHIFT + 1) as usize;

/// Allocator state. Single-threaded by construction.
pub struct Pool {
    state: UnsafeCell<State>,
}

struct State {
    /// First byte not yet carved into a block; zero before the first claim.
    next: usize,
    /// End of the heap as grown so far.
    end: usize,
    /// Head of each class's free list, zero when empty. A free block holds
    /// the address of the next one in its first word.
    free: [usize; CLASSES],
}

// SAFETY: a guest instance has exactly one thread of execution.
unsafe impl Sync for Pool {}

impl Pool {
    /// An allocator that has not yet claimed any heap.
    #[must_use]
    pub const fn new() -> Pool {
        Pool {
            state: UnsafeCell::new(State {
                next: 0,
                end: 0,
                free: [0; CLASSES],
            }),
        }
    }
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

/// The class of a block that can hold `layout`, and the block's size.
fn class(layout: Layout) -> Option<(usize, usize)> {
    let size = layout
        .size()
        .max(layout.align())
        .max(1 << MIN_SHIFT)
        .checked_next_power_of_two()?;
    let shift = size.trailing_zeros();
    (shift <= MAX_SHIFT).then(|| ((shift - MIN_SHIFT) as usize, size))
}

impl State {
    /// A new block of `size` bytes at a multiple of `align`, from the end of
    /// the heap; null when the heap cannot grow that far.
    fn carve(&mut self, size: usize, align: usize) -> *mut u8 {
        if self.end == 0 {
            // First claim: `sbrk(0)` returns the heap's start without growing it.
            // SAFETY: the stub takes a byte count and returns the previous heap end.
            let base = unsafe { crate::host::__solo_sbrk(0) } as usize;
            self.next = base;
            self.end = base;
        }
        let start = (self.next + align - 1) & !(align - 1);
        let Some(finish) = start.checked_add(size) else {
            return core::ptr::null_mut();
        };
        if finish > self.end {
            let grow = (finish - self.end).div_ceil(PAGE) * PAGE;
            // SAFETY: as above.
            if unsafe { crate::host::__solo_sbrk(grow as u64) } == 0 {
                return core::ptr::null_mut();
            }
            self.end += grow;
        }
        self.next = finish;
        start as *mut u8
    }
}

unsafe impl GlobalAlloc for Pool {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: single-threaded; no other reference to the state exists.
        let s = unsafe { &mut *self.state.get() };
        let Some((index, size)) = class(layout) else {
            return core::ptr::null_mut();
        };
        // Every block of a class is carved at a multiple of its size or of a
        // page, whichever is smaller, so a free block suits any alignment up
        // to that. A larger alignment (above a page) is carved afresh.
        let natural = size.min(PAGE);
        let head = s.free[index];
        if head != 0 && layout.align() <= natural {
            // SAFETY: `head` is a free block of this class; its first word is the link.
            s.free[index] = unsafe { *(head as *const usize) };
            return head as *mut u8;
        }
        s.carve(size, natural.max(layout.align()))
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: single-threaded; no other reference to the state exists.
        let s = unsafe { &mut *self.state.get() };
        // A block handed out for `layout` had a class.
        let Some((index, _)) = class(layout) else {
            return;
        };
        // SAFETY: `ptr` is a block of at least 16 bytes that its owner gave up.
        unsafe { *(ptr as *mut usize) = s.free[index] };
        s.free[index] = ptr as usize;
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: `GlobalAlloc::realloc`'s contract guarantees a valid layout of `new_size`.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        if class(layout) == class(new_layout) {
            // The block already holds `new_size` bytes.
            return ptr;
        }
        // SAFETY: as for `alloc` and `dealloc`, on blocks this allocator owns.
        unsafe {
            let new = self.alloc(new_layout);
            if !new.is_null() {
                core::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
            new
        }
    }
}
