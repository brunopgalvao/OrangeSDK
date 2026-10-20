//! A bump allocator over the VM heap (spec 01 §3.2, 02 §4 `sbrk`).
//!
//! Guests are single-threaded and short-lived, so memory is never freed; a
//! call that needs more than the heap allows aborts the instance by returning
//! null, which `alloc` turns into a handled allocation error.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

const PAGE: usize = 4096;

/// Bump allocator state. Single-threaded by construction.
pub struct Bump {
    state: UnsafeCell<State>,
}

struct State {
    next: usize,
    end: usize,
}

// SAFETY: a guest instance has exactly one thread of execution.
unsafe impl Sync for Bump {}

impl Bump {
    /// An allocator that has not yet claimed any heap.
    #[must_use]
    pub const fn new() -> Bump {
        Bump {
            state: UnsafeCell::new(State { next: 0, end: 0 }),
        }
    }
}

impl Default for Bump {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: single-threaded; no other reference to the state exists.
        let s = unsafe { &mut *self.state.get() };
        let align = layout.align().max(1);
        let start = (s.next + align - 1) & !(align - 1);
        let Some(finish) = start.checked_add(layout.size()) else {
            return core::ptr::null_mut();
        };
        if finish > s.end {
            let need = finish - s.end;
            let pages = need.div_ceil(PAGE) * PAGE;
            // SAFETY: the stub takes a byte count and returns the previous heap end.
            let old_end = unsafe { crate::host::__solo_sbrk(pages as u64) } as usize;
            if old_end == 0 {
                return core::ptr::null_mut();
            }
            if s.end == 0 {
                // First claim: the heap begins at the returned address.
                s.next = old_end;
                s.end = old_end + pages;
                return unsafe { self.alloc(layout) };
            }
            s.end = old_end + pages;
        }
        s.next = finish;
        start as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}
