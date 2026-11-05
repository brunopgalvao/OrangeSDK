//! Decoders of untrusted bytes reserve memory in proportion to the bytes
//! they are given, never to a length or count prefix alone. A counting
//! global allocator records the largest single request while each hostile
//! input is decoded. It lives in this crate because measuring allocations
//! takes an `unsafe impl GlobalAlloc`, which only `-jit` and `-sandbox`
//! crates may contain.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use orange_vm::builder::ModuleBuilder;
use orange_vm::isa::Instruction;
use orange_vm::leb128::write_uleb;
use orange_vm::module::{Module, SECTION_CODE, SECTION_JUMP_TABLE};

/// The system allocator, recording the largest request it has served.
struct Counting;

static LARGEST: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to `System` with the caller's arguments
// unchanged, so `System`'s guarantees carry over; the only addition is an
// atomic maximum, which allocates nothing and cannot unwind.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        // SAFETY: forwarded unchanged (see the impl).
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        // SAFETY: forwarded unchanged (see the impl).
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged (see the impl).
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        // SAFETY: forwarded unchanged (see the impl).
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The largest single allocation `f` makes. The harness runs the tests of
/// this file one after another (there is one test), so nothing else counts.
fn largest(f: impl FnOnce()) -> usize {
    LARGEST.store(0, Ordering::Relaxed);
    f();
    LARGEST.load(Ordering::Relaxed)
}

const LIMIT: usize = 1 << 20;

fn module_with(id: u8, count: u32) -> Vec<u8> {
    let mut b = ModuleBuilder::new();
    b.block(&[Instruction::Halt]);
    b.jump_table.push(None);
    let b = b.export("main", 0);
    let mut payload = Vec::new();
    write_uleb(count, &mut payload);
    payload.extend_from_slice(&[1, 0, 1]);
    let mut b = b;
    b.raw_overrides.insert(id, payload);
    b.build()
}

#[test]
fn hostile_length_prefixes_reserve_nothing_large() {
    // A code section claiming 2^24 - 1 blocks, and a jump table claiming
    // 2^20 slots, in a few bytes each.
    for (id, count) in [(SECTION_CODE, (1 << 24) - 1), (SECTION_JUMP_TABLE, 1 << 20)] {
        let bytes = module_with(id, count);
        let used = largest(|| {
            assert!(Module::parse(&bytes, &|_| true).is_err());
        });
        assert!(
            used < LIMIT,
            "section {id}: {used} bytes for a {}-byte module",
            bytes.len()
        );
    }

    // A snapshot file whose header, and then whose first key, claims 4 GiB.
    let dir = orange_scratch::Scratch::dir("alloc", "snapshot");
    let path = dir.join("s.snap");
    let header = orange_store::snapshot::SnapshotHeader {
        entries: 1,
        ..Default::default()
    };
    orange_store::snapshot::Snapshot::write(&path, &header, [(vec![1], vec![2])]).unwrap();
    let good = std::fs::read(&path).unwrap();
    let mut bad_header = good.clone();
    bad_header[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(&path, &bad_header).unwrap();
    let used = largest(|| assert!(orange_store::snapshot::Snapshot::open(&path).is_err()));
    assert!(used < LIMIT, "snapshot header: {used} bytes");

    let header_len = u32::from_le_bytes(good[12..16].try_into().unwrap()) as usize;
    let mut bad_key = good.clone();
    let key_at = 16 + header_len;
    bad_key[key_at..key_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(&path, &bad_key).unwrap();
    let snapshot = orange_store::snapshot::Snapshot::open(&path).unwrap();
    let used = largest(|| {
        let mut entries = snapshot.entries().unwrap();
        assert!(entries.next().unwrap().is_err());
    });
    assert!(used < LIMIT, "snapshot key: {used} bytes");
}
