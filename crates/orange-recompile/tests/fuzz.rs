//! Seeded fuzzing of the recompiler (spec 03 §8): mutated ELF files and
//! random instruction words never panic it, and whatever it accepts is a
//! module the loader accepts. See `orange-fuzz` for the long mode.

#![allow(clippy::cast_possible_truncation)]

use orange_fuzz::Rng;
use orange_recompile::riscv::{decode, decode_at, decode_compressed};
use orange_recompile::{Input, Options, recompile};
use orange_vm::module::Module;

const HELLO: &[u8] = include_bytes!("fixtures/hello.elf");
/// A larger guest: the example module, with the module runtime linked in.
const COUNTER: &[u8] = include_bytes!("../../orange-node/tests/fixtures/counter.elf");

/// The file offset and size of the `.text` section of `elf`.
fn text(elf: &[u8]) -> (usize, usize) {
    let word = |at: usize, n: usize| {
        let mut v = 0u64;
        for i in (0..n).rev() {
            v = v << 8 | u64::from(elf[at + i]);
        }
        usize::try_from(v).unwrap()
    };
    let (shoff, shentsize, shnum, shstrndx) =
        (word(0x28, 8), word(0x3A, 2), word(0x3C, 2), word(0x3E, 2));
    let names = word(shoff + shstrndx * shentsize + 0x18, 8);
    (0..shnum)
        .map(|i| shoff + i * shentsize)
        .find(|h| elf[names + word(*h, 4)..].starts_with(b".text\0"))
        .map(|h| (word(h + 0x18, 8), word(h + 0x20, 8)))
        .expect("hello has a .text section")
}

/// Recompiles `bytes` if it loads; an accepted module must validate.
fn check(bytes: &[u8]) -> bool {
    let Ok(input) = Input::load(bytes) else {
        return false;
    };
    let Ok(module) = recompile(&input, &Options::default()) else {
        return false;
    };
    Module::parse(&module, &|_| true).expect("the recompiler emits valid modules");
    true
}

#[test]
fn mutated_elf_files_never_panic_the_recompiler() {
    assert!(check(HELLO) && check(COUNTER));
    let mut accepted = 0u32;
    orange_fuzz::run("recompile-mutated-elf", 300, |r| {
        let elf = if r.chance(1, 2) { HELLO } else { COUNTER };
        accepted += u32::from(check(&r.mutate(elf)));
    });
    assert!(accepted > 0);
}

#[test]
fn random_code_words_never_panic_the_recompiler() {
    let mut accepted = 0u32;
    orange_fuzz::run("recompile-code-words", 300, |r| {
        let base = if r.chance(1, 2) { HELLO } else { COUNTER };
        let (off, size) = text(base);
        let mut elf = base.to_vec();
        for _ in 0..=r.below(3) {
            // A whole aligned word or half-word of code replaced, so the
            // decoder sees a new instruction rather than a torn one.
            let at = off + 2 * r.index(size / 2 - 1);
            let n = if r.chance(1, 2) { 2 } else { 4 };
            let end = (at + n).min(off + size);
            let bytes = r.bytes(end - at);
            elf[at..end].copy_from_slice(&bytes);
        }
        accepted += u32::from(check(&elf));
    });
    assert!(accepted > 0);
}

#[test]
fn random_instruction_words_decode_without_panicking() {
    orange_fuzz::run("riscv-decode", 20_000, |r: &mut Rng| {
        let w = r.u64() as u32;
        let _ = decode(w);
        let _ = decode_compressed(w as u16);
        let len = r.index(6);
        let _ = decode_at(&w.to_le_bytes()[..len.min(4)], 0);
    });
}
