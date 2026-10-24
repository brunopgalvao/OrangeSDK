//! Deterministic randomness for the fuzz and differential tests.
//!
//! Every harness runs a fixed number of cases from a fixed seed, so a plain
//! `cargo test` is reproducible and takes a bounded time. Two environment
//! variables widen a run without touching the code:
//!
//! - `SOLO_FUZZ_SCALE=<n>` runs every harness `n` times its default number of
//!   cases (the long mode; `SOLO_FUZZ_SCALE=1000 cargo test --release`).
//! - `SOLO_FUZZ_SEED=<n>` starts every harness from another seed, so repeated
//!   long runs explore different cases.
//!
//! A failing case names its harness, index and seed on the panic output;
//! `SOLO_FUZZ_CASE=<index>` (with the same `SOLO_FUZZ_SEED`) runs that case
//! alone.

#![forbid(unsafe_code)]

/// A `SplitMix64` generator: tiny, fast, and the same on every platform.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// A generator from `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Rng {
        Rng(seed)
    }

    /// The next 64 random bits.
    pub fn u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number in `0..n`.
    ///
    /// # Panics
    /// When `n` is 0.
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "empty range");
        self.u64() % n
    }

    /// A `usize` in `0..n`.
    ///
    /// # Panics
    /// When `n` is 0.
    pub fn index(&mut self, n: usize) -> usize {
        usize::try_from(self.below(n as u64)).expect("below a usize")
    }

    /// True with probability `num / den`.
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }

    /// One element of a non-empty slice.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.index(items.len())]
    }

    /// One random byte.
    pub fn byte(&mut self) -> u8 {
        self.u64().to_le_bytes()[0]
    }

    /// `len` random bytes.
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    /// A 32-byte array.
    pub fn array32(&mut self) -> [u8; 32] {
        let mut out = [0; 32];
        out.copy_from_slice(&self.bytes(32));
        out
    }

    /// A value that is often an edge: zero, one, all ones, a power of two,
    /// one either side of one, or plain random bits.
    pub fn edgy(&mut self) -> u64 {
        let shift = self.below(64);
        match self.below(8) {
            0 => 0,
            1 => 1,
            2 => u64::MAX,
            3 => 1 << shift,
            4 => (1u64 << shift).wrapping_sub(1),
            5 => (1u64 << shift).wrapping_add(1),
            6 => self.below(256),
            _ => self.u64(),
        }
    }

    /// A copy of `input` with one to four random edits: bit flips, bytes set
    /// to boundary values, insertions, deletions, truncation, a duplicated
    /// run, and four or eight bytes overwritten with a huge length.
    pub fn mutate(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = input.to_vec();
        for _ in 0..=self.below(4) {
            self.edit(&mut out);
        }
        out
    }

    fn edit(&mut self, out: &mut Vec<u8>) {
        let len = out.len();
        let at = self.index(len + 1);
        match self.below(8) {
            0 if at < len => out[at] ^= 1 << self.below(8),
            1 if at < len => out[at] = *self.pick(&[0, 1, 0x7F, 0x80, 0xFF]),
            2 => out.insert(at, self.byte()),
            3 if at < len => {
                out.remove(at);
            }
            4 => out.truncate(at),
            5 if at < len => {
                let end = (at + 1 + self.index(16)).min(len);
                let run = out[at..end].to_vec();
                out.splice(at..at, run);
            }
            6 if at + 4 <= len => {
                let huge = *self.pick(&[u32::MAX, 0x7FFF_FFFF, 0x0100_0000, 0xFFFF]);
                out[at..at + 4].copy_from_slice(&huge.to_le_bytes());
            }
            7 if at + 8 <= len => {
                let huge = *self.pick(&[u64::MAX, 1 << 40, 1 << 32]);
                out[at..at + 8].copy_from_slice(&huge.to_be_bytes());
            }
            _ => out.push(self.byte()),
        }
    }
}

/// The multiplier `SOLO_FUZZ_SCALE` asks for: 1 when unset or unparsable.
#[must_use]
pub fn parse_scale(value: Option<&str>) -> u64 {
    value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(1)
}

/// The base seed `SOLO_FUZZ_SEED` asks for: 0 when unset or unparsable.
#[must_use]
pub fn parse_seed(value: Option<&str>) -> u64 {
    value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// The single case `SOLO_FUZZ_CASE` asks for, if any.
#[must_use]
pub fn parse_case(value: Option<&str>) -> Option<u64> {
    value.and_then(|v| v.trim().parse::<u64>().ok())
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The seed of case `index` of harness `name` from base seed `base`.
#[must_use]
pub fn case_seed(name: &str, base: u64, index: u64) -> u64 {
    // FNV-1a of the name, so harnesses draw unrelated streams.
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for b in name.bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01B3);
    }
    Rng::new(h ^ base.rotate_left(17) ^ index.wrapping_mul(0x9E37_79B9_7F4A_7C15)).u64()
}

/// Names the failing case on the panic output while it is alive.
struct Reporter<'a> {
    name: &'a str,
    index: u64,
    base: u64,
    seed: u64,
}

impl Drop for Reporter<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "solo-fuzz: harness {} failed at case {} (seed {:#x}); rerun it alone with SOLO_FUZZ_SEED={} SOLO_FUZZ_CASE={}",
                self.name, self.index, self.seed, self.base, self.index
            );
        }
    }
}

/// Runs `cases` times `SOLO_FUZZ_SCALE` cases of harness `name`, each with
/// its own generator, or only case `SOLO_FUZZ_CASE`, and returns how many
/// ran.
pub fn run(name: &str, cases: u64, mut case: impl FnMut(&mut Rng)) -> u64 {
    let total = cases.saturating_mul(parse_scale(env("SOLO_FUZZ_SCALE").as_deref()));
    let only = parse_case(env("SOLO_FUZZ_CASE").as_deref());
    run_cases(name, total, only, &mut case)
}

/// The body of [`run`], not generic, so that coverage sees one copy of it.
fn run_cases(name: &str, total: u64, only: Option<u64>, case: &mut dyn FnMut(&mut Rng)) -> u64 {
    let base = parse_seed(env("SOLO_FUZZ_SEED").as_deref());
    let indices = match only {
        Some(i) => i..i + 1,
        None => 0..total,
    };
    let ran = indices.end - indices.start;
    for index in indices {
        let seed = case_seed(name, base, index);
        let _reporter = Reporter {
            name,
            index,
            base,
            seed,
        };
        case(&mut Rng::new(seed));
    }
    ran
}

/// Inputs [`evolve`] keeps to mutate further.
const CORPUS: usize = 512;

/// Runs harness `name` as an evolving corpus: each case mutates an input
/// of the corpus (or, one time in sixteen, tries plain random bytes) and
/// hands it to `accept`; inputs `accept` takes join the corpus, so a decoder
/// that refuses most random bytes is still driven deep into what it
/// accepts. The corpus starts as the `seeds` that `accept` takes. Returns
/// how many inputs were accepted.
pub fn evolve(
    name: &str,
    cases: u64,
    seeds: impl IntoIterator<Item = Vec<u8>>,
    mut accept: impl FnMut(&[u8]) -> bool,
) -> u64 {
    let corpus: Vec<Vec<u8>> = seeds.into_iter().filter(|s| accept(s)).collect();
    evolve_corpus(name, cases, corpus, &mut accept)
}

/// The body of [`evolve`], not generic, so that coverage sees one copy of it.
fn evolve_corpus(
    name: &str,
    cases: u64,
    mut corpus: Vec<Vec<u8>>,
    accept: &mut dyn FnMut(&[u8]) -> bool,
) -> u64 {
    let mut accepted = 0;
    run(name, cases, |r| {
        let input = if corpus.is_empty() || r.chance(1, 16) {
            let len = r.index(96);
            r.bytes(len)
        } else {
            let base = r.index(corpus.len());
            r.mutate(&corpus[base])
        };
        if accept(&input) {
            accepted += 1;
            if corpus.len() < CORPUS {
                corpus.push(input);
            } else {
                let slot = r.index(CORPUS);
                corpus[slot] = input;
            }
        }
    });
    accepted
}

/// Seeds for a decoder of an unknown layout: for every first byte below
/// `tags`, that byte followed by up to `len` zero bytes.
#[must_use]
pub fn zero_seeds(tags: u8, len: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for tag in 0..tags {
        for n in 0..=len {
            let mut s = vec![0; n + 1];
            s[0] = tag;
            out.push(s);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_is_fixed() {
        // The first outputs of SplitMix64 from 0, as published.
        let mut r = Rng::new(0);
        assert_eq!(r.u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(r.u64(), 0x6E78_9E6A_A1B9_65F4);
    }

    #[test]
    fn helpers_stay_in_range() {
        let mut r = Rng::new(7);
        for _ in 0..2000 {
            assert!(r.below(5) < 5);
            assert!(r.index(3) < 3);
            assert!([1, 2, 3].contains(r.pick(&[1, 2, 3])));
            assert_eq!(r.bytes(9).len(), 9);
            let _ = r.edgy();
            let _ = r.chance(1, 2);
            let _ = r.array32();
        }
        assert!(!r.chance(0, 1));
        assert!(r.chance(1, 1));
    }

    #[test]
    #[should_panic(expected = "empty range")]
    fn an_empty_range_is_refused() {
        Rng::new(0).below(0);
    }

    #[test]
    fn mutation_changes_and_grows_and_shrinks() {
        let mut r = Rng::new(3);
        let input: Vec<u8> = (0..64).collect();
        let (mut longer, mut shorter, mut changed) = (false, false, false);
        for _ in 0..4000 {
            let m = r.mutate(&input);
            longer |= m.len() > input.len();
            shorter |= m.len() < input.len();
            changed |= m.len() == input.len() && m != input;
        }
        assert!(longer && shorter && changed);
        // Every edit also works on empty input.
        for _ in 0..200 {
            let _ = r.mutate(&[]);
        }
    }

    #[test]
    fn settings_parse() {
        assert_eq!(parse_scale(None), 1);
        assert_eq!(parse_scale(Some("x")), 1);
        assert_eq!(parse_scale(Some("0")), 1);
        assert_eq!(parse_scale(Some(" 40 ")), 40);
        assert_eq!(parse_seed(None), 0);
        assert_eq!(parse_seed(Some("9")), 9);
        assert_eq!(parse_case(None), None);
        assert_eq!(parse_case(Some("12")), Some(12));
        assert_ne!(case_seed("a", 0, 0), case_seed("b", 0, 0));
        assert_ne!(case_seed("a", 0, 0), case_seed("a", 0, 1));
        assert_ne!(case_seed("a", 0, 0), case_seed("a", 1, 0));
    }

    #[test]
    fn run_counts_cases_and_is_deterministic() {
        let mut first = Vec::new();
        let n = run("count", 5, |r| first.push(r.u64()));
        assert!(n >= 5);
        let mut second = Vec::new();
        run("count", 5, |r| second.push(r.u64()));
        assert_eq!(first, second);
        // One case alone draws what it drew in the full run.
        let mut alone = Vec::new();
        assert_eq!(
            run_cases("count", 5, Some(3), &mut |r| alone.push(r.u64())),
            1
        );
        assert_eq!(alone, [first[3]]);
    }

    #[test]
    fn evolve_grows_a_corpus_and_replaces_once_full() {
        // Accepts inputs that start with 7: rare from random bytes, common
        // once the seed is in the corpus.
        let n = evolve("evolve", 4000, zero_seeds(8, 2), |b| b.first() == Some(&7));
        assert!(n > 600, "{n}");
        // With no seed accepted the corpus starts empty.
        assert!(evolve("evolve-empty", 50, [vec![1]], |b| b.len() > 200) == 0);
    }

    #[test]
    #[should_panic(expected = "boom")]
    fn a_failing_case_is_reported() {
        run("fails", 1, |_| panic!("boom"));
    }
}
