//! Work split over the machine's cores (codex ADRs 0046 and 0048): pieces of
//! a computation that do not depend on each other, each run of them on a
//! thread of its own, the results in order. Without the `std` feature (the
//! kernel's build) everything runs on the calling thread. The results never
//! depend on how many threads computed them.

use alloc::vec::Vec;
use core::ops::Range;

/// The cores this machine offers; one without the `std` feature.
pub(crate) fn threads() -> usize {
    #[cfg(feature = "std")]
    {
        std::thread::available_parallelism().map_or(1, core::num::NonZero::get)
    }
    #[cfg(not(feature = "std"))]
    {
        1
    }
}

/// `run` over `0..len` split into at most `threads` runs of consecutive
/// positions, each on a thread of its own when there are two or more; the
/// results of every run, in order.
#[cfg(feature = "std")]
pub(crate) fn map<T, F>(len: usize, threads: usize, run: &F) -> Vec<T>
where
    T: Send,
    F: Fn(Range<usize>) -> Vec<T> + Sync,
{
    let per = len.div_ceil(threads.max(1)).max(1);
    if per >= len {
        return run(0..len);
    }
    std::thread::scope(|s| {
        let runs: Vec<_> = (0..len.div_ceil(per))
            .map(|i| {
                let range = i * per..((i + 1) * per).min(len);
                s.spawn(move || run(range))
            })
            .collect();
        runs.into_iter()
            .flat_map(|r| r.join().expect("a run does not panic"))
            .collect()
    })
}

/// Without threads, `run` over all of `0..len`.
#[cfg(not(feature = "std"))]
pub(crate) fn map<T, F>(len: usize, _threads: usize, run: &F) -> Vec<T>
where
    F: Fn(Range<usize>) -> Vec<T>,
{
    run(0..len)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::ops::Range;

    #[test]
    fn runs_cover_every_position_once_in_order() {
        for len in 0..20usize {
            for threads in 0..8usize {
                let out = super::map(len, threads, &|r: Range<usize>| r.collect::<Vec<_>>());
                assert_eq!(out, (0..len).collect::<Vec<_>>(), "{len} {threads}");
            }
        }
        assert!(super::threads() >= 1);
    }
}
