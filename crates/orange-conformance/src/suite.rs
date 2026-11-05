//! Running a set of cases: the expected-failure list, the comparison of
//! backends, and the per-category report.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;

use crate::check::check;
use crate::fixture::TestCase;
use crate::run::Runner;

/// One entry of the expected-failure list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectation {
    /// A test id; with a trailing `*`, every id that starts with the rest;
    /// `type:N`, every case whose transaction has EIP-2718 type `N` (0 for
    /// legacy).
    pub pattern: String,
    /// Why the case fails: the documented difference from Ethereum.
    pub reason: String,
}

impl Expectation {
    fn is_pattern(&self) -> bool {
        self.pattern.ends_with('*') || self.pattern.starts_with("type:")
    }

    fn matches(&self, case: &TestCase) -> bool {
        if let Some(n) = self.pattern.strip_prefix("type:") {
            return n.parse() == Ok(case.tx_type());
        }
        match self.pattern.strip_suffix('*') {
            Some(prefix) => case.id.starts_with(prefix),
            None => case.id == self.pattern,
        }
    }
}

/// Reads an expected-failure list: one `<id, prefix* or type:N> | <reason>`
/// per line; blank lines and lines starting with `#` are ignored.
///
/// # Errors
/// A line without a reason, naming the line.
pub fn expectations(text: &str) -> Result<Vec<Expectation>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.split_once(" | ") {
            Some((pattern, reason)) if !pattern.trim().is_empty() && !reason.trim().is_empty() => {
                out.push(Expectation {
                    pattern: pattern.trim().to_string(),
                    reason: reason.trim().to_string(),
                });
            }
            _ => return Err(format!("line {}: expected `<test id> | <reason>`", n + 1)),
        }
    }
    Ok(out)
}

/// Results of one category.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Cases that pass.
    pub passed: usize,
    /// Cases that fail and are on the expected-failure list.
    pub expected: usize,
    /// Cases that fail and are not.
    pub failed: usize,
}

/// The results of a run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Counts by category.
    pub categories: BTreeMap<String, Counts>,
    /// Failures not on the list, as `(id, what differs)`.
    pub failures: Vec<(String, String)>,
    /// Ids listed individually that passed: the list must drop them.
    pub unexpected_passes: Vec<String>,
    /// List entries that matched no failing case in this run.
    pub unused: Vec<String>,
}

impl Report {
    /// Whether every case passed or failed as listed and every individually
    /// listed case failed. Prefix entries that excuse nothing are allowed
    /// only when `allow_unused` (a run over part of the fixture set).
    #[must_use]
    pub fn ok(&self, allow_unused: bool) -> bool {
        self.failures.is_empty()
            && self.unexpected_passes.is_empty()
            && (allow_unused || self.unused.is_empty())
    }

    /// Totals over every category.
    #[must_use]
    pub fn total(&self) -> Counts {
        self.categories
            .values()
            .fold(Counts::default(), |t, c| Counts {
                passed: t.passed + c.passed,
                expected: t.expected + c.expected,
                failed: t.failed + c.failed,
            })
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::new();
        let mut row = |name: &str,
                       passed: &dyn fmt::Display,
                       expected: &dyn fmt::Display,
                       failed: &dyn fmt::Display| {
            let _ = writeln!(out, "{name:<48} {passed:>7} {expected:>9} {failed:>7}");
        };
        row("category", &"passed", &"expected", &"failed");
        for (name, c) in &self.categories {
            row(name, &c.passed, &c.expected, &c.failed);
        }
        let t = self.total();
        row("total", &t.passed, &t.expected, &t.failed);
        for (id, why) in &self.failures {
            let _ = writeln!(out, "FAIL {id}: {why}");
        }
        for id in &self.unexpected_passes {
            let _ = writeln!(out, "PASS {id}: listed as an expected failure");
        }
        for pattern in &self.unused {
            let _ = writeln!(out, "UNUSED {pattern}: matches no failing case");
        }
        f.write_str(&out)
    }
}

/// Runs every case on every runner. The first runner's result is checked
/// against the fixture; every other runner must produce exactly the same
/// result (spec 07 §4.1), or the case fails whatever the fixture says.
///
/// # Panics
/// If `runners` is empty.
pub fn run(cases: &[TestCase], runners: &mut [Runner], expected: &[Expectation]) -> Report {
    let mut report = Report::default();
    let mut used = vec![false; expected.len()];
    for case in cases {
        let verdict = verdict(case, runners);
        let counts = report.categories.entry(case.category.clone()).or_default();
        let listed = expected.iter().position(|e| e.matches(case));
        match (verdict, listed) {
            (Ok(()), Some(i)) if !expected[i].is_pattern() => {
                used[i] = true;
                counts.passed += 1;
                report.unexpected_passes.push(case.id.clone());
            }
            (Ok(()), _) => counts.passed += 1,
            (Err(_), Some(i)) => {
                used[i] = true;
                counts.expected += 1;
            }
            (Err(why), None) => {
                counts.failed += 1;
                report.failures.push((case.id.clone(), why));
            }
        }
    }
    report.unused = expected
        .iter()
        .zip(used)
        .filter(|(_, used)| !used)
        .map(|(e, _)| e.pattern.clone())
        .collect();
    report
}

fn verdict(case: &TestCase, runners: &mut [Runner]) -> Result<(), String> {
    let input = case.to_case()?;
    let (first, others) = runners.split_first_mut().expect("at least one runner");
    let result = first.run(&input);
    for other in others {
        if other.run(&input) != result {
            return Err(format!(
                "the {} disagrees with the {}",
                other.label(),
                first.label()
            ));
        }
    }
    check(case, &result)
}
