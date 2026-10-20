//! The `solo-conformance` command: runs fixture files or directories of them
//! and prints the report.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use solo_host::Backend;

use crate::run::Runner;
use crate::{GUEST, fixture, suite};

const USAGE: &str = "usage: solo-conformance [--native | --both] [--expected FILE] PATH...\n\
    Runs the execution-spec state tests in PATH (fixture files, or directories searched for *.json)\n\
    through the conformance guest on the interpreter (default), the native backend, or both.";

/// Every `*.json` file under `path` (or `path` itself), sorted.
///
/// # Errors
/// When a directory cannot be read.
pub fn fixture_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    if !path.is_dir() {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut out = Vec::new();
    let entries = std::fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))?;
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            out.extend(fixture_files(&p)?);
        } else if p.extension().is_some_and(|x| x == "json") {
            out.push(p);
        }
    }
    out.sort();
    Ok(out)
}

/// Runs the command with `args` (without the program name), writing the
/// report to `out`. Returns the exit code: 0 when every case passed or
/// failed as listed and, under `--native` or `--both`, the guest ran as
/// native code; 1 otherwise; 2 for a usage or input error.
pub fn main(args: &[String], out: &mut String) -> i32 {
    match run(args, out) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(e) => {
            let _ = writeln!(out, "{e}");
            2
        }
    }
}

fn run(args: &[String], out: &mut String) -> Result<bool, String> {
    let mut backends = vec![Backend::Interpreter];
    let mut expected = Vec::new();
    let mut paths = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--native" => backends = vec![Backend::Native],
            "--both" => backends = vec![Backend::Interpreter, Backend::Native],
            "--expected" => {
                let file = args.next().ok_or(USAGE)?;
                let text = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
                expected = suite::expectations(&text).map_err(|e| format!("{file}: {e}"))?;
            }
            _ if arg.starts_with("--") => return Err(USAGE.to_string()),
            _ => paths.push(PathBuf::from(arg)),
        }
    }
    if paths.is_empty() {
        return Err(USAGE.to_string());
    }
    let mut cases = Vec::new();
    for path in &paths {
        for file in fixture_files(path)? {
            let text =
                std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            cases.extend(fixture::parse(&text).map_err(|e| format!("{}: {e}", file.display()))?);
        }
    }
    let mut runners = backends
        .into_iter()
        .map(|b| Runner::new(GUEST, b))
        .collect::<Result<Vec<_>, _>>()?;
    let report = suite::run(&cases, &mut runners, &expected);
    let _ = write!(out, "{report}");
    // The executor falls back to the interpreter when the native backend
    // cannot compile the guest; a run that asked for native code and got
    // none has compared nothing against the interpreter.
    let native = runners
        .iter()
        .filter(|r| r.backend() == Backend::Native)
        .all(|r| r.runs_natively() == Some(true));
    if !native {
        let _ = writeln!(
            out,
            "the native backend did not run the guest as native code"
        );
    }
    Ok(report.ok(true) && native)
}
