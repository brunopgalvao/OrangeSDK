//! The committed conformance subset (spec 07 §4.2): every case through the
//! conformance guest on the interpreter and the native backend, compared with
//! the fixtures, with every failure on the expected-failure list and every
//! list entry used; and again with feature gate 2 active, the precompiles on
//! the host (spec 19), each case agreeing with the guest's own precompiles.

use std::path::Path;
use std::process::Command;

use solo_conformance::cli::fixture_files;
use solo_conformance::suite::{self, Counts};
use solo_conformance::{GUEST, Runner, TestCase, fixture};
use solo_host::Backend;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/state_tests");
const EXPECTED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/expected-failures.txt"
);

fn cases() -> Vec<TestCase> {
    let mut cases = Vec::new();
    for file in fixture_files(Path::new(FIXTURES)).unwrap() {
        cases.extend(fixture::parse(&std::fs::read_to_string(file).unwrap()).unwrap());
    }
    cases
}

#[test]
fn committed_subset_passes_on_both_backends() {
    let cases = cases();
    let expected = suite::expectations(&std::fs::read_to_string(EXPECTED).unwrap()).unwrap();
    let mut runners = vec![
        Runner::new(GUEST, Backend::Interpreter).unwrap(),
        Runner::new(GUEST, Backend::Native).unwrap(),
    ];
    let report = suite::run(&cases, &mut runners, &expected);
    println!("{report}");
    assert!(report.ok(false), "{report}");
    assert_eq!(runners[0].backend(), Backend::Interpreter);
    assert_eq!(runners[0].runs_natively(), None);
    // The native runner compiled the guest rather than falling back (spec 07 §4.1).
    assert_eq!(runners[1].runs_natively(), Some(true));
    // Pinned so that a change to the subset or to the results is deliberate.
    assert_eq!(
        report.total(),
        Counts {
            passed: 534,
            expected: 22,
            failed: 0
        }
    );
    assert_eq!(report.categories.len(), 28);
}

#[test]
fn committed_subset_passes_with_gate_2_on_both_backends() {
    let cases = cases();
    let expected = suite::expectations(&std::fs::read_to_string(EXPECTED).unwrap()).unwrap();
    let mut runners = vec![
        Runner::gated(GUEST, Backend::Interpreter).unwrap(),
        Runner::gated(GUEST, Backend::Native).unwrap(),
        Runner::new(GUEST, Backend::Native).unwrap(),
    ];
    let report = suite::run(&cases, &mut runners, &expected);
    println!("{report}");
    assert!(report.ok(false), "{report}");
    assert!(runners[0].is_gated() && runners[1].is_gated() && !runners[2].is_gated());
    assert_eq!(runners[1].label(), "Native backend with gate 2");
    assert_eq!(runners[1].runs_natively(), Some(true));
    assert_eq!(
        report.total(),
        Counts {
            passed: 534,
            expected: 22,
            failed: 0
        }
    );
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_solo-conformance"))
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("solo-conformance-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn fixture_file(rel: &str) -> String {
    format!("{FIXTURES}/{rel}")
}

#[test]
fn command_runs_a_directory_on_both_backends() {
    let out = bin()
        .args([
            "--both",
            "--expected",
            EXPECTED,
            &fixture_file("istanbul/eip1344_chainid"),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("istanbul/eip1344_chainid"), "{stdout}");
    assert!(!stdout.contains("native code"), "{stdout}");
    // Prefix and type entries need not excuse anything in a partial run.
    let total = stdout.lines().find(|l| l.starts_with("total")).unwrap();
    assert_eq!(
        total.split_whitespace().collect::<Vec<_>>(),
        ["total", "4", "1", "0"],
        "{stdout}"
    );
}

#[test]
fn command_runs_with_gate_2() {
    let out = bin()
        .args([
            "--native",
            "--gated",
            &fixture_file("prague/eip2537_bls_12_381_precompiles/bls12_map_fp_to_g1"),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    let total = stdout.lines().find(|l| l.starts_with("total")).unwrap();
    assert_eq!(total.split_whitespace().nth(3), Some("0"), "{stdout}");
}

#[test]
fn command_reports_failures() {
    let out = bin()
        .args([
            "--native",
            &fixture_file("istanbul/eip1344_chainid/chainid/chainid.json"),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("FAIL tests/istanbul/eip1344_chainid/test_chainid.py::test_chainid[fork_Osaka-typed_transaction_3-state_test]: the transaction was refused"), "{stdout}");
}

/// A run that asked for the native backend fails unless the guest really ran
/// as native code: the executor would otherwise fall back to the interpreter
/// and compare it with itself. With no case to run, nothing ran natively.
#[test]
fn command_fails_when_the_native_backend_ran_nothing() {
    let empty = scratch("empty");
    std::fs::create_dir_all(&empty).unwrap();
    for backends in ["--native", "--both"] {
        let out = bin()
            .args([backends, empty.to_str().unwrap()])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(1), "{stdout}");
        assert!(
            stdout.contains("the native backend did not run the guest as native code"),
            "{stdout}"
        );
    }
    let out = bin().arg(empty.to_str().unwrap()).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn command_usage_and_input_errors() {
    let usage = |args: &[&str]| {
        let out = bin().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    assert!(usage(&[]).contains("usage:"));
    assert!(usage(&["--expected"]).contains("usage:"));
    assert!(usage(&["--bogus", "x"]).contains("usage:"));
    assert!(usage(&["--expected", "/nonexistent/list.txt", "x"]).contains("/nonexistent/list.txt"));
    let bad_list = scratch("bad-list.txt");
    std::fs::write(&bad_list, "no reason here\n").unwrap();
    assert!(usage(&["--expected", bad_list.to_str().unwrap(), "x"]).contains("line 1"));
    assert!(usage(&["/nonexistent/fixture.json"]).contains("/nonexistent/fixture.json"));
    let not_json = scratch("not.json");
    std::fs::write(&not_json, "{").unwrap();
    assert!(usage(&[not_json.to_str().unwrap()]).contains("not JSON"));
}

#[test]
fn fixture_files_reads_directories_recursively_and_skips_other_files() {
    let dir = scratch("tree");
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub/b.json"), "{}").unwrap();
    std::fs::write(dir.join("a.json"), "{}").unwrap();
    std::fs::write(dir.join("notes.txt"), "").unwrap();
    let files = fixture_files(&dir).unwrap();
    assert_eq!(files, vec![dir.join("a.json"), dir.join("sub/b.json")]);
    assert_eq!(
        fixture_files(&dir.join("a.json")).unwrap(),
        vec![dir.join("a.json")]
    );
}

#[cfg(unix)]
#[test]
fn fixture_files_reports_an_unreadable_directory() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("locked");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let result = fixture_files(&dir);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(result.unwrap_err().contains("locked"));
}
