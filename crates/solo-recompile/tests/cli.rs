//! The command line wrapper: exit codes and messages.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_solo-recompile"))
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("solo-recompile-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

#[test]
fn usage_error() {
    let out = bin().output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
}

#[test]
fn missing_input() {
    let out = bin()
        .args(["/nonexistent/input.elf", "/nonexistent/out.solo"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("/nonexistent/input.elf"));
}

#[test]
fn not_an_elf() {
    let input = scratch("garbage.elf");
    std::fs::write(&input, b"garbage").unwrap();
    let out = bin()
        .args([input.to_str().unwrap(), "/nonexistent/out.solo"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot parse ELF"));
}

#[test]
fn unwritable_output() {
    let input = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/hello.elf");
    let out = bin()
        .args([input, "/nonexistent/dir/out.solo"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("/nonexistent/dir/out.solo"));
}

#[test]
fn recompiles_hello() {
    let input = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/hello.elf");
    let output = scratch("hello.solo");
    let out = bin()
        .args([input, output.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("bytes"));
    let bytes = std::fs::read(&output).unwrap();
    assert_eq!(&bytes[..4], b"SOLO");
}

#[test]
fn recompile_error_is_reported() {
    // Rename the export symbol so the ELF loads but has nothing to export.
    let mut bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/hello.elf"
    ))
    .unwrap();
    // The name appears in the symbol table and in debug strings; rename every copy.
    let positions: Vec<usize> = bytes
        .windows(17)
        .enumerate()
        .filter(|(_, w)| *w == b"solo_export_main\0")
        .map(|(i, _)| i)
        .collect();
    assert!(!positions.is_empty());
    for pos in positions {
        bytes[pos] = b'x';
    }
    let input = scratch("noexport.elf");
    std::fs::write(&input, &bytes).unwrap();
    let out = bin()
        .args([
            input.to_str().unwrap(),
            scratch("noexport.solo").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no solo_export_* symbol"));
}
