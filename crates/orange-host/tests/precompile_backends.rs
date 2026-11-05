//! The precompile host functions (spec 05 §4.8) must compute what revm 43's
//! `Crypto` trait computes on its pure-Rust backends, the ones the kernel's
//! revm runs in the guest (spec 05 §5). revm-precompile switches backend by
//! feature (`blst`, `c-kzg`, ...), and Cargo unifies features across a
//! build, so a dependency anywhere in the workspace that turned one on would
//! swap the host's backend without any change to `orange-host`. This test
//! fails when any build of the workspace enables a revm-precompile feature
//! other than `std`.

use std::process::Command;

/// The revm-precompile features the cargo tree output names.
fn features(tree: &str) -> Vec<&str> {
    let marker = "revm-precompile feature \"";
    let mut found: Vec<&str> = tree
        .match_indices(marker)
        .filter_map(|(i, _)| {
            let rest = &tree[i + marker.len()..];
            rest.find('"').map(|end| &rest[..end])
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

#[test]
fn features_are_read_from_the_tree() {
    let tree = "revm-precompile v43.0.3\n├── revm-precompile feature \"std\"\n│   └── revm-precompile feature \"blst\"\n└── revm-precompile feature \"std\"\n";
    assert_eq!(features(tree), ["blst", "std"]);
}

#[test]
fn revm_precompile_builds_with_its_pure_rust_backends_only() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let out = Command::new(cargo)
        .args([
            "tree",
            "--locked",
            "--workspace",
            "--edges",
            "features",
            "--invert",
            "revm-precompile",
            "--manifest-path",
            manifest,
        ])
        .output()
        .expect("cargo runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let tree = String::from_utf8(out.stdout).expect("utf-8");
    assert_eq!(features(&tree), ["std"], "{tree}");
}
