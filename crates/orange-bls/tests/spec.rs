//! Spec 12 states the lengths of its signature tags and where the rotation
//! tag parts from the certificate tag; both must match the code.

use orange_bls::certificate::{ROTATION_TAG, TAG};
use orange_bls::sig::{DST_POSSESSION, DST_SIGNATURE};

const SPEC: &str = include_str!("../../../spec/12-threshold-certificates.md");

/// The tag and the length the spec's table gives for `name`.
fn table_tag(name: &str) -> (String, usize) {
    let row = SPEC
        .lines()
        .find(|l| l.starts_with(&format!("| `{name}` |")))
        .unwrap_or_else(|| panic!("no row for {name}"));
    let cell = row.split('|').nth(2).unwrap().trim();
    let (tag, rest) = cell.trim_start_matches('`').split_once('`').unwrap();
    let len = rest
        .trim()
        .strip_prefix('(')
        .and_then(|r| r.strip_suffix(" bytes)"))
        .unwrap()
        .parse()
        .unwrap();
    (tag.to_string(), len)
}

#[test]
fn the_signature_tags_are_as_long_as_the_spec_says() {
    for (name, dst) in [("DST_SIG", DST_SIGNATURE), ("DST_POP", DST_POSSESSION)] {
        let (tag, len) = table_tag(name);
        assert_eq!(tag.as_bytes(), dst, "{name}");
        assert_eq!(len, dst.len(), "{name}");
    }
}

#[test]
fn the_rotation_tag_parts_from_the_certificate_tag_where_the_spec_says() {
    let first = ROTATION_TAG
        .iter()
        .zip(TAG.iter())
        .position(|(a, b)| a != b)
        .unwrap();
    let ordinal = [
        "first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth", "ninth",
    ][first];
    assert!(
        SPEC.contains(&format!(
            "differs from the certificate tag in its {ordinal} byte"
        )),
        "spec 12 §7 should name the {ordinal} byte"
    );
}
