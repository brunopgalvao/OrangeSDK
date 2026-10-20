//! The worked example of spec 10 §7, value for value.

use solo_trie::{EMPTY, Proof, Terminal, Trie, branch_hash, keccak256, leaf_hash};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn h32(s: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

const PATH_A: &str = "3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb";
const PATH_B: &str = "b5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510";
const PATH_C: &str = "0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2";
const VALUE_1: &str = "c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6";
const VALUE_2: &str = "ad7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5";
const VALUE_3: &str = "2a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4de";
const LEAF_A: &str = "c3fd1ef33b82b45747a4dfeaa6bd2bb314df989be8ade3eb7e4738c78db82912";
const LEAF_B: &str = "5bc843c9d95183b878cfd5794d53c4c9d6e908fe1a6b20dccfd74dc0aa081e40";
const LEAF_C: &str = "315a952a5f964923400b9628a78f149ee38cfa30fdafa297eca98eee688ddace";
const BRANCH_CA: &str = "b600ff7b28e7cb984a9a124e17ac49a2a76d6474e0a7ff4a1ebcd147fe7d9ce8";
const BRANCH_0: &str = "1fe8b3b11661b5428f424fa077bc6943bb2b377c312de263d913ffc159db8069";
const ROOT: &str = "c263b0367df71e753bca510361673e7ea418ef6cbd2c8e10d5754d509aa23605";

const PROOF_A: &str = concat!(
    "0300",
    "5bc843c9d95183b878cfd5794d53c4c9d6e908fe1a6b20dccfd74dc0aa081e40",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "315a952a5f964923400b9628a78f149ee38cfa30fdafa297eca98eee688ddace",
    "01",
    "3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb",
    "c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6",
);
const PROOF_D: &str = concat!(
    "0100",
    "1fe8b3b11661b5428f424fa077bc6943bb2b377c312de263d913ffc159db8069",
    "01",
    "b5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510",
    "ad7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5",
);
const PROOF_K1: &str = concat!(
    "0200",
    "5bc843c9d95183b878cfd5794d53c4c9d6e908fe1a6b20dccfd74dc0aa081e40",
    "b600ff7b28e7cb984a9a124e17ac49a2a76d6474e0a7ff4a1ebcd147fe7d9ce8",
    "00",
);

fn example() -> Trie {
    let mut t = Trie::new();
    t.insert(b"a", b"1");
    t.insert(b"b", b"2");
    t.insert(b"c", b"3");
    t
}

#[test]
fn paths_and_leaves() {
    assert_eq!(hex(&keccak256(b"a")), PATH_A);
    assert_eq!(hex(&keccak256(b"b")), PATH_B);
    assert_eq!(hex(&keccak256(b"c")), PATH_C);
    assert_eq!(hex(&keccak256(b"1")), VALUE_1);
    assert_eq!(hex(&keccak256(b"2")), VALUE_2);
    assert_eq!(hex(&keccak256(b"3")), VALUE_3);
    let leaf = |p: &str, v: &str| hex(&leaf_hash(keccak256, &h32(p), &h32(v)));
    assert_eq!(leaf(PATH_A, VALUE_1), LEAF_A);
    assert_eq!(leaf(PATH_B, VALUE_2), LEAF_B);
    assert_eq!(leaf(PATH_C, VALUE_3), LEAF_C);
}

#[test]
fn shape_and_root() {
    // c (00…) and a (001…) share two bits; b (1…) is alone on the right.
    let ca = branch_hash(keccak256, &h32(LEAF_C), &h32(LEAF_A));
    assert_eq!(hex(&ca), BRANCH_CA);
    let left = branch_hash(keccak256, &ca, &EMPTY);
    assert_eq!(hex(&left), BRANCH_0);
    assert_eq!(hex(&branch_hash(keccak256, &left, &h32(LEAF_B))), ROOT);
    assert_eq!(hex(&example().root()), ROOT);
    // Every insertion order gives the same root.
    let mut t = Trie::new();
    t.insert(b"c", b"3");
    t.insert(b"a", b"1");
    t.insert(b"b", b"2");
    assert_eq!(hex(&t.root()), ROOT);
    // One entry: the root is its leaf. None: zero.
    let mut one = Trie::new();
    one.insert(b"a", b"1");
    assert_eq!(hex(&one.root()), LEAF_A);
    assert!(one.remove(b"a"));
    assert_eq!(one.root(), EMPTY);
}

#[test]
fn proofs() {
    let t = example();
    let root = h32(ROOT);
    let a = t.prove(b"a");
    assert_eq!(hex(&a.encode()), PROOF_A);
    assert_eq!(a.verify(keccak256, &root, b"a"), Ok(Some(h32(VALUE_1))));
    // Absent `d` (1…) ends at the leaf of b.
    let d = t.prove(b"d");
    assert_eq!(hex(&d.encode()), PROOF_D);
    assert_eq!(d.verify(keccak256, &root, b"d"), Ok(None));
    assert_eq!(
        d.terminal,
        Terminal::Leaf {
            path: h32(PATH_B),
            value_hash: h32(VALUE_2)
        }
    );
    // Absent `k1` (01…) ends at the empty side of the depth-1 branch.
    assert_eq!(&hex(&keccak256(b"k1"))[..2], "50");
    let k1 = t.prove(b"k1");
    assert_eq!(hex(&k1.encode()), PROOF_K1);
    assert_eq!(k1.verify(keccak256, &root, b"k1"), Ok(None));
    for (proof, key) in [(PROOF_A, &b"a"[..]), (PROOF_D, b"d"), (PROOF_K1, b"k1")] {
        let bytes: Vec<u8> = (0..proof.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&proof[i..i + 2], 16).unwrap())
            .collect();
        let decoded = Proof::decode(&bytes).unwrap();
        assert_eq!(decoded, t.prove(key));
    }
}
