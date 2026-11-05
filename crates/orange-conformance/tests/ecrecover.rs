//! The ECRECOVER precompile (address 0x01) as the kernel runs it: revm's
//! precompile over the kernel's `HostCrypto::secp256k1_ecrecover`, which
//! mirrors a high-s signature to `(r, n - s)` with the parity flipped, over
//! the host's `secp256k1_recover` (spec 07 §4.2).
//!
//! The pinned execution-spec release recovers senders on every transaction
//! but never makes a contract call the precompile on a real signature, so
//! these cases do: valid signatures with low and high s and both parities,
//! and every input Ethereum answers with empty output. A contract calls the
//! precompile and stores what came back; the expected addresses come from
//! go-ethereum's own signature vector and from signing on the host with
//! `k256`, independently of the guest.

mod common;

use common::{CONTRACT, case};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use orange_abi::chain::call_status;
use orange_conformance::{GUEST, Runner};
use orange_host::Backend;
use orange_host::hash::keccak256;

/// The order of secp256k1.
const N: [u8; 32] = word("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        _ => c - b'a' + 10,
    }
}

/// A 32-byte word from 64 lowercase hex digits.
const fn word(hex: &str) -> [u8; 32] {
    let h = hex.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(h[2 * i]) << 4) | nibble(h[2 * i + 1]);
        i += 1;
    }
    out
}

fn uint(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// `a - b` for big-endian words with `a >= b`.
fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(a[i]) - i16::from(b[i]) - borrow;
        borrow = i16::from(d < 0);
        if d < 0 {
            d += 256;
        }
        out[i] = u8::try_from(d).unwrap();
    }
    out
}

fn address_of(key: &VerifyingKey) -> [u8; 20] {
    let point = key.to_encoded_point(false);
    keccak256(&point.as_bytes()[1..])[12..].try_into().unwrap()
}

/// The precompile's 128-byte input.
fn input(hash: [u8; 32], v: [u8; 32], r: [u8; 32], s: [u8; 32]) -> [u8; 128] {
    let mut out = [0u8; 128];
    for (i, w) in [hash, v, r, s].iter().enumerate() {
        out[32 * i..32 * i + 32].copy_from_slice(w);
    }
    out
}

/// Writes `input` to memory, `STATICCALL`s 0x01 with it, and stores the
/// call's success in slot 2, the return data size in slot 1 and the first
/// returned word in slot 0.
fn recovering_contract(input: &[u8; 128]) -> Vec<u8> {
    let mut code = Vec::new();
    for (i, w) in input.chunks(32).enumerate() {
        code.push(0x7F);
        code.extend_from_slice(w);
        code.extend_from_slice(&[0x60, u8::try_from(32 * i).unwrap(), 0x52]);
    }
    code.extend_from_slice(&[
        0x60, 0x20, 0x60, 0x80, 0x60, 0x80, 0x60, 0x00, 0x60, 0x01, 0x5A, 0xFA, // STATICCALL
        0x60, 0x02, 0x55, // SSTORE(2, success)
        0x3D, 0x60, 0x01, 0x55, // SSTORE(1, RETURNDATASIZE)
        0x60, 0x80, 0x51, 0x60, 0x00, 0x55, // SSTORE(0, MLOAD(0x80))
        0x00,
    ]);
    code
}

/// Runs the precompile on `input` on both backends and returns the address it
/// recovered, `None` for empty output.
fn recover(input: &[u8; 128]) -> Option<[u8; 20]> {
    let mut results = Vec::new();
    for backend in [Backend::Interpreter, Backend::Native] {
        let executed = Runner::new(GUEST, backend)
            .unwrap()
            .run(&case(recovering_contract(input), 200_000, Vec::new()))
            .unwrap();
        assert_eq!(executed.outcome.status, call_status::SUCCESS, "{backend:?}");
        let storage = &executed.post[&CONTRACT].storage;
        assert_eq!(storage.get(&uint(2)), Some(&uint(1)), "the call succeeds");
        let size = storage.get(&uint(1)).copied().unwrap_or_default();
        let word = storage.get(&uint(0)).copied().unwrap_or_default();
        let recovered = if size == uint(32) {
            assert_eq!(word[..12], [0; 12], "an address word");
            Some(word[12..].try_into().unwrap())
        } else {
            assert_eq!((size, word), ([0; 32], [0; 32]), "empty output");
            None
        };
        results.push(recovered);
    }
    assert_eq!(results[0], results[1], "the backends agree");
    results[0]
}

/// go-ethereum's signature test vector (`crypto/signature_test.go`).
#[test]
fn go_ethereum_vector_recovers_its_key() {
    let hash = word("ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008");
    let r = word("90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e54998");
    let s = word("4a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc93");
    let public = bytes(
        "e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a\
         0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652",
    );
    let expected: [u8; 20] = keccak256(&public)[12..].try_into().unwrap();
    assert_eq!(recover(&input(hash, uint(28), r, s)), Some(expected));
    // The other parity names a different key, or none.
    assert_ne!(recover(&input(hash, uint(27), r, s)), Some(expected));
}

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|p| (nibble(p[0]) << 4) | nibble(p[1]))
        .collect()
}

/// A signature by `[2; 32]` over `hash`: its address, `v`, `r` and low `s`.
fn signed(hash: &[u8; 32]) -> ([u8; 20], u64, [u8; 32], [u8; 32]) {
    let key = SigningKey::from_slice(&[2; 32]).unwrap();
    let (sig, rid) = key.sign_prehash_recoverable(hash).unwrap();
    let (sig, rid) = match sig.normalize_s() {
        Some(low) => (low, RecoveryId::from_byte(rid.to_byte() ^ 1).unwrap()),
        None => (sig, rid),
    };
    (
        address_of(key.verifying_key()),
        27 + u64::from(rid.to_byte()),
        sig.r().to_bytes().into(),
        sig.s().to_bytes().into(),
    )
}

/// What `k256` recovers from `(r, s)` with parity `rid`, if anything.
fn host_recover(hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32], rid: u8) -> Option<[u8; 20]> {
    let sig = Signature::from_scalars(*r, *s).ok()?;
    let rid = RecoveryId::from_byte(rid)?;
    VerifyingKey::recover_from_prehash(hash, &sig, rid)
        .ok()
        .map(|k| address_of(&k))
}

#[test]
fn low_and_high_s_recover_the_signer() {
    for message in [b"orange".as_slice(), b"conformance", b"ecrecover"] {
        let hash = keccak256(message);
        let (signer, v, r, s) = signed(&hash);
        assert_eq!(recover(&input(hash, uint(v), r, s)), Some(signer), "low s");
        // Ethereum's precompile accepts high s (EIP-2 binds only
        // transactions): (r, n - s) with the other parity is the same key.
        let high = sub(&N, &s);
        let flipped = if v == 27 { 28 } else { 27 };
        assert_eq!(
            recover(&input(hash, uint(flipped), r, high)),
            Some(signer),
            "high s"
        );
        // Wrong parity: whatever the curve gives, which is not the signer.
        let wrong = host_recover(&hash, &r, &s, u8::try_from(flipped - 27).unwrap());
        assert_ne!(wrong, Some(signer));
        assert_eq!(recover(&input(hash, uint(flipped), r, s)), wrong, "wrong v");
    }
}

#[test]
fn malformed_inputs_return_nothing() {
    let hash = keccak256(b"orange");
    let (_, v, r, s) = signed(&hash);
    let mut high_byte_v = uint(v);
    high_byte_v[0] = 1;
    let one = uint(1);
    for (name, v, r, s) in [
        ("v = 0", uint(0), r, s),
        ("v = 1", uint(1), r, s),
        ("v = 29", uint(29), r, s),
        ("v with a high byte set", high_byte_v, r, s),
        ("r = 0", uint(v), [0; 32], s),
        ("r = n", uint(v), N, s),
        ("r > n", uint(v), sub(&[0xFF; 32], &one), s),
        ("s = 0", uint(v), r, [0; 32]),
        ("s = n", uint(v), r, N),
        ("s > n", uint(v), r, [0xFF; 32]),
    ] {
        assert_eq!(recover(&input(hash, v, r, s)), None, "{name}");
    }
}
