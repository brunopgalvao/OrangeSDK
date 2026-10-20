//! Hash functions the host provides (spec 05 §4.3) and the code hash (spec 03 §1).

use blake2::Blake2b;
use blake2::digest::consts::U32;
use sha2::Digest;
use tiny_keccak::{Hasher, Keccak};

/// `keccak256` of `data`.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(data);
    k.finalize(&mut out);
    out
}

/// `sha256` of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

/// `blake2b` with a 32-byte digest.
#[must_use]
pub fn blake2b256(data: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }

    #[test]
    fn known_digests() {
        assert_eq!(
            hex(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&blake2b256(b"")),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }
}
