//! Canonical LEB128 (spec 02 §2).
//!
//! `u:n` is unsigned, at most 5 bytes, value below 2^32. `s:imm` is signed, at
//! most 10 bytes, any `i64`. An encoding is canonical when it is the shortest
//! that represents the value; a decoder rejects everything else so that every
//! instruction has exactly one byte representation.

use alloc::vec::Vec;

/// Why a LEB128 read failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LebError {
    /// The input ended inside the number.
    Truncated,
    /// More bytes than the maximum for this kind, or bits beyond the value range.
    Overflow,
    /// A longer encoding than necessary.
    NonCanonical,
}

/// Maximum byte length of `u:n`.
pub const ULEB_MAX_LEN: usize = 5;
/// Maximum byte length of `s:imm`.
pub const SLEB_MAX_LEN: usize = 10;

/// Reads a canonical `u:n`, returning the value and the bytes consumed.
///
/// # Errors
/// See [`LebError`].
pub fn read_uleb(bytes: &[u8]) -> Result<(u32, usize), LebError> {
    let mut value: u64 = 0;
    for (i, &b) in bytes.iter().enumerate().take(ULEB_MAX_LEN) {
        value |= u64::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            if value > u64::from(u32::MAX) {
                return Err(LebError::Overflow);
            }
            let len = i + 1;
            #[allow(clippy::cast_possible_truncation)]
            let value = value as u32;
            if uleb_len(value) != len {
                return Err(LebError::NonCanonical);
            }
            return Ok((value, len));
        }
    }
    if bytes.len() < ULEB_MAX_LEN {
        Err(LebError::Truncated)
    } else {
        Err(LebError::Overflow)
    }
}

/// Reads a canonical `s:imm`, returning the value and the bytes consumed.
///
/// # Errors
/// See [`LebError`].
pub fn read_sleb(bytes: &[u8]) -> Result<(i64, usize), LebError> {
    let mut value: u64 = 0;
    for (i, &b) in bytes.iter().enumerate().take(SLEB_MAX_LEN) {
        let shift = 7 * i;
        let payload = u64::from(b & 0x7F);
        if i == SLEB_MAX_LEN - 1 {
            // Only bit 63 remains; the byte must be 0x00 or 0x7F (sign fill).
            if b != 0x00 && b != 0x7F {
                return Err(LebError::Overflow);
            }
            value |= (payload & 1) << 63;
        } else {
            value |= payload << shift;
        }
        if b & 0x80 == 0 {
            let len = i + 1;
            let bits = 7 * len;
            #[allow(clippy::cast_possible_wrap)]
            let signed = if bits < 64 && (b & 0x40) != 0 {
                (value | (u64::MAX << bits)) as i64
            } else {
                value as i64
            };
            if sleb_len(signed) != len {
                return Err(LebError::NonCanonical);
            }
            return Ok((signed, len));
        }
    }
    // The tenth byte always returns above, so reaching here means the input
    // ended early.
    Err(LebError::Truncated)
}

/// Byte length of the canonical encoding of `v`.
#[must_use]
pub const fn uleb_len(v: u32) -> usize {
    let mut v = v;
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// Byte length of the canonical encoding of `v`.
#[must_use]
pub const fn sleb_len(v: i64) -> usize {
    let mut v = v;
    let mut n = 1;
    loop {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        let done = (v == 0 && byte & 0x40 == 0) || (v == -1 && byte & 0x40 != 0);
        if done {
            return n;
        }
        n += 1;
    }
}

/// Appends the canonical encoding of `v`.
pub fn write_uleb(v: u32, out: &mut Vec<u8>) {
    let mut v = v;
    loop {
        #[allow(clippy::cast_possible_truncation)]
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Appends the canonical encoding of `v`.
pub fn write_sleb(v: i64, out: &mut Vec<u8>) {
    let mut v = v;
    loop {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        let done = (v == 0 && byte & 0x40 == 0) || (v == -1 && byte & 0x40 != 0);
        if done {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;

    #[test]
    fn uleb_known_values() {
        let cases: [(u32, &[u8]); 6] = [
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7F]),
            (128, &[0x80, 0x01]),
            (16_383, &[0xFF, 0x7F]),
            (u32::MAX, &[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]),
        ];
        for (v, enc) in cases {
            let mut out = Vec::new();
            write_uleb(v, &mut out);
            assert_eq!(out, enc, "encode {v}");
            assert_eq!(read_uleb(enc), Ok((v, enc.len())), "decode {v}");
            assert_eq!(uleb_len(v), enc.len());
        }
    }

    #[test]
    fn uleb_rejects_non_canonical_truncated_and_overflow() {
        assert_eq!(read_uleb(&[0x80, 0x00]), Err(LebError::NonCanonical));
        assert_eq!(read_uleb(&[0xFF, 0x80, 0x00]), Err(LebError::NonCanonical));
        assert_eq!(read_uleb(&[]), Err(LebError::Truncated));
        assert_eq!(read_uleb(&[0x80]), Err(LebError::Truncated));
        assert_eq!(
            read_uleb(&[0x80, 0x80, 0x80, 0x80]),
            Err(LebError::Truncated)
        );
        // 2^32 needs bit 32: fifth byte 0x10.
        assert_eq!(
            read_uleb(&[0x80, 0x80, 0x80, 0x80, 0x10]),
            Err(LebError::Overflow)
        );
        // Six bytes with continuation set on the fifth.
        assert_eq!(
            read_uleb(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01]),
            Err(LebError::Overflow)
        );
    }

    #[test]
    fn sleb_known_values() {
        let cases: [(i64, &[u8]); 10] = [
            (0, &[0x00]),
            (1, &[0x01]),
            (-1, &[0x7F]),
            (63, &[0x3F]),
            (64, &[0xC0, 0x00]),
            (-64, &[0x40]),
            (-65, &[0xBF, 0x7F]),
            (128, &[0x80, 0x01]),
            (
                i64::MAX,
                &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00],
            ),
            (
                i64::MIN,
                &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F],
            ),
        ];
        for (v, enc) in cases {
            let mut out = Vec::new();
            write_sleb(v, &mut out);
            assert_eq!(out, enc, "encode {v}");
            assert_eq!(read_sleb(enc), Ok((v, enc.len())), "decode {v}");
            assert_eq!(sleb_len(v), enc.len());
        }
    }

    #[test]
    fn sleb_rejects_non_canonical_truncated_and_overflow() {
        // 0 written in two bytes, -1 written in two bytes.
        assert_eq!(read_sleb(&[0x80, 0x00]), Err(LebError::NonCanonical));
        assert_eq!(read_sleb(&[0xFF, 0x7F]), Err(LebError::NonCanonical));
        assert_eq!(read_sleb(&[]), Err(LebError::Truncated));
        assert_eq!(read_sleb(&[0x80]), Err(LebError::Truncated));
        // Tenth byte may only be 0x00 or 0x7F.
        assert_eq!(
            read_sleb(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]),
            Err(LebError::Overflow)
        );
        // Eleven bytes.
        assert_eq!(
            read_sleb(&[
                0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00
            ]),
            Err(LebError::Overflow)
        );
        // Ten bytes, continuation set on the ninth, tenth byte 0x7F but value
        // representable in nine bytes: non-canonical.
        assert_eq!(
            read_sleb(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]),
            Err(LebError::NonCanonical)
        );
    }

    #[test]
    fn errors_are_debuggable() {
        assert_eq!(alloc::format!("{:?}", LebError::Overflow), "Overflow");
        let v: Vec<u8> = vec![];
        assert!(v.is_empty());
    }

    proptest! {
        #[test]
        fn uleb_roundtrip(v in any::<u32>()) {
            let mut out = Vec::new();
            write_uleb(v, &mut out);
            prop_assert_eq!(out.len(), uleb_len(v));
            prop_assert_eq!(read_uleb(&out), Ok((v, out.len())));
        }

        #[test]
        fn sleb_roundtrip(v in any::<i64>()) {
            let mut out = Vec::new();
            write_sleb(v, &mut out);
            prop_assert_eq!(out.len(), sleb_len(v));
            prop_assert_eq!(read_sleb(&out), Ok((v, out.len())));
        }

        #[test]
        fn uleb_padding_is_rejected(v in any::<u32>()) {
            let mut out = Vec::new();
            write_uleb(v, &mut out);
            if out.len() < ULEB_MAX_LEN {
                let last = out.len() - 1;
                out[last] |= 0x80;
                out.push(0x00);
                prop_assert_eq!(read_uleb(&out), Err(LebError::NonCanonical));
            }
        }
    }
}
