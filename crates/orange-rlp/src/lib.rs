//! Recursive Length Prefix (RLP) as Ethereum defines it: strings and lists,
//! with the canonical-form checks the Yellow Paper requires (no leading
//! zeros in lengths, single bytes below 0x80 never prefixed).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

/// A decoded RLP item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item<'a> {
    /// A byte string.
    Bytes(&'a [u8]),
    /// A list of items.
    List(Vec<Item<'a>>),
}

/// Why decoding failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The input ended inside an item.
    Truncated,
    /// A length that is not in canonical form, or a single byte that should not have been prefixed.
    NonCanonical,
    /// Bytes left after the item.
    Trailing,
    /// The item was not of the expected kind, or an integer had leading zeros or was too wide.
    Shape,
    /// Lists nested deeper than [`MAX_DEPTH`].
    TooDeep,
}

/// The deepest nesting of lists [`decode`] accepts. Every structure OrangeSDK
/// reads from RLP is at most four lists deep (a transaction's access list
/// entry's storage keys, a receipt's log's topics); a limit keeps the
/// recursive decoder's stack bounded, where a 30 KB string of nested lists
/// would otherwise overflow a host thread's stack and abort the process.
pub const MAX_DEPTH: usize = 16;

fn be_len(bytes: &[u8]) -> Result<usize, Error> {
    if bytes.is_empty() || bytes.len() > 8 || bytes[0] == 0 {
        return Err(Error::NonCanonical);
    }
    let mut v: usize = 0;
    for b in bytes {
        v = (v << 8) | usize::from(*b);
    }
    if v < 56 {
        return Err(Error::NonCanonical);
    }
    Ok(v)
}

/// Decodes one item from the start of `input`, returning it and the bytes consumed.
///
/// # Errors
/// See [`Error`].
pub fn decode_prefix(input: &[u8]) -> Result<(Item<'_>, usize), Error> {
    decode_nested(input, 0)
}

/// [`decode_prefix`] for an item inside `depth` lists.
fn decode_nested(input: &[u8], depth: usize) -> Result<(Item<'_>, usize), Error> {
    let first = *input.first().ok_or(Error::Truncated)?;
    let (payload_start, payload_len, is_list) = match first {
        0x00..=0x7F => return Ok((Item::Bytes(&input[..1]), 1)),
        0x80..=0xB7 => (1, usize::from(first - 0x80), false),
        0xB8..=0xBF => {
            let n = usize::from(first - 0xB7);
            let len = be_len(input.get(1..1 + n).ok_or(Error::Truncated)?)?;
            (1 + n, len, false)
        }
        0xC0..=0xF7 => (1, usize::from(first - 0xC0), true),
        0xF8..=0xFF => {
            let n = usize::from(first - 0xF7);
            let len = be_len(input.get(1..1 + n).ok_or(Error::Truncated)?)?;
            (1 + n, len, true)
        }
    };
    let end = payload_start
        .checked_add(payload_len)
        .ok_or(Error::Truncated)?;
    let payload = input.get(payload_start..end).ok_or(Error::Truncated)?;
    if is_list {
        if depth == MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        let mut items = Vec::new();
        let mut pos = 0;
        while pos < payload.len() {
            let (item, used) = decode_nested(&payload[pos..], depth + 1)?;
            items.push(item);
            pos += used;
        }
        Ok((Item::List(items), end))
    } else {
        if payload_len == 1 && payload[0] < 0x80 {
            return Err(Error::NonCanonical);
        }
        Ok((Item::Bytes(payload), end))
    }
}

/// Decodes exactly one item, rejecting trailing bytes.
///
/// # Errors
/// See [`Error`].
pub fn decode(input: &[u8]) -> Result<Item<'_>, Error> {
    let (item, used) = decode_prefix(input)?;
    if used != input.len() {
        return Err(Error::Trailing);
    }
    Ok(item)
}

impl<'a> Item<'a> {
    /// The bytes of a string item.
    ///
    /// # Errors
    /// `Shape` for a list.
    pub fn bytes(&self) -> Result<&'a [u8], Error> {
        match self {
            Item::Bytes(b) => Ok(b),
            Item::List(_) => Err(Error::Shape),
        }
    }

    /// The items of a list.
    ///
    /// # Errors
    /// `Shape` for a string.
    pub fn list(&self) -> Result<&[Item<'a>], Error> {
        match self {
            Item::List(items) => Ok(items),
            Item::Bytes(_) => Err(Error::Shape),
        }
    }

    /// A big-endian unsigned integer without leading zeros, at most 32 bytes.
    ///
    /// # Errors
    /// `Shape` for a list, a leading zero, or more than 32 bytes.
    pub fn u256(&self) -> Result<[u8; 32], Error> {
        let b = self.bytes()?;
        if b.len() > 32 || b.first() == Some(&0) {
            return Err(Error::Shape);
        }
        let mut out = [0u8; 32];
        out[32 - b.len()..].copy_from_slice(b);
        Ok(out)
    }

    /// A big-endian unsigned integer that fits 64 bits.
    ///
    /// # Errors
    /// `Shape` as for [`Item::u256`], or if wider than 8 bytes.
    ///
    /// # Panics
    /// Never; the slice converted is exactly 8 bytes.
    pub fn u64(&self) -> Result<u64, Error> {
        let v = self.u256()?;
        if v[..24].iter().any(|b| *b != 0) {
            return Err(Error::Shape);
        }
        Ok(u64::from_be_bytes(v[24..].try_into().expect("8 bytes")))
    }

    /// A big-endian unsigned integer that fits 128 bits.
    ///
    /// # Errors
    /// `Shape` as for [`Item::u256`], or if wider than 16 bytes.
    ///
    /// # Panics
    /// Never; the slice converted is exactly 16 bytes.
    pub fn u128(&self) -> Result<u128, Error> {
        let v = self.u256()?;
        if v[..16].iter().any(|b| *b != 0) {
            return Err(Error::Shape);
        }
        Ok(u128::from_be_bytes(v[16..].try_into().expect("16 bytes")))
    }

    /// A fixed-size byte string.
    ///
    /// # Errors
    /// `Shape` if the length differs.
    pub fn array<const N: usize>(&self) -> Result<[u8; N], Error> {
        let b = self.bytes()?;
        b.try_into().map_err(|_| Error::Shape)
    }
}

fn encode_length(len: usize, offset: u8, out: &mut Vec<u8>) {
    if len < 56 {
        #[allow(clippy::cast_possible_truncation)]
        out.push(offset + len as u8);
    } else {
        let be = (len as u64).to_be_bytes();
        let skip = be.iter().take_while(|b| **b == 0).count();
        #[allow(clippy::cast_possible_truncation)]
        out.push(offset + 55 + (8 - skip) as u8);
        out.extend_from_slice(&be[skip..]);
    }
}

/// Re-encodes a decoded item. Decoding enforces canonical form, so this
/// reproduces the original bytes exactly.
pub fn encode_item(item: &Item<'_>, out: &mut Vec<u8>) {
    match item {
        Item::Bytes(bytes) => encode_bytes(bytes, out),
        Item::List(items) => {
            let mut payload = Vec::new();
            for i in items {
                encode_item(i, &mut payload);
            }
            encode_list(&payload, out);
        }
    }
}

/// Appends the encoding of a byte string.
pub fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
        return;
    }
    encode_length(bytes.len(), 0x80, out);
    out.extend_from_slice(bytes);
}

/// Appends the encoding of an unsigned integer (big-endian, no leading zeros; zero is the empty string).
pub fn encode_uint(value: u128, out: &mut Vec<u8>) {
    let be = value.to_be_bytes();
    let skip = be.iter().take_while(|b| **b == 0).count();
    encode_bytes(&be[skip..], out);
}

/// Appends the encoding of a list whose items are already encoded in `payload`.
pub fn encode_list(payload: &[u8], out: &mut Vec<u8>) {
    encode_length(payload.len(), 0xC0, out);
    out.extend_from_slice(payload);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;

    fn enc_b(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bytes(b, &mut out);
        out
    }

    #[test]
    fn yellow_paper_examples() {
        assert_eq!(enc_b(b"dog"), vec![0x83, b'd', b'o', b'g']);
        assert_eq!(enc_b(b""), vec![0x80]);
        assert_eq!(enc_b(&[0x0F]), vec![0x0F]);
        assert_eq!(enc_b(&[0x04, 0x00]), vec![0x82, 0x04, 0x00]);
        let mut cat_dog = Vec::new();
        encode_bytes(b"cat", &mut cat_dog);
        encode_bytes(b"dog", &mut cat_dog);
        let mut list = Vec::new();
        encode_list(&cat_dog, &mut list);
        assert_eq!(
            list,
            vec![0xC8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
        );
        let mut empty = Vec::new();
        encode_list(&[], &mut empty);
        assert_eq!(empty, vec![0xC0]);
        let long = vec![b'a'; 1024];
        let enc = enc_b(&long);
        assert_eq!(&enc[..3], &[0xB9, 0x04, 0x00]);
        assert_eq!(decode(&enc), Ok(Item::Bytes(&long)));
        let mut uint = Vec::new();
        encode_uint(0, &mut uint);
        encode_uint(1, &mut uint);
        encode_uint(1024, &mut uint);
        assert_eq!(uint, vec![0x80, 0x01, 0x82, 0x04, 0x00]);
        // A list longer than 55 bytes uses the long-list form.
        let mut payload = Vec::new();
        for _ in 0..20 {
            encode_bytes(b"abc", &mut payload);
        }
        let mut big = Vec::new();
        encode_list(&payload, &mut big);
        assert_eq!(big[0], 0xF8);
        assert_eq!(big[1], 80);
        assert_eq!(decode(&big).unwrap().list().unwrap().len(), 20);
    }

    #[test]
    fn decoding_and_accessors() {
        let item = decode(&[0xC8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']).unwrap();
        let items = item.list().unwrap();
        assert_eq!(items[0].bytes(), Ok(&b"cat"[..]));
        assert_eq!(items[1].bytes(), Ok(&b"dog"[..]));
        assert_eq!(item.bytes(), Err(Error::Shape));
        assert_eq!(items[0].list(), Err(Error::Shape));
        assert_eq!(decode(&[0x82, 0x04, 0x00]).unwrap().u64(), Ok(1024));
        assert_eq!(decode(&[0x80]).unwrap().u64(), Ok(0));
        assert_eq!(decode(&[0x80]).unwrap().u128(), Ok(0));
        assert_eq!(decode(&[0x7F]).unwrap().u64(), Ok(127));
        assert_eq!(
            decode(&[0x82, 0x00, 0x01]).unwrap().u64(),
            Err(Error::Shape)
        );
        let nine = decode(&[0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(nine.u64(), Err(Error::Shape));
        assert_eq!(nine.u128(), Ok(1u128 << 64));
        let seventeen = decode(&[0x91, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(seventeen.u128(), Err(Error::Shape));
        assert_eq!(seventeen.u256().unwrap()[15], 1);
        let mut wide = vec![0xA1];
        wide.extend_from_slice(&[1u8; 33]);
        assert_eq!(decode(&wide).unwrap().u256(), Err(Error::Shape));
        assert_eq!(decode(&[0x82, 1, 2]).unwrap().array::<2>(), Ok([1, 2]));
        assert_eq!(
            decode(&[0x82, 1, 2]).unwrap().array::<3>(),
            Err(Error::Shape)
        );
        assert_eq!(decode(&[0xC0]).unwrap().u256(), Err(Error::Shape));
    }

    #[test]
    fn malformed_inputs() {
        assert_eq!(decode(&[]), Err(Error::Truncated));
        assert_eq!(decode(&[0x83, b'd', b'o']), Err(Error::Truncated));
        assert_eq!(decode(&[0xB8]), Err(Error::Truncated));
        assert_eq!(decode(&[0xB8, 0x05, 1, 2]), Err(Error::NonCanonical)); // long form for a short length
        assert_eq!(decode(&[0xB8, 0x40, 1, 2]), Err(Error::Truncated));
        assert_eq!(decode(&[0xC8, 0x83, b'c']), Err(Error::Truncated));
        assert_eq!(decode(&[0x81, 0x05]), Err(Error::NonCanonical));
        assert_eq!(decode(&[0xB8, 0x01, 0xAA]), Err(Error::NonCanonical));
        assert_eq!(decode(&[0xB9, 0x00, 0x40]), Err(Error::NonCanonical));
        assert_eq!(decode(&[0xF8, 0x01, 0x05]), Err(Error::NonCanonical));
        assert_eq!(decode(&[0x05, 0x06]), Err(Error::Trailing));
        assert_eq!(decode(&[0xC2, 0x81, 0x01]), Err(Error::NonCanonical));
        assert_eq!(decode(&[0xF8]), Err(Error::Truncated));
        assert!(alloc::format!("{:?}", Error::Shape).contains("Shape"));
        assert!(alloc::format!("{:?}", Item::Bytes(&[1])).contains("Bytes"));
    }

    fn nested(depth: usize) -> Vec<u8> {
        let mut v = Vec::new();
        for _ in 0..depth {
            let mut out = Vec::new();
            encode_list(&v, &mut out);
            v = out;
        }
        v
    }

    #[test]
    fn nesting_is_bounded() {
        assert!(decode(&nested(MAX_DEPTH)).is_ok());
        assert_eq!(decode(&nested(MAX_DEPTH + 1)), Err(Error::TooDeep));
        // 40 000 lists in 120 KB, under the mempool's 128 KiB transaction
        // limit, used to overflow the stack and abort the process.
        assert_eq!(decode(&nested(40_000)), Err(Error::TooDeep));
    }

    #[test]
    fn items_reencode_exactly() {
        let mut inner = Vec::new();
        encode_bytes(&[1, 2, 3], &mut inner);
        encode_bytes(&[0x7F], &mut inner);
        encode_bytes(&[0xAB; 60], &mut inner);
        let mut nested = Vec::new();
        encode_list(&inner, &mut nested);
        let mut outer = Vec::new();
        encode_list(&[nested.clone(), enc_b(&[])].concat(), &mut outer);
        let item = decode(&outer).unwrap();
        let mut again = Vec::new();
        encode_item(&item, &mut again);
        assert_eq!(again, outer);
    }

    proptest! {
        #[test]
        fn bytes_roundtrip(v in proptest::collection::vec(any::<u8>(), 0..300)) {
            let enc = enc_b(&v);
            prop_assert_eq!(decode(&enc), Ok(Item::Bytes(&v)));
        }

        #[test]
        fn uint_roundtrip(v in any::<u128>()) {
            let mut out = Vec::new();
            encode_uint(v, &mut out);
            prop_assert_eq!(decode(&out).unwrap().u128(), Ok(v));
        }

        #[test]
        fn lists_roundtrip(items in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..40), 0..20)) {
            let mut payload = Vec::new();
            for i in &items {
                encode_bytes(i, &mut payload);
            }
            let mut out = Vec::new();
            encode_list(&payload, &mut out);
            let decoded = decode(&out).unwrap();
            let list = decoded.list().unwrap();
            prop_assert_eq!(list.len(), items.len());
            for (d, i) in list.iter().zip(&items) {
                prop_assert_eq!(d.bytes(), Ok(i.as_slice()));
            }
        }
    }
}
