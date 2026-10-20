//! The canonical encoding (spec 06 §2): little-endian fixed integers,
//! ULEB128-length-prefixed bytes and vectors, one-byte enum tags, and
//! `option` as a 0 or 1 byte. Two encodings of the same value are
//! byte-identical, and a decoder rejects anything that is not canonical.

use alloc::string::String;
use alloc::vec::Vec;

/// Why decoding failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended early.
    Truncated,
    /// A length prefix that is not the shortest ULEB128, or above 2^32.
    BadLength,
    /// An enum tag or option byte outside its range.
    BadTag(u8),
    /// A `String` that is not UTF-8.
    BadUtf8,
    /// Bytes left after the value.
    Trailing,
}

/// Appends encodings to a buffer.
#[derive(Debug, Default)]
pub struct Encoder {
    out: Vec<u8>,
}

impl Encoder {
    /// An empty encoder.
    #[must_use]
    pub fn new() -> Encoder {
        Encoder::default()
    }

    /// The bytes written so far.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.out
    }

    /// Writes a canonical ULEB128 length.
    pub fn write_len(&mut self, n: usize) {
        let mut v = n as u64;
        loop {
            #[allow(clippy::cast_possible_truncation)]
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                self.out.push(byte);
                return;
            }
            self.out.push(byte | 0x80);
        }
    }

    /// Writes raw bytes with no prefix.
    pub fn raw(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    /// Writes a value.
    pub fn put<T: Encode + ?Sized>(&mut self, value: &T) -> &mut Self {
        value.encode(self);
        self
    }
}

/// Reads encodings from a slice.
#[derive(Debug)]
pub struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// A decoder over `bytes`.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Decoder<'a> {
        Decoder { bytes, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    /// Takes `n` raw bytes.
    ///
    /// # Errors
    /// `Truncated` if fewer remain.
    pub fn raw(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        let s = self
            .bytes
            .get(self.pos..end)
            .ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    /// Reads a canonical ULEB128 length below 2^32.
    ///
    /// # Errors
    /// `BadLength` for a non-canonical or oversized prefix, `Truncated` at end of input.
    pub fn read_len(&mut self) -> Result<usize, DecodeError> {
        let mut value: u64 = 0;
        for i in 0..5 {
            let b = *self.bytes.get(self.pos + i).ok_or(DecodeError::Truncated)?;
            value |= u64::from(b & 0x7F) << (7 * i);
            if b & 0x80 == 0 {
                let canonical = i == 0 || b != 0;
                if !canonical || value > u64::from(u32::MAX) {
                    return Err(DecodeError::BadLength);
                }
                self.pos += i + 1;
                return usize::try_from(value).map_err(|_| DecodeError::BadLength);
            }
        }
        Err(DecodeError::BadLength)
    }

    /// Reads a value.
    ///
    /// # Errors
    /// See [`DecodeError`].
    pub fn get<T: Decode>(&mut self) -> Result<T, DecodeError> {
        T::decode(self)
    }

    /// Fails unless every byte was consumed.
    ///
    /// # Errors
    /// `Trailing` if bytes remain.
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(DecodeError::Trailing)
        }
    }
}

/// A value with a canonical encoding.
pub trait Encode {
    /// Appends the encoding.
    fn encode(&self, e: &mut Encoder);

    /// The encoding as a fresh vector.
    fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode(&mut e);
        e.finish()
    }
}

/// A value that can be decoded.
pub trait Decode: Sized {
    /// Reads one value.
    ///
    /// # Errors
    /// See [`DecodeError`].
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError>;

    /// Decodes exactly `bytes`, rejecting trailing data.
    ///
    /// # Errors
    /// See [`DecodeError`].
    fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(bytes);
        let v = Self::decode(&mut d)?;
        d.finish()?;
        Ok(v)
    }
}

macro_rules! int {
    ($($t:ty),*) => {$(
        impl Encode for $t {
            fn encode(&self, e: &mut Encoder) {
                e.raw(&self.to_le_bytes());
            }
        }
        impl Decode for $t {
            fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                let raw = d.raw(core::mem::size_of::<$t>())?;
                Ok(<$t>::from_le_bytes(raw.try_into().expect("exact size")))
            }
        }
    )*};
}
int!(u8, u16, u32, u64, u128, i64);

impl Encode for bool {
    fn encode(&self, e: &mut Encoder) {
        e.raw(&[u8::from(*self)]);
    }
}

impl Decode for bool {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match d.raw(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            t => Err(DecodeError::BadTag(t)),
        }
    }
}

impl<const N: usize> Encode for [u8; N] {
    fn encode(&self, e: &mut Encoder) {
        e.raw(self);
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(d.raw(N)?.try_into().expect("exact size"))
    }
}

impl Encode for [u8] {
    fn encode(&self, e: &mut Encoder) {
        e.write_len(self.len());
        e.raw(self);
    }
}

impl Encode for Vec<u8> {
    fn encode(&self, e: &mut Encoder) {
        self.as_slice().encode(e);
    }
}

impl Decode for Vec<u8> {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let n = d.read_len()?;
        Ok(d.raw(n)?.to_vec())
    }
}

impl Encode for str {
    fn encode(&self, e: &mut Encoder) {
        self.as_bytes().encode(e);
    }
}

impl Encode for String {
    fn encode(&self, e: &mut Encoder) {
        self.as_str().encode(e);
    }
}

impl Decode for String {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        String::from_utf8(Vec::<u8>::decode(d)?).map_err(|_| DecodeError::BadUtf8)
    }
}

/// Vectors of non-byte values: a count followed by the elements.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Seq<T>(pub Vec<T>);

impl<T: Encode> Encode for Seq<T> {
    fn encode(&self, e: &mut Encoder) {
        e.write_len(self.0.len());
        for item in &self.0 {
            item.encode(e);
        }
    }
}

impl<T: Decode> Decode for Seq<T> {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let n = d.read_len()?;
        let mut v = Vec::new();
        for _ in 0..n {
            v.push(T::decode(d)?);
        }
        Ok(Seq(v))
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode(&self, e: &mut Encoder) {
        match self {
            None => e.raw(&[0]),
            Some(v) => {
                e.raw(&[1]);
                v.encode(e);
            }
        }
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match d.raw(1)?[0] {
            0 => Ok(None),
            1 => Ok(Some(T::decode(d)?)),
            t => Err(DecodeError::BadTag(t)),
        }
    }
}

impl Encode for () {
    fn encode(&self, _: &mut Encoder) {}
}

impl Decode for () {
    fn decode(_: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;

    #[test]
    fn integers_and_arrays() {
        assert_eq!(0x0102u16.to_bytes(), vec![2, 1]);
        assert_eq!(1u32.to_bytes(), vec![1, 0, 0, 0]);
        assert_eq!((-1i64).to_bytes(), vec![0xFF; 8]);
        assert_eq!(u128::MAX.to_bytes().len(), 16);
        assert_eq!(7u8.to_bytes(), vec![7]);
        assert_eq!([9u8; 3].to_bytes(), vec![9, 9, 9]);
        assert_eq!(u64::from_bytes(&[5, 0, 0, 0, 0, 0, 0, 0]), Ok(5));
        assert_eq!(u64::from_bytes(&[5, 0, 0]), Err(DecodeError::Truncated));
        assert_eq!(u8::from_bytes(&[1, 2]), Err(DecodeError::Trailing));
        assert_eq!(<[u8; 2]>::from_bytes(&[1, 2]), Ok([1, 2]));
        assert_eq!(<[u8; 2]>::from_bytes(&[1]), Err(DecodeError::Truncated));
        assert_eq!(true.to_bytes(), vec![1]);
        assert_eq!(bool::from_bytes(&[0]), Ok(false));
        assert_eq!(bool::from_bytes(&[1]), Ok(true));
        assert_eq!(bool::from_bytes(&[2]), Err(DecodeError::BadTag(2)));
        assert_eq!(().to_bytes(), Vec::<u8>::new());
        assert_eq!(<()>::from_bytes(&[]), Ok(()));
    }

    #[test]
    fn bytes_strings_and_lengths() {
        assert_eq!(b"abc".to_vec().to_bytes(), vec![3, b'a', b'b', b'c']);
        assert_eq!(
            Vec::<u8>::from_bytes(&[3, b'a', b'b', b'c']),
            Ok(b"abc".to_vec())
        );
        assert_eq!("hi".to_bytes(), vec![2, b'h', b'i']);
        assert_eq!(String::from("hi").to_bytes(), vec![2, b'h', b'i']);
        assert_eq!(String::from_bytes(&[2, b'h', b'i']), Ok(String::from("hi")));
        assert_eq!(String::from_bytes(&[1, 0xFF]), Err(DecodeError::BadUtf8));
        let long = vec![7u8; 300];
        let enc = long.to_bytes();
        assert_eq!(&enc[..2], &[0xAC, 0x02]);
        assert_eq!(Vec::<u8>::from_bytes(&enc), Ok(long));
        // Non-canonical length, truncated body, oversized length.
        assert_eq!(
            Vec::<u8>::from_bytes(&[0x80, 0x00]),
            Err(DecodeError::BadLength)
        );
        assert_eq!(
            Vec::<u8>::from_bytes(&[5, 1, 2]),
            Err(DecodeError::Truncated)
        );
        assert_eq!(
            Vec::<u8>::from_bytes(&[0x80, 0x80, 0x80, 0x80, 0x10]),
            Err(DecodeError::BadLength)
        );
        assert_eq!(
            Vec::<u8>::from_bytes(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01]),
            Err(DecodeError::BadLength)
        );
        assert_eq!(Vec::<u8>::from_bytes(&[0x80]), Err(DecodeError::Truncated));
        assert_eq!(Vec::<u8>::from_bytes(&[]), Err(DecodeError::Truncated));
        let mut d = Decoder::new(&[1, 2, 3]);
        assert_eq!(d.remaining(), 3);
        assert_eq!(d.raw(2), Ok(&[1u8, 2][..]));
        assert_eq!(d.raw(usize::MAX), Err(DecodeError::Truncated));
        assert_eq!(d.remaining(), 1);
        assert_eq!(d.finish(), Err(DecodeError::Trailing));
        assert!(alloc::format!("{:?}", Decoder::new(&[])).contains("Decoder"));
        assert!(alloc::format!("{:?}", Encoder::new()).contains("Encoder"));
    }

    #[test]
    fn sequences_and_options() {
        let s = Seq(vec![1u16, 2, 3]);
        assert_eq!(s.to_bytes(), vec![3, 1, 0, 2, 0, 3, 0]);
        assert_eq!(
            Seq::<u16>::from_bytes(&[3, 1, 0, 2, 0, 3, 0]),
            Ok(s.clone())
        );
        assert_eq!(
            Seq::<u16>::from_bytes(&[2, 1, 0]),
            Err(DecodeError::Truncated)
        );
        assert_eq!(Seq::<u16>::default(), Seq(vec![]));
        assert_eq!(Some(5u8).to_bytes(), vec![1, 5]);
        assert_eq!(None::<u8>.to_bytes(), vec![0]);
        assert_eq!(Option::<u8>::from_bytes(&[1, 5]), Ok(Some(5)));
        assert_eq!(Option::<u8>::from_bytes(&[0]), Ok(None));
        assert_eq!(Option::<u8>::from_bytes(&[2]), Err(DecodeError::BadTag(2)));
        assert_eq!(Option::<u8>::from_bytes(&[]), Err(DecodeError::Truncated));
        let mut e = Encoder::new();
        e.put(&1u8).put(&Some(2u8)).put("x");
        assert_eq!(e.finish(), vec![1, 1, 2, 1, b'x']);
        let mut d = Decoder::new(&[1, 1, 2]);
        assert_eq!(d.get::<u8>(), Ok(1));
        assert_eq!(d.get::<Option<u8>>(), Ok(Some(2)));
        assert_eq!(d.finish(), Ok(()));
    }

    proptest! {
        #[test]
        fn bytes_roundtrip(v in proptest::collection::vec(any::<u8>(), 0..2000)) {
            prop_assert_eq!(Vec::<u8>::from_bytes(&v.to_bytes()), Ok(v));
        }

        #[test]
        fn ints_roundtrip(a in any::<u64>(), b in any::<i64>(), c in any::<u128>()) {
            let mut e = Encoder::new();
            e.put(&a).put(&b).put(&c);
            let bytes = e.finish();
            let mut d = Decoder::new(&bytes);
            prop_assert_eq!(d.get::<u64>(), Ok(a));
            prop_assert_eq!(d.get::<i64>(), Ok(b));
            prop_assert_eq!(d.get::<u128>(), Ok(c));
            prop_assert_eq!(d.finish(), Ok(()));
        }
    }
}
