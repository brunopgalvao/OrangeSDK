//! The Solidity ABI encoding of the calls a relayer makes (spec 17 §7):
//! enough of the encoding for words, `bytes`, `bytes32[]` and tuples.

use solo_abi::types::{Address, Hash};
use solo_trie::keccak256;

/// A value to encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A 32-byte word: any integer, `address`, `bool` or `bytes32`.
    Word(Hash),
    /// `bytes`.
    Bytes(Vec<u8>),
    /// `bytes32[]` (or any array of words).
    Words(Vec<Hash>),
    /// A tuple (a Solidity struct).
    Tuple(Vec<Value>),
}

impl Value {
    /// An unsigned integer word.
    #[must_use]
    pub fn uint(v: u128) -> Value {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&v.to_be_bytes());
        Value::Word(w)
    }

    /// An address word.
    #[must_use]
    pub fn address(a: &Address) -> Value {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(a);
        Value::Word(w)
    }

    fn is_dynamic(&self) -> bool {
        match self {
            Value::Word(_) => false,
            Value::Bytes(_) | Value::Words(_) => true,
            Value::Tuple(items) => items.iter().any(Value::is_dynamic),
        }
    }

    /// The encoding of this value where it stands in a tail, or inline for a static one.
    fn encode_body(&self) -> Vec<u8> {
        match self {
            Value::Word(w) => w.to_vec(),
            Value::Bytes(b) => {
                let mut out = len_word(b.len()).to_vec();
                out.extend_from_slice(b);
                out.resize(32 + b.len().next_multiple_of(32), 0);
                out
            }
            Value::Words(words) => {
                let mut out = len_word(words.len()).to_vec();
                for w in words {
                    out.extend_from_slice(w);
                }
                out
            }
            Value::Tuple(items) => encode(items),
        }
    }
}

fn len_word(n: usize) -> Hash {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&(n as u64).to_be_bytes());
    w
}

/// The head-and-tail encoding of `values`, as of a function's arguments.
#[must_use]
pub fn encode(values: &[Value]) -> Vec<u8> {
    let head_len: usize = values
        .iter()
        .map(|v| {
            if v.is_dynamic() {
                32
            } else {
                v.encode_body().len()
            }
        })
        .sum();
    let mut head = Vec::with_capacity(head_len);
    let mut tail = Vec::new();
    for v in values {
        let body = v.encode_body();
        if v.is_dynamic() {
            head.extend_from_slice(&len_word(head_len + tail.len()));
            tail.extend_from_slice(&body);
        } else {
            head.extend_from_slice(&body);
        }
    }
    head.extend_from_slice(&tail);
    head
}

/// The selector of the function with the canonical signature `signature`.
#[must_use]
pub fn selector(signature: &str) -> [u8; 4] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// The calldata of a call to `signature` with `args`.
#[must_use]
pub fn call(signature: &str, args: &[Value]) -> Vec<u8> {
    let mut out = selector(signature).to_vec();
    out.extend_from_slice(&encode(args));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(v: u16) -> Hash {
        let mut w = [0u8; 32];
        w[30..].copy_from_slice(&v.to_be_bytes());
        w
    }

    #[test]
    fn selectors_are_solidity_ones() {
        assert_eq!(
            selector("transfer(address,uint256)"),
            [0xa9, 0x05, 0x9c, 0xbb]
        );
        assert_eq!(
            selector("send(uint64,address,bytes)"),
            solo_abi::bridge::SEND_SELECTOR
        );
    }

    #[test]
    fn encodes_heads_and_tails() {
        // f(uint256 a, bytes b, (uint256,uint256) c, bytes32[] d)
        let data = encode(&[
            Value::uint(1),
            Value::Bytes(vec![0xAB; 33]),
            Value::Tuple(vec![Value::uint(2), Value::uint(3)]),
            Value::Words(vec![word(4)]),
        ]);
        let mut expected = Vec::new();
        for w in [word(1), word(160), word(2), word(3), word(256), word(33)] {
            expected.extend_from_slice(&w);
        }
        expected.extend_from_slice(&[0xAB; 33]);
        expected.extend_from_slice(&[0; 31]);
        expected.extend_from_slice(&word(1));
        expected.extend_from_slice(&word(4));
        assert_eq!(data, expected);
        // A dynamic tuple stands in the tail with its own heads and tails.
        let data = encode(&[Value::Tuple(vec![
            Value::address(&[7; 20]),
            Value::Bytes(vec![]),
        ])]);
        let mut expected = word(32).to_vec();
        let mut a = [0u8; 32];
        a[12..].copy_from_slice(&[7; 20]);
        expected.extend_from_slice(&a);
        expected.extend_from_slice(&word(64));
        expected.extend_from_slice(&word(0));
        assert_eq!(data, expected);
        assert_eq!(&call("f()", &[])[..], &selector("f()")[..]);
    }
}
