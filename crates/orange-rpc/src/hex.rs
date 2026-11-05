//! The hex encodings of Ethereum JSON-RPC: quantities (`0x` hex without
//! leading zeros) and data (`0x` hex, two digits per byte).

use core::fmt::Write as _;

use crate::RpcError;

/// Encodes a quantity as minimal `0x` hex.
#[must_use]
pub fn quantity(v: u128) -> String {
    format!("{v:#x}")
}

/// Encodes a big-endian unsigned integer of any width as a quantity.
#[must_use]
pub fn quantity_be(bytes: &[u8]) -> String {
    let hex = data(bytes);
    let digits = hex[2..].trim_start_matches('0');
    if digits.is_empty() {
        "0x0".to_owned()
    } else {
        format!("0x{digits}")
    }
}

/// Encodes bytes as `0x` hex.
#[must_use]
pub fn data(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decodes `0x` hex into bytes.
///
/// # Errors
/// Invalid params if the prefix is missing, the length is odd or a digit is not hex.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, RpcError> {
    let hex = s
        .strip_prefix("0x")
        .ok_or_else(|| RpcError::invalid_params("expected 0x-prefixed hex"))?;
    if hex.len() % 2 != 0 {
        return Err(RpcError::invalid_params("odd-length hex"));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let Some(digits) = hex.get(i..i + 2) else {
            return Err(RpcError::invalid_params("bad hex digit"));
        };
        let Ok(byte) = u8::from_str_radix(digits, 16) else {
            return Err(RpcError::invalid_params("bad hex digit"));
        };
        out.push(byte);
    }
    Ok(out)
}

/// Decodes exactly `n` bytes of `0x` hex.
fn parse_fixed(s: &str, n: usize) -> Result<Vec<u8>, RpcError> {
    let bytes = parse_hex(s)?;
    if bytes.len() == n {
        Ok(bytes)
    } else {
        Err(RpcError::invalid_params(format!("expected {n} bytes")))
    }
}

/// Decodes a 20-byte address.
///
/// # Errors
/// Invalid params if `s` is not `0x` hex of 20 bytes.
pub fn parse_address(s: &str) -> Result<[u8; 20], RpcError> {
    Ok(parse_fixed(s, 20)?.try_into().unwrap_or_default())
}

/// Decodes a 32-byte hash.
///
/// # Errors
/// Invalid params if `s` is not `0x` hex of 32 bytes.
pub fn parse_hash(s: &str) -> Result<[u8; 32], RpcError> {
    Ok(parse_fixed(s, 32)?.try_into().unwrap_or_default())
}

/// Decodes a 32-byte word given either as a quantity (`0x0`) or as data of at
/// most 32 bytes, left-padded with zeros, as geth reads storage slots.
///
/// # Errors
/// Invalid params if the prefix is missing, a digit is not hex, or there are
/// more than 64 digits.
pub fn parse_word(s: &str) -> Result<[u8; 32], RpcError> {
    let hex = s
        .strip_prefix("0x")
        .ok_or_else(|| RpcError::invalid_params("expected 0x-prefixed hex"))?;
    if hex.len() > 64 {
        return Err(RpcError::invalid_params(
            "hex string too long, want at most 32 bytes",
        ));
    }
    parse_hash(&format!("0x{hex:0>64}"))
}

/// Decodes a `0x` hex quantity of at most 128 bits.
///
/// # Errors
/// Invalid params if the prefix is missing or the number does not fit.
pub fn parse_big(s: &str) -> Result<u128, RpcError> {
    let hex = s
        .strip_prefix("0x")
        .ok_or_else(|| RpcError::invalid_params("expected 0x-prefixed quantity"))?;
    let Ok(n) = u128::from_str_radix(hex, 16) else {
        return Err(RpcError::invalid_params("bad quantity"));
    };
    Ok(n)
}

/// Decodes a `0x` hex quantity of at most 64 bits.
///
/// # Errors
/// Invalid params if the prefix is missing or the number does not fit.
pub fn parse_quantity(s: &str) -> Result<u64, RpcError> {
    let Ok(n) = u64::try_from(parse_big(s)?) else {
        return Err(RpcError::invalid_params("bad quantity"));
    };
    Ok(n)
}
