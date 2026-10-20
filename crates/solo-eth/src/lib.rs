//! Ethereum transactions as the reference kernel accepts them: legacy
//! (pre-EIP-155 and EIP-155), EIP-2930 access-list and EIP-1559 dynamic-fee
//! transactions. Decoding, the bytes each signature covers, signature-value
//! checks, and the Osaka intrinsic-gas rules. Signature *recovery* is left to
//! the caller, which in the kernel is a host function. Also the logs bloom.
//! `no_std`, shared by the kernel guest and the RPC server.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

use solo_rlp::{Item, decode as rlp_decode, encode_bytes, encode_item, encode_list, encode_uint};

/// Gas every transaction pays.
pub const TX_BASE_GAS: u64 = 21_000;
/// Extra gas of a contract creation (EIP-2).
pub const TX_CREATE_GAS: u64 = 32_000;
/// Gas per zero calldata byte.
pub const ZERO_BYTE_GAS: u64 = 4;
/// Gas per non-zero calldata byte.
pub const NONZERO_BYTE_GAS: u64 = 16;
/// Gas per 32-byte word of initcode (EIP-3860).
pub const INITCODE_WORD_GAS: u64 = 2;
/// Largest initcode (EIP-3860).
pub const MAX_INITCODE_SIZE: usize = 49_152;
/// Gas per access-list address (EIP-2930).
pub const ACCESS_ADDRESS_GAS: u64 = 2_400;
/// Gas per access-list storage key (EIP-2930).
pub const ACCESS_KEY_GAS: u64 = 1_900;
/// Floor gas per calldata token (EIP-7623).
pub const FLOOR_TOKEN_GAS: u64 = 10;
/// Largest gas limit of one transaction (EIP-7825).
pub const MAX_TX_GAS: u64 = 1 << 24;

/// Half the secp256k1 group order: the largest `s` EIP-2 allows.
const HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// Why a transaction was not decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not a well-formed transaction of a supported type.
    Malformed,
    /// A transaction type this kernel does not execute (blob, set-code, unknown).
    Unsupported,
    /// `r` or `s` out of range, `s` above half the order, or a bad `v`.
    BadSignature,
}

/// One access-list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessItem {
    /// Address.
    pub address: [u8; 20],
    /// Storage keys.
    pub keys: Vec<[u8; 32]>,
}

/// A decoded transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tx {
    /// 0 legacy, 1 access list, 2 dynamic fee.
    pub tx_type: u8,
    /// Chain id; `None` only for a pre-EIP-155 legacy transaction.
    pub chain_id: Option<u64>,
    /// Nonce.
    pub nonce: u64,
    /// Gas price, or the maximum fee per gas of a dynamic-fee transaction.
    pub gas_price: u128,
    /// Maximum priority fee per gas of a dynamic-fee transaction.
    pub priority_fee: Option<u128>,
    /// Gas limit.
    pub gas_limit: u64,
    /// Recipient; `None` creates a contract.
    pub to: Option<[u8; 20]>,
    /// Value in wei.
    pub value: u128,
    /// Calldata or initcode.
    pub input: Vec<u8>,
    /// Access list (empty for legacy).
    pub access_list: Vec<AccessItem>,
    /// `v` as on the wire for legacy, the y parity for typed transactions.
    pub v: u64,
    /// Signature `r`.
    pub r: [u8; 32],
    /// Signature `s`.
    pub s: [u8; 32],
    /// The bytes whose `keccak256` the signature covers.
    pub signing_payload: Vec<u8>,
}

fn u64_of(item: &Item<'_>) -> Result<u64, Error> {
    item.u64().ok().ok_or(Error::Malformed)
}

fn u128_of(item: &Item<'_>) -> Result<u128, Error> {
    item.u128().ok().ok_or(Error::Malformed)
}

fn to_field(item: &Item<'_>) -> Result<Option<[u8; 20]>, Error> {
    let bytes = item.bytes().ok().ok_or(Error::Malformed)?;
    match bytes.len() {
        0 => Ok(None),
        20 => Ok(Some(item.array().ok().ok_or(Error::Malformed)?)),
        _ => Err(Error::Malformed),
    }
}

fn access_list(item: &Item<'_>) -> Result<Vec<AccessItem>, Error> {
    let entries = item.list().ok().ok_or(Error::Malformed)?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let pair = entry.list().ok().ok_or(Error::Malformed)?;
        let [address, keys] = pair else {
            return Err(Error::Malformed);
        };
        let address = address.array().ok().ok_or(Error::Malformed)?;
        let keys = keys
            .list()
            .ok()
            .ok_or(Error::Malformed)?
            .iter()
            .map(|k| k.array().ok().ok_or(Error::Malformed))
            .collect::<Result<Vec<[u8; 32]>, Error>>()?;
        out.push(AccessItem { address, keys });
    }
    Ok(out)
}

fn signature_values(r: &Item<'_>, s: &Item<'_>) -> Result<([u8; 32], [u8; 32]), Error> {
    let r = r.u256().ok().ok_or(Error::Malformed)?;
    let s = s.u256().ok().ok_or(Error::Malformed)?;
    if r == [0; 32] || s == [0; 32] || s > HALF_ORDER {
        return Err(Error::BadSignature);
    }
    Ok((r, s))
}

/// The RLP list of `fields`, prefixed by `prefix` (the type byte, if any).
fn payload(prefix: Option<u8>, fields: &[Item<'_>], extra: &[u128]) -> Vec<u8> {
    let mut body = Vec::new();
    for f in fields {
        encode_item(f, &mut body);
    }
    for x in extra {
        encode_uint(*x, &mut body);
    }
    let mut out = Vec::new();
    out.extend(prefix);
    encode_list(&body, &mut out);
    out
}

/// Decodes a raw transaction as `eth_sendRawTransaction` receives it.
///
/// # Errors
/// See [`Error`].
pub fn decode(raw: &[u8]) -> Result<Tx, Error> {
    match raw.first() {
        None => Err(Error::Malformed),
        Some(0x01) => typed(1, &raw[1..]),
        Some(0x02) => typed(2, &raw[1..]),
        Some(0x00..=0x7F) => Err(Error::Unsupported),
        Some(_) => legacy(raw),
    }
}

fn legacy(raw: &[u8]) -> Result<Tx, Error> {
    let item = rlp_decode(raw).ok().ok_or(Error::Malformed)?;
    let fields = item.list().ok().ok_or(Error::Malformed)?;
    let [nonce, gas_price, gas_limit, to, value, input, v, r, s] = fields else {
        return Err(Error::Malformed);
    };
    let v = u64_of(v)?;
    let chain_id = match v {
        27 | 28 => None,
        v if v >= 35 => Some((v - 35) / 2),
        _ => return Err(Error::BadSignature),
    };
    let (r, s) = signature_values(r, s)?;
    let signing_payload = match chain_id {
        Some(id) => payload(None, &fields[..6], &[u128::from(id), 0, 0]),
        None => payload(None, &fields[..6], &[]),
    };
    Ok(Tx {
        tx_type: 0,
        chain_id,
        nonce: u64_of(nonce)?,
        gas_price: u128_of(gas_price)?,
        priority_fee: None,
        gas_limit: u64_of(gas_limit)?,
        to: to_field(to)?,
        value: u128_of(value)?,
        input: input.bytes().ok().ok_or(Error::Malformed)?.to_vec(),
        access_list: Vec::new(),
        v,
        r,
        s,
        signing_payload,
    })
}

fn typed(tx_type: u8, body: &[u8]) -> Result<Tx, Error> {
    let item = rlp_decode(body).ok().ok_or(Error::Malformed)?;
    let fields = item.list().ok().ok_or(Error::Malformed)?;
    // Both types share a layout once the dynamic-fee type's priority fee is set aside.
    let (chain_id, nonce, priority_fee, gas_price, rest, unsigned) = match (tx_type, fields) {
        (1, [chain_id, nonce, gas_price, rest @ ..]) if rest.len() == 8 => {
            (chain_id, nonce, None, gas_price, rest, 8)
        }
        (2, [chain_id, nonce, priority, max_fee, rest @ ..]) if rest.len() == 8 => {
            (chain_id, nonce, Some(priority), max_fee, rest, 9)
        }
        _ => return Err(Error::Malformed),
    };
    // Both arms checked that exactly eight fields remain.
    let (gas_limit, to, value, input) = (&rest[0], &rest[1], &rest[2], &rest[3]);
    let (list, parity, r, s) = (&rest[4], &rest[5], &rest[6], &rest[7]);
    let v = u64_of(parity)?;
    if v > 1 {
        return Err(Error::BadSignature);
    }
    let (r, s) = signature_values(r, s)?;
    Ok(Tx {
        tx_type,
        chain_id: Some(u64_of(chain_id)?),
        nonce: u64_of(nonce)?,
        gas_price: u128_of(gas_price)?,
        priority_fee: priority_fee.map(|p| u128_of(p)).transpose()?,
        gas_limit: u64_of(gas_limit)?,
        to: to_field(to)?,
        value: u128_of(value)?,
        input: input.bytes().ok().ok_or(Error::Malformed)?.to_vec(),
        access_list: access_list(list)?,
        v,
        r,
        s,
        signing_payload: payload(Some(tx_type), &fields[..unsigned], &[]),
    })
}

impl Tx {
    /// The recovery id (0 or 1) for `secp256k1_recover`.
    #[must_use]
    pub fn recovery_id(&self) -> u8 {
        let parity = match (self.tx_type, self.chain_id) {
            (0, None) => self.v - 27,
            (0, Some(id)) => self.v - 35 - 2 * id,
            _ => self.v,
        };
        u8::from(parity == 1)
    }

    /// `r || s || recovery id`.
    #[must_use]
    pub fn signature(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.recovery_id();
        out
    }

    /// Zero bytes in the input.
    #[allow(clippy::naive_bytecount)]
    fn zero_bytes(&self) -> u64 {
        self.input.iter().filter(|b| **b == 0).count() as u64
    }

    /// Calldata tokens (EIP-7623): zero bytes count one, others four.
    #[must_use]
    pub fn tokens(&self) -> u64 {
        let zeros = self.zero_bytes();
        let nonzero = self.input.len() as u64 - zeros;
        zeros + 4 * nonzero
    }

    /// Intrinsic gas before execution, not counting the EIP-7623 floor.
    #[must_use]
    pub fn intrinsic_gas(&self) -> u64 {
        let zeros = self.zero_bytes();
        let nonzero = self.input.len() as u64 - zeros;
        let mut gas = TX_BASE_GAS + zeros * ZERO_BYTE_GAS + nonzero * NONZERO_BYTE_GAS;
        if self.to.is_none() {
            gas += TX_CREATE_GAS + INITCODE_WORD_GAS * (self.input.len() as u64).div_ceil(32);
        }
        for item in &self.access_list {
            gas += ACCESS_ADDRESS_GAS + ACCESS_KEY_GAS * item.keys.len() as u64;
        }
        gas
    }

    /// The least gas the transaction is charged (EIP-7623 floor).
    #[must_use]
    pub fn floor_gas(&self) -> u64 {
        TX_BASE_GAS + FLOOR_TOKEN_GAS * self.tokens()
    }

    /// The smallest gas limit the transaction may carry.
    #[must_use]
    pub fn min_gas_limit(&self) -> u64 {
        self.intrinsic_gas().max(self.floor_gas())
    }

    /// Whether the initcode of a creation is within EIP-3860's limit.
    #[must_use]
    pub fn initcode_ok(&self) -> bool {
        self.to.is_some() || self.input.len() <= MAX_INITCODE_SIZE
    }

    /// Price paid per gas under `base_fee`, or `None` if the transaction cannot pay it.
    #[must_use]
    pub fn effective_gas_price(&self, base_fee: u128) -> Option<u128> {
        if self.gas_price < base_fee {
            return None;
        }
        Some(match self.priority_fee {
            Some(tip) => self.gas_price.min(base_fee.saturating_add(tip)),
            None => self.gas_price,
        })
    }

    /// Value plus the gas limit at the maximum price: what the sender must hold.
    #[must_use]
    pub fn max_cost(&self) -> Option<u128> {
        u128::from(self.gas_limit)
            .checked_mul(self.gas_price)?
            .checked_add(self.value)
    }
}

/// The 2048-bit logs bloom of a set of logs, each given as its address and topics.
#[must_use]
pub fn logs_bloom(logs: &[(&[u8; 20], &[[u8; 32]])], keccak: fn(&[u8]) -> [u8; 32]) -> [u8; 256] {
    let mut bloom = [0u8; 256];
    let mut add = |data: &[u8]| {
        let h = keccak(data);
        for i in [0, 2, 4] {
            let bit = (usize::from(h[i]) << 8 | usize::from(h[i + 1])) & 2047;
            bloom[255 - bit / 8] |= 1 << (bit % 8);
        }
    };
    for (address, topics) in logs {
        add(&address[..]);
        for topic in *topics {
            add(topic);
        }
    }
    bloom
}

/// Encodes a legacy transaction's six unsigned fields; a helper for tooling and tests.
#[must_use]
pub fn legacy_unsigned(
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: Option<[u8; 20]>,
    value: u128,
    input: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    encode_uint(u128::from(nonce), &mut body);
    encode_uint(gas_price, &mut body);
    encode_uint(u128::from(gas_limit), &mut body);
    encode_bytes(to.as_ref().map_or(&[][..], |t| &t[..]), &mut body);
    encode_uint(value, &mut body);
    encode_bytes(input, &mut body);
    body
}
