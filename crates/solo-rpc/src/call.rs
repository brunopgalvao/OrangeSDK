//! Messages for `eth_call` and `eth_estimateGas`: the call object, the
//! intrinsic gas a message needs, and the error a failed message becomes.

use serde_json::{Map, Value};
use solo_abi::chain::{AccessItem, CallRequest, CallResult, SignedAuthorization, call_status};
use solo_abi::codec::Seq;
use solo_eth::Tx;

use crate::RpcError;
use crate::hex::{
    data, parse_address, parse_big, parse_hash, parse_hex, parse_quantity, parse_word,
    quantity_be,
};

/// The error for an `accessList` that is not a list of entries.
const BAD_ACCESS_LIST: &str = "accessList must be a list of objects with address and storageKeys";

/// The error for an `authorizationList` that is not a list of authorizations.
const BAD_AUTHORIZATION_LIST: &str =
    "authorizationList must be a list of objects with chainId, address, nonce, yParity, r and s";

/// geth's texts for the `Panic(uint256)` codes the Solidity compiler emits.
const PANIC_REASONS: [(u8, &str); 10] = [
    (0x00, "generic panic"),
    (0x01, "assert(false)"),
    (0x11, "arithmetic underflow or overflow"),
    (0x12, "division or modulo by zero"),
    (0x21, "enum overflow"),
    (0x22, "invalid encoded storage byte array accessed"),
    (
        0x31,
        "out-of-bounds array access; popping on an empty array",
    ),
    (0x32, "out-of-bounds access of an array or bytesN"),
    (0x41, "out of memory"),
    (0x51, "uninitialized function"),
];

/// Selector of `Error(string)`.
const ERROR_SELECTOR: [u8; 4] = [0x08, 0xc3, 0x79, 0xa0];
/// Selector of `Panic(uint256)`.
const PANIC_SELECTOR: [u8; 4] = [0x4e, 0x48, 0x7b, 0x71];

/// A string field of `object`: `None` when absent or null.
fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<Option<&'a str>, RpcError> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(RpcError::invalid_params(format!("{name} must be a string"))),
    }
}

/// One `accessList` entry: an address and its storage keys, both required
/// as in geth.
fn access_item(item: &Value) -> Result<AccessItem, RpcError> {
    let (Some(Value::String(address)), Some(Value::Array(keys))) =
        (item.get("address"), item.get("storageKeys"))
    else {
        return Err(RpcError::invalid_params(BAD_ACCESS_LIST));
    };
    let mut parsed = Vec::with_capacity(keys.len());
    for key in keys {
        parsed.push(parse_hash(key.as_str().unwrap_or_default())?);
    }
    Ok(AccessItem {
        address: parse_address(address)?,
        keys: Seq(parsed),
    })
}

/// A call object's `accessList`: absent or null is empty.
fn access_list(value: Option<&Value>) -> Result<Vec<AccessItem>, RpcError> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(list)) => list.iter().map(access_item).collect(),
        Some(_) => Err(RpcError::invalid_params(BAD_ACCESS_LIST)),
    }
}

/// One `authorizationList` entry, every field required as in geth; `v` is
/// accepted for `yParity`.
fn authorization(item: &Value) -> Result<SignedAuthorization, RpcError> {
    let Value::Object(object) = item else {
        return Err(RpcError::invalid_params(BAD_AUTHORIZATION_LIST));
    };
    let required = |name: &str| -> Result<&str, RpcError> {
        field(object, name)?.ok_or_else(|| RpcError::invalid_params(BAD_AUTHORIZATION_LIST))
    };
    let parity = match field(object, "yParity")? {
        Some(p) => p,
        None => required("v")?,
    };
    Ok(SignedAuthorization {
        chain_id: parse_word(required("chainId")?)?,
        address: parse_address(required("address")?)?,
        nonce: parse_quantity(required("nonce")?)?,
        y_parity: u8::try_from(parse_quantity(parity)?)
            .map_err(|_| RpcError::invalid_params(BAD_AUTHORIZATION_LIST))?,
        r: parse_word(required("r")?)?,
        s: parse_word(required("s")?)?,
    })
}

/// A call object's `authorizationList`: absent or null is empty.
fn authorization_list(value: Option<&Value>) -> Result<Vec<SignedAuthorization>, RpcError> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(list)) => list.iter().map(authorization).collect(),
        Some(_) => Err(RpcError::invalid_params(BAD_AUTHORIZATION_LIST)),
    }
}

/// Reads a call object (`from`, `to`, `gas`, `value`, `input` or `data`,
/// `accessList`, `authorizationList`). Fee fields are accepted and ignored:
/// messages run at a gas price of zero. A missing `gas` is zero, which the
/// kernel reads as its cap. The access list is charged and warmed as in an
/// EIP-2930 transaction, and an authorization list makes the message an
/// EIP-7702 one, so an estimate made with them covers a transaction sent
/// with them.
///
/// # Errors
/// Invalid params if the object is missing or a field does not parse.
pub fn call_request(value: Option<&Value>) -> Result<CallRequest, RpcError> {
    let Some(Value::Object(object)) = value else {
        return Err(RpcError::invalid_params("expected a transaction object"));
    };
    let from = field(object, "from")?.map(parse_address).transpose()?;
    let to = field(object, "to")?.map(parse_address).transpose()?;
    let gas = field(object, "gas")?.map(parse_quantity).transpose()?;
    let value = field(object, "value")?.map(parse_big).transpose()?;
    let input = field(object, "input")?;
    let data = field(object, "data")?;
    if input.is_some() && data.is_some() && input != data {
        return Err(RpcError::invalid_params(
            "both \"data\" and \"input\" are set and not equal. Please use \"input\" to pass transaction call data",
        ));
    }
    let bytes = input.or(data).map(parse_hex).transpose()?;
    Ok(CallRequest {
        from: from.unwrap_or_default(),
        to,
        value: value.unwrap_or_default(),
        data: bytes.unwrap_or_default(),
        gas: gas.unwrap_or_default(),
        access_list: Seq(access_list(object.get("accessList"))?),
        authorization_list: Seq(authorization_list(object.get("authorizationList"))?),
    })
}

/// The least gas `request` can run with: the intrinsic cost, access and
/// authorization lists included, or the EIP-7623 calldata floor, whichever
/// is higher.
#[must_use]
pub fn min_gas(request: &CallRequest) -> u64 {
    Tx {
        tx_type: 0,
        chain_id: None,
        nonce: 0,
        gas_price: 0,
        priority_fee: None,
        gas_limit: 0,
        to: request.to,
        value: request.value,
        input: request.data.clone(),
        access_list: request
            .access_list
            .0
            .iter()
            .map(|item| solo_eth::AccessItem {
                address: item.address,
                keys: item.keys.0.clone(),
            })
            .collect(),
        authorization_list: request.authorization_list.0.iter().map(eth_authorization).collect(),
        v: 0,
        r: [0; 32],
        s: [0; 32],
        signing_payload: Vec::new(),
    }
    .min_gas_limit()
}

/// A call's authorization as `solo-eth` reads one from a transaction.
#[must_use]
pub fn eth_authorization(auth: &SignedAuthorization) -> solo_eth::Authorization {
    solo_eth::Authorization {
        chain_id: auth.chain_id,
        address: auth.address,
        nonce: auth.nonce,
        y_parity: auth.y_parity,
        r: auth.r,
        s: auth.s,
    }
}

/// A big-endian ABI word as a `usize`, if it fits.
fn word_usize(word: &[u8]) -> Option<usize> {
    let (high, low) = word.split_at(24);
    if high.iter().any(|b| *b != 0) {
        return None;
    }
    usize::try_from(u64::from_be_bytes(low.try_into().ok()?)).ok()
}

/// The string an ABI-encoded `(string)` holds.
fn abi_string(args: &[u8]) -> Option<String> {
    let offset = word_usize(args.get(..32)?)?;
    let len = word_usize(args.get(offset..offset.checked_add(32)?)?)?;
    let start = offset + 32;
    let bytes = args.get(start..start.checked_add(len)?)?;
    String::from_utf8(bytes.to_vec()).ok()
}

/// What revert data says, as geth renders it: the reason of `Error(string)`,
/// the meaning of a `Panic(uint256)` code, or `None` for anything else.
#[must_use]
pub fn revert_reason(output: &[u8]) -> Option<String> {
    let (selector, args) = output.split_at_checked(4)?;
    if selector == ERROR_SELECTOR {
        return abi_string(args);
    }
    if selector != PANIC_SELECTOR {
        return None;
    }
    let code: [u8; 32] = args.get(..32)?.try_into().ok()?;
    let small = code[..31].iter().all(|b| *b == 0);
    Some(
        PANIC_REASONS
            .iter()
            .find(|(c, _)| small && *c == code[31])
            .map_or_else(
                || format!("unknown panic code: {}", quantity_be(&code)),
                |(_, reason)| (*reason).to_owned(),
            ),
    )
}

/// The JSON-RPC error of a message that did not succeed: a revert is code 3
/// with the revert data, as geth reports it; anything else is a server error.
#[must_use]
pub fn call_error(result: &CallResult) -> RpcError {
    match result.status {
        call_status::REVERT => RpcError {
            code: 3,
            message: revert_reason(&result.output).map_or_else(
                || "execution reverted".to_owned(),
                |reason| format!("execution reverted: {reason}"),
            ),
            data: Some(data(&result.output)),
        },
        call_status::HALT => {
            RpcError::server("execution halted: out of gas or an exceptional halt")
        }
        _ => RpcError::server("message cannot run: it fails the kernel's validation"),
    }
}
