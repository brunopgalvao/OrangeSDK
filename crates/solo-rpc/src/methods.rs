//! Method dispatch (JSON-RPC 2.0).

use core::fmt::Write as _;

use serde_json::{Value, json};
use solo_abi::Encode;
use solo_abi::chain::{BlockHeader, Receipt, TRANSFER_GAS, reason};
use solo_host::hash::keccak256;
use solo_node::{Node, NodeError, SubmitError};

/// A JSON-RPC error with Ethereum's conventional codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    /// Error code.
    pub code: i64,
    /// Message.
    pub message: String,
}

impl RpcError {
    fn invalid_params(message: impl Into<String>) -> RpcError {
        RpcError {
            code: -32602,
            message: message.into(),
        }
    }
}

impl From<NodeError> for RpcError {
    fn from(e: NodeError) -> RpcError {
        RpcError {
            code: -32603,
            message: e.to_string(),
        }
    }
}

impl From<SubmitError> for RpcError {
    fn from(e: SubmitError) -> RpcError {
        match e {
            SubmitError::Rejected(code) => RpcError {
                code: -32000,
                message: format!("transaction rejected: {}", reason_text(code)),
            },
            SubmitError::Node(e) => e.into(),
        }
    }
}

/// Human text for a kernel rejection reason.
#[must_use]
pub fn reason_text(code: u32) -> &'static str {
    match code {
        reason::MALFORMED => "malformed transaction",
        reason::BAD_SIGNATURE => "invalid signature",
        reason::WRONG_CHAIN => "wrong chain id",
        reason::BAD_NONCE => "nonce too low or too high",
        reason::INSUFFICIENT_FUNDS => "insufficient funds for value and gas",
        reason::GAS_TOO_LOW => "intrinsic gas too low",
        reason::UNSUPPORTED => "transaction type not supported",
        _ => "rejected",
    }
}

/// Encodes a quantity as minimal `0x` hex.
#[must_use]
pub fn quantity(v: u128) -> String {
    format!("{v:#x}")
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

/// Decodes a `0x` hex quantity.
///
/// # Errors
/// Invalid params if the prefix is missing or the number does not fit.
pub fn parse_quantity(s: &str) -> Result<u64, RpcError> {
    let hex = s
        .strip_prefix("0x")
        .ok_or_else(|| RpcError::invalid_params("expected 0x-prefixed quantity"))?;
    let Ok(n) = u64::from_str_radix(hex, 16) else {
        return Err(RpcError::invalid_params("bad quantity"));
    };
    Ok(n)
}

fn param_str(params: &[Value], index: usize) -> Result<&str, RpcError> {
    params
        .get(index)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params(format!("missing string parameter {index}")))
}

fn param_array<const N: usize>(params: &[Value], index: usize) -> Result<[u8; N], RpcError> {
    let bytes = parse_hex(param_str(params, index)?)?;
    let Ok(array) = <[u8; N]>::try_from(bytes) else {
        return Err(RpcError::invalid_params(format!("expected {N} bytes")));
    };
    Ok(array)
}

/// Serves Ethereum JSON-RPC over a node.
pub struct Rpc {
    node: Node,
    /// Gas price the node advertises, in wei.
    pub gas_price: u128,
    /// Set by `solo_stop`; the server loop exits when it sees it.
    pub stopped: bool,
}

impl Rpc {
    /// Wraps a started node.
    #[must_use]
    pub fn new(node: Node) -> Rpc {
        Rpc {
            node,
            gas_price: 1_000_000_000,
            stopped: false,
        }
    }

    /// The node.
    #[must_use]
    pub fn node(&self) -> &Node {
        &self.node
    }

    /// The node, mutably.
    pub fn node_mut(&mut self) -> &mut Node {
        &mut self.node
    }

    /// Handles one JSON-RPC request object and returns the response object.
    /// Malformed requests get a JSON-RPC error response, never a panic.
    pub fn handle(&mut self, request: &Value) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let Some(method) = request.get("method").and_then(Value::as_str) else {
            return error_response(&id, -32600, "missing method");
        };
        let empty = Vec::new();
        let params = request
            .get("params")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        match self.dispatch(method, params) {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(e) => error_response(&id, e.code, &e.message),
        }
    }

    /// Handles a request body: a single request or a batch.
    pub fn handle_body(&mut self, body: &str) -> Value {
        match serde_json::from_str::<Value>(body) {
            Ok(Value::Array(batch)) => Value::Array(batch.iter().map(|r| self.handle(r)).collect()),
            Ok(single) => self.handle(&single),
            Err(_) => error_response(&Value::Null, -32700, "parse error"),
        }
    }

    fn block_number(&mut self) -> Result<u64, RpcError> {
        Ok(self.node.block_number()?)
    }

    fn resolve_block(&mut self, tag: &str) -> Result<u64, RpcError> {
        Ok(match tag {
            "latest" | "safe" | "finalized" | "pending" => self.block_number()?,
            "earliest" => 0,
            hex => parse_quantity(hex)?,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch(&mut self, method: &str, params: &[Value]) -> Result<Value, RpcError> {
        Ok(match method {
            "eth_chainId" => json!(quantity(u128::from(self.node.chain_id()?))),
            "net_version" => json!(self.node.chain_id()?.to_string()),
            "web3_clientVersion" => json!("solo/0.0.1"),
            "eth_blockNumber" => json!(quantity(u128::from(self.block_number()?))),
            "eth_gasPrice" | "eth_maxPriorityFeePerGas" => json!(quantity(self.gas_price)),
            "eth_estimateGas" => json!(quantity(u128::from(TRANSFER_GAS))),
            "eth_syncing" => json!(false),
            "solo_stop" => {
                self.stopped = true;
                json!(true)
            }
            "eth_accounts" => json!([]),
            "eth_getBalance" => {
                let address = param_array::<20>(params, 0)?;
                json!(quantity(self.node.account(&address)?.balance))
            }
            "eth_getTransactionCount" => {
                let address = param_array::<20>(params, 0)?;
                json!(quantity(u128::from(self.node.account(&address)?.nonce)))
            }
            "eth_getCode" => json!("0x"),
            "eth_sendRawTransaction" => {
                let raw = parse_hex(param_str(params, 0)?)?;
                json!(data(&self.node.submit(&raw)?))
            }
            "eth_getTransactionReceipt" => {
                let hash = param_array::<32>(params, 0)?;
                match self.node.receipt(&hash)? {
                    Some(receipt) => self.receipt_json(&hash, &receipt)?,
                    None => Value::Null,
                }
            }
            "eth_getTransactionByHash" => {
                let hash = param_array::<32>(params, 0)?;
                let raw = self.node.transaction(&hash)?;
                match (raw, self.node.receipt(&hash)?) {
                    (Some(raw), Some(receipt)) => self.transaction_json(&hash, &raw, &receipt)?,
                    _ => Value::Null,
                }
            }
            "eth_getBlockByNumber" => {
                let tag = param_str(params, 0)?;
                let full = params.get(1).and_then(Value::as_bool).unwrap_or(false);
                match self.resolve_block(tag)? {
                    0 => self.genesis_block_json(),
                    n => match self.node.block_by_number(n)? {
                        Some(header) => self.block_json(&header, full)?,
                        None => Value::Null,
                    },
                }
            }
            "eth_getBlockByHash" => {
                let hash = param_array::<32>(params, 0)?;
                let full = params.get(1).and_then(Value::as_bool).unwrap_or(false);
                match self.node.block_by_hash(&hash)? {
                    Some(header) => self.block_json(&header, full)?,
                    None => Value::Null,
                }
            }
            "eth_feeHistory" => json!({
                "oldestBlock": quantity(u128::from(self.block_number()?)),
                "baseFeePerGas": [quantity(self.gas_price), quantity(self.gas_price)],
                "gasUsedRatio": [0.0],
                "reward": [[quantity(0)]],
            }),
            other => {
                return Err(RpcError {
                    code: -32601,
                    message: format!("method not found: {other}"),
                });
            }
        })
    }

    fn receipt_json(&mut self, hash: &[u8; 32], receipt: &Receipt) -> Result<Value, RpcError> {
        let block_hash = self.block_hash(receipt.height)?;
        let gas_price = self
            .node
            .transaction(hash)?
            .map(|raw| legacy_fields(&raw).gas_price)
            .unwrap_or_default();
        Ok(json!({
            "transactionHash": data(hash),
            "transactionIndex": quantity(u128::from(receipt.index)),
            "blockNumber": quantity(u128::from(receipt.height)),
            "blockHash": data(&block_hash),
            "from": data(&receipt.from),
            "to": data(&receipt.to),
            "status": quantity(u128::from(receipt.status)),
            "gasUsed": quantity(u128::from(receipt.gas_used)),
            "cumulativeGasUsed": quantity(u128::from(receipt.gas_used)),
            "effectiveGasPrice": quantity(gas_price),
            "contractAddress": Value::Null,
            "logs": [],
            "logsBloom": data(&[0u8; 256]),
            "type": "0x0",
        }))
    }

    fn transaction_json(
        &mut self,
        hash: &[u8; 32],
        raw: &[u8],
        receipt: &Receipt,
    ) -> Result<Value, RpcError> {
        let block_hash = self.block_hash(receipt.height)?;
        let fields = legacy_fields(raw);
        Ok(json!({
            "hash": data(hash),
            "nonce": quantity(fields.nonce),
            "blockHash": data(&block_hash),
            "blockNumber": quantity(u128::from(receipt.height)),
            "transactionIndex": quantity(u128::from(receipt.index)),
            "from": data(&receipt.from),
            "to": data(&receipt.to),
            "value": quantity(fields.value),
            "gas": quantity(fields.gas_limit),
            "gasPrice": quantity(fields.gas_price),
            "input": "0x",
            "v": quantity(fields.v),
            "r": data(&fields.r),
            "s": data(&fields.s),
            "type": "0x0",
        }))
    }

    /// Hash of the header at `height`; zero if the node has no such block.
    fn block_hash(&mut self, height: u64) -> Result<[u8; 32], RpcError> {
        Ok(self
            .node
            .block_by_number(height)?
            .map(|header| keccak256(&header.to_bytes()))
            .unwrap_or_default())
    }

    fn genesis_block_json(&self) -> Value {
        json!({
            "number": quantity(0),
            "hash": data(&[0u8; 32]),
            "parentHash": data(&[0u8; 32]),
            "timestamp": quantity(0),
            "transactions": [],
            "gasUsed": quantity(0),
            "gasLimit": quantity(30_000_000),
            "stateRoot": data(&[0u8; 32]),
            "receiptsRoot": data(&[0u8; 32]),
            "miner": data(&[0u8; 20]),
            "difficulty": "0x0",
            "nonce": "0x0000000000000000",
            "extraData": "0x",
            "logsBloom": data(&[0u8; 256]),
            "baseFeePerGas": quantity(self.gas_price),
            "size": quantity(0),
            "uncles": [],
        })
    }

    fn block_json(&mut self, header: &BlockHeader, full: bool) -> Result<Value, RpcError> {
        let hash = keccak256(&header.to_bytes());
        let mut transactions = Vec::new();
        for tx_hash in &header.tx_hashes.0 {
            if full {
                let raw = self.node.transaction(tx_hash)?.unwrap_or_default();
                let receipt = self.node.receipt(tx_hash)?.unwrap_or_default();
                transactions.push(self.transaction_json(tx_hash, &raw, &receipt)?);
            } else {
                transactions.push(json!(data(tx_hash)));
            }
        }
        Ok(json!({
            "number": quantity(u128::from(header.height)),
            "hash": data(&hash),
            "parentHash": data(&header.parent_hash),
            "timestamp": quantity(u128::from(header.timestamp_ms / 1000)),
            "transactions": transactions,
            "gasUsed": quantity(u128::from(header.gas_used)),
            "gasLimit": quantity(30_000_000),
            "stateRoot": data(&header.state_root),
            "receiptsRoot": data(&header.receipts_root),
            "miner": data(&[0u8; 20]),
            "difficulty": "0x0",
            "nonce": "0x0000000000000000",
            "extraData": "0x",
            "logsBloom": data(&[0u8; 256]),
            "baseFeePerGas": quantity(self.gas_price),
            "size": quantity(0),
            "uncles": [],
        }))
    }
}

fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Fields of a legacy transaction the RPC reports back.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Legacy {
    /// Nonce.
    pub nonce: u128,
    /// Gas price in wei.
    pub gas_price: u128,
    /// Gas limit.
    pub gas_limit: u128,
    /// Value in wei.
    pub value: u128,
    /// Signature `v`.
    pub v: u128,
    /// Signature `r`.
    pub r: [u8; 32],
    /// Signature `s`.
    pub s: [u8; 32],
}

/// Decodes the fields of a legacy transaction, zero for anything that does
/// not parse. The kernel only stores transactions it validated, so a stored
/// one always parses; the lenient form keeps block views total.
#[must_use]
pub fn legacy_fields(raw: &[u8]) -> Legacy {
    fn parse(raw: &[u8]) -> Option<Legacy> {
        let item = solo_rlp::decode(raw).ok()?;
        let f = item.list().ok()?;
        if f.len() != 9 {
            return None;
        }
        Some(Legacy {
            nonce: f[0].u128().ok()?,
            gas_price: f[1].u128().ok()?,
            gas_limit: f[2].u128().ok()?,
            value: f[4].u128().ok()?,
            v: f[6].u128().ok()?,
            r: f[7].u256().ok()?,
            s: f[8].u256().ok()?,
        })
    }
    parse(raw).unwrap_or_default()
}
