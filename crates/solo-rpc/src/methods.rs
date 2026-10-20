//! Method dispatch (JSON-RPC 2.0).

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde_json::{Value, json};
use solo_abi::Encode;
use solo_abi::chain::{
    BASE_FEE, BLOCK_GAS_LIMIT, BlockHeader, CallRequest, CallResult, Receipt, call_status, reason,
};
use solo_eth::{MAX_INITCODE_SIZE, MAX_TX_GAS};
use solo_host::hash::keccak256;
use solo_node::{Node, NodeError, SubmitError};

use crate::call::{call_error, call_request, min_gas};
use crate::filter::{Blocks, Filter};
pub use crate::hex::{
    data, parse_address, parse_big, parse_hash, parse_hex, parse_quantity, parse_word, quantity,
    quantity_be,
};
use crate::views::{self, Destination, Position, created_address, decode_or_blank};

/// Default widest block range one `eth_getLogs` request may search
/// ([`Rpc::max_log_range`]): every block in it costs a kernel query.
pub const MAX_LOG_RANGE: u64 = 10_000;

/// Default most requests one batch may carry ([`Rpc::max_batch`]), geth's
/// default.
pub const MAX_BATCH: usize = 1000;

/// Work the node must keep doing while requests are served: polling the
/// network and ticking the clock. Requests run on the thread that drives
/// consensus, so the server runs this between connections, and long requests
/// run it between their steps (see [`Rpc::run_background`]).
pub type Background = Box<dyn FnMut(&mut Node)>;

/// Most blocks one `eth_feeHistory` request reports, as in geth.
pub const MAX_FEE_HISTORY: u64 = 1024;

/// Gas a call with value forwards for free; part of geth's first guess in
/// gas estimation.
const CALL_STIPEND: u64 = 2_300;

/// A JSON-RPC error with Ethereum's conventional codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    /// Error code.
    pub code: i64,
    /// Message.
    pub message: String,
    /// Error data: the revert data of a reverted message, as `0x` hex.
    pub data: Option<String>,
}

impl RpcError {
    fn with_code(code: i64, message: String) -> RpcError {
        RpcError {
            code,
            message,
            data: None,
        }
    }

    /// Invalid params (-32602).
    pub(crate) fn invalid_params(message: impl Into<String>) -> RpcError {
        RpcError::with_code(-32602, message.into())
    }

    /// A server error (-32000), the code geth uses for failed requests.
    pub(crate) fn server(message: impl Into<String>) -> RpcError {
        RpcError::with_code(-32000, message.into())
    }
}

impl From<NodeError> for RpcError {
    fn from(e: NodeError) -> RpcError {
        RpcError::with_code(-32603, e.to_string())
    }
}

impl From<SubmitError> for RpcError {
    fn from(e: SubmitError) -> RpcError {
        match e {
            SubmitError::Rejected(code) => RpcError::server(reason_text(code)),
            SubmitError::Node(e) => e.into(),
            SubmitError::Pool(e) => RpcError::server(e.to_string()),
        }
    }
}

/// geth's text for a kernel rejection reason.
#[must_use]
pub fn reason_text(code: u32) -> &'static str {
    match code {
        reason::MALFORMED => "malformed transaction",
        reason::BAD_SIGNATURE => "invalid sender",
        reason::WRONG_CHAIN => "invalid chain id for signer",
        reason::BAD_NONCE => "invalid nonce",
        reason::INSUFFICIENT_FUNDS => "insufficient funds for gas * price + value",
        reason::GAS_TOO_LOW => "intrinsic gas too low",
        reason::UNSUPPORTED => "transaction type not supported",
        reason::FEE_TOO_LOW => {
            "max fee per gas less than block base fee, or max priority fee per gas higher than max fee per gas"
        }
        reason::GAS_LIMIT_TOO_HIGH => "transaction gas limit too high",
        reason::INITCODE_TOO_LARGE => "max initcode size exceeded",
        reason::SENDER_NOT_EOA => "sender not an eoa",
        _ => "rejected",
    }
}

/// The address that signed a raw transaction, if it decodes and recovers.
#[must_use]
pub fn sender(raw: &[u8]) -> Option<[u8; 20]> {
    let tx = solo_eth::decode(raw).ok()?;
    let sig = tx.signature();
    let signature = Signature::from_slice(&sig[..64]).ok()?;
    let id = RecoveryId::from_byte(sig[64])?;
    let key =
        VerifyingKey::recover_from_prehash(&keccak256(&tx.signing_payload), &signature, id).ok()?;
    let point = key.to_encoded_point(false);
    keccak256(&point.as_bytes()[1..])[12..].try_into().ok()
}

fn param_str(params: &[Value], index: usize) -> Result<&str, RpcError> {
    params
        .get(index)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params(format!("missing string parameter {index}")))
}

fn address_param(params: &[Value], index: usize) -> Result<[u8; 20], RpcError> {
    parse_address(param_str(params, index)?)
}

fn hash_param(params: &[Value], index: usize) -> Result<[u8; 32], RpcError> {
    parse_hash(param_str(params, index)?)
}

/// `eth_feeHistory`'s block count: a quantity, a decimal string or a number.
fn block_count(value: Option<&Value>) -> Result<u64, RpcError> {
    let count = match value {
        Some(Value::String(s)) if s.starts_with("0x") => return parse_quantity(s),
        Some(Value::String(s)) => s.parse().ok(),
        Some(Value::Number(n)) => n.as_u64(),
        _ => None,
    };
    count.ok_or(RpcError::invalid_params("invalid block count"))
}

/// `eth_feeHistory`'s reward percentiles: increasing, within 0 to 100.
fn percentiles(value: Option<&Value>) -> Result<Vec<f64>, RpcError> {
    let invalid = || RpcError::invalid_params("invalid reward percentile");
    let list = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(list)) => list,
        Some(_) => return Err(invalid()),
    };
    let mut out: Vec<f64> = Vec::with_capacity(list.len());
    for p in list.iter().map(Value::as_f64) {
        match p {
            Some(p) if (0.0..=100.0).contains(&p) && out.last().is_none_or(|last| p > *last) => {
                out.push(p);
            }
            _ => return Err(invalid()),
        }
    }
    Ok(out)
}

/// The priority fees paid at each percentile of a block's gas, as geth
/// computes them: transactions sorted by tip, weighted by gas used.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn rewards(receipts: &[Receipt], gas_used: u64, percentiles: &[f64]) -> Vec<String> {
    let mut sorted: Vec<(u128, u64)> = receipts
        .iter()
        .map(|r| {
            let tip = r.effective_gas_price.saturating_sub(u128::from(BASE_FEE));
            (tip, r.gas_used)
        })
        .collect();
    sorted.sort_by_key(|(tip, _)| *tip);
    let mut index = 0;
    let mut sum = sorted.first().map_or(0, |(_, gas)| *gas);
    let mut out = Vec::with_capacity(percentiles.len());
    for p in percentiles {
        // Gas amounts are far below 2^53, so the float arithmetic is exact
        // enough, and the threshold is non-negative and at most `gas_used`.
        let threshold = (gas_used as f64 * p / 100.0) as u64;
        while sum < threshold && index + 1 < sorted.len() {
            index += 1;
            sum += sorted[index].1;
        }
        out.push(quantity(sorted.get(index).map_or(0, |(tip, _)| *tip)));
    }
    out
}

/// Serves Ethereum JSON-RPC over a node.
///
/// Requests run on the caller's thread, which also drives the node, so what
/// one request can make the node compute is bounded: each kernel query by
/// the node's query budget ([`Node::query_gas`]), and the requests that
/// make many queries (batches, gas estimation, log and fee-history scans)
/// hand the node its [`Background`] work between them.
pub struct Rpc {
    node: Node,
    background: Option<Background>,
    /// Priority fee the node suggests, in wei (`eth_maxPriorityFeePerGas`);
    /// `eth_gasPrice` adds the base fee, zero in the reference kernel.
    pub gas_price: u128,
    /// Widest block range one `eth_getLogs` request may search, counted
    /// within the chain; [`MAX_LOG_RANGE`] unless changed.
    pub max_log_range: u64,
    /// Most requests one batch may carry; [`MAX_BATCH`] unless changed.
    pub max_batch: usize,
    /// Set by `solo_stop`; the server loop exits when it sees it.
    pub stopped: bool,
}

impl Rpc {
    /// Wraps a started node.
    #[must_use]
    pub fn new(node: Node) -> Rpc {
        Rpc {
            node,
            background: None,
            gas_price: 1_000_000_000,
            max_log_range: MAX_LOG_RANGE,
            max_batch: MAX_BATCH,
            stopped: false,
        }
    }

    /// Sets the node's background work; see [`Rpc::run_background`].
    pub fn set_background(&mut self, work: Background) {
        self.background = Some(work);
    }

    /// Runs the background work once, if any is set. The HTTP server calls
    /// this between connections; requests call it between batch entries,
    /// between gas-estimation runs and between the blocks of a log or
    /// fee-history scan, so the node keeps voting while they are served.
    /// The head can move during such a request.
    pub fn run_background(&mut self) {
        if let Some(work) = self.background.as_mut() {
            work(&mut self.node);
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
            return error_response(&id, &RpcError::with_code(-32600, "missing method".into()));
        };
        let empty = Vec::new();
        let params = request
            .get("params")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        match self.dispatch(method, params) {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(e) => error_response(&id, &e),
        }
    }

    /// Handles a request body: a single request or a batch. A batch longer
    /// than [`Rpc::max_batch`] gets one error, under the id of its first
    /// request, as geth answers it.
    pub fn handle_body(&mut self, body: &str) -> Value {
        match serde_json::from_str::<Value>(body) {
            Ok(Value::Array(batch)) if batch.len() > self.max_batch => {
                let id = batch.iter().find_map(|r| r.get("id")).cloned();
                let error = RpcError::with_code(-32600, "batch too large".into());
                json!([error_response(&id.unwrap_or(Value::Null), &error)])
            }
            Ok(Value::Array(batch)) => {
                let mut out = Vec::with_capacity(batch.len());
                for request in &batch {
                    self.run_background();
                    out.push(self.handle(request));
                }
                Value::Array(out)
            }
            Ok(single) => self.handle(&single),
            Err(_) => error_response(
                &Value::Null,
                &RpcError::with_code(-32700, "parse error".into()),
            ),
        }
    }

    fn block_number(&mut self) -> Result<u64, RpcError> {
        Ok(self.node.block_number()?)
    }

    fn resolve_block(&mut self, tag: &str) -> Result<u64, RpcError> {
        Ok(match tag {
            "latest" | "pending" => self.block_number()?,
            "safe" | "finalized" => self.node.finalized_height()?,
            "earliest" => 0,
            hex => parse_quantity(hex)?,
        })
    }

    /// Checks the block parameter of a state method. The node keeps the
    /// state at the head only, so the parameter must name the head: a tag
    /// (`latest`, `pending`, `safe` and `finalized` all name it, spec 08
    /// section 8), its number or its hash, directly or as an EIP-1898 object
    /// with `blockHash` or `blockNumber`. A block above the head does not
    /// exist and one below it has no state left, as on a pruned geth node;
    /// both are errors rather than answers from another block's state.
    fn check_block(&mut self, param: Option<&Value>) -> Result<(), RpcError> {
        let height = match param {
            None | Some(Value::Null) => return Ok(()),
            Some(Value::String(hash)) if hash.len() == 66 => self.hash_height(hash)?,
            Some(Value::String(tag)) => self.state_height(tag)?,
            Some(Value::Object(object)) => {
                if let Some(hash) = object.get("blockHash") {
                    self.hash_height(hash.as_str().unwrap_or_default())?
                } else {
                    let number = object.get("blockNumber").and_then(Value::as_str);
                    self.state_height(number.unwrap_or("latest"))?
                }
            }
            Some(_) => return Err(RpcError::invalid_params("invalid block parameter")),
        };
        let head = self.block_number()?;
        if height > head {
            return Err(RpcError::server("header not found"));
        }
        if height < head {
            return Err(RpcError::server(format!(
                "historical state not available: block {height}, the node keeps the state of block {head} only"
            )));
        }
        Ok(())
    }

    /// The height a state method's block tag or number names; every tag but
    /// `earliest` is the head.
    fn state_height(&mut self, tag: &str) -> Result<u64, RpcError> {
        match tag {
            "latest" | "pending" | "safe" | "finalized" => self.block_number(),
            "earliest" => Ok(0),
            hex => parse_quantity(hex),
        }
    }

    fn hash_height(&mut self, hash: &str) -> Result<u64, RpcError> {
        match self.node.block_by_hash(&parse_hash(hash)?)? {
            Some(header) => Ok(header.height),
            None => Err(RpcError::server("header for hash not found")),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch(&mut self, method: &str, params: &[Value]) -> Result<Value, RpcError> {
        Ok(match method {
            "eth_chainId" => json!(quantity(u128::from(self.node.chain_id()?))),
            "net_version" => json!(self.node.chain_id()?.to_string()),
            "web3_clientVersion" => json!("solo/0.0.1"),
            "eth_blockNumber" => json!(quantity(u128::from(self.block_number()?))),
            "eth_gasPrice" => json!(quantity(u128::from(BASE_FEE) + self.gas_price)),
            "eth_maxPriorityFeePerGas" => json!(quantity(self.gas_price)),
            "eth_syncing" => json!(false),
            "solo_stop" => {
                self.stopped = true;
                json!(true)
            }
            "eth_accounts" => json!([]),
            "eth_getBalance" => {
                let address = address_param(params, 0)?;
                self.check_block(params.get(1))?;
                json!(quantity(self.node.account(&address)?.balance))
            }
            "eth_getTransactionCount" => {
                let address = address_param(params, 0)?;
                self.check_block(params.get(1))?;
                let nonce = if params.get(1).and_then(Value::as_str) == Some("pending") {
                    self.node.pending_nonce(&address)?
                } else {
                    self.node.account(&address)?.nonce
                };
                json!(quantity(u128::from(nonce)))
            }
            "eth_getCode" => {
                let address = address_param(params, 0)?;
                self.check_block(params.get(1))?;
                json!(data(&self.node.code(&address)?))
            }
            "eth_getStorageAt" => {
                let address = address_param(params, 0)?;
                let slot = parse_word(param_str(params, 1)?)?;
                self.check_block(params.get(2))?;
                json!(data(&self.node.storage(&address, &slot)?))
            }
            "eth_call" => {
                let request = call_request(params.first())?;
                self.check_block(params.get(1))?;
                let result = self.run(&request)?;
                if result.status != call_status::SUCCESS {
                    return Err(call_error(&result));
                }
                json!(data(&result.output))
            }
            "eth_estimateGas" => {
                let request = call_request(params.first())?;
                self.check_block(params.get(1))?;
                json!(quantity(u128::from(self.estimate_gas(request)?)))
            }
            "eth_sendRawTransaction" => {
                let raw = parse_hex(param_str(params, 0)?)?;
                match self.node.submit(&raw) {
                    Ok(hash) => json!(data(&hash)),
                    Err(SubmitError::Rejected(code)) => return Err(self.rejection(code, &raw)?),
                    Err(e) => return Err(e.into()),
                }
            }
            "eth_getTransactionReceipt" => {
                let hash = hash_param(params, 0)?;
                match self.node.receipt(&hash)? {
                    Some(receipt) => self.receipt_json(&hash, &receipt)?,
                    None => Value::Null,
                }
            }
            "eth_getTransactionByHash" => self.transaction_by_hash(&hash_param(params, 0)?)?,
            "eth_getBlockByNumber" => {
                let height = self.resolve_block(param_str(params, 0)?)?;
                let full = params.get(1).and_then(Value::as_bool).unwrap_or(false);
                match self.header_at(height)? {
                    Some((header, hash)) => self.block_json(&header, &hash, full)?,
                    None => Value::Null,
                }
            }
            "eth_getBlockByHash" => {
                let hash = hash_param(params, 0)?;
                let full = params.get(1).and_then(Value::as_bool).unwrap_or(false);
                match self.node.block_by_hash(&hash)? {
                    Some(header) => self.block_json(&header, &hash, full)?,
                    None => Value::Null,
                }
            }
            "eth_getBlockReceipts" => {
                let block = param_str(params, 0)?;
                let found = if block.len() == 66 {
                    let hash = parse_hash(block)?;
                    self.node.block_by_hash(&hash)?.map(|header| (header, hash))
                } else {
                    let height = self.resolve_block(block)?;
                    self.header_at(height)?
                };
                match found {
                    Some((header, hash)) => self.block_receipts_json(&header, &hash)?,
                    None => Value::Null,
                }
            }
            "eth_getLogs" => self.logs(&Filter::parse(params.first())?)?,
            "eth_feeHistory" => self.fee_history(params)?,
            "txpool_status" => crate::txpool::status(self.node.mempool()),
            "txpool_content" => crate::txpool::content(self.node.mempool()),
            other => {
                return Err(RpcError::with_code(
                    -32601,
                    format!("method not found: {other}"),
                ));
            }
        })
    }

    /// The JSON-RPC error for a kernel rejection, with the details geth gives.
    fn rejection(&mut self, code: u32, raw: &[u8]) -> Result<RpcError, RpcError> {
        let tx = decode_or_blank(raw);
        let text = reason_text(code);
        let message = match code {
            reason::BAD_NONCE => {
                let from = sender(raw).unwrap_or_default();
                let state = self.node.account(&from)?.nonce;
                // A nonce ahead of the account waits in the pool (spec 14),
                // so a bad nonce is a used one, or the last one, which no
                // transaction may carry (EIP-2681).
                if tx.nonce < state {
                    format!(
                        "nonce too low: address {}, tx: {} state: {state}",
                        data(&from),
                        tx.nonce
                    )
                } else {
                    format!(
                        "nonce has max value: address {}, nonce: {}",
                        data(&from),
                        tx.nonce
                    )
                }
            }
            reason::GAS_TOO_LOW => format!(
                "{text}: gas {}, minimum needed {}",
                tx.gas_limit,
                tx.min_gas_limit()
            ),
            reason::GAS_LIMIT_TOO_HIGH => format!(
                "{text} (cap: {}, tx: {})",
                MAX_TX_GAS.min(BLOCK_GAS_LIMIT),
                tx.gas_limit
            ),
            reason::INITCODE_TOO_LARGE => format!(
                "{text}: code size {}, limit {MAX_INITCODE_SIZE}",
                tx.input.len()
            ),
            _ => text.to_owned(),
        };
        Ok(RpcError::server(message))
    }

    /// Runs a message, first checking what the kernel would refuse it for so
    /// the error can say why.
    fn run(&mut self, request: &CallRequest) -> Result<CallResult, RpcError> {
        let needed = min_gas(request);
        if request.gas != 0 && request.gas < needed {
            return Err(RpcError::server(format!(
                "intrinsic gas too low: gas {}, minimum needed {needed}",
                request.gas
            )));
        }
        if request.to.is_none() && request.data.len() > MAX_INITCODE_SIZE {
            return Err(RpcError::server(format!(
                "max initcode size exceeded: code size {}, limit {MAX_INITCODE_SIZE}",
                request.data.len()
            )));
        }
        if request.value > 0 {
            let balance = self.node.account(&request.from)?.balance;
            if balance < request.value {
                return Err(RpcError::server(format!(
                    "insufficient funds for gas * price + value: address {} have {balance} want {}",
                    data(&request.from),
                    request.value
                )));
            }
        }
        self.execute(request)
    }

    /// Runs a message in the kernel. One that computes past the node's query
    /// budget is aborted, as geth aborts a call past its RPC timeout.
    fn execute(&mut self, request: &CallRequest) -> Result<CallResult, RpcError> {
        match self.node.call(request) {
            Err(e) if e.is_out_of_gas() => Err(RpcError::server(
                "execution aborted: the message ran past the node's query budget",
            )),
            result => Ok(result?),
        }
    }

    /// Runs `request` with `gas` and moves the bound of the search it
    /// settles. The node's background work runs first: an estimate takes
    /// several runs.
    fn narrow(
        &mut self,
        request: &mut CallRequest,
        gas: u64,
        lo: &mut u64,
        hi: &mut u64,
    ) -> Result<(), RpcError> {
        self.run_background();
        request.gas = gas;
        if self.execute(request)?.status == call_status::SUCCESS {
            *hi = gas;
        } else {
            *lo = gas;
        }
        Ok(())
    }

    /// geth's gas estimation: run at the cap (or the requested gas), then
    /// search between what the message used and the cap for the least gas it
    /// succeeds with, stopping within 1.5% above the answer.
    fn estimate_gas(&mut self, mut request: CallRequest) -> Result<u64, RpcError> {
        let mut hi = match request.gas {
            0 => MAX_TX_GAS,
            gas => gas.min(MAX_TX_GAS),
        };
        request.gas = hi;
        let first = self.run(&request)?;
        if first.status == call_status::HALT {
            return Err(RpcError::server(format!(
                "gas required exceeds allowance ({hi})"
            )));
        }
        if first.status != call_status::SUCCESS {
            return Err(call_error(&first));
        }
        // What the message used bounds what it needs from below, and most
        // messages need exactly that.
        let used = first.gas_used;
        let mut lo = used.max(min_gas(&request)) - 1;
        if used < hi {
            self.narrow(&mut request, used, &mut lo, &mut hi)?;
        }
        // Refunds and the 63/64 rule can need more; geth's first guess.
        let optimistic = (used + CALL_STIPEND) * 64 / 63;
        if lo + 1 < hi && optimistic < hi {
            self.narrow(&mut request, optimistic, &mut lo, &mut hi)?;
        }
        while lo + 1 < hi && (hi - lo) * 1000 >= hi * 15 {
            // Most messages need little more than they used: bisect towards the low side.
            let mid = lo.midpoint(hi).min(lo * 2);
            self.narrow(&mut request, mid, &mut lo, &mut hi)?;
        }
        Ok(hi)
    }

    /// The header at `height` with its hash. Height 0 is the genesis, which
    /// the kernel does not store: an empty header whose hash is zero, the
    /// parent hash of block 1.
    fn header_at(&mut self, height: u64) -> Result<Option<(BlockHeader, [u8; 32])>, RpcError> {
        if height == 0 {
            return Ok(Some((BlockHeader::default(), [0; 32])));
        }
        Ok(self.node.block_by_number(height)?.map(|header| {
            let hash = keccak256(&header.to_bytes());
            (header, hash)
        }))
    }

    /// The receipts of a block's transactions, in order.
    fn receipts_of(&mut self, header: &BlockHeader) -> Result<Vec<Receipt>, RpcError> {
        let mut out = Vec::with_capacity(header.tx_hashes.0.len());
        for hash in &header.tx_hashes.0 {
            out.push(self.node.receipt(hash)?.unwrap_or_default());
        }
        Ok(out)
    }

    /// Where the mined transaction `hash` went. Bytes that do not decode
    /// went nowhere.
    fn destination(&mut self, hash: &[u8; 32]) -> Result<Destination, RpcError> {
        let raw = self.node.transaction(hash)?.unwrap_or_default();
        Ok(match solo_eth::decode(&raw) {
            Ok(tx) if tx.to.is_none() => Destination {
                to: None,
                contract: sender(&raw).map(|from| created_address(&from, tx.nonce)),
            },
            Ok(tx) => Destination {
                to: tx.to,
                contract: None,
            },
            Err(_) => Destination::default(),
        })
    }

    fn receipt_json(&mut self, hash: &[u8; 32], receipt: &Receipt) -> Result<Value, RpcError> {
        let (header, block_hash) = self.header_at(receipt.height)?.unwrap_or_default();
        let earlier = header.tx_hashes.0.iter().take(receipt.index as usize);
        let mut first_log = 0;
        for tx_hash in earlier {
            let logs = self.node.receipt(tx_hash)?.unwrap_or_default().logs;
            first_log += logs.0.len() as u64;
        }
        let destination = self.destination(hash)?;
        Ok(views::receipt(
            hash,
            receipt,
            destination,
            &block_hash,
            first_log,
        ))
    }

    fn block_receipts_json(
        &mut self,
        header: &BlockHeader,
        hash: &[u8; 32],
    ) -> Result<Value, RpcError> {
        let receipts = self.receipts_of(header)?;
        let mut out = Vec::with_capacity(receipts.len());
        let mut first_log = 0;
        for (tx_hash, receipt) in header.tx_hashes.0.iter().zip(&receipts) {
            let destination = self.destination(tx_hash)?;
            out.push(views::receipt(
                tx_hash,
                receipt,
                destination,
                hash,
                first_log,
            ));
            first_log += receipt.logs.0.len() as u64;
        }
        Ok(Value::Array(out))
    }

    fn transaction_by_hash(&mut self, hash: &[u8; 32]) -> Result<Value, RpcError> {
        if let Some(receipt) = self.node.receipt(hash)? {
            let raw = self.node.transaction(hash)?.unwrap_or_default();
            let (_, block_hash) = self.header_at(receipt.height)?.unwrap_or_default();
            let position = Position {
                block_hash,
                height: receipt.height,
                index: receipt.index,
            };
            let mined = Some((&position, receipt.effective_gas_price));
            return Ok(views::transaction(
                hash,
                &decode_or_blank(&raw),
                &receipt.from,
                mined,
            ));
        }
        let pending = self.node.mempool().get(hash);
        Ok(pending.map_or(Value::Null, |p| {
            views::transaction(hash, &decode_or_blank(&p.raw), &p.sender, None)
        }))
    }

    fn block_json(
        &mut self,
        header: &BlockHeader,
        hash: &[u8; 32],
        full: bool,
    ) -> Result<Value, RpcError> {
        let receipts = self.receipts_of(header)?;
        let mut size = header.to_bytes().len();
        let mut transactions = Vec::with_capacity(receipts.len());
        for (tx_hash, receipt) in header.tx_hashes.0.iter().zip(&receipts) {
            let raw = self.node.transaction(tx_hash)?.unwrap_or_default();
            size += raw.len();
            transactions.push(if full {
                let position = Position {
                    block_hash: *hash,
                    height: header.height,
                    index: receipt.index,
                };
                let mined = Some((&position, receipt.effective_gas_price));
                views::transaction(tx_hash, &decode_or_blank(&raw), &receipt.from, mined)
            } else {
                json!(data(tx_hash))
            });
        }
        let logs: Vec<_> = receipts.iter().flat_map(|r| r.logs.0.iter()).collect();
        Ok(views::block(
            header,
            hash,
            &transactions,
            &views::bloom(&logs),
            size,
        ))
    }

    /// The heights a filter covers, within the chain and the range limit.
    fn filter_heights(&mut self, blocks: &Blocks) -> Result<(u64, u64), RpcError> {
        match blocks {
            Blocks::Hash(hash) => match self.node.block_by_hash(hash)? {
                Some(header) => Ok((header.height, header.height)),
                None => Err(RpcError::server("unknown block")),
            },
            Blocks::Range(from, to) => {
                let from = self.resolve_block(from.as_deref().unwrap_or("latest"))?;
                let to = self.resolve_block(to.as_deref().unwrap_or("latest"))?;
                if from > to {
                    return Err(RpcError::invalid_params("invalid block range"));
                }
                let to = to.min(self.block_number()?);
                if to.saturating_sub(from) >= self.max_log_range {
                    return Err(RpcError::with_code(
                        -32005,
                        format!(
                            "block range too large: {} blocks, the limit is {}",
                            to - from + 1,
                            self.max_log_range
                        ),
                    ));
                }
                // The genesis has no logs.
                Ok((from.max(1), to))
            }
        }
    }

    fn logs(&mut self, filter: &Filter) -> Result<Value, RpcError> {
        let (from, to) = self.filter_heights(&filter.blocks)?;
        let mut out = Vec::new();
        for height in from..=to {
            self.run_background();
            let (header, block_hash) = self.header_at(height)?.unwrap_or_default();
            let mut log_index = 0;
            for tx_hash in &header.tx_hashes.0 {
                let receipt = self.node.receipt(tx_hash)?.unwrap_or_default();
                let position = Position {
                    block_hash,
                    height,
                    index: receipt.index,
                };
                for log in &receipt.logs.0 {
                    if filter.matches(log) {
                        out.push(views::log(log, tx_hash, &position, log_index));
                    }
                    log_index += 1;
                }
            }
        }
        Ok(Value::Array(out))
    }

    #[allow(clippy::cast_precision_loss)]
    fn fee_history(&mut self, params: &[Value]) -> Result<Value, RpcError> {
        let count = block_count(params.first())?;
        let newest = self.resolve_block(param_str(params, 1)?)?;
        let percentiles = percentiles(params.get(2))?;
        let head = self.block_number()?;
        if newest > head {
            return Err(RpcError::server(format!(
                "request beyond head block: requested {newest}, head {head}"
            )));
        }
        if count == 0 {
            return Ok(
                json!({ "oldestBlock": quantity(0), "baseFeePerGas": [], "gasUsedRatio": [] }),
            );
        }
        let count = count.min(MAX_FEE_HISTORY).min(newest + 1);
        let oldest = newest + 1 - count;
        let mut ratios = Vec::new();
        let mut reward = Vec::new();
        for height in oldest..=newest {
            self.run_background();
            let (header, _) = self.header_at(height)?.unwrap_or_default();
            // Gas amounts are far below 2^53: the ratio is exact enough.
            ratios.push(header.gas_used as f64 / BLOCK_GAS_LIMIT as f64);
            let receipts = self.receipts_of(&header)?;
            reward.push(rewards(&receipts, header.gas_used, &percentiles));
        }
        let blocks = ratios.len();
        let mut history = json!({
            "oldestBlock": quantity(u128::from(oldest)),
            "baseFeePerGas": vec![quantity(u128::from(BASE_FEE)); blocks + 1],
            "gasUsedRatio": ratios,
            "baseFeePerBlobGas": vec![quantity(0); blocks + 1],
            "blobGasUsedRatio": vec![0.0; blocks],
        });
        if !percentiles.is_empty() {
            history["reward"] = json!(reward);
        }
        Ok(history)
    }
}

fn error_response(id: &Value, error: &RpcError) -> Value {
    let mut body = json!({ "code": error.code, "message": error.message });
    if let Some(data) = &error.data {
        body["data"] = json!(data);
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": body })
}
