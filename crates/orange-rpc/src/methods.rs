//! Method dispatch (JSON-RPC 2.0).

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use orange_abi::chain::{
    BLOCK_GAS_LIMIT, BlockHeader, CallRequest, CallResult, Log, Receipt, call_status, reason,
};
use orange_eth::{MAX_INITCODE_SIZE, MAX_TX_GAS};
use orange_host::hash::keccak256;
use orange_node::{Node, NodeError, SubmitError};
use serde_json::{Value, json};

use crate::call::{call_error, call_request, min_gas};
use crate::filter::{Blocks, Filter};
pub use crate::hex::{
    data, parse_address, parse_big, parse_hash, parse_hex, parse_quantity, parse_word, quantity,
    quantity_be,
};
use crate::indexed::By;
use crate::proof;
use crate::views::{self, Destination, Position, created_address, decode_or_blank};

/// Default widest block range one `eth_getLogs` request may search
/// ([`Rpc::max_log_range`]): every block in it costs a kernel query.
pub const MAX_LOG_RANGE: u64 = 10_000;

/// Default most requests one batch may carry ([`Rpc::max_batch`]), geth's
/// default.
pub const MAX_BATCH: usize = 1000;

/// Default most bytes of JSON one batch answers, and one `txpool_content`
/// ([`Rpc::max_response_bytes`]), geth's `BatchResponseMaxSize` (spec 20
/// §8.6).
pub const MAX_RESPONSE_BYTES: usize = 25_000_000;

/// Default most logs one `eth_getLogs` request answers ([`Rpc::max_logs`],
/// spec 20 §8.6).
pub const MAX_LOGS: usize = 10_000;

/// Work the node must keep doing while requests are served: polling the
/// network and ticking the clock. Requests run on the thread that drives
/// consensus, so the server runs this after each request it answers, and
/// long requests run it between their steps (see [`Rpc::run_background`]).
pub type Background = Box<dyn FnMut(&mut Node)>;

/// What [`Rpc::handle_with`] asks first about each method, with its
/// parameters: an answer, or `None` to serve the method as usual.
pub type Intercept<'a> =
    &'a mut dyn FnMut(&mut Rpc, &str, &[Value]) -> Option<Result<Value, RpcError>>;

/// Most storage keys one `eth_getProof` request may ask for (spec 20 §4.1):
/// each costs a kernel query and a proof on the thread that drives
/// consensus.
pub const MAX_PROOF_KEYS: usize = 1024;

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
        reason::FEE_TOO_LOW => "max fee per gas less than block base fee",
        reason::TIP_ABOVE_FEE_CAP => "max priority fee per gas higher than max fee per gas",
        reason::GAS_LIMIT_TOO_HIGH => "transaction gas limit too high",
        reason::INITCODE_TOO_LARGE => "max initcode size exceeded",
        reason::SENDER_NOT_EOA => "sender not an eoa",
        reason::SYSTEM_ACTION => {
            "not a valid system action (governance, upgrade or module install)"
        }
        reason::STAKING_ACTION => "not a valid staking action",
        reason::OUTBOX_MESSAGE => "not a valid outbox message",
        reason::BRIDGE_CALL => "not a valid bridge call",
        reason::BRIDGE_UPDATE => "light client update does not advance the light client",
        reason::MESSAGE_DELIVERED => "message already delivered",
        reason::INBOX_PAUSED => "inbox paused",
        _ => "rejected",
    }
}

/// The address that signed a raw transaction, if it decodes and recovers.
#[must_use]
pub fn sender(raw: &[u8]) -> Option<[u8; 20]> {
    let tx = orange_eth::decode(raw).ok()?;
    let sig = tx.signature();
    let signature = Signature::from_slice(&sig[..64]).ok()?;
    let id = RecoveryId::from_byte(sig[64])?;
    let key =
        VerifyingKey::recover_from_prehash(&keccak256(&tx.signing_payload), &signature, id).ok()?;
    let point = key.to_encoded_point(false);
    keccak256(&point.as_bytes()[1..])[12..].try_into().ok()
}

pub(crate) fn param_str(params: &[Value], index: usize) -> Result<&str, RpcError> {
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

/// Serves Ethereum JSON-RPC over a node.
///
/// Requests run on the caller's thread, which also drives the node, so what
/// one request can make the node compute is bounded: each kernel query by
/// the node's query budget ([`Node::query_gas`]), and the requests that
/// make many queries (batches, gas estimation, log and fee-history scans,
/// the storage keys of a proof) hand the node its [`Background`] work
/// between them.
pub struct Rpc {
    node: Node,
    background: Option<Background>,
    /// The priority fee the node suggests before any block carries a priced
    /// transaction, in wei: the tip oracle's starting point (spec 23 §7.1,
    /// [`Rpc::suggest_tip`]); one gwei unless changed.
    pub gas_price: u128,
    /// The tip oracle's memory.
    pub(crate) oracle: crate::fees::Oracle,
    /// Widest block range one `eth_getLogs` request may search, counted
    /// within the chain; [`MAX_LOG_RANGE`] unless changed.
    pub max_log_range: u64,
    /// Most requests one batch may carry; [`MAX_BATCH`] unless changed.
    pub max_batch: usize,
    /// Most bytes of JSON one batch's answers, and one `txpool_content`,
    /// may take; [`MAX_RESPONSE_BYTES`] unless changed.
    pub max_response_bytes: usize,
    /// Most logs one `eth_getLogs` request answers; [`MAX_LOGS`] unless
    /// changed.
    pub max_logs: usize,
    /// The installed filters of `eth_newFilter` and its kin.
    pub(crate) filters: crate::filters::Filters,
    /// How long a filter lives without being polled;
    /// [`crate::filters::FILTER_TIMEOUT`] unless changed.
    pub filter_timeout: std::time::Duration,
    /// Most filters installed at once; [`crate::filters::MAX_FILTERS`]
    /// unless changed.
    pub max_filters: usize,
    /// Set by `orange_stop`; the server loop exits when it sees it.
    pub stopped: bool,
    /// Whether `orange_stop` is served: off unless changed, since anything
    /// that reaches the address could stop the node; a node whose operator
    /// stops it through its JSON-RPC turns it on (`--rpc-stop`).
    pub stop_allowed: bool,
    /// The origins whose browser pages the HTTP server answers (spec 20
    /// §8.5), `*` for any; none unless changed. A request without an
    /// `Origin` header, which is what clients outside browsers send, is
    /// answered whatever this holds.
    pub cors: Vec<String>,
}

impl Rpc {
    /// Wraps a started node.
    #[must_use]
    pub fn new(node: Node) -> Rpc {
        Rpc {
            node,
            background: None,
            gas_price: 1_000_000_000,
            oracle: crate::fees::Oracle::default(),
            max_log_range: MAX_LOG_RANGE,
            max_batch: MAX_BATCH,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_logs: MAX_LOGS,
            filters: crate::filters::Filters::default(),
            filter_timeout: crate::filters::FILTER_TIMEOUT,
            max_filters: crate::filters::MAX_FILTERS,
            stopped: false,
            stop_allowed: false,
            cors: Vec::new(),
        }
    }

    /// Sets the node's background work; see [`Rpc::run_background`].
    pub fn set_background(&mut self, work: Background) {
        self.background = Some(work);
    }

    /// Runs the background work once, if any is set. The HTTP server calls
    /// this after each request it answers; requests call it between batch
    /// entries, between gas-estimation runs, between the blocks of a log or
    /// fee-history scan and between the storage keys of `eth_getProof`, so
    /// the node keeps voting while they are served.
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
        self.handle_with(request, &mut |_, _, _| None)
    }

    /// [`Rpc::handle`], with `intercept` given the first say on every
    /// method: what it answers is the answer, and a method it answers
    /// `None` to is served as usual. The WebSocket serves `eth_subscribe`
    /// and `eth_unsubscribe` so (spec 20 §8.7.3).
    pub fn handle_with(&mut self, request: &Value, intercept: Intercept<'_>) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let Some(method) = request.get("method").and_then(Value::as_str) else {
            return error_response(&id, &RpcError::with_code(-32600, "missing method".into()));
        };
        let empty = Vec::new();
        let params = request
            .get("params")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        let result = match intercept(self, method, params) {
            Some(result) => result,
            None => self.dispatch(method, params),
        };
        match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(e) => error_response(&id, &e),
        }
    }

    /// Handles a request body: a single request or a batch. A batch longer
    /// than [`Rpc::max_batch`] gets one error, under the id of its first
    /// request, as geth answers it; once a batch's answers pass
    /// [`Rpc::max_response_bytes`], the requests after are answered
    /// `response too large` without being run, as geth answers them.
    pub fn handle_body(&mut self, body: &str) -> Value {
        self.handle_body_with(body, &mut |_, _, _| None)
    }

    /// [`Rpc::handle_body`], with every request of it handled as
    /// [`Rpc::handle_with`] handles it.
    pub fn handle_body_with(&mut self, body: &str, intercept: Intercept<'_>) -> Value {
        match serde_json::from_str::<Value>(body) {
            Ok(Value::Array(batch)) if batch.len() > self.max_batch => {
                let id = batch.iter().find_map(|r| r.get("id")).cloned();
                let error = RpcError::with_code(-32600, "batch too large".into());
                json!([error_response(&id.unwrap_or(Value::Null), &error)])
            }
            Ok(Value::Array(batch)) => {
                let mut out = Vec::with_capacity(batch.len());
                let mut spent = 0;
                for request in &batch {
                    if spent > self.max_response_bytes {
                        let id = request.get("id").cloned().unwrap_or(Value::Null);
                        out.push(error_response(&id, &too_large()));
                        continue;
                    }
                    self.run_background();
                    let answer = self.handle_with(request, intercept);
                    spent += encoded_len(&answer);
                    out.push(answer);
                }
                Value::Array(out)
            }
            Ok(single) => self.handle_with(&single, intercept),
            Err(_) => error_response(
                &Value::Null,
                &RpcError::with_code(-32700, "parse error".into()),
            ),
        }
    }

    pub(crate) fn block_number(&mut self) -> Result<u64, RpcError> {
        Ok(self.node.block_number()?)
    }

    pub(crate) fn resolve_block(&mut self, tag: &str) -> Result<u64, RpcError> {
        Ok(match tag {
            "latest" | "pending" => self.block_number()?,
            "safe" | "finalized" => self.node.finalized_height()?,
            "earliest" => 0,
            hex => parse_quantity(hex)?,
        })
    }

    /// The height a state method's block parameter names: a tag (`latest`,
    /// `pending`, `safe` and `finalized` all name the head, spec 08 section
    /// 8; `earliest` is the genesis), a number or a hash, directly or as an
    /// EIP-1898 object with `blockHash` or `blockNumber`. `None` is the head,
    /// served from the current state; an older height is served from the
    /// node's state history (spec 20 §5). A block above the head does not
    /// exist, and one whose state the node no longer keeps is refused as a
    /// pruned geth node refuses it, rather than answered from another
    /// block's state.
    fn state_at(&mut self, param: Option<&Value>) -> Result<Option<u64>, RpcError> {
        let height = match param {
            None | Some(Value::Null) => return Ok(None),
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
        if height == head {
            return Ok(None);
        }
        if height < self.node.oldest_state() {
            let (header, _) = self.header_at(height)?.unwrap_or_default();
            return Err(self.unavailable(&header.state_root, height));
        }
        Ok(Some(height))
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

    /// The height the block parameter of `eth_getProof` names, the head
    /// included.
    fn proof_height(&mut self, param: Option<&Value>) -> Result<u64, RpcError> {
        match self.state_at(param)? {
            Some(height) => Ok(height),
            None => self.block_number(),
        }
    }

    fn hash_height(&mut self, hash: &str) -> Result<u64, RpcError> {
        match self.header_by_hash(&parse_hash(hash)?)? {
            Some(header) => Ok(header.height),
            None => Err(RpcError::server("header for hash not found")),
        }
    }

    /// The header of the block whose hash is `hash`, the genesis block's
    /// included: the kernel indexes every block it stores by its hash
    /// (spec 20 §3.1).
    pub(crate) fn header_by_hash(
        &mut self,
        hash: &[u8; 32],
    ) -> Result<Option<BlockHeader>, RpcError> {
        Ok(self.node.block_by_hash(hash)?)
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch(&mut self, method: &str, params: &[Value]) -> Result<Value, RpcError> {
        Ok(match method {
            "eth_chainId" => json!(quantity(u128::from(self.node.chain_id()?))),
            "net_version" => json!(self.node.chain_id()?.to_string()),
            "web3_clientVersion" => json!("orange/0.0.1"),
            "web3_sha3" => json!(data(&keccak256(&parse_hex(param_str(params, 0)?)?))),
            "net_listening" => json!(true),
            "net_peerCount" => json!(quantity(u128::from(self.node.status()?.peers))),
            "eth_blockNumber" => json!(quantity(u128::from(self.block_number()?))),
            "eth_gasPrice" => json!(quantity(self.gas_price()?)),
            "eth_maxPriorityFeePerGas" => json!(quantity(self.suggest_tip()?)),
            // No blob transaction is accepted (§2.1): the blob base fee
            // stays at its minimum.
            "eth_blobBaseFee" => json!(quantity(1)),
            "eth_syncing" => json!(false),
            "orange_stop" if !self.stop_allowed => {
                return Err(RpcError::with_code(
                    -32601,
                    "method not found: orange_stop (this node serves it only when started with --rpc-stop)".into(),
                ));
            }
            "orange_stop" => {
                self.stopped = true;
                json!(true)
            }
            "eth_accounts" => json!([]),
            "eth_getBalance" => {
                let address = address_param(params, 0)?;
                let at = self.state_at(params.get(1))?;
                json!(quantity(self.node.account_at(&address, at)?.balance))
            }
            "eth_getTransactionCount" => {
                let address = address_param(params, 0)?;
                let at = self.state_at(params.get(1))?;
                let nonce = if params.get(1).and_then(Value::as_str) == Some("pending") {
                    self.node.pending_nonce(&address)?
                } else {
                    self.node.account_at(&address, at)?.nonce
                };
                json!(quantity(u128::from(nonce)))
            }
            "eth_getCode" => {
                let address = address_param(params, 0)?;
                let at = self.state_at(params.get(1))?;
                json!(data(&self.node.code_at(&address, at)?))
            }
            "eth_getStorageAt" => {
                let address = address_param(params, 0)?;
                let slot = parse_word(param_str(params, 1)?)?;
                let at = self.state_at(params.get(2))?;
                json!(data(&self.node.storage_at(&address, &slot, at)?))
            }
            "eth_getProof" => self.proof(params)?,
            "eth_call" => {
                let request = call_request(params.first())?;
                let at = self.state_at(params.get(1))?;
                let result = self.run(&request, at)?;
                if result.status != call_status::SUCCESS {
                    return Err(call_error(&result));
                }
                json!(data(&result.output))
            }
            "eth_estimateGas" => {
                let request = call_request(params.first())?;
                let at = self.state_at(params.get(1))?;
                json!(quantity(u128::from(self.estimate_gas(request, at)?)))
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
                match self.header_by_hash(&hash)? {
                    Some(header) => self.block_json(&header, &hash, full)?,
                    None => Value::Null,
                }
            }
            "eth_getBlockReceipts" => {
                let block = param_str(params, 0)?;
                let found = if block.len() == 66 {
                    let hash = parse_hash(block)?;
                    self.header_by_hash(&hash)?.map(|header| (header, hash))
                } else {
                    let height = self.resolve_block(block)?;
                    self.header_at(height)?
                };
                match found {
                    Some((header, hash)) => self.block_receipts_json(&header, &hash)?,
                    None => Value::Null,
                }
            }
            "eth_getBlockTransactionCountByNumber" => self.transaction_count(By::Number, params)?,
            "eth_getBlockTransactionCountByHash" => self.transaction_count(By::Hash, params)?,
            "eth_getTransactionByBlockNumberAndIndex" => self.transaction_at(By::Number, params)?,
            "eth_getTransactionByBlockHashAndIndex" => self.transaction_at(By::Hash, params)?,
            "eth_getUncleCountByBlockNumber" => self.uncle_count(By::Number, params)?,
            "eth_getUncleCountByBlockHash" => self.uncle_count(By::Hash, params)?,
            "eth_getUncleByBlockNumberAndIndex" | "eth_getUncleByBlockHashAndIndex" => Value::Null,
            "eth_getLogs" => self.logs(&Filter::parse(params.first())?)?,
            "eth_feeHistory" => self.fee_history(params)?,
            "eth_newFilter" => self.new_log_filter(params)?,
            "eth_newBlockFilter" => self.new_block_filter()?,
            "eth_newPendingTransactionFilter" => self.new_pending_filter()?,
            "eth_getFilterChanges" => self.filter_changes(params)?,
            "eth_getFilterLogs" => self.filter_logs(params)?,
            "eth_uninstallFilter" => self.uninstall_filter(params)?,
            // Subscriptions need a connection that stays open: the
            // WebSocket serves them before they get here (§8.7.3), and over
            // HTTP they are answered as geth answers them there (§8.3).
            "eth_subscribe" | "eth_unsubscribe" => {
                return Err(RpcError::with_code(
                    -32601,
                    "notifications not supported".into(),
                ));
            }
            "txpool_status" => crate::txpool::status(self.node.mempool()),
            "txpool_content" => {
                crate::txpool::content(self.node.mempool(), self.max_response_bytes)?
            }
            "orange_getFinalityProof" => crate::bridge::finality_proof(&mut self.node, params)?,
            "orange_getOutboxProof" => crate::bridge::outbox_proof(&mut self.node, params)?,
            "orange_getRotation" => crate::bridge::rotation(&mut self.node, params)?,
            "orange_getGroupKey" => crate::bridge::group_key(&self.node),
            "orange_getGovernance" => crate::governance::governance(&mut self.node)?,
            "orange_getProposals" => crate::governance::proposals(&mut self.node)?,
            "orange_getProposal" => crate::governance::proposal(&mut self.node, params)?,
            "orange_upgradeStatus" => crate::upgrades::upgrade_status(&mut self.node)?,
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
                tx.min_gas_limit() + orange_abi::governance::surcharge(tx.to.as_ref(), &tx.input)
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
            reason::FEE_TOO_LOW => format!(
                "{text}: address {}, maxFeePerGas: {}, baseFee: {}",
                data(&sender(raw).unwrap_or_default()),
                tx.gas_price,
                self.node.fee_status().base_fee
            ),
            reason::TIP_ABOVE_FEE_CAP => format!(
                "{text}: address {}, maxPriorityFeePerGas: {}, maxFeePerGas: {}",
                data(&sender(raw).unwrap_or_default()),
                tx.priority_fee.unwrap_or_default(),
                tx.gas_price
            ),
            _ => text.to_owned(),
        };
        Ok(RpcError::server(message))
    }

    /// `eth_getProof(address, slots, block)`: the account and the slots with
    /// their spec 10 proofs against the block's state root (spec 20 §4), at
    /// most [`MAX_PROOF_KEYS`] slots. Each slot is a kernel query, so the
    /// node's background work runs before each; the head can move meanwhile,
    /// and every read names the height the request resolved to.
    fn proof(&mut self, params: &[Value]) -> Result<Value, RpcError> {
        let address = address_param(params, 0)?;
        let Some(Value::Array(keys)) = params.get(1) else {
            return Err(RpcError::invalid_params("missing storage keys"));
        };
        if keys.len() > MAX_PROOF_KEYS {
            return Err(RpcError::invalid_params(format!(
                "too many storage keys: {}, the limit is {MAX_PROOF_KEYS}",
                keys.len()
            )));
        }
        let mut slots = Vec::with_capacity(keys.len());
        for key in keys {
            let key = key.as_str().unwrap_or_default();
            slots.push((key.to_owned(), parse_word(key)?));
        }
        let height = self.proof_height(params.get(2))?;
        let (header, _) = self.header_at(height)?.unwrap_or_default();
        // `proof_height` refused a height whose state is gone, and the node
        // keeps a height's trie as long as its state: this error is the
        // same, should the two ever disagree.
        let unavailable = self.unavailable(&header.state_root, height);
        let key = proof::account_key(&address);
        let account_proof = self.node.state_proof_at(height, &key).ok_or(unavailable)?;
        let account = self.node.account_at(&address, Some(height))?;
        let present = matches!(account_proof.terminal,
            orange_trie::Terminal::Leaf { path, .. } if path == keccak256(&key));
        let mut storage = Vec::with_capacity(slots.len());
        for (requested, slot) in &slots {
            self.run_background();
            // The background work can execute blocks and prune the height,
            // its trie with its state: the proof is looked up first, so the
            // error is the pruned-state one.
            let unavailable = self.unavailable(&header.state_root, height);
            let slot_proof = self
                .node
                .state_proof_at(height, &proof::slot_key(&address, slot))
                .ok_or(unavailable)?;
            let value = self.node.storage_at(&address, slot, Some(height))?;
            storage.push(proof::storage_entry(requested, &value, &slot_proof));
        }
        Ok(proof::response(
            &address,
            present.then_some(&account),
            &header.state_root,
            &account_proof,
            &storage,
        ))
    }

    /// The error for `height`, whose header carries `root`, once the node no
    /// longer keeps its state (spec 20 §5.3).
    fn unavailable(&self, root: &[u8; 32], height: u64) -> RpcError {
        RpcError::server(missing_state(root, height, self.node.oldest_state()))
    }

    /// Runs a message, first checking what the kernel would refuse it for so
    /// the error can say why.
    fn run(&mut self, request: &CallRequest, at: Option<u64>) -> Result<CallResult, RpcError> {
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
            let balance = self.node.account_at(&request.from, at)?.balance;
            if balance < request.value {
                return Err(RpcError::server(format!(
                    "insufficient funds for gas * price + value: address {} have {balance} want {}",
                    data(&request.from),
                    request.value
                )));
            }
        }
        self.execute(request, at)
    }

    /// Runs a message in the kernel. One that computes past the node's query
    /// budget is aborted, as geth aborts a call past its RPC timeout.
    fn execute(&mut self, request: &CallRequest, at: Option<u64>) -> Result<CallResult, RpcError> {
        match self.node.call_at(request, at) {
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
        at: Option<u64>,
        gas: u64,
        bounds: (&mut u64, &mut u64),
    ) -> Result<(), RpcError> {
        let (lo, hi) = bounds;
        self.run_background();
        request.gas = gas;
        if self.execute(request, at)?.status == call_status::SUCCESS {
            *hi = gas;
        } else {
            *lo = gas;
        }
        Ok(())
    }

    /// geth's gas estimation: run at the cap (or the requested gas), then
    /// search between what the message used and the cap for the least gas it
    /// succeeds with, stopping within 1.5% above the answer.
    fn estimate_gas(&mut self, mut request: CallRequest, at: Option<u64>) -> Result<u64, RpcError> {
        let mut hi = match request.gas {
            0 => MAX_TX_GAS,
            gas => gas.min(MAX_TX_GAS),
        };
        request.gas = hi;
        let first = self.run(&request, at)?;
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
            self.narrow(&mut request, at, used, (&mut lo, &mut hi))?;
        }
        // Refunds and the 63/64 rule can need more; geth's first guess.
        let optimistic = (used + CALL_STIPEND) * 64 / 63;
        if lo + 1 < hi && optimistic < hi {
            self.narrow(&mut request, at, optimistic, (&mut lo, &mut hi))?;
        }
        while lo + 1 < hi && (hi - lo) * 1000 >= hi * 15 {
            // Most messages need little more than they used: bisect towards the low side.
            let mid = lo.midpoint(hi).min(lo * 2);
            self.narrow(&mut request, at, mid, (&mut lo, &mut hi))?;
        }
        Ok(hi)
    }

    /// The header at `height` with its hash; height 0 is the genesis block,
    /// which the kernel stores at `kernel_init` (spec 20 §3.1).
    pub(crate) fn header_at(
        &mut self,
        height: u64,
    ) -> Result<Option<(BlockHeader, [u8; 32])>, RpcError> {
        Ok(self.node.block_by_number(height)?.map(|header| {
            let hash = orange_eth::header::block_hash(&header, keccak256);
            (header, hash)
        }))
    }

    /// The receipts of a block's transactions, in order.
    pub(crate) fn receipts_of(&mut self, header: &BlockHeader) -> Result<Vec<Receipt>, RpcError> {
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
        Ok(match orange_eth::decode(&raw) {
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

    /// The system receipt of the block whose hash is `block_hash`, with its
    /// hash, if the end of that block logged anything (spec 20 §3.5).
    pub(crate) fn system_receipt(
        &mut self,
        block_hash: &[u8; 32],
    ) -> Result<Option<([u8; 32], Receipt)>, RpcError> {
        let hash = keccak256(&orange_abi::chain::system_receipt_preimage(block_hash));
        Ok(self.node.receipt(&hash)?.map(|r| (hash, r)))
    }

    fn receipt_json(&mut self, hash: &[u8; 32], receipt: &Receipt) -> Result<Value, RpcError> {
        let (header, block_hash) = self.header_at(receipt.height)?.unwrap_or_default();
        let earlier = header.tx_hashes.0.iter().take(receipt.index as usize);
        let mut first_log = 0;
        for tx_hash in earlier {
            let logs = self.node.receipt(tx_hash)?.unwrap_or_default().logs;
            first_log += logs.0.len() as u64;
        }
        let destination = if self.node.transaction(hash)?.is_none() {
            // A system receipt, of no transaction: its logs are the
            // governance address's end of the block.
            Destination {
                to: Some(receipt.to),
                contract: None,
            }
        } else {
            self.destination(hash)?
        };
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

    pub(crate) fn transaction_by_hash(&mut self, hash: &[u8; 32]) -> Result<Value, RpcError> {
        if let Some(receipt) = self.node.receipt(hash)? {
            // A system receipt has no transaction.
            let Some(raw) = self.node.transaction(hash)? else {
                return Ok(Value::Null);
            };
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
        let mut raws = Vec::with_capacity(receipts.len());
        let mut transactions = Vec::with_capacity(receipts.len());
        for (tx_hash, receipt) in header.tx_hashes.0.iter().zip(&receipts) {
            let raw = self.node.transaction(tx_hash)?.unwrap_or_default();
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
            raws.push(raw);
        }
        let size = views::block_size(header, &raws);
        Ok(views::block(header, hash, &transactions, size))
    }

    /// The heights a filter covers, within the chain and the range limit.
    fn filter_heights(&mut self, blocks: &Blocks) -> Result<(u64, u64), RpcError> {
        match blocks {
            Blocks::Hash(hash) => match self.header_by_hash(hash)? {
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

    /// `eth_getLogs`: at most [`Rpc::max_logs`] logs, or an error.
    pub(crate) fn logs(&mut self, filter: &Filter) -> Result<Value, RpcError> {
        let (from, to) = self.filter_heights(&filter.blocks)?;
        let (logs, _) = self.scan_logs(filter, from, to)?;
        if logs.len() > self.max_logs {
            return Err(RpcError::with_code(
                -32005,
                format!("query returned more than {} results", self.max_logs),
            ));
        }
        Ok(Value::Array(logs))
    }

    /// The logs `filter` matches in the blocks `from..=to`, which exist, and
    /// the last block scanned: the scan stops after the block that takes it
    /// past [`Rpc::max_logs`], or at `to`. The node's background work runs
    /// before each block.
    pub(crate) fn scan_logs(
        &mut self,
        filter: &Filter,
        from: u64,
        to: u64,
    ) -> Result<(Vec<Value>, u64), RpcError> {
        let mut out = Vec::new();
        for height in from..=to {
            if out.len() > self.max_logs {
                return Ok((out, height - 1));
            }
            self.run_background();
            let logs = self.block_logs(height, &|log| filter.matches(log))?;
            out.extend(logs.into_iter().map(|(_, view)| view));
        }
        Ok((out, to))
    }

    /// The logs of the block at `height`, which exists, that `keep` keeps,
    /// each with its view, in the order `eth_getLogs` answers them: its
    /// transactions' logs, then the system receipt's (spec 20 §3.5).
    pub(crate) fn block_logs(
        &mut self,
        height: u64,
        keep: &dyn Fn(&Log) -> bool,
    ) -> Result<Vec<(Log, Value)>, RpcError> {
        let mut out = Vec::new();
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
                if keep(log) {
                    out.push((log.clone(), views::log(log, tx_hash, &position, log_index)));
                }
                log_index += 1;
            }
        }
        // What the end of the block logged comes after its transactions'
        // logs, under the system receipt's hash (spec 20 §3.5).
        if let Some((hash, receipt)) = self.system_receipt(&block_hash)? {
            let position = Position {
                block_hash,
                height,
                index: receipt.index,
            };
            for log in &receipt.logs.0 {
                if keep(log) {
                    out.push((log.clone(), views::log(log, &hash, &position, log_index)));
                }
                log_index += 1;
            }
        }
        Ok(out)
    }

    /// The header `newHeads` announces for the block at `height`, if it
    /// exists (spec 20 §8.7.3).
    pub(crate) fn head_json(&mut self, height: u64) -> Result<Option<Value>, RpcError> {
        Ok(self
            .header_at(height)?
            .map(|(header, hash)| views::head(&header, &hash)))
    }
}

/// The error for a height whose state the node does not keep, in the words
/// of a pruned geth node (spec 20 §5).
fn missing_state(root: &[u8; 32], height: u64, oldest: u64) -> String {
    format!(
        "missing trie node {} (path ) state of block {height} is not available, the node keeps the state from block {oldest}",
        &data(root)[2..]
    )
}

/// geth's error for an answer past the response limit (-32003).
pub(crate) fn too_large() -> RpcError {
    RpcError::with_code(-32003, "response too large".into())
}

/// The length of `value` as compact JSON, as the server sends it.
pub(crate) fn encoded_len(value: &Value) -> usize {
    value.to_string().len()
}

fn error_response(id: &Value, error: &RpcError) -> Value {
    let mut body = json!({ "code": error.code, "message": error.message });
    if let Some(data) = &error.data {
        body["data"] = json!(data);
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": body })
}
