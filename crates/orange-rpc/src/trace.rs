//! geth's tracing methods (spec 20 §9): `debug_traceTransaction`,
//! `debug_traceBlockByNumber`, `debug_traceBlockByHash` and
//! `debug_traceCall`, with `callTracer`, `prestateTracer` and `noopTracer`.
//! The kernel executes the block again, or the call, with a tracer
//! (`orange_abi::trace`); this module reads the tracer object, checks the
//! trace against the receipts the block recorded, and writes the records
//! in geth's JSON.

use orange_abi::chain::{BlockHeader, CallResult, call_status};
use orange_abi::trace::{
    AccountState, CallFrame, TraceBlockRequest, TraceCallRequest, TraceConfig, TxTrace,
    frame_error, kind, tracer,
};
use orange_host::hash::keccak256;
use serde_json::{Map, Value, json};

use crate::Rpc;
use crate::call::{call_error, call_request, revert_reason};
use crate::hex::{data, quantity};
use crate::indexed::By;
use crate::methods::{RpcError, encoded_len, param_str, parse_hash, too_large};

/// A tracer object (geth's `TraceConfig`) as read.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracer {
    /// What the kernel runs.
    pub config: TraceConfig,
    /// `noopTracer`: the result is `{}`.
    pub noop: bool,
    /// `prestateTracer`'s `disableCode`.
    pub disable_code: bool,
    /// `prestateTracer`'s `disableStorage`.
    pub disable_storage: bool,
    /// `prestateTracer`'s `includeEmpty`.
    pub include_empty: bool,
}

/// A boolean option of `tracerConfig`: absent or null is false.
fn flag(object: &Map<String, Value>, name: &str) -> Result<bool, RpcError> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(RpcError::invalid_params(format!(
            "{name} must be a boolean"
        ))),
    }
}

/// Reads a tracer object. `tracer` names `callTracer`, `prestateTracer` or
/// `noopTracer`; without one geth runs its struct logger, opcode by opcode,
/// which the kernel does not record, so it is refused, as are the overrides
/// of `debug_traceCall`. `timeout` and `reexec` are accepted and have no
/// effect: the node's trace budget bounds the work, and the node keeps the
/// state it keeps.
///
/// # Errors
/// -32602 for a tracer object that does not parse or names another tracer,
/// -32000 for the struct logger.
pub fn tracer_of(value: Option<&Value>) -> Result<Tracer, RpcError> {
    let empty = Map::new();
    let object = match value {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(object)) => object,
        Some(_) => return Err(RpcError::invalid_params("tracer config must be an object")),
    };
    for field in ["stateOverrides", "blockOverrides"] {
        if object.get(field).is_some_and(|v| !v.is_null()) {
            return Err(RpcError::invalid_params(format!(
                "{field} are not supported"
            )));
        }
    }
    let options = match object.get("tracerConfig") {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(options)) => options,
        Some(_) => return Err(RpcError::invalid_params("tracerConfig must be an object")),
    };
    let name = match object.get("tracer") {
        None | Some(Value::Null) => None,
        Some(Value::String(name)) => Some(name.as_str()),
        Some(_) => return Err(RpcError::invalid_params("tracer must be a string")),
    };
    let mut config = TraceConfig::default();
    let mut out = Tracer {
        config: TraceConfig::default(),
        noop: false,
        disable_code: false,
        disable_storage: false,
        include_empty: false,
    };
    match name {
        None => {
            return Err(RpcError::server(
                "opcode-level tracing (the struct logger) is not supported: ask for callTracer or prestateTracer",
            ));
        }
        Some("callTracer") => {
            config.tracer = tracer::CALL;
            config.only_top_call = flag(options, "onlyTopCall")?;
            config.with_log = flag(options, "withLog")?;
        }
        Some("prestateTracer") => {
            config.tracer = tracer::PRESTATE;
            config.diff_mode = flag(options, "diffMode")?;
            out.disable_code = flag(options, "disableCode")?;
            out.disable_storage = flag(options, "disableStorage")?;
            out.include_empty = flag(options, "includeEmpty")?;
        }
        Some("noopTracer") => {
            config.tracer = tracer::CALL;
            config.only_top_call = true;
            out.noop = true;
        }
        Some(other) => {
            return Err(RpcError::invalid_params(format!(
                "tracer not supported: {other} (this node runs callTracer, prestateTracer and noopTracer)"
            )));
        }
    }
    out.config = config;
    Ok(out)
}

/// geth's name of a frame's opcode.
fn kind_name(k: u8) -> &'static str {
    match k {
        kind::CREATE => "CREATE",
        kind::CREATE2 => "CREATE2",
        kind::CALLCODE => "CALLCODE",
        kind::DELEGATECALL => "DELEGATECALL",
        kind::STATICCALL => "STATICCALL",
        kind::SELFDESTRUCT => "SELFDESTRUCT",
        _ => "CALL",
    }
}

/// geth's error text for a failed frame (`core/vm/errors.go`); empty when
/// it did not fail.
#[must_use]
pub fn error_text(frame: &CallFrame) -> String {
    let text = match frame.error {
        frame_error::NONE => "",
        frame_error::REVERTED => "execution reverted",
        frame_error::OUT_OF_GAS => "out of gas",
        frame_error::DEPTH => "max call depth exceeded",
        frame_error::INSUFFICIENT_BALANCE => "insufficient balance for transfer",
        frame_error::COLLISION => "contract address collision",
        frame_error::INVALID_JUMP => "invalid jump destination",
        frame_error::INVALID_OPCODE if frame.op == 0xFE => "invalid opcode: INVALID",
        frame_error::INVALID_OPCODE => {
            return format!("invalid opcode: opcode {:#x} not defined", frame.op);
        }
        frame_error::STACK_UNDERFLOW => {
            return format!("stack underflow ({} <=> {})", frame.stack, frame.bound);
        }
        frame_error::STACK_OVERFLOW => {
            return format!("stack limit reached {} ({})", frame.stack, frame.bound);
        }
        frame_error::WRITE_PROTECTION => "write protection",
        frame_error::RETURN_DATA_OUT_OF_BOUNDS => "return data out of bounds",
        frame_error::NONCE_OVERFLOW => "nonce uint64 overflow",
        frame_error::CODE_SIZE => "max code size exceeded",
        frame_error::INVALID_CODE => "invalid code: must not begin with 0xef",
        frame_error::INITCODE_SIZE => "max initcode size exceeded",
        frame_error::GAS_OVERFLOW => "gas uint64 overflow",
        _ => "precompile failed",
    };
    text.to_owned()
}

/// One frame as geth's `callTracer` writes it, its children given; its
/// logs dropped when it or an ancestor failed (`clearFailedLogs`).
fn frame_json(frame: &CallFrame, calls: Vec<Value>, failed: bool) -> Value {
    let mut out = Map::new();
    out.insert("from".into(), json!(data(&frame.from)));
    out.insert("gas".into(), json!(quantity(u128::from(frame.gas))));
    out.insert(
        "gasUsed".into(),
        json!(quantity(u128::from(frame.gas_used))),
    );
    if let Some(to) = &frame.to {
        out.insert("to".into(), json!(data(to)));
    }
    out.insert("input".into(), json!(data(&frame.input)));
    if !frame.output.is_empty() {
        out.insert("output".into(), json!(data(&frame.output)));
    }
    let error = error_text(frame);
    if !error.is_empty() {
        out.insert("error".into(), json!(error));
    }
    if frame.error == frame_error::REVERTED
        && let Some(reason) = revert_reason(&frame.output)
    {
        out.insert("revertReason".into(), json!(reason));
    }
    if !calls.is_empty() {
        out.insert("calls".into(), Value::Array(calls));
    }
    if !failed && !frame.logs.0.is_empty() {
        let logs = frame.logs.0.iter().map(|log| {
            json!({
                "address": data(&log.address),
                "topics": log.topics.0.iter().map(|t| data(t)).collect::<Vec<_>>(),
                "data": data(&log.data),
                "index": quantity(u128::from(log.index)),
                "position": quantity(u128::from(log.position)),
            })
        });
        out.insert("logs".into(), Value::Array(logs.collect()));
    }
    if let Some(value) = frame.value {
        out.insert("value".into(), json!(quantity(value)));
    }
    out.insert("type".into(), json!(kind_name(frame.kind)));
    Value::Object(out)
}

/// The frame at `frames[at]` with its children, which follow it one level
/// deeper; and the index after them.
fn subtree(frames: &[CallFrame], at: usize, parent_failed: bool) -> (Value, usize) {
    let frame = &frames[at];
    let failed = parent_failed || frame.error != frame_error::NONE;
    let mut calls = Vec::new();
    let mut next = at + 1;
    while next < frames.len() && frames[next].depth > frame.depth {
        let (child, after) = subtree(frames, next, failed);
        calls.push(child);
        next = after;
    }
    (frame_json(frame, calls, failed), next)
}

/// geth's `callTracer` result: the top frame, its calls nested in it.
#[must_use]
pub fn call_json(trace: &TxTrace) -> Value {
    if trace.frames.0.is_empty() {
        return json!({});
    }
    subtree(&trace.frames.0, 0, false).0
}

/// An account's fields as geth's `prestateTracer` writes them, each when
/// given: `balance`, `code`, `codeHash`, `nonce` (not zero, a JSON number),
/// `storage` (not empty).
#[derive(Default)]
struct Fields {
    balance: Option<u128>,
    code: Option<Vec<u8>>,
    code_hash: Option<[u8; 32]>,
    nonce: u64,
    storage: Map<String, Value>,
}

impl Fields {
    fn json(self) -> Value {
        let mut out = Map::new();
        if let Some(balance) = self.balance {
            out.insert("balance".into(), json!(quantity(balance)));
        }
        if let Some(code) = &self.code {
            out.insert("code".into(), json!(data(code)));
        }
        if let Some(hash) = &self.code_hash {
            out.insert("codeHash".into(), json!(data(hash)));
        }
        if self.nonce != 0 {
            out.insert("nonce".into(), json!(self.nonce));
        }
        if !self.storage.is_empty() {
            out.insert("storage".into(), Value::Object(self.storage));
        }
        Value::Object(out)
    }
}

/// The code hash geth reports for `code`: none without code.
fn hash_of(code: &[u8]) -> Option<[u8; 32]> {
    (!code.is_empty()).then(|| keccak256(code))
}

/// An account before the message, as geth's `lookupAccount` reads it, with
/// `storage`.
fn before_json(old: &AccountState, options: &Tracer, storage: Map<String, Value>) -> Value {
    Fields {
        balance: Some(old.balance),
        code: (!options.disable_code && !old.code.is_empty()).then(|| old.code.clone()),
        code_hash: hash_of(&old.code),
        nonce: old.nonce,
        storage,
    }
    .json()
}

/// geth's `prestateTracer` result: every account the message read or
/// wrote as it was before; with `diffMode`, `pre` and `post` of only what
/// changed (geth's `processDiffState`). An account that did not exist
/// before is left out of `pre` unless `includeEmpty`; one the message
/// created and destroyed has no `post`.
#[must_use]
pub fn prestate_json(trace: &TxTrace, options: &Tracer) -> Value {
    let blank = AccountState::default();
    let mut pre = Map::new();
    let mut post = Map::new();
    for account in &trace.accounts.0 {
        let key = data(&account.address);
        let old = account.pre.as_ref().unwrap_or(&blank);
        let keep = account.pre.is_some() || options.include_empty;
        let slots: Vec<_> = account
            .slots
            .0
            .iter()
            .filter(|_| !options.disable_storage)
            .collect();
        let deleted = account.created && account.post.is_none();
        if !options.config.diff_mode || deleted {
            let storage = slots
                .iter()
                .map(|s| (data(&s.slot), json!(data(&s.pre))))
                .collect();
            if keep {
                pre.insert(key, before_json(old, options, storage));
            }
            continue;
        }
        let new = account.post.as_ref().unwrap_or(&blank);
        let mut changed = Fields::default();
        let mut old_storage = Map::new();
        let mut modified = new.nonce != old.nonce;
        changed.nonce = new.nonce * u64::from(modified);
        if new.balance != old.balance {
            changed.balance = Some(new.balance);
        }
        let new_hash = hash_of(&new.code);
        if new_hash.is_some() && new_hash != hash_of(&old.code) {
            changed.code_hash = new_hash;
        }
        if !options.disable_code && new.code != old.code {
            changed.code = Some(new.code.clone());
        }
        for slot in slots.iter().filter(|s| s.pre != s.post) {
            modified = true;
            if slot.pre != [0; 32] {
                old_storage.insert(data(&slot.slot), json!(data(&slot.pre)));
            }
            if slot.post != [0; 32] {
                changed
                    .storage
                    .insert(data(&slot.slot), json!(data(&slot.post)));
            }
        }
        modified |=
            changed.balance.is_some() || changed.code_hash.is_some() || changed.code.is_some();
        if !modified {
            continue;
        }
        post.insert(key.clone(), changed.json());
        if keep {
            pre.insert(key, before_json(old, options, old_storage));
        }
    }
    if options.config.diff_mode {
        json!({ "post": post, "pre": pre })
    } else {
        Value::Object(pre)
    }
}

/// A trace's result as `tracer` writes it.
#[must_use]
pub fn result_json(trace: &TxTrace, options: &Tracer) -> Value {
    if options.noop {
        return json!({});
    }
    if options.config.tracer == tracer::PRESTATE {
        return prestate_json(trace, options);
    }
    call_json(trace)
}

/// The error of a trace that ran past the node's trace budget.
fn aborted() -> RpcError {
    RpcError::server("execution aborted: the trace ran past the node's trace budget (--trace-gas)")
}

/// The error of a transaction a block records that could not run (codex
/// ADR 0022).
fn could_not_run() -> RpcError {
    RpcError::server("transaction could not run: it fails the kernel's validation")
}

/// `error` unless the traced message ran.
fn ran(trace: &TxTrace, error: RpcError) -> Result<(), RpcError> {
    if trace.ran {
        return Ok(());
    }
    Err(error)
}

impl Rpc {
    /// The traces of block `header`, or of its transaction `only`, checked
    /// against the receipts the block recorded: a trace that disagrees
    /// with them is refused rather than served.
    fn traces_of(
        &mut self,
        header: &BlockHeader,
        only: Option<[u8; 32]>,
        options: &Tracer,
    ) -> Result<Vec<TxTrace>, RpcError> {
        let height = header.height;
        let parent = height.saturating_sub(1);
        if height > 0 && parent < self.node().oldest_state() {
            let root = self.header_at(parent)?.unwrap_or_default().0.state_root;
            return Err(self.unavailable(&root, parent));
        }
        let request = TraceBlockRequest {
            height,
            tx: only,
            config: options.config.clone(),
        };
        let traces = match self.node_mut().trace_block(&request) {
            Err(e) if e.is_out_of_gas() => return Err(aborted()),
            result => result?,
        };
        let Some(traces) = traces else {
            return Err(RpcError::server(format!(
                "the body of block {height} is no longer kept by this node, which cannot trace it"
            )));
        };
        let expected: Vec<[u8; 32]> = header
            .tx_hashes
            .0
            .iter()
            .copied()
            .filter(|h| only.is_none_or(|o| o == *h))
            .collect();
        let hashes: Vec<[u8; 32]> = traces.iter().map(|t| t.tx_hash).collect();
        if hashes != expected {
            return Err(RpcError::server(format!(
                "trace diverged from block {height}: it executed other transactions than the block records"
            )));
        }
        for trace in &traces {
            let receipt = self.node_mut().receipt(&trace.tx_hash)?.unwrap_or_default();
            if (trace.gas_used, trace.status) != (receipt.gas_used, receipt.status) {
                return Err(RpcError::server(format!(
                    "trace diverged from block {height}: transaction {} used {} gas with status {}, its receipt records {} with status {}",
                    data(&trace.tx_hash),
                    trace.gas_used,
                    trace.status,
                    receipt.gas_used,
                    receipt.status
                )));
            }
        }
        Ok(traces)
    }

    /// An answer within the response budget: none from a trace the kernel
    /// stopped recording, nor longer than [`Rpc::max_response_bytes`].
    fn bounded(&self, value: Value, truncated: bool) -> Result<Value, RpcError> {
        if truncated || encoded_len(&value) > self.max_response_bytes {
            return Err(too_large());
        }
        Ok(value)
    }

    /// `debug_traceTransaction(hash, tracer)`.
    pub(crate) fn trace_transaction(&mut self, params: &[Value]) -> Result<Value, RpcError> {
        let hash = parse_hash(param_str(params, 0)?)?;
        let options = tracer_of(params.get(1))?;
        // A system receipt (spec 20 §3.5) has no transaction.
        let found = match self.node_mut().transaction(&hash)? {
            Some(_) => self.node_mut().receipt(&hash)?,
            None => None,
        };
        let Some(receipt) = found else {
            return Err(RpcError::server("transaction not found"));
        };
        let header = self.header_at(receipt.height)?.unwrap_or_default().0;
        let traces = self.traces_of(&header, Some(hash), &options)?;
        let trace = &traces[0];
        ran(trace, could_not_run())?;
        self.bounded(result_json(trace, &options), trace.truncated)
    }

    /// `debug_traceBlockByNumber(block, tracer)` and `…ByHash`: one
    /// `{txHash, result}` per transaction the block records, or `{txHash,
    /// error}` for one that could not run.
    pub(crate) fn trace_block_by(&mut self, by: By, params: &[Value]) -> Result<Value, RpcError> {
        let options = tracer_of(params.get(1))?;
        let Some(header) = self.named_block(by, params)? else {
            return Err(RpcError::server(match by {
                By::Number => "block not found",
                By::Hash => "header for hash not found",
            }));
        };
        let traces = self.traces_of(&header, None, &options)?;
        let out = traces.iter().map(|trace| {
            if trace.ran {
                json!({ "txHash": data(&trace.tx_hash), "result": result_json(trace, &options) })
            } else {
                json!({ "txHash": data(&trace.tx_hash), "error": could_not_run().message })
            }
        });
        let truncated = traces.iter().any(|t| t.truncated);
        self.bounded(Value::Array(out.collect()), truncated)
    }

    /// `debug_traceCall(call, block, tracer)`: the call as `eth_call` runs
    /// it, traced; a call that reverts or halts is traced too, as geth
    /// traces it.
    pub(crate) fn trace_call(&mut self, params: &[Value]) -> Result<Value, RpcError> {
        let call = call_request(params.first())?;
        let at = self.state_at(params.get(1))?;
        let options = tracer_of(params.get(2))?;
        self.admit_call(&call, at)?;
        let request = TraceCallRequest {
            call,
            config: options.config.clone(),
        };
        let trace = match self.node_mut().trace_call(&request, at) {
            Err(e) if e.is_out_of_gas() => return Err(aborted()),
            result => result?,
        };
        // A message the kernel would not run, which `admit_call` did not
        // foresee, fails as `eth_call` fails.
        let invalid = call_error(&CallResult {
            status: call_status::INVALID,
            ..CallResult::default()
        });
        ran(&trace, invalid)?;
        self.bounded(result_json(&trace, &options), trace.truncated)
    }
}
