//! Tracing (spec 20 §9): what a traced message records, off the consensus
//! path. A block executes without any of this; the `trace_block` and
//! `trace_call` queries run the same code with a [`Tracing`] in the message.
//!
//! `callTracer` is a revm [`Inspector`]: it opens a frame at every call and
//! creation, precompiles and native contracts included (a native contract,
//! a kernel module behind the outbox or the governance address, is one
//! frame: what it does inside is not EVM code), and closes it with its gas,
//! output and error. Logs are taken from revm's journal rather than from the
//! `LOG` opcode, so that the outbox's `MessageSent`, which a precompile
//! writes to the journal, is a log of its frame like any other: a frame
//! takes the logs the journal gained since it last looked each time a child
//! opens, and at its own end; a child that reverts has its logs cut from the
//! journal, and the parent's mark moves to where the journal stands.
//!
//! `prestateTracer` needs no inspector: revm's state after a transaction
//! holds every account and slot it loaded, with each slot's value before the
//! transaction, which the kernel's own state still holds until the changes
//! are committed.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use orange_abi::chain::Account;
use orange_abi::codec::Seq;
use orange_abi::trace::{
    AccountState, AccountTrace, CallFrame, FRAME_BYTES, FrameLog, MAX_TRACE_BYTES, SlotTrace,
    TraceConfig, TxTrace, frame_error, kind,
};
use orange_abi::types::Address;
use revm::Inspector;
use revm::bytecode::opcode::OpCode;
use revm::context_interface::{ContextTr, JournalTr};
use revm::interpreter::interpreter_types::Jumps;
use revm::interpreter::{
    CallInputs, CallOutcome, CallScheme, CreateInputs, CreateOutcome, CreateScheme,
    InstructionResult, Interpreter,
};
use revm::primitives::{Address as RAddress, U256};
use revm::state::EvmState;

use crate::state;

/// A message's tracer: the tracer and options asked for, whether the
/// message is a call query (the provider caps a module's gas as for one,
/// spec 16 §6, although a traced call keeps its changes until the query
/// ends, so that the state after it can be read), and the accounts a
/// prestate lists whatever the message touches: the treasury the kernel
/// pays the base fee to after the EVM.
#[derive(Debug, Clone)]
pub struct Tracing {
    /// The tracer.
    pub config: TraceConfig,
    /// Whether the message is a call query.
    pub query: bool,
    /// Accounts every prestate lists.
    pub extra: Vec<Address>,
    /// How many logs the block's transactions before this one emitted, from
    /// which this one's logs are numbered.
    pub log_offset: u32,
}

/// The stack limit of the EVM.
const STACK_LIMIT: u32 = 1024;

/// A frame being recorded.
struct Open {
    /// Its index in `frames`, if it is recorded.
    index: Option<usize>,
    /// How far into the journal's logs it has looked.
    mark: usize,
    /// How many frames it has opened, so far.
    calls: u32,
    /// The opcode it last ran, and the stack's length then.
    op: u8,
    stack: u32,
}

/// geth's `callTracer` over revm.
pub struct CallTracer {
    config: TraceConfig,
    log_offset: u32,
    frames: Vec<CallFrame>,
    open: Vec<Open>,
    bytes: u64,
    truncated: bool,
}

impl CallTracer {
    /// A tracer with `config`.
    pub fn new(config: TraceConfig, log_offset: u32) -> CallTracer {
        CallTracer {
            config,
            log_offset,
            frames: Vec::new(),
            open: Vec::new(),
            bytes: 0,
            truncated: false,
        }
    }

    /// The frames recorded, in the order they opened, and whether recording
    /// stopped at the budget.
    pub fn finish(self) -> (Vec<CallFrame>, bool) {
        (self.frames, self.truncated)
    }

    /// Whether `bytes` more fit the budget; once one does not, nothing more
    /// is recorded.
    fn afford(&mut self, bytes: u64) -> bool {
        if self.truncated || self.bytes + bytes > MAX_TRACE_BYTES {
            self.truncated = true;
            return false;
        }
        self.bytes += bytes;
        true
    }

    /// The logs the journal gained since the innermost frame last looked go
    /// to it, when logs are asked for and it is recorded.
    fn take_logs<CTX: ContextTr>(&mut self, ctx: &CTX) {
        let logs = ctx.journal_ref().logs();
        let Some(top) = self.open.last_mut() else {
            return;
        };
        let (from, index, position) = (top.mark, top.index, top.calls);
        top.mark = logs.len();
        let (true, Some(index)) = (self.config.with_log, index) else {
            return;
        };
        for (at, log) in logs.iter().enumerate().skip(from) {
            let size = (log.data.data.len() + 32 * log.data.topics().len()) as u64 + 100;
            if !self.afford(size) {
                return;
            }
            self.frames[index].logs.0.push(FrameLog {
                address: log.address.0.0,
                topics: Seq(log.data.topics().iter().map(|t| t.0).collect()),
                data: log.data.data.to_vec(),
                // A log's place in the journal is its place among the
                // transaction's logs: a revert cuts the journal back, and the
                // next log takes the place again, as geth's log index does.
                index: self.log_offset + at as u32,
                position,
            });
        }
    }

    /// Opens a frame below the innermost one.
    fn open<CTX: ContextTr>(&mut self, ctx: &CTX, frame: CallFrame) {
        self.take_logs(ctx);
        let depth = self.open.len() as u32;
        let recorded = (depth == 0 || !self.config.only_top_call)
            && self.afford(FRAME_BYTES + frame.input.len() as u64);
        let index = recorded.then(|| {
            self.frames.push(CallFrame { depth, ..frame });
            self.frames.len() - 1
        });
        self.open.push(Open {
            index,
            mark: ctx.journal_ref().logs().len(),
            calls: 0,
            op: 0,
            stack: 0,
        });
    }

    /// Closes the innermost frame with what it returned.
    fn close<CTX: ContextTr>(
        &mut self,
        ctx: &CTX,
        result: InstructionResult,
        output: &[u8],
        gas_used: u64,
        created: Option<RAddress>,
    ) {
        self.take_logs(ctx);
        let Some(open) = self.open.pop() else {
            return;
        };
        if let Some(parent) = self.open.last_mut() {
            parent.mark = ctx.journal_ref().logs().len();
            // A log's position counts the frames recorded before it, as
            // geth counts the calls of its frame: none with `onlyTopCall`.
            parent.calls += u32::from(open.index.is_some());
        }
        let Some(index) = open.index else {
            return;
        };
        let error = error_of(result);
        let keep = error == frame_error::NONE || error == frame_error::REVERTED;
        let output = if keep && self.afford(output.len() as u64) {
            output.to_vec()
        } else {
            Vec::new()
        };
        let frame = &mut self.frames[index];
        // geth's frame keeps no gas when it fails other than by reverting,
        // except where it never started: past the call depth, without the
        // value, at the last nonce.
        let started = !matches!(
            error,
            frame_error::DEPTH | frame_error::INSUFFICIENT_BALANCE | frame_error::NONCE_OVERFLOW
        );
        frame.gas_used = if keep || !started {
            gas_used
        } else {
            frame.gas
        };
        frame.output = output;
        frame.error = error;
        if matches!(frame.kind, kind::CREATE | kind::CREATE2) {
            frame.to = created
                .filter(|_| error == frame_error::NONE)
                .map(|a| a.0.0);
        }
        if matches!(
            error,
            frame_error::INVALID_OPCODE
                | frame_error::STACK_UNDERFLOW
                | frame_error::STACK_OVERFLOW
        ) {
            let (inputs, outputs) = OpCode::new(open.op)
                .map_or((0, 0), |o| (u32::from(o.inputs()), u32::from(o.outputs())));
            frame.op = open.op;
            frame.stack = open.stack;
            frame.bound = if error == frame_error::STACK_OVERFLOW {
                STACK_LIMIT + inputs - outputs
            } else {
                inputs
            };
        }
    }
}

/// geth's name for why a frame ended (`core/vm/errors.go`).
fn error_of(result: InstructionResult) -> u8 {
    use InstructionResult as R;
    match result {
        R::Stop | R::Return | R::SelfDestruct => frame_error::NONE,
        R::Revert => frame_error::REVERTED,
        R::CallTooDeep => frame_error::DEPTH,
        R::OutOfFunds | R::OverflowPayment => frame_error::INSUFFICIENT_BALANCE,
        R::OutOfGas
        | R::MemoryOOG
        | R::MemoryLimitOOG
        | R::PrecompileOOG
        | R::ReentrancySentryOOG => frame_error::OUT_OF_GAS,
        R::InvalidOperandOOG => frame_error::GAS_OVERFLOW,
        R::OpcodeNotFound | R::InvalidFEOpcode | R::NotActivated | R::InvalidImmediateEncoding => {
            frame_error::INVALID_OPCODE
        }
        R::CallNotAllowedInsideStatic | R::StateChangeDuringStaticCall => {
            frame_error::WRITE_PROTECTION
        }
        R::InvalidJump => frame_error::INVALID_JUMP,
        R::StackUnderflow => frame_error::STACK_UNDERFLOW,
        R::StackOverflow => frame_error::STACK_OVERFLOW,
        R::OutOfOffset => frame_error::RETURN_DATA_OUT_OF_BOUNDS,
        R::CreateCollision => frame_error::COLLISION,
        R::NonceOverflow => frame_error::NONCE_OVERFLOW,
        R::CreateContractSizeLimit => frame_error::CODE_SIZE,
        R::CreateInitCodeSizeLimit => frame_error::INITCODE_SIZE,
        R::CreateContractStartingWithEF
        | R::CreateInitCodeStartingEF00
        | R::InvalidEOFInitCode
        | R::InvalidExtDelegateCallTarget => frame_error::INVALID_CODE,
        _ => frame_error::PRECOMPILE,
    }
}

fn value_word(v: U256) -> u128 {
    u128::try_from(v).unwrap_or(u128::MAX)
}

impl<CTX: ContextTr> Inspector<CTX> for CallTracer {
    fn step(&mut self, interp: &mut Interpreter, _: &mut CTX) {
        if let Some(top) = self.open.last_mut() {
            top.op = interp.bytecode.opcode();
            top.stack = interp.stack.len() as u32;
        }
    }

    fn call(&mut self, ctx: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        // geth names the frame by the account whose code runs, and its
        // caller by the account the code runs as.
        let (kind, from, to, value) = match inputs.scheme {
            CallScheme::Call => (
                kind::CALL,
                inputs.caller,
                inputs.target_address,
                Some(inputs.call_value()),
            ),
            CallScheme::StaticCall => {
                (kind::STATICCALL, inputs.caller, inputs.target_address, None)
            }
            CallScheme::DelegateCall => (
                kind::DELEGATECALL,
                inputs.target_address,
                inputs.bytecode_address,
                Some(inputs.call_value()),
            ),
            CallScheme::CallCode => (
                kind::CALLCODE,
                inputs.target_address,
                inputs.bytecode_address,
                Some(inputs.call_value()),
            ),
        };
        let input = inputs.input.bytes(ctx).to_vec();
        self.open(
            ctx,
            CallFrame {
                kind,
                from: from.0.0,
                to: Some(to.0.0),
                value: value.map(value_word),
                gas: inputs.gas_limit,
                input,
                ..CallFrame::default()
            },
        );
        None
    }

    fn call_end(&mut self, ctx: &mut CTX, _: &CallInputs, outcome: &mut CallOutcome) {
        let result = &outcome.result;
        self.close(
            ctx,
            result.result,
            &result.output,
            result.gas.total_gas_spent(),
            None,
        );
    }

    fn create(&mut self, ctx: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        let kind = match inputs.scheme() {
            CreateScheme::Create2 { .. } => kind::CREATE2,
            _ => kind::CREATE,
        };
        self.open(
            ctx,
            CallFrame {
                kind,
                from: inputs.caller().0.0,
                value: Some(value_word(inputs.value())),
                gas: inputs.gas_limit(),
                input: inputs.init_code().to_vec(),
                ..CallFrame::default()
            },
        );
        None
    }

    fn create_end(&mut self, ctx: &mut CTX, _: &CreateInputs, outcome: &mut CreateOutcome) {
        let result = &outcome.result;
        self.close(
            ctx,
            result.result,
            &result.output,
            result.gas.total_gas_spent(),
            outcome.address,
        );
    }

    fn selfdestruct(&mut self, contract: RAddress, target: RAddress, value: U256) {
        // `SELFDESTRUCT` ends its frame, so every log of the frame not taken
        // yet came before it: the frame closes with them at the position
        // before this one, and `calls` counts it only then.
        let depth = self.open.len() as u32;
        if self.config.only_top_call || depth == 0 || !self.afford(FRAME_BYTES) {
            return;
        }
        self.frames.push(CallFrame {
            kind: kind::SELFDESTRUCT,
            depth,
            from: contract.0.0,
            to: Some(target.0.0),
            value: Some(value_word(value)),
            ..CallFrame::default()
        });
    }
}

/// An account's fields as the kernel's state holds them now; none when it
/// is not in state.
fn account_state(address: &Address) -> Option<AccountState> {
    let account: Account = state::get(&state::account_key(address))?;
    Some(AccountState {
        balance: account.balance,
        nonce: account.nonce,
        code: crate::evm::code_of(&account),
    })
}

/// Whether `code` is a native contract's designator, whose storage is its
/// module's namespace rather than EVM slots (spec 16 §5).
fn native(code: &[u8]) -> bool {
    orange_abi::modules::designated(code).is_some()
}

/// The accounts and slots `changes` loaded, and `extra`, as they were
/// before the transaction: the kernel's state still holds that, as the
/// changes are not committed yet. Slots of a native contract are left out.
pub fn prestate(changes: &EvmState, extra: &[Address]) -> Vec<AccountTrace> {
    let mut accounts: BTreeMap<Address, AccountTrace> = BTreeMap::new();
    for (address, account) in changes {
        let a = address.0.0;
        let pre = account_state(&a);
        let slots = if pre.as_ref().is_some_and(|p| native(&p.code)) {
            Vec::new()
        } else {
            account
                .storage
                .iter()
                .map(|(slot, value)| SlotTrace {
                    slot: slot.to_be_bytes::<32>(),
                    pre: value.original_value.to_be_bytes::<32>(),
                    post: [0; 32],
                })
                .collect()
        };
        accounts.insert(
            a,
            AccountTrace {
                address: a,
                pre,
                post: None,
                slots: Seq(slots),
                created: account.is_created(),
            },
        );
    }
    for a in extra {
        accounts.entry(*a).or_insert_with(|| AccountTrace {
            address: *a,
            pre: account_state(a),
            ..AccountTrace::default()
        });
    }
    let mut out: Vec<AccountTrace> = accounts.into_values().collect();
    for account in &mut out {
        account.slots.0.sort_by_key(|s| s.slot);
    }
    out
}

/// Fills in each account's state after the transaction, everything the
/// kernel did for it included, from the kernel's state.
pub fn poststate(trace: &mut TxTrace) {
    for account in &mut trace.accounts.0 {
        account.post = account_state(&account.address);
        for slot in &mut account.slots.0 {
            slot.post = crate::evm::storage(&account.address, &slot.slot);
        }
    }
}

/// Finishes the trace of a message once the kernel is done with it: the
/// top frame has the message's gas limit and the gas its receipt records,
/// as geth's `callTracer` reports them, and the prestate the state after it.
pub fn settle(trace: &mut TxTrace, gas_limit: u64, gas_used: u64) {
    if let Some(top) = trace.frames.0.first_mut() {
        top.gas = gas_limit;
        top.gas_used = gas_used;
    }
    trace.gas_used = gas_used;
    poststate(trace);
}
