//! Tracing (spec 20 §9): the reference kernel's `trace_block` and
//! `trace_call` queries re-execute a block's transactions, or a call, with
//! a tracer attached, and answer with these records; the RPC renders them
//! as geth's `callTracer` and `prestateTracer` do (`debug_traceTransaction`
//! and its kin). Tracing runs only in queries, off the consensus path: a
//! block executes exactly as it does without it.

use alloc::vec::Vec;

use crate::chain::CallRequest;
use crate::codec::{Decode, DecodeError, Decoder, Encode, Encoder, Seq};
use crate::types::{Address, Hash};

macro_rules! record {
    ($(#[$meta:meta])* $name:ident { $($(#[$fmeta:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name {
            $($(#[$fmeta])* pub $field: $ty,)*
        }
        impl Encode for $name {
            fn encode(&self, e: &mut Encoder) {
                $(self.$field.encode(e);)*
            }
        }
        impl Decode for $name {
            fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                Ok($name { $($field: d.get()?,)* })
            }
        }
    };
}

/// Query method names of tracing.
pub mod query {
    /// `(TraceBlockRequest) -> Seq<TxTrace>`, run over the state after the
    /// block before `height` (`QueryArgs.at = height − 1`): the block at
    /// `height` executed again from the body this node finalized, each
    /// transaction it records traced, or only `tx` and none after it.
    /// Status 1 when the node no longer has the block's body.
    pub const TRACE_BLOCK: &str = "trace_block";
    /// `(TraceCallRequest) -> TxTrace`: a call as `call` runs it, traced.
    pub const TRACE_CALL: &str = "trace_call";
}

/// `TraceConfig::tracer` values.
pub mod tracer {
    /// geth's `callTracer`: the tree of call frames.
    pub const CALL: u8 = 0;
    /// geth's `prestateTracer`: the accounts and slots a transaction read
    /// or wrote, before it and, for `diffMode`, after it.
    pub const PRESTATE: u8 = 1;
}

/// The most bytes of input, output and log data one trace records, about
/// half of the RPC's 25 MB response budget once written as hex. A trace
/// that would record more stops recording and is marked truncated, and the
/// RPC answers it as too large.
pub const MAX_TRACE_BYTES: u64 = 12_000_000;

/// What one frame record costs against [`MAX_TRACE_BYTES`] besides its
/// data: the fields of its JSON object.
pub const FRAME_BYTES: u64 = 200;

/// `CallFrame::error` values: why a frame failed, as geth names it
/// (`core/vm/errors.go`).
pub mod frame_error {
    /// The frame did not fail.
    pub const NONE: u8 = 0;
    /// `execution reverted`.
    pub const REVERTED: u8 = 1;
    /// `out of gas`.
    pub const OUT_OF_GAS: u8 = 2;
    /// `max call depth exceeded`.
    pub const DEPTH: u8 = 3;
    /// `insufficient balance for transfer`.
    pub const INSUFFICIENT_BALANCE: u8 = 4;
    /// `contract address collision`.
    pub const COLLISION: u8 = 5;
    /// `invalid jump destination`.
    pub const INVALID_JUMP: u8 = 6;
    /// `invalid opcode: …`, the opcode in `CallFrame::op`.
    pub const INVALID_OPCODE: u8 = 7;
    /// `stack underflow (<len> <=> <required>)`.
    pub const STACK_UNDERFLOW: u8 = 8;
    /// `stack limit reached <len> (<limit>)`.
    pub const STACK_OVERFLOW: u8 = 9;
    /// `write protection`.
    pub const WRITE_PROTECTION: u8 = 10;
    /// `return data out of bounds`.
    pub const RETURN_DATA_OUT_OF_BOUNDS: u8 = 11;
    /// `nonce uint64 overflow`.
    pub const NONCE_OVERFLOW: u8 = 12;
    /// `max code size exceeded`.
    pub const CODE_SIZE: u8 = 13;
    /// `invalid code: must not begin with 0xef`.
    pub const INVALID_CODE: u8 = 14;
    /// `max initcode size exceeded`.
    pub const INITCODE_SIZE: u8 = 15;
    /// `gas uint64 overflow`.
    pub const GAS_OVERFLOW: u8 = 16;
    /// A precompile, the outbox or a native contract failed otherwise:
    /// `precompile failed`.
    pub const PRECOMPILE: u8 = 17;
}

/// `CallFrame::kind` values: the opcode that opened the frame, as geth's
/// `callTracer` names it in `type`.
pub mod kind {
    /// `CREATE`, and a transaction that creates.
    pub const CREATE: u8 = 0xF0;
    /// `CALL`, and a transaction that calls.
    pub const CALL: u8 = 0xF1;
    /// `CALLCODE`.
    pub const CALLCODE: u8 = 0xF2;
    /// `DELEGATECALL`.
    pub const DELEGATECALL: u8 = 0xF4;
    /// `CREATE2`.
    pub const CREATE2: u8 = 0xF5;
    /// `STATICCALL`.
    pub const STATICCALL: u8 = 0xFA;
    /// `SELFDESTRUCT`.
    pub const SELFDESTRUCT: u8 = 0xFF;
}

record! {
    /// Which tracer runs, and its options (geth's `tracerConfig`).
    TraceConfig {
        /// `tracer::*`.
        tracer: u8,
        /// `callTracer`'s `onlyTopCall`: no frames below the top one.
        only_top_call: bool,
        /// `callTracer`'s `withLog`: each frame's logs.
        with_log: bool,
        /// `prestateTracer`'s `diffMode`: what changed, before and after.
        diff_mode: bool,
    }
}

record! {
    /// `query::TRACE_BLOCK` parameters.
    TraceBlockRequest {
        /// The block.
        height: u64,
        /// Trace only this transaction of the block, and stop after it.
        tx: Option<Hash>,
        /// The tracer.
        config: TraceConfig,
    }
}

record! {
    /// `query::TRACE_CALL` parameters.
    TraceCallRequest {
        /// The call, as `eth_call` takes it.
        call: CallRequest,
        /// The tracer.
        config: TraceConfig,
    }
}

record! {
    /// A log as `callTracer`'s `withLog` reports it.
    FrameLog {
        /// Emitting contract.
        address: Address,
        /// Topics.
        topics: Seq<Hash>,
        /// Data.
        data: Vec<u8>,
        /// The log's index in its block, as its receipt numbers it among the
        /// block's logs (geth's `log.Index`); in a call, among the call's.
        index: u32,
        /// How many frames the emitting frame had opened before the log.
        position: u32,
    }
}

record! {
    /// One call frame, in the order frames open: a frame's children follow
    /// it with a greater `depth`.
    CallFrame {
        /// `kind::*`.
        kind: u8,
        /// 0 for the transaction's own frame.
        depth: u32,
        /// Caller.
        from: Address,
        /// Callee, or the created contract; none for a failed creation.
        to: Option<Address>,
        /// Value; none for `STATICCALL`.
        value: Option<u128>,
        /// Gas given to the frame; the transaction's gas limit for depth 0.
        gas: u64,
        /// Gas the frame used; the receipt's gas used for depth 0.
        gas_used: u64,
        /// Calldata or initcode.
        input: Vec<u8>,
        /// Return data, the created code, or revert data.
        output: Vec<u8>,
        /// `frame_error::*`.
        error: u8,
        /// The opcode an `INVALID_OPCODE`, `STACK_UNDERFLOW` or
        /// `STACK_OVERFLOW` error names.
        op: u8,
        /// The stack's length at that opcode.
        stack: u32,
        /// What the opcode needed of the stack: the items it takes for an
        /// underflow, the most it may start with for an overflow.
        bound: u32,
        /// Logs the frame emitted, when the tracer asked for them.
        logs: Seq<FrameLog>,
    }
}

record! {
    /// An account's fields at one point of a trace.
    AccountState {
        /// Balance.
        balance: u128,
        /// Nonce.
        nonce: u64,
        /// Code; empty for none.
        code: Vec<u8>,
    }
}

record! {
    /// A storage slot a transaction read or wrote.
    SlotTrace {
        /// The slot.
        slot: Hash,
        /// Its value before the transaction.
        pre: Hash,
        /// Its value after it.
        post: Hash,
    }
}

record! {
    /// An account a transaction read or wrote.
    AccountTrace {
        /// The account.
        address: Address,
        /// Before the transaction; none when it did not exist.
        pre: Option<AccountState>,
        /// After the transaction; none when it does not exist.
        post: Option<AccountState>,
        /// Its slots the transaction read or wrote.
        slots: Seq<SlotTrace>,
        /// Whether the transaction created it.
        created: bool,
    }
}

record! {
    /// The trace of one transaction or call.
    TxTrace {
        /// The transaction's hash; zero for a call.
        tx_hash: Hash,
        /// Whether it ran: a transaction a block records but that could not
        /// run (codex ADR 0022) did not.
        ran: bool,
        /// Its status, 1 for success, as in its receipt.
        status: u8,
        /// Gas it used, as in its receipt.
        gas_used: u64,
        /// `callTracer`: its frames.
        frames: Seq<CallFrame>,
        /// `prestateTracer`: its accounts, in address order.
        accounts: Seq<AccountTrace>,
        /// Whether recording stopped at [`MAX_TRACE_BYTES`].
        truncated: bool,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: Encode + Decode + PartialEq + core::fmt::Debug>(v: &T) {
        assert_eq!(&T::from_bytes(&v.to_bytes()).unwrap(), v);
    }

    #[test]
    fn records_roundtrip() {
        let config = TraceConfig {
            tracer: tracer::PRESTATE,
            only_top_call: true,
            with_log: true,
            diff_mode: true,
        };
        roundtrip(&TraceBlockRequest {
            height: 7,
            tx: Some([3; 32]),
            config: config.clone(),
        });
        roundtrip(&TraceCallRequest {
            call: CallRequest::default(),
            config,
        });
        roundtrip(&TxTrace {
            tx_hash: [1; 32],
            ran: true,
            status: 1,
            gas_used: 21_000,
            frames: Seq(alloc::vec![CallFrame {
                kind: kind::CALL,
                to: Some([2; 20]),
                value: Some(5),
                logs: Seq(alloc::vec![FrameLog {
                    position: 1,
                    ..FrameLog::default()
                }]),
                ..CallFrame::default()
            }]),
            accounts: Seq(alloc::vec![AccountTrace {
                pre: Some(AccountState::default()),
                slots: Seq(alloc::vec![SlotTrace::default()]),
                ..AccountTrace::default()
            }]),
            truncated: false,
        });
        assert!(alloc::format!("{:?}", TxTrace::default()).contains("TxTrace"));
        assert_eq!(
            (kind::CREATE, kind::SELFDESTRUCT, frame_error::PRECOMPILE),
            (0xF0, 0xFF, 17)
        );
        assert_eq!(
            (query::TRACE_BLOCK, query::TRACE_CALL),
            ("trace_block", "trace_call")
        );
        assert_eq!((MAX_TRACE_BYTES, FRAME_BYTES), (12_000_000, 200));
    }
}
