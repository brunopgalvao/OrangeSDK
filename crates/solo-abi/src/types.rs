//! Types that cross the host–kernel boundary (spec 06 §3–§5).

use alloc::vec::Vec;

use crate::codec::{Decode, DecodeError, Decoder, Encode, Encoder, Seq};

/// A 32-byte hash or identifier.
pub type Hash = [u8; 32];
/// A 20-byte account address.
pub type Address = [u8; 20];

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

record! {
    /// Block context handed to the state transition entrypoints (spec 06 §5).
    ExecContext {
        /// Block height.
        height: u64,
        /// Consensus slot.
        slot: u64,
        /// Block timestamp in milliseconds.
        timestamp_ms: u64,
        /// Proposer identity.
        proposer: Hash,
        /// Parent block hash.
        parent_hash: Hash,
        /// Randomness for `PREVRANDAO`.
        prev_randao: Hash,
        /// Opaque fee parameters carried in the header.
        fee_params: Vec<u8>,
        /// Which fork schedule applies.
        fork_schedule_id: u32,
        /// Execution lag in blocks.
        exec_lag_k: u32,
    }
}

record! {
    /// Block-building limits.
    Limits {
        /// Gas limit.
        max_gas: u64,
        /// Byte limit.
        max_bytes: u32,
        /// Transaction count limit.
        max_txs: u32,
    }
}

record! {
    /// A block as the driver and the state transition exchange it.
    Block {
        /// Opaque header.
        header: Vec<u8>,
        /// Transactions.
        txs: Seq<Vec<u8>>,
        /// Validator participation record.
        participation: Vec<u8>,
    }
}

record! {
    /// Summary of a block's execution.
    ExecuteSummary {
        /// Gas used.
        gas_used: u64,
        /// Transactions executed.
        tx_count: u32,
        /// Receipts root.
        receipts_root: Hash,
        /// Logs bloom.
        logs_bloom: Vec<u8>,
    }
}

record! {
    /// Result of `kernel_stf_execute_block`.
    ExecuteResult {
        /// State root after the block.
        state_root: Hash,
        /// Summary.
        summary: ExecuteSummary,
        /// Receipts.
        receipts: Seq<Vec<u8>>,
    }
}

record! {
    /// A module to install at genesis.
    ModuleInstall {
        /// Reserved address.
        address: Address,
        /// Code hash.
        code_hash: Hash,
        /// Capability bits.
        capabilities: u64,
        /// Init argument.
        init: Vec<u8>,
    }
}

record! {
    /// Genesis configuration.
    Genesis {
        /// Chain id.
        chain_id: u64,
        /// Opaque fee schedule.
        fee_schedule: Vec<u8>,
        /// Modules installed at genesis.
        modules: Seq<ModuleInstall>,
        /// Opaque chain parameters.
        params: Vec<u8>,
        /// Opaque initial validator set.
        validators: Vec<u8>,
    }
}

record! {
    /// Argument of `kernel_migrate`.
    MigrateArgs {
        /// Version of the kernel being replaced.
        from_version: u32,
        /// Its exported driver state.
        driver_state: Vec<u8>,
    }
}

record! {
    /// Argument of `kernel_stf_validate_tx`.
    ValidateArgs {
        /// Transaction bytes.
        tx: Vec<u8>,
        /// Context.
        context: ExecContext,
    }
}

record! {
    /// Argument of `kernel_stf_build_block`.
    BuildArgs {
        /// Context.
        context: ExecContext,
        /// Limits.
        limits: Limits,
        /// Candidate transactions from the mempool.
        candidates: Seq<Vec<u8>>,
    }
}

record! {
    /// Argument of `kernel_stf_execute_block`.
    ExecuteArgs {
        /// The block.
        block: Block,
        /// Context.
        context: ExecContext,
    }
}

record! {
    /// Argument of `kernel_stf_finalize_block`.
    FinalizeArgs {
        /// Height.
        height: u64,
        /// Finality certificate.
        certificate: Vec<u8>,
    }
}

record! {
    /// Argument of `kernel_query`.
    QueryArgs {
        /// Method name.
        method: Vec<u8>,
        /// Encoded parameters.
        params: Vec<u8>,
        /// Height to query at, or latest.
        at: Option<u64>,
    }
}

record! {
    /// Result of `kernel_query`.
    QueryResult {
        /// Status code; 0 is success.
        status: u32,
        /// Encoded body.
        body: Vec<u8>,
    }
}

/// Result of `kernel_stf_validate_tx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidateResult {
    /// Admissible, with ordering priority and the fee reserved at admission.
    Valid {
        /// Priority.
        priority: u64,
        /// Reserved fee.
        reserved_fee: u64,
    },
    /// Rejected.
    Invalid {
        /// Reason code.
        reason: u32,
    },
}

impl Encode for ValidateResult {
    fn encode(&self, e: &mut Encoder) {
        match self {
            ValidateResult::Valid {
                priority,
                reserved_fee,
            } => {
                e.raw(&[0]);
                e.put(priority).put(reserved_fee);
            }
            ValidateResult::Invalid { reason } => {
                e.raw(&[1]);
                e.put(reason);
            }
        }
    }
}

impl Decode for ValidateResult {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match d.raw(1)?[0] {
            0 => Ok(ValidateResult::Valid {
                priority: d.get()?,
                reserved_fee: d.get()?,
            }),
            1 => Ok(ValidateResult::Invalid { reason: d.get()? }),
            t => Err(DecodeError::BadTag(t)),
        }
    }
}

/// Driver inputs (spec 06 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Input {
    NetworkMessage {
        peer: Hash,
        topic: u16,
        payload: Vec<u8>,
    },
    BlobReceived {
        blob_id: Hash,
        payload: Vec<u8>,
    },
    Request {
        peer: Hash,
        request_id: u64,
        payload: Vec<u8>,
    },
    Response {
        request_id: u64,
        payload: Vec<u8>,
    },
    TimerFired {
        timer_id: u64,
        now_ms: u64,
    },
    TxArrived {
        tx_hash: Hash,
        size: u32,
    },
    MempoolContents {
        txs: Seq<Vec<u8>>,
    },
    BlockExecuted {
        height: u64,
        block_hash: Hash,
        state_root: Hash,
        result: ExecuteSummary,
    },
    Started {
        now_ms: u64,
        resumed_state: Option<Vec<u8>>,
    },
    PeerConnected {
        peer: Hash,
    },
    PeerDisconnected {
        peer: Hash,
    },
}

impl Encode for Input {
    fn encode(&self, e: &mut Encoder) {
        match self {
            Input::NetworkMessage {
                peer,
                topic,
                payload,
            } => {
                e.raw(&[0]);
                e.put(peer).put(topic).put(payload);
            }
            Input::BlobReceived { blob_id, payload } => {
                e.raw(&[1]);
                e.put(blob_id).put(payload);
            }
            Input::Request {
                peer,
                request_id,
                payload,
            } => {
                e.raw(&[2]);
                e.put(peer).put(request_id).put(payload);
            }
            Input::Response {
                request_id,
                payload,
            } => {
                e.raw(&[3]);
                e.put(request_id).put(payload);
            }
            Input::TimerFired { timer_id, now_ms } => {
                e.raw(&[4]);
                e.put(timer_id).put(now_ms);
            }
            Input::TxArrived { tx_hash, size } => {
                e.raw(&[5]);
                e.put(tx_hash).put(size);
            }
            Input::MempoolContents { txs } => {
                e.raw(&[6]);
                e.put(txs);
            }
            Input::BlockExecuted {
                height,
                block_hash,
                state_root,
                result,
            } => {
                e.raw(&[7]);
                e.put(height).put(block_hash).put(state_root).put(result);
            }
            Input::Started {
                now_ms,
                resumed_state,
            } => {
                e.raw(&[8]);
                e.put(now_ms).put(resumed_state);
            }
            Input::PeerConnected { peer } => {
                e.raw(&[9]);
                e.put(peer);
            }
            Input::PeerDisconnected { peer } => {
                e.raw(&[10]);
                e.put(peer);
            }
        }
    }
}

impl Decode for Input {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(match d.raw(1)?[0] {
            0 => Input::NetworkMessage {
                peer: d.get()?,
                topic: d.get()?,
                payload: d.get()?,
            },
            1 => Input::BlobReceived {
                blob_id: d.get()?,
                payload: d.get()?,
            },
            2 => Input::Request {
                peer: d.get()?,
                request_id: d.get()?,
                payload: d.get()?,
            },
            3 => Input::Response {
                request_id: d.get()?,
                payload: d.get()?,
            },
            4 => Input::TimerFired {
                timer_id: d.get()?,
                now_ms: d.get()?,
            },
            5 => Input::TxArrived {
                tx_hash: d.get()?,
                size: d.get()?,
            },
            6 => Input::MempoolContents { txs: d.get()? },
            7 => Input::BlockExecuted {
                height: d.get()?,
                block_hash: d.get()?,
                state_root: d.get()?,
                result: d.get()?,
            },
            8 => Input::Started {
                now_ms: d.get()?,
                resumed_state: d.get()?,
            },
            9 => Input::PeerConnected { peer: d.get()? },
            10 => Input::PeerDisconnected { peer: d.get()? },
            t => return Err(DecodeError::BadTag(t)),
        })
    }
}

/// Driver effects (spec 06 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Effect {
    Send {
        peer: Hash,
        topic: u16,
        payload: Vec<u8>,
    },
    Broadcast {
        topic: u16,
        payload: Vec<u8>,
    },
    Disseminate {
        blob_id: Hash,
        payload: Vec<u8>,
    },
    Request {
        peer: Hash,
        request_id: u64,
        payload: Vec<u8>,
    },
    Respond {
        request_id: u64,
        payload: Vec<u8>,
    },
    SetTimer {
        timer_id: u64,
        deadline_ms: u64,
    },
    CancelTimer {
        timer_id: u64,
    },
    ExecuteBlock {
        block: Block,
    },
    FinalizeBlock {
        height: u64,
        certificate: Vec<u8>,
    },
    PersistState {
        state: Vec<u8>,
    },
    PeerScore {
        peer: Hash,
        delta: i64,
    },
    MempoolTake {
        max_bytes: u32,
        max_gas: u64,
    },
    MempoolAdmit {
        tx_hash: Hash,
    },
    MempoolReject {
        tx_hash: Hash,
        reason: u32,
    },
    Metric {
        name: Vec<u8>,
        value: i64,
    },
}

impl Encode for Effect {
    fn encode(&self, e: &mut Encoder) {
        match self {
            Effect::Send {
                peer,
                topic,
                payload,
            } => {
                e.raw(&[0]);
                e.put(peer).put(topic).put(payload);
            }
            Effect::Broadcast { topic, payload } => {
                e.raw(&[1]);
                e.put(topic).put(payload);
            }
            Effect::Disseminate { blob_id, payload } => {
                e.raw(&[2]);
                e.put(blob_id).put(payload);
            }
            Effect::Request {
                peer,
                request_id,
                payload,
            } => {
                e.raw(&[3]);
                e.put(peer).put(request_id).put(payload);
            }
            Effect::Respond {
                request_id,
                payload,
            } => {
                e.raw(&[4]);
                e.put(request_id).put(payload);
            }
            Effect::SetTimer {
                timer_id,
                deadline_ms,
            } => {
                e.raw(&[5]);
                e.put(timer_id).put(deadline_ms);
            }
            Effect::CancelTimer { timer_id } => {
                e.raw(&[6]);
                e.put(timer_id);
            }
            Effect::ExecuteBlock { block } => {
                e.raw(&[7]);
                e.put(block);
            }
            Effect::FinalizeBlock {
                height,
                certificate,
            } => {
                e.raw(&[8]);
                e.put(height).put(certificate);
            }
            Effect::PersistState { state } => {
                e.raw(&[9]);
                e.put(state);
            }
            Effect::PeerScore { peer, delta } => {
                e.raw(&[10]);
                e.put(peer).put(delta);
            }
            Effect::MempoolTake { max_bytes, max_gas } => {
                e.raw(&[11]);
                e.put(max_bytes).put(max_gas);
            }
            Effect::MempoolAdmit { tx_hash } => {
                e.raw(&[12]);
                e.put(tx_hash);
            }
            Effect::MempoolReject { tx_hash, reason } => {
                e.raw(&[13]);
                e.put(tx_hash).put(reason);
            }
            Effect::Metric { name, value } => {
                e.raw(&[14]);
                e.put(name).put(value);
            }
        }
    }
}

impl Decode for Effect {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(match d.raw(1)?[0] {
            0 => Effect::Send {
                peer: d.get()?,
                topic: d.get()?,
                payload: d.get()?,
            },
            1 => Effect::Broadcast {
                topic: d.get()?,
                payload: d.get()?,
            },
            2 => Effect::Disseminate {
                blob_id: d.get()?,
                payload: d.get()?,
            },
            3 => Effect::Request {
                peer: d.get()?,
                request_id: d.get()?,
                payload: d.get()?,
            },
            4 => Effect::Respond {
                request_id: d.get()?,
                payload: d.get()?,
            },
            5 => Effect::SetTimer {
                timer_id: d.get()?,
                deadline_ms: d.get()?,
            },
            6 => Effect::CancelTimer { timer_id: d.get()? },
            7 => Effect::ExecuteBlock { block: d.get()? },
            8 => Effect::FinalizeBlock {
                height: d.get()?,
                certificate: d.get()?,
            },
            9 => Effect::PersistState { state: d.get()? },
            10 => Effect::PeerScore {
                peer: d.get()?,
                delta: d.get()?,
            },
            11 => Effect::MempoolTake {
                max_bytes: d.get()?,
                max_gas: d.get()?,
            },
            12 => Effect::MempoolAdmit { tx_hash: d.get()? },
            13 => Effect::MempoolReject {
                tx_hash: d.get()?,
                reason: d.get()?,
            },
            14 => Effect::Metric {
                name: d.get()?,
                value: d.get()?,
            },
            t => return Err(DecodeError::BadTag(t)),
        })
    }
}

/// Export names of the kernel entrypoints (spec 06 §3).
pub mod exports {
    /// `kernel_init(Genesis)`.
    pub const INIT: &str = "kernel_init";
    /// `kernel_driver_step(Input) -> vec<Effect>`.
    pub const DRIVER_STEP: &str = "kernel_driver_step";
    /// `kernel_driver_state() -> bytes`.
    pub const DRIVER_STATE: &str = "kernel_driver_state";
    /// `kernel_migrate(MigrateArgs)`.
    pub const MIGRATE: &str = "kernel_migrate";
    /// `kernel_version() -> u32`: the kernel's version (spec 06 §7.1).
    pub const VERSION: &str = "kernel_version";
    /// `kernel_stf_validate_tx(ValidateArgs) -> ValidateResult`.
    pub const VALIDATE_TX: &str = "kernel_stf_validate_tx";
    /// `kernel_stf_build_block(BuildArgs) -> Block`.
    pub const BUILD_BLOCK: &str = "kernel_stf_build_block";
    /// `kernel_stf_execute_block(ExecuteArgs) -> ExecuteResult`.
    pub const EXECUTE_BLOCK: &str = "kernel_stf_execute_block";
    /// `kernel_stf_finalize_block(FinalizeArgs)`.
    pub const FINALIZE_BLOCK: &str = "kernel_stf_finalize_block";
    /// `kernel_query(QueryArgs) -> QueryResult`.
    pub const QUERY: &str = "kernel_query";
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn roundtrip<T: Encode + Decode + PartialEq + core::fmt::Debug>(v: &T) {
        let bytes = v.to_bytes();
        assert_eq!(&T::from_bytes(&bytes).unwrap(), v, "{bytes:?}");
    }

    fn ctx() -> ExecContext {
        ExecContext {
            height: 7,
            slot: 9,
            timestamp_ms: 1_000,
            proposer: [1; 32],
            parent_hash: [2; 32],
            prev_randao: [3; 32],
            fee_params: vec![4, 5],
            fork_schedule_id: 1,
            exec_lag_k: 3,
        }
    }

    #[test]
    fn records_roundtrip() {
        roundtrip(&ctx());
        roundtrip(&Limits {
            max_gas: 1,
            max_bytes: 2,
            max_txs: 3,
        });
        let block = Block {
            header: vec![1],
            txs: Seq(vec![vec![2], vec![3, 4]]),
            participation: vec![5],
        };
        roundtrip(&block);
        let summary = ExecuteSummary {
            gas_used: 10,
            tx_count: 2,
            receipts_root: [6; 32],
            logs_bloom: vec![0; 8],
        };
        roundtrip(&summary);
        roundtrip(&ExecuteResult {
            state_root: [7; 32],
            summary: summary.clone(),
            receipts: Seq(vec![vec![1]]),
        });
        let install = ModuleInstall {
            address: [8; 20],
            code_hash: [9; 32],
            capabilities: 0b101,
            init: vec![],
        };
        roundtrip(&install);
        roundtrip(&Genesis {
            chain_id: 1,
            fee_schedule: vec![1],
            modules: Seq(vec![install]),
            params: vec![],
            validators: vec![2],
        });
        roundtrip(&MigrateArgs {
            from_version: 1,
            driver_state: vec![9],
        });
        roundtrip(&ValidateArgs {
            tx: vec![1, 2],
            context: ctx(),
        });
        roundtrip(&BuildArgs {
            context: ctx(),
            limits: Limits::default(),
            candidates: Seq(vec![vec![1]]),
        });
        roundtrip(&ExecuteArgs {
            block,
            context: ctx(),
        });
        roundtrip(&FinalizeArgs {
            height: 3,
            certificate: vec![1],
        });
        roundtrip(&QueryArgs {
            method: b"eth_chainId".to_vec(),
            params: vec![],
            at: Some(4),
        });
        roundtrip(&QueryArgs {
            method: vec![],
            params: vec![],
            at: None,
        });
        roundtrip(&QueryResult {
            status: 0,
            body: vec![1],
        });
        assert_eq!(ExecContext::default().height, 0);
        assert!(alloc::format!("{:?}", Limits::default()).contains("Limits"));
    }

    #[test]
    fn validate_result_tags() {
        let valid = ValidateResult::Valid {
            priority: 5,
            reserved_fee: 6,
        };
        let invalid = ValidateResult::Invalid { reason: 9 };
        roundtrip(&valid);
        roundtrip(&invalid);
        assert_eq!(valid.to_bytes()[0], 0);
        assert_eq!(invalid.to_bytes()[0], 1);
        assert_eq!(
            ValidateResult::from_bytes(&[2]),
            Err(DecodeError::BadTag(2))
        );
        assert_eq!(ValidateResult::from_bytes(&[]), Err(DecodeError::Truncated));
    }

    #[test]
    fn inputs_roundtrip_with_their_tags() {
        let summary = ExecuteSummary::default();
        let all = vec![
            Input::NetworkMessage {
                peer: [1; 32],
                topic: 2,
                payload: vec![3],
            },
            Input::BlobReceived {
                blob_id: [1; 32],
                payload: vec![3],
            },
            Input::Request {
                peer: [1; 32],
                request_id: 2,
                payload: vec![3],
            },
            Input::Response {
                request_id: 2,
                payload: vec![3],
            },
            Input::TimerFired {
                timer_id: 1,
                now_ms: 2,
            },
            Input::TxArrived {
                tx_hash: [1; 32],
                size: 2,
            },
            Input::MempoolContents {
                txs: Seq(vec![vec![1]]),
            },
            Input::BlockExecuted {
                height: 1,
                block_hash: [2; 32],
                state_root: [3; 32],
                result: summary,
            },
            Input::Started {
                now_ms: 1,
                resumed_state: Some(vec![2]),
            },
            Input::PeerConnected { peer: [1; 32] },
            Input::PeerDisconnected { peer: [1; 32] },
        ];
        for (tag, input) in all.iter().enumerate() {
            roundtrip(input);
            assert_eq!(input.to_bytes()[0] as usize, tag);
        }
        assert_eq!(Input::from_bytes(&[11]), Err(DecodeError::BadTag(11)));
    }

    #[test]
    fn effects_roundtrip_with_their_tags() {
        let all = vec![
            Effect::Send {
                peer: [1; 32],
                topic: 2,
                payload: vec![3],
            },
            Effect::Broadcast {
                topic: 2,
                payload: vec![3],
            },
            Effect::Disseminate {
                blob_id: [1; 32],
                payload: vec![3],
            },
            Effect::Request {
                peer: [1; 32],
                request_id: 2,
                payload: vec![3],
            },
            Effect::Respond {
                request_id: 2,
                payload: vec![3],
            },
            Effect::SetTimer {
                timer_id: 1,
                deadline_ms: 2,
            },
            Effect::CancelTimer { timer_id: 1 },
            Effect::ExecuteBlock {
                block: Block::default(),
            },
            Effect::FinalizeBlock {
                height: 1,
                certificate: vec![2],
            },
            Effect::PersistState { state: vec![1] },
            Effect::PeerScore {
                peer: [1; 32],
                delta: -3,
            },
            Effect::MempoolTake {
                max_bytes: 1,
                max_gas: 2,
            },
            Effect::MempoolAdmit { tx_hash: [1; 32] },
            Effect::MempoolReject {
                tx_hash: [1; 32],
                reason: 2,
            },
            Effect::Metric {
                name: b"m".to_vec(),
                value: 1,
            },
        ];
        for (tag, effect) in all.iter().enumerate() {
            roundtrip(effect);
            assert_eq!(effect.to_bytes()[0] as usize, tag);
        }
        let list = Seq(all.clone());
        roundtrip(&list);
        assert_eq!(Effect::from_bytes(&[15]), Err(DecodeError::BadTag(15)));
        assert_eq!(exports::INIT, "kernel_init");
        assert_eq!(exports::QUERY, "kernel_query");
        assert!(exports::DRIVER_STEP.starts_with("kernel_driver"));
        assert!(exports::DRIVER_STATE.starts_with("kernel_driver"));
        assert!(exports::MIGRATE.starts_with("kernel_"));
        assert_eq!(exports::VERSION, "kernel_version");
        for e in [
            exports::VALIDATE_TX,
            exports::BUILD_BLOCK,
            exports::EXECUTE_BLOCK,
            exports::FINALIZE_BLOCK,
        ] {
            assert!(e.starts_with("kernel_stf_"));
        }
    }
}
