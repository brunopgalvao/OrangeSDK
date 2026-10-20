//! The single-node dev driver: one block per slot from whatever the mempool
//! holds, executed and finalized immediately.

use alloc::vec::Vec;

use solo_abi::chain::{BlockHeader, DriverState};
use solo_abi::codec::Seq;
use solo_abi::types::{Block, Effect, Input, MigrateArgs};
use solo_abi::{Decode, Encode};

use crate::state;

const TIMER: u64 = 1;
const STATE_KEY: &[u8] = b"meta/driver";

/// The persisted driver state.
pub fn load() -> DriverState {
    state::get(STATE_KEY).unwrap_or(DriverState { next_height: 1, ..DriverState::default() })
}

fn save(s: &DriverState) {
    state::set(STATE_KEY, s);
}

/// `kernel_migrate`: adopts the previous kernel's driver state when it decodes.
pub fn migrate(args: &MigrateArgs) {
    match DriverState::from_bytes(&args.driver_state) {
        Ok(s) => save(&s),
        Err(_) => solo_guest::trap(),
    }
}

/// `kernel_driver_step`.
pub fn step(input: &Input) -> Seq<Effect> {
    let params = state::params();
    let mut s = load();
    let mut effects = Vec::new();
    match input {
        Input::Started { now_ms, resumed_state } => {
            if let Some(bytes) = resumed_state
                && let Ok(restored) = DriverState::from_bytes(bytes)
            {
                s = restored;
            }
            s.pending = false;
            s.last_now_ms = *now_ms;
            effects.push(Effect::SetTimer { timer_id: TIMER, deadline_ms: now_ms + params.slot_ms });
        }
        Input::TimerFired { timer_id, now_ms } if *timer_id == TIMER => {
            s.last_now_ms = *now_ms;
            if s.pending {
                effects.push(Effect::SetTimer { timer_id: TIMER, deadline_ms: now_ms + params.slot_ms });
            } else {
                s.pending = true;
                effects.push(Effect::MempoolTake { max_bytes: 1 << 20, max_gas: u64::from(params.max_txs) * 21_000 });
            }
        }
        Input::MempoolContents { txs } => {
            let header = BlockHeader {
                height: s.next_height,
                parent_hash: s.last_hash,
                timestamp_ms: s.last_now_ms,
                ..BlockHeader::default()
            };
            let mut selected = txs.0.clone();
            selected.truncate(params.max_txs as usize);
            effects.push(Effect::ExecuteBlock {
                block: Block { header: header.to_bytes(), txs: Seq(selected), participation: Vec::new() },
            });
        }
        Input::BlockExecuted { height, block_hash, .. } => {
            s.next_height = height + 1;
            s.last_hash = *block_hash;
            s.pending = false;
            effects.push(Effect::FinalizeBlock { height: *height, certificate: Vec::new() });
            effects.push(Effect::Metric { name: b"blocks".to_vec(), value: 1 });
            effects.push(Effect::SetTimer { timer_id: TIMER, deadline_ms: s.last_now_ms + params.slot_ms });
        }
        _ => {}
    }
    save(&s);
    effects.push(Effect::PersistState { state: s.to_bytes() });
    Seq(effects)
}
