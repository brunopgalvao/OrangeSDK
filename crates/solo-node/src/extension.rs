//! The privileged host functions a node supplies (spec 05 §4.2, §4.5–4.7).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use solo_host::{Extension, Overlay, Storage};
use solo_vm::host::{Capability, HostContext};
use solo_vm::isa::Reg;
use solo_vm::status::{HostStatus, Termination};

/// Node-local services the extension reads and writes. Shared with the
/// [`crate::Node`] so it can fire timers and read persisted state.
#[derive(Debug, Default)]
pub struct NodeServices {
    /// Current time in milliseconds, set by the node before every step.
    pub now_ms: u64,
    /// Pending timers as `(timer_id, deadline_ms)`.
    pub timers: BTreeMap<u64, u64>,
    /// Node-local persisted key-value pairs (`persist_*`).
    pub persisted: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Network effects issued through host functions, recorded in order as
    /// `(function name, payload)`. The dev node has no peers.
    pub network: Vec<(&'static str, Vec<u8>)>,
}

/// Handles served by the extension; all above `EXTENSION_HANDLE_BASE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[allow(missing_docs)]
pub enum Handle {
    StorageCommit = 100,
    TimeNow = 101,
    TimerSet = 102,
    TimerCancel = 103,
    PersistSet = 104,
    PersistGet = 105,
    NetSend = 110,
    NetBroadcast = 111,
    NetDisseminate = 112,
    NetRequest = 113,
    NetRespond = 114,
    NetPeerScore = 115,
}

const FUNCTIONS: &[(&str, Handle)] = &[
    ("storage_commit", Handle::StorageCommit),
    ("time_now", Handle::TimeNow),
    ("timer_set", Handle::TimerSet),
    ("timer_cancel", Handle::TimerCancel),
    ("persist_set", Handle::PersistSet),
    ("persist_get", Handle::PersistGet),
    ("net_send", Handle::NetSend),
    ("net_broadcast", Handle::NetBroadcast),
    ("net_disseminate", Handle::NetDisseminate),
    ("net_request", Handle::NetRequest),
    ("net_respond", Handle::NetRespond),
    ("net_peer_score", Handle::NetPeerScore),
];

/// The extension installed into the node's executor.
pub struct NodeExtension {
    services: Rc<RefCell<NodeServices>>,
}

impl NodeExtension {
    /// An extension over shared services.
    #[must_use]
    pub fn new(services: Rc<RefCell<NodeServices>>) -> NodeExtension {
        NodeExtension { services }
    }
}

/// The state commitment of version 0: `keccak256` over every visible
/// `(key, value)` pair in key order, each length-prefixed. A placeholder
/// for the binary trie; deterministic and cheap to verify by recomputation.
pub fn commitment<S: Storage>(state: &Overlay<S>) -> [u8; 32] {
    let mut buf = Vec::new();
    for (k, v) in state.scan(&[]) {
        buf.extend_from_slice(&(k.len() as u64).to_le_bytes());
        buf.extend_from_slice(&k);
        buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
        buf.extend_from_slice(&v);
    }
    solo_host::hash::keccak256(&buf)
}

fn fault() -> Termination {
    Termination::HostError(HostStatus::MemoryFault.code())
}

fn read(ctx: &HostContext<'_>, ptr: u32, len: u32) -> Result<Vec<u8>, Termination> {
    ctx.memory
        .read(ptr, len)
        .map(<[u8]>::to_vec)
        .map_err(|_| fault())
}

fn per_32(bytes: u32) -> u64 {
    u64::from(bytes.div_ceil(32))
}

impl<S: Storage> Extension<S> for NodeExtension {
    fn resolve(&self, name: &str, capability: Capability) -> Option<u32> {
        if capability != Capability::Privileged {
            return None;
        }
        FUNCTIONS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, h)| *h as u32)
    }

    fn call(
        &mut self,
        handle: u32,
        ctx: &mut HostContext<'_>,
        state: &mut Overlay<S>,
    ) -> Result<(), Termination> {
        let (a0, a1, a2, a3) = (
            ctx.arg32(Reg::A0),
            ctx.arg32(Reg::A1),
            ctx.arg32(Reg::A2),
            ctx.arg32(Reg::A3),
        );
        let mut services = self.services.borrow_mut();
        match handle {
            h if h == Handle::StorageCommit as u32 => {
                ctx.charge(10_000)?;
                let root = commitment(state);
                ctx.memory.write(a0, &root).map_err(|_| fault())?;
                ctx.set(Reg::A0, 0);
            }
            h if h == Handle::TimeNow as u32 => {
                ctx.charge(10)?;
                ctx.set(Reg::A0, services.now_ms);
            }
            h if h == Handle::TimerSet as u32 => {
                ctx.charge(10)?;
                services.timers.insert(ctx.arg(Reg::A0), ctx.arg(Reg::A1));
                ctx.set(Reg::A0, 0);
            }
            h if h == Handle::TimerCancel as u32 => {
                ctx.charge(10)?;
                services.timers.remove(&ctx.arg(Reg::A0));
                ctx.set(Reg::A0, 0);
            }
            h if h == Handle::PersistSet as u32 => {
                ctx.charge(100 + per_32(a3))?;
                let key = read(ctx, a0, a1)?;
                let value = read(ctx, a2, a3)?;
                services.persisted.insert(key, value);
                ctx.set(Reg::A0, 0);
            }
            h if h == Handle::PersistGet as u32 => {
                ctx.charge(100)?;
                let key = read(ctx, a0, a1)?;
                match services.persisted.get(&key).cloned() {
                    Some(value) => {
                        let n = value.len().min(a3 as usize);
                        ctx.memory.write(a2, &value[..n]).map_err(|_| fault())?;
                        ctx.charge(per_32(u32::try_from(n).expect("bounded by cap")))?;
                        ctx.set(Reg::A0, value.len() as u64);
                    }
                    None => ctx.set(Reg::A0, u64::from(u32::MAX)),
                }
            }
            h if (Handle::NetSend as u32..=Handle::NetPeerScore as u32).contains(&h) => {
                let name = FUNCTIONS
                    .iter()
                    .find(|(_, f)| *f as u32 == h)
                    .map_or("net", |(n, _)| *n);
                let payload = match h {
                    h if h == Handle::NetSend as u32 || h == Handle::NetRequest as u32 => {
                        ctx.charge(100 + per_32(a2))?;
                        read(ctx, a1, a2)?
                    }
                    h if h == Handle::NetBroadcast as u32 || h == Handle::NetRespond as u32 => {
                        ctx.charge(100 + per_32(a2))?;
                        read(ctx, a1, a2)?
                    }
                    h if h == Handle::NetDisseminate as u32 => {
                        ctx.charge(1_000 + per_32(a2))?;
                        read(ctx, a1, a2)?
                    }
                    _ => {
                        ctx.charge(10)?;
                        Vec::new()
                    }
                };
                services.network.push((name, payload));
                ctx.set(Reg::A0, 0);
            }
            _ => return Err(Termination::HostError(HostStatus::Unavailable.code())),
        }
        Ok(())
    }
}
