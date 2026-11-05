//! The privileged host functions a node supplies (spec 05 §4.2, §4.5–4.7),
//! including the state commitment and proofs of spec 10.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use orange_abi::staking::KEY_ROLE_THRESHOLD;
use orange_host::storage::MAX_STORED_KEY_LEN;
use orange_host::{Extension, Overlay, Storage};
use orange_vm::host::{Capability, HostContext};
use orange_vm::isa::Reg;
use orange_vm::status::{HostStatus, Termination};

/// A message the node wants delivered. Produced by the network effects of
/// spec 06 §4.2 and by the host functions of spec 05 §4.5 alike; a transport
/// drains them with [`crate::Node::take_outbound`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Outbound {
    Send {
        peer: [u8; 32],
        topic: u16,
        payload: Vec<u8>,
    },
    Broadcast {
        topic: u16,
        payload: Vec<u8>,
    },
    Disseminate {
        blob_id: [u8; 32],
        payload: Vec<u8>,
    },
    Request {
        peer: [u8; 32],
        request_id: u64,
        payload: Vec<u8>,
    },
    Respond {
        request_id: u64,
        payload: Vec<u8>,
    },
    PeerScore {
        peer: [u8; 32],
        delta: i64,
    },
}

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
    /// The `persist_set` writes since the node last collected them, in
    /// order, for a [`crate::DriverStore`] to journal.
    pub persist_writes: Vec<(Vec<u8>, Vec<u8>)>,
    /// Messages waiting for the transport, in order.
    pub outbound: Vec<Outbound>,
    /// The consensus key (`sign` with key role 0), if this node has one.
    pub key: Option<k256::ecdsa::SigningKey>,
    /// The threshold keystore (`sign` with key role 2).
    pub keystore: crate::keystore::Keystore,
    /// Request ids handed out by `net_request`.
    pub next_request_id: u64,
    /// The state trie behind each root `storage_commit` returned, in order:
    /// O(1) copy-on-write clones, so the node can keep the trie a block
    /// header commits to and prove against it later. The node clears this
    /// before every kernel call.
    pub commitments: Vec<orange_trie::Trie>,
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
    Sign = 106,
    StorageProof = 107,
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
    ("sign", Handle::Sign),
    ("storage_proof", Handle::StorageProof),
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

/// The state commitment (spec 10): the root of the binary Merkle trie over
/// every visible key except those under `local/` (node-local bookkeeping such
/// as the finalized height). What `storage_commit` writes.
pub fn commitment<S: Storage>(state: &mut Overlay<S>) -> [u8; 32] {
    state.commitment()
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

fn read_id(ctx: &HostContext<'_>, ptr: u32) -> Result<[u8; 32], Termination> {
    let bytes = read(ctx, ptr, 32)?;
    Ok(<[u8; 32]>::try_from(bytes.as_slice()).expect("32 bytes read"))
}

/// Signs a 32-byte digest, returning `r || s || recovery id`.
#[must_use]
pub fn sign_recoverable(key: &k256::ecdsa::SigningKey, digest: &[u8; 32]) -> Option<[u8; 65]> {
    let (signature, recovery) = key.sign_prehash_recoverable(digest).ok()?;
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&signature.to_bytes());
    out[64] = recovery.to_byte();
    Some(out)
}

/// The validator id of a key: `keccak256` of the uncompressed public key.
#[must_use]
pub fn validator_id(key: &k256::ecdsa::SigningKey) -> [u8; 32] {
    let point = key.verifying_key().to_encoded_point(false);
    orange_host::hash::keccak256(&point.as_bytes()[1..])
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

    #[allow(clippy::too_many_lines)]
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
                let trie = state.state_trie();
                ctx.memory.write(a0, &trie.root()).map_err(|_| fault())?;
                services.commitments.push(trie);
                ctx.set(Reg::A0, 0);
            }
            h if h == Handle::StorageProof as u32 => {
                ctx.charge(2_000)?;
                // Any stored key, a sandboxed one with its namespace included.
                if a1 == 0 || a1 as usize > MAX_STORED_KEY_LEN {
                    ctx.set(Reg::A0, 0);
                } else {
                    let key = read(ctx, a0, a1)?;
                    let proof = state.state_trie().prove(&key).encode();
                    let n = proof.len().min(a3 as usize);
                    ctx.memory.write(a2, &proof[..n]).map_err(|_| fault())?;
                    ctx.charge(per_32(u32::try_from(n).expect("bounded by cap")))?;
                    ctx.set(Reg::A0, proof.len() as u64);
                }
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
                services.persist_writes.push((key.clone(), value.clone()));
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
            h if h == Handle::Sign as u32 => {
                ctx.charge(10_000)?;
                let msg = read(ctx, a1, a2)?;
                let cap = ctx.arg32(Reg::A4);
                let services = &mut *services;
                let reply = match ctx.arg(Reg::A0) {
                    0 => match (&services.key, <[u8; 32]>::try_from(msg.as_slice())) {
                        (Some(key), Ok(digest)) if cap >= 65 => {
                            sign_recoverable(key, &digest).map(Vec::from)
                        }
                        _ => None,
                    },
                    KEY_ROLE_THRESHOLD => services.keystore.handle(services.key.as_ref(), &msg),
                    _ => None,
                };
                match reply {
                    Some(bytes) => {
                        // Key role 2 answers vary in length: like every variable-length
                        // result, they are truncated to `cap` and report their full length.
                        let n = bytes.len().min(cap as usize);
                        ctx.memory.write(a3, &bytes[..n]).map_err(|_| fault())?;
                        ctx.set(Reg::A0, bytes.len() as u64);
                    }
                    None => ctx.set(Reg::A0, 0),
                }
            }
            h if h == Handle::NetSend as u32 => {
                ctx.charge(100 + per_32(a2))?;
                let peer = read_id(ctx, a0)?;
                let payload = read(ctx, a1, a2)?;
                services.outbound.push(Outbound::Send {
                    peer,
                    topic: u16::try_from(ctx.arg(Reg::A3) & 0xFFFF).expect("masked"),
                    payload,
                });
                ctx.set(Reg::A0, 0);
            }
            h if h == Handle::NetBroadcast as u32 => {
                ctx.charge(100 + per_32(a2))?;
                let payload = read(ctx, a1, a2)?;
                services.outbound.push(Outbound::Broadcast {
                    topic: u16::try_from(a0 & 0xFFFF).expect("masked"),
                    payload,
                });
                ctx.set(Reg::A0, 0);
            }
            h if h == Handle::NetDisseminate as u32 => {
                ctx.charge(1_000 + per_32(a2))?;
                let blob_id = read_id(ctx, a0)?;
                let payload = read(ctx, a1, a2)?;
                services
                    .outbound
                    .push(Outbound::Disseminate { blob_id, payload });
                ctx.set(Reg::A0, 0);
            }
            h if h == Handle::NetRequest as u32 => {
                ctx.charge(100 + per_32(a2))?;
                let peer = read_id(ctx, a0)?;
                let payload = read(ctx, a1, a2)?;
                services.next_request_id += 1;
                let request_id = services.next_request_id;
                services.outbound.push(Outbound::Request {
                    peer,
                    request_id,
                    payload,
                });
                ctx.set(Reg::A0, request_id);
            }
            h if h == Handle::NetRespond as u32 => {
                ctx.charge(100 + per_32(a2))?;
                let payload = read(ctx, a1, a2)?;
                services.outbound.push(Outbound::Respond {
                    request_id: ctx.arg(Reg::A0),
                    payload,
                });
                ctx.set(Reg::A0, 0);
            }
            h if h == Handle::NetPeerScore as u32 => {
                ctx.charge(10)?;
                let peer = read_id(ctx, a0)?;
                #[allow(clippy::cast_possible_wrap)]
                let delta = i64::from(a1 as i32);
                services.outbound.push(Outbound::PeerScore { peer, delta });
                ctx.set(Reg::A0, 0);
            }
            _ => return Err(Termination::HostError(HostStatus::Unavailable.code())),
        }
        Ok(())
    }
}
