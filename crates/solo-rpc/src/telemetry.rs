//! `GET /metrics` and `GET /status` on the JSON-RPC address (spec 11 §2).

use serde_json::{Value, json};
use solo_metrics::{CONTENT_TYPE, Status};

use crate::Rpc;
use crate::http::response;
use crate::methods::data;

/// The `/status` document (spec 11 §6).
#[must_use]
pub fn status_json(s: &Status) -> Value {
    json!({
        "version": s.version,
        "chainId": s.chain_id,
        "chainName": s.chain_name,
        "head": s.head,
        "headAgeSeconds": s.head_age_seconds,
        "finalized": s.finalized,
        "p2p": s.p2p,
        "peers": s.peers,
        "mempool": s.mempool,
        "uptimeSeconds": s.uptime_seconds,
        "validator": s.validator.as_ref().map(|id| data(id)),
        "upgradeAlert": s.upgrade_alert,
        "missingGates": gates(s.missing_gates),
        "kernelVersion": s.kernel_version,
        "kernelHash": data(&s.kernel_hash),
        "activeGates": gates(s.active_gates),
        "pendingUpgrade": s.pending_upgrade.as_ref().map(|p| json!({
            "codeHash": data(&p.code_hash),
            "activationHeight": p.activation_height,
        })),
    })
}

/// The gates of a bit set, ascending.
#[must_use]
pub fn gates(mask: u64) -> Vec<u32> {
    (0..64u32).filter(|g| mask >> g & 1 == 1).collect()
}

/// The `GET /metrics` response: every family in the text format 0.0.4.
pub fn metrics_response(rpc: &mut Rpc) -> Vec<u8> {
    response("200 OK", CONTENT_TYPE, &rpc.node_mut().metrics_text())
}

/// The `GET /status` response; `503` when the kernel cannot answer.
pub fn status_response(rpc: &mut Rpc) -> Vec<u8> {
    match rpc.node_mut().status() {
        Ok(s) => response("200 OK", "application/json", &status_json(&s).to_string()),
        Err(e) => response("503 Service Unavailable", "text/plain", &e.to_string()),
    }
}
