//! `solo_upgradeStatus`: the kernel's upgrade and feature-gate state (spec
//! 13 §6) together with this host's view of it (spec 13 §7), so that an
//! operator, or a script rehearsing an upgrade, can watch a proposal travel
//! from staging to the switch and a gate from signalling to activation on
//! every node. Chain state is the same on every node; the `host` object is
//! this node's alone.

use serde_json::{Value, json};
use solo_node::Node;

use crate::hex::data;
use crate::methods::RpcError;
use crate::telemetry::gates;

/// `solo_upgradeStatus()`: the kernel's `upgrade_status` as JSON, with the
/// gates and validator signals spelled out, plus `host`: the running
/// kernel's code hash, the gates active for the next block and the ones
/// this release supports, the upgrade it has prepared, its alert, and how
/// many kernel switches it has performed.
///
/// # Errors
/// A server error if the node fails to answer the query.
pub fn upgrade_status(node: &mut Node) -> Result<Value, RpcError> {
    let s = node.upgrade_status()?;
    let host = node.upgrades();
    let pending = s.pending.as_ref().map(|p| {
        json!({
            "codeHash": data(&p.code_hash),
            "activationHeight": p.activation_height,
            "requiredGates": gates(p.required_gates),
            "size": p.size,
            "chunks": p.chunks,
            "proposedAt": p.proposed_at,
        })
    });
    let enacted = s.enacted.as_ref().map(|e| {
        json!({
            "codeHash": data(&e.code_hash),
            "height": e.height,
            "fromVersion": e.from_version,
            "toVersion": e.to_version,
        })
    });
    let records: Vec<Value> = s
        .gates
        .gates
        .0
        .iter()
        .map(|r| {
            json!({
                "gate": r.gate,
                "streak": r.streak,
                "activationHeight": r.activation_height,
            })
        })
        .collect();
    let validators: Vec<Value> = s
        .validators
        .0
        .iter()
        .map(|v| {
            json!({
                "id": data(&v.id),
                "weight": v.weight,
                "signal": v.signal.as_ref().map(|sig| json!({
                    "epoch": sig.epoch,
                    "features": gates(sig.features),
                })),
            })
        })
        .collect();
    Ok(json!({
        "version": s.version,
        "params": {
            "governance": data(&s.params.governance),
            "minDelay": s.params.min_delay,
            "epochBlocks": s.params.epoch_blocks,
        },
        "pending": pending,
        "enacted": enacted,
        "gates": {
            "nextEpoch": s.gates.next_epoch,
            "lockedIn": gates(s.gates.locked_in()),
            "records": records,
        },
        "validators": validators,
        "host": {
            "kernelHash": data(&node.kernel_hash()),
            "activeGates": gates(host.active()),
            "supportedGates": gates(host.features),
            "prepared": host.prepared.map(|h| data(&h)),
            "alert": host.alert,
            "switches": host.switches.len(),
        },
    }))
}
