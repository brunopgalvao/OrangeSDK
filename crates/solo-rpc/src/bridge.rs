//! The bridge's methods (spec 17 §7): what a relayer of the Solo-to-Ethereum
//! bridge needs from a node beside the Ethereum methods, a stored threshold
//! certificate with the proposal it certifies, and the proof of an outbox
//! slot against the state root of a recent height.

use serde_json::{Value, json};
use solo_node::Node;

use crate::hex::{data, quantity};
use crate::methods::RpcError;

fn failed(e: &solo_bridge::Error) -> RpcError {
    RpcError::server(e.to_string())
}

/// `solo_getFinalityProof(height)`: the threshold certificate the node
/// stored for `height`, the proposal it certifies, and the light client's
/// `submit` calldata; `null` if the node stored none.
///
/// # Errors
/// A server error if the node fails or the stored proposal has no anchor.
pub fn finality_proof(node: &mut Node, height: u64) -> Result<Value, RpcError> {
    let Some(proof) = solo_bridge::finality_proof(node, height).map_err(|e| failed(&e))? else {
        return Ok(Value::Null);
    };
    let s = solo_bridge::Submission::new(&proof).map_err(|e| failed(&e))?;
    Ok(json!({
        "height": quantity(u128::from(s.height)),
        "blockHash": data(&s.block_hash),
        "anchorHeight": quantity(u128::from(s.anchor_height)),
        "anchorRoot": data(&s.anchor_root),
        "certificate": data(&proof.certificate),
        "proposal": data(&proof.proposal),
        "signature": data(&s.signature),
        "calldata": data(&s.calldata()),
    }))
}

/// `solo_getOutboxProof(nonce, height)`: the message hash in the outbox
/// slot of `nonce` and the sibling hashes proving it against the state root
/// of `height`; `null` if the node no longer keeps that height's state.
///
/// # Errors
/// A server error if the node fails or the message is not in that state.
pub fn outbox_proof(node: &mut Node, nonce: u64, height: u64) -> Result<Value, RpcError> {
    let Some(p) = solo_bridge::slot_proof(node, nonce, height).map_err(|e| failed(&e))? else {
        return Ok(Value::Null);
    };
    Ok(json!({
        "nonce": quantity(u128::from(p.nonce)),
        "height": quantity(u128::from(p.height)),
        "messageHash": data(&p.message_hash),
        "stateRoot": data(&p.root()),
        "siblings": p.siblings.iter().map(|s| data(s)).collect::<Vec<_>>(),
    }))
}
