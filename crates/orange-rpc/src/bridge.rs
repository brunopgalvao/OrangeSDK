//! The bridge's methods (spec 17 §7): what a relayer of the OrangeSDK-to-Ethereum
//! bridge needs from a node beside the Ethereum methods, a stored threshold
//! certificate with the proposal it certifies, and the proof of an outbox
//! slot against the state root of a recent height.

use orange_node::Node;
use serde_json::{Value, json};

use crate::hex::{data, parse_quantity, quantity};
use crate::methods::{RpcError, param_str};

#[allow(clippy::needless_pass_by_value)]
fn failed(e: orange_bridge::Error) -> RpcError {
    RpcError::server(e.to_string())
}

/// `orange_getFinalityProof(height)`: the threshold certificate the node
/// stored for `height`, the proposal it certifies, and the light client's
/// `submit` calldata; `null` if the node stored none.
///
/// # Errors
/// Invalid params, or a server error if the node fails or the stored
/// proposal has no anchor.
pub fn finality_proof(node: &mut Node, params: &[Value]) -> Result<Value, RpcError> {
    let height = parse_quantity(param_str(params, 0)?)?;
    let Some(proof) = orange_bridge::finality_proof(node, height).map_err(failed)? else {
        return Ok(Value::Null);
    };
    let s = orange_bridge::Submission::new(&proof).map_err(failed)?;
    Ok(json!({
        "keyId": s.key_id.map(|id| quantity(u128::from(id))),
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

/// `orange_getRotation(fromKeyId)`: the handoff out of key set `fromKeyId`
/// that the chain recorded, with the new key and the signature in EIP-2537
/// encoding and the light client's `rotate` calldata; `null` if none.
///
/// # Errors
/// Invalid params, or a server error if the node fails.
pub fn rotation(node: &mut Node, params: &[Value]) -> Result<Value, RpcError> {
    let from = parse_quantity(param_str(params, 0)?)?;
    let Some(r) = orange_bridge::rotation(node, from).map_err(failed)? else {
        return Ok(Value::Null);
    };
    Ok(json!({
        "from": quantity(u128::from(r.from)),
        "to": quantity(u128::from(r.to)),
        "height": quantity(u128::from(r.height)),
        "key": data(&r.key),
        "keyEip2537": data(&r.key_eip2537),
        "signature": data(&r.signature),
        "calldata": data(&r.calldata()),
    }))
}

/// `orange_getOutboxProof(nonce, height)`: the message hash in the outbox
/// slot of `nonce` and the sibling hashes proving it against the state root
/// of `height`; `null` if the node no longer keeps that height's state.
///
/// # Errors
/// Invalid params, or a server error if the node fails or the message is
/// not in that state.
pub fn outbox_proof(node: &mut Node, params: &[Value]) -> Result<Value, RpcError> {
    let (nonce, height) = (
        parse_quantity(param_str(params, 0)?)?,
        parse_quantity(param_str(params, 1)?)?,
    );
    let Some(p) = orange_bridge::slot_proof(node, nonce, height).map_err(failed)? else {
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

/// `orange_getGroupKey()`: the active key set of the node's chain at its head
/// (spec 15 §6), `{keyId, groupKey}` with the 96-byte group key a
/// threshold certificate of that set verifies under: what a joining node
/// trusts its snapshot by (spec 22 §7.2); `null` before the chain adopted
/// its first key set, or on a chain without one.
#[must_use]
pub fn group_key(node: &Node) -> Value {
    use orange_abi::Decode as _;
    use orange_abi::staking::keys;
    let id = node
        .state_get(keys::ACTIVE)
        .and_then(|b| u64::from_bytes(&b).ok());
    let key = node.state_get(keys::GROUP_KEY).filter(|k| k.len() == 96);
    match (id, key) {
        (Some(id), Some(key)) => json!({
            "keyId": quantity(u128::from(id)),
            "groupKey": data(&key),
        }),
        _ => Value::Null,
    }
}
