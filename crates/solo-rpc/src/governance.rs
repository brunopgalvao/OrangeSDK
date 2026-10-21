//! Governance read methods (spec 13 §9.8): the governance track in force,
//! the guardian and the proposal rules, and the open proposals with their
//! live tallies and votes, for explorers, voters and the `solo` command.

use serde_json::{Value, json};
use solo_abi::Decode;
use solo_abi::governance::{GovernanceStatus, ProposalView, mode, query, status};
use solo_node::Node;

use crate::hex::{data, parse_quantity, quantity};
use crate::methods::{RpcError, param_str};

/// The mode's name; the kernel admits no third.
fn mode_text(m: u8) -> &'static str {
    if m == mode::STAKE { "stake" } else { "key" }
}

/// A status's name; the kernel keeps no third.
fn status_text(s: u8) -> &'static str {
    if s == status::PASSED {
        "passed"
    } else {
        "voting"
    }
}

/// The JSON view of an open proposal.
fn proposal_json(v: &ProposalView) -> Value {
    let p = &v.proposal;
    let votes: Vec<Value> = v
        .votes
        .0
        .iter()
        .map(|b| {
            json!({
                "validator": data(&b.validator),
                "address": data(&b.validator[12..]),
                "support": b.support,
                "weight": quantity(u128::from(b.weight)),
            })
        })
        .collect();
    json!({
        "id": quantity(u128::from(p.id)),
        "proposer": data(&p.proposer),
        "deposit": quantity(p.deposit),
        "target": data(&p.target),
        "data": data(&p.data),
        "submittedAt": quantity(u128::from(p.submitted_at)),
        "votingEnd": quantity(u128::from(p.voting_end)),
        "executableAt": quantity(u128::from(p.executable_at)),
        "expiresAt": quantity(u128::from(p.expires_at)),
        "fastTrack": p.fast_track,
        "status": status_text(p.status),
        "tally": {
            "yes": quantity(u128::from(v.yes)),
            "no": quantity(u128::from(v.no)),
            "total": quantity(u128::from(v.total)),
        },
        "votes": votes,
    })
}

/// The kernel's `governance` status; the default (the key track, nothing
/// open) from a kernel that does not serve the query.
fn status_of(node: &mut Node) -> Result<GovernanceStatus, RpcError> {
    let r = node.query(query::GOVERNANCE, &[])?;
    let status = (r.status == 0).then(|| GovernanceStatus::from_bytes(&r.body));
    status
        .transpose()
        .map(Option::unwrap_or_default)
        .map_err(|_| RpcError::server("the kernel's governance status does not decode"))
}

/// `solo_getGovernance()`: the mode, the key, the guardian, the proposal
/// rules, the next proposal id and the open proposals.
///
/// # Errors
/// A server error if the node fails.
pub fn governance(node: &mut Node) -> Result<Value, RpcError> {
    let s = status_of(node)?;
    let proposals: Vec<Value> = s.proposals.0.iter().map(proposal_json).collect();
    Ok(json!({
        "mode": mode_text(s.mode),
        "key": data(&s.key),
        "guardian": data(&s.guardian),
        "params": {
            "votingBlocks": quantity(u128::from(s.params.voting_blocks)),
            "timelockBlocks": quantity(u128::from(s.params.timelock_blocks)),
            "quorumBps": quantity(u128::from(s.params.quorum_bps)),
            "deposit": quantity(s.params.deposit),
        },
        "nextId": quantity(u128::from(s.next_id)),
        "proposals": proposals,
    }))
}

/// `solo_getProposals()`: the open proposals, in id order, each with its
/// live tally over the current validator set and every vote.
///
/// # Errors
/// A server error if the node fails.
pub fn proposals(node: &mut Node) -> Result<Value, RpcError> {
    let s = status_of(node)?;
    Ok(Value::Array(
        s.proposals.0.iter().map(proposal_json).collect(),
    ))
}

/// `solo_getProposal(id)`: one open proposal, or `null` once it is executed,
/// vetoed, failed or expired.
///
/// # Errors
/// Invalid params, or a server error if the node fails.
pub fn proposal(node: &mut Node, params: &[Value]) -> Result<Value, RpcError> {
    let id = parse_quantity(param_str(params, 0)?)?;
    let r = node.query(query::PROPOSAL, &solo_abi::Encode::to_bytes(&id))?;
    if r.status != 0 {
        return Ok(Value::Null);
    }
    let view = ProposalView::from_bytes(&r.body)
        .ok()
        .ok_or(RpcError::server("the kernel's proposal does not decode"))?;
    Ok(proposal_json(&view))
}
