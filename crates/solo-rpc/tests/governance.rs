//! The governance read methods (spec 13 §9.8) on a one-validator chain
//! under the stake track: the status, a proposal from submission through
//! its vote, its passing and its execution, and the parameter errors.

mod common;

use common::{CHAIN_ID, ETHER, Fields, SLOT_MS, Wallet, err_code, kernel_module, node_key, ok};
use serde_json::{Value, json};
use solo_abi::Encode;
use solo_abi::chain::{Allocation, GenesisParams, UpgradeParams, Validator, ValidatorSet};
use solo_abi::codec::Seq;
use solo_abi::governance::{Call, GOVERNANCE_ADDRESS, GovernanceParams, mode};
use solo_abi::types::Genesis;
use solo_host::hash::keccak256;
use solo_node::{Node, NodeConfig, validator_id};
use solo_rpc::Rpc;
use solo_rpc::methods::data;

const GAS: u64 = 200_000;

/// A chain under the stake track whose one validator is the node's key,
/// with `alice` as the governance key, so the guardian, and funded.
fn stake_node(alice: &Wallet) -> Node {
    let key = node_key();
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        allocations: Seq(vec![Allocation {
            address: alice.address,
            balance: 100 * ETHER,
            ..Allocation::default()
        }]),
        upgrades: UpgradeParams {
            governance: alice.address,
            min_delay: 1,
            epoch_blocks: 0,
        },
        governance: GovernanceParams {
            mode: mode::STAKE,
            voting_blocks: 2,
            timelock_blocks: 1,
            quorum_bps: 5_000,
            deposit: ETHER,
        },
        ..GenesisParams::default()
    };
    let set = ValidatorSet {
        validators: Seq(vec![Validator {
            id: validator_id(&key),
            weight: 7,
        }]),
    };
    let genesis = Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: set.to_bytes(),
    };
    let config = NodeConfig {
        now_ms: 1_000,
        key: Some(key),
        ..NodeConfig::default()
    };
    let mut node = Node::open(&kernel_module(), &genesis, config).unwrap();
    node.start(None).unwrap();
    node
}

/// The validator's account: its consensus key's address, which signs with
/// gas price zero because it holds nothing.
fn validator() -> Wallet {
    let key = node_key();
    let point = key.verifying_key().to_encoded_point(false);
    let digest = keccak256(&point.as_bytes()[1..]);
    Wallet {
        key,
        address: digest[12..].try_into().unwrap(),
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn proposals_are_read_from_submission_to_execution() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(stake_node(&alice));
    let mut now = 1_000;
    let mut tick = |rpc: &mut Rpc, blocks: u64| {
        for _ in 0..blocks {
            now += SLOT_MS;
            rpc.node_mut().tick(now).unwrap();
        }
    };
    tick(&mut rpc, 1);
    let status = ok(&mut rpc, "solo_getGovernance", json!([]));
    assert_eq!(status["mode"], "stake");
    assert_eq!(status["key"], data(&alice.address));
    assert_eq!(status["guardian"], data(&alice.address));
    assert_eq!(
        status["params"],
        json!({"votingBlocks": "0x2", "timelockBlocks": "0x1", "quorumBps": "0x1388", "deposit": "0xde0b6b3a7640000"})
    );
    assert_eq!(status["nextId"], "0x1");
    assert_eq!(status["proposals"], json!([]));
    assert_eq!(ok(&mut rpc, "solo_getProposals", json!([])), json!([]));
    assert_eq!(
        ok(&mut rpc, "solo_getProposal", json!(["0x1"])),
        Value::Null
    );

    // Alice, no validator, proposes with the deposit: a new guardian.
    let action = Call::SetGuardian {
        guardian: [0xAB; 20],
    }
    .encode();
    let submit = Call::Submit {
        target: GOVERNANCE_ADDRESS,
        data: action.clone(),
    }
    .encode();
    let raw = alice.legacy(&Fields {
        nonce: 0,
        to: Some(GOVERNANCE_ADDRESS),
        value: ETHER,
        gas_limit: GAS,
        data: &submit,
    });
    let hash = ok(&mut rpc, "eth_sendRawTransaction", json!([data(&raw)]));
    tick(&mut rpc, 1);
    let receipt = ok(&mut rpc, "eth_getTransactionReceipt", json!([hash]));
    assert_eq!(receipt["status"], "0x1");
    let height = receipt["blockNumber"].as_str().unwrap();
    let submitted = u64::from_str_radix(&height[2..], 16).unwrap();
    let proposals = ok(&mut rpc, "solo_getProposals", json!([]));
    let p = &proposals[0];
    assert_eq!(proposals.as_array().unwrap().len(), 1);
    assert_eq!(p["id"], "0x1");
    assert_eq!(p["proposer"], data(&alice.address));
    assert_eq!(p["deposit"], "0xde0b6b3a7640000");
    assert_eq!(p["target"], data(&GOVERNANCE_ADDRESS));
    assert_eq!(p["data"], data(&action));
    assert_eq!(p["submittedAt"], height);
    assert_eq!(p["votingEnd"], format!("{:#x}", submitted + 2));
    assert_eq!(p["executableAt"], format!("{:#x}", submitted + 4));
    assert_eq!(p["expiresAt"], format!("{:#x}", submitted + 5));
    assert_eq!(p["fastTrack"], false);
    assert_eq!(p["status"], "voting");
    assert_eq!(
        p["tally"],
        json!({"yes": "0x0", "no": "0x0", "total": "0x7"})
    );
    assert_eq!(p["votes"], json!([]));
    assert_eq!(ok(&mut rpc, "solo_getGovernance", json!([]))["nextId"], "0x2");

    // The validator votes yes; the tally and the vote show at once.
    let voter = validator();
    let vote = Call::Vote {
        id: 1,
        support: true,
    }
    .encode();
    let raw = voter.legacy_on(
        &Fields {
            nonce: 0,
            to: Some(GOVERNANCE_ADDRESS),
            value: 0,
            gas_limit: GAS,
            data: &vote,
        },
        0,
        CHAIN_ID,
    );
    ok(&mut rpc, "eth_sendRawTransaction", json!([data(&raw)]));
    tick(&mut rpc, 1);
    let p = ok(&mut rpc, "solo_getProposal", json!(["0x1"]));
    assert_eq!(
        p["tally"],
        json!({"yes": "0x7", "no": "0x0", "total": "0x7"})
    );
    assert_eq!(
        p["votes"],
        json!([{
            "validator": data(&validator_id(&node_key())),
            "address": data(&voter.address),
            "support": true,
            "weight": "0x7",
        }])
    );
    // Voting ends: passed, waiting out the timelock.
    while rpc.node_mut().block_number().unwrap() <= submitted + 2 {
        tick(&mut rpc, 1);
    }
    let p = ok(&mut rpc, "solo_getProposal", json!(["0x1"]));
    assert_eq!(p["status"], "passed");
    assert_eq!(ok(&mut rpc, "solo_getProposals", json!([]))[0]["status"], "passed");
    // Anyone executes it once the timelock is over; then nothing is open.
    while rpc.node_mut().block_number().unwrap() + 1 < submitted + 4 {
        tick(&mut rpc, 1);
    }
    let execute = Call::Execute { id: 1 }.encode();
    let raw = alice.legacy(&Fields {
        nonce: 1,
        to: Some(GOVERNANCE_ADDRESS),
        value: 0,
        gas_limit: GAS,
        data: &execute,
    });
    let hash = ok(&mut rpc, "eth_sendRawTransaction", json!([data(&raw)]));
    tick(&mut rpc, 1);
    let receipt = ok(&mut rpc, "eth_getTransactionReceipt", json!([hash]));
    assert_eq!(receipt["status"], "0x1");
    assert_eq!(receipt["logs"].as_array().unwrap().len(), 2);
    assert_eq!(
        ok(&mut rpc, "solo_getProposal", json!(["0x1"])),
        Value::Null
    );
    let status = ok(&mut rpc, "solo_getGovernance", json!([]));
    assert_eq!(status["guardian"], data(&[0xAB; 20]));
    assert_eq!(status["proposals"], json!([]));
    // Parameter errors.
    assert_eq!(err_code(&mut rpc, "solo_getProposal", json!([])), -32602);
    assert_eq!(err_code(&mut rpc, "solo_getProposal", json!(["zz"])), -32602);
    assert_eq!(err_code(&mut rpc, "solo_getProposal", json!([1])), -32602);
}
