//! The governance read methods (spec 13 §9.8) on a one-validator chain
//! under the stake track: the status, a proposal from submission through
//! its vote, its passing and its execution, and the parameter errors.

mod common;

use common::{
    CHAIN_ID, ETHER, Fields, GAS_PRICE, SLOT_MS, Wallet, err, err_code, kernel_module, node_key, ok,
};
use orange_abi::Encode;
use orange_abi::chain::{Allocation, GenesisParams, UpgradeParams, Validator, ValidatorSet};
use orange_abi::codec::Seq;
use orange_abi::governance::{Call, GOVERNANCE_ADDRESS, GOVERNANCE_GAS, GovernanceParams, mode};
use orange_abi::types::Genesis;
use orange_host::hash::keccak256;
use orange_node::{Node, NodeConfig, validator_id};
use orange_rpc::Rpc;
use orange_rpc::methods::data;
use serde_json::{Value, json};

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

/// A hex quantity.
fn number(v: &Value) -> u128 {
    u128::from_str_radix(&v.as_str().unwrap()[2..], 16).unwrap()
}

fn balance(rpc: &mut Rpc, address: &[u8; 20]) -> u128 {
    number(&ok(rpc, "eth_getBalance", json!([data(address), "latest"])))
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
    let status = ok(&mut rpc, "orange_getGovernance", json!([]));
    assert_eq!(status["mode"], "stake");
    assert_eq!(status["key"], data(&alice.address));
    assert_eq!(status["guardian"], data(&alice.address));
    assert_eq!(
        status["params"],
        json!({"votingBlocks": "0x2", "timelockBlocks": "0x1", "quorumBps": "0x1388", "deposit": "0xde0b6b3a7640000"})
    );
    assert_eq!(status["nextId"], "0x1");
    assert_eq!(status["proposals"], json!([]));
    assert_eq!(ok(&mut rpc, "orange_getProposals", json!([])), json!([]));
    assert_eq!(
        ok(&mut rpc, "orange_getProposal", json!(["0x1"])),
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
    // The deposit is held by the governance address, and the surcharge is
    // paid like every fee: at the gas price, to the zero address.
    let submit_fee = number(&receipt["gasUsed"]) * GAS_PRICE;
    assert!(number(&receipt["gasUsed"]) > u128::from(GOVERNANCE_GAS));
    assert_eq!(
        balance(&mut rpc, &alice.address),
        100 * ETHER - ETHER - submit_fee
    );
    assert_eq!(balance(&mut rpc, &GOVERNANCE_ADDRESS), ETHER);
    assert_eq!(balance(&mut rpc, &[0; 20]), submit_fee);
    let proposals = ok(&mut rpc, "orange_getProposals", json!([]));
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
    assert_eq!(p["delegators"], json!([]));
    assert_eq!(
        (&p["call"], &p["value"], &p["gas"]),
        (&json!(false), &json!("0x0"), &json!("0x0"))
    );
    assert_eq!(
        ok(&mut rpc, "orange_getGovernance", json!([]))["nextId"],
        "0x2"
    );

    // The validator votes yes with the gas `eth_estimateGas` gives, which
    // carries the surcharge (spec 13 §9.9): one gas less is refused as the
    // shortfall it is. The tally and the vote show at once.
    let voter = validator();
    let vote = Call::Vote {
        id: 1,
        support: true,
    }
    .encode();
    let estimate = ok(
        &mut rpc,
        "eth_estimateGas",
        json!([{"from": data(&voter.address), "to": data(&GOVERNANCE_ADDRESS), "data": data(&vote)}]),
    );
    assert_eq!(number(&estimate), 21_860 + u128::from(GOVERNANCE_GAS));
    let with_gas = |gas_limit: u64| {
        voter.legacy_on(
            &Fields {
                nonce: 0,
                to: Some(GOVERNANCE_ADDRESS),
                value: 0,
                gas_limit,
                data: &vote,
            },
            0,
            CHAIN_ID,
        )
    };
    assert_eq!(
        err(
            &mut rpc,
            "eth_sendRawTransaction",
            json!([data(&with_gas(71_859))])
        ),
        (
            -32000,
            "intrinsic gas too low: gas 71859, minimum needed 71860".into()
        )
    );
    let hash = ok(
        &mut rpc,
        "eth_sendRawTransaction",
        json!([data(&with_gas(71_860))]),
    );
    tick(&mut rpc, 1);
    let receipt = ok(&mut rpc, "eth_getTransactionReceipt", json!([hash]));
    assert_eq!(
        (&receipt["status"], &receipt["gasUsed"]),
        (&json!("0x1"), &estimate)
    );
    let p = ok(&mut rpc, "orange_getProposal", json!(["0x1"]));
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
    let p = ok(&mut rpc, "orange_getProposal", json!(["0x1"]));
    assert_eq!(p["status"], "passed");
    assert_eq!(
        ok(&mut rpc, "orange_getProposals", json!([]))[0]["status"],
        "passed"
    );
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
    // Executed, the proposal names the transaction that executed it.
    assert_eq!(
        ok(&mut rpc, "orange_getProposal", json!(["0x1"])),
        json!({
            "id": "0x1",
            "status": "executed",
            "executedAt": receipt["blockNumber"],
            "atEndOfBlock": false,
            "transactionHash": hash,
        })
    );
    let status = ok(&mut rpc, "orange_getGovernance", json!([]));
    assert_eq!(status["guardian"], data(&[0xAB; 20]));
    assert_eq!(status["proposals"], json!([]));
    // The deposit came back; the two calls' fees, surcharges included, went
    // to the zero address.
    let execute_fee = number(&receipt["gasUsed"]) * GAS_PRICE;
    assert_eq!(
        balance(&mut rpc, &alice.address),
        100 * ETHER - submit_fee - execute_fee
    );
    assert_eq!(balance(&mut rpc, &GOVERNANCE_ADDRESS), 0);
    assert_eq!(balance(&mut rpc, &[0; 20]), submit_fee + execute_fee);
    // Parameter errors.
    assert_eq!(err_code(&mut rpc, "orange_getProposal", json!([])), -32602);
    assert_eq!(
        err_code(&mut rpc, "orange_getProposal", json!(["zz"])),
        -32602
    );
    assert_eq!(err_code(&mut rpc, "orange_getProposal", json!([1])), -32602);
}

/// Sends `call` from `from` with `value` and returns its transaction hash.
fn send(rpc: &mut Rpc, from: &Wallet, nonce: u64, value: u128, call: &Call) -> Value {
    let raw = from.legacy(&Fields {
        nonce,
        to: Some(GOVERNANCE_ADDRESS),
        value,
        gas_limit: GAS,
        data: &call.encode(),
    });
    ok(rpc, "eth_sendRawTransaction", json!([data(&raw)]))
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_fast_track_execution_logs_in_the_system_receipt() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(stake_node(&alice));
    let mut now = 1_000;
    let mut tick = |rpc: &mut Rpc| {
        now += SLOT_MS;
        rpc.node_mut().tick(now).unwrap();
    };
    tick(&mut rpc);
    // A proposal, and the validators' `reject` of it on the fast track.
    let guardian = Call::SetGuardian {
        guardian: [0xAB; 20],
    }
    .encode();
    send(
        &mut rpc,
        &alice,
        0,
        ETHER,
        &Call::Submit {
            target: GOVERNANCE_ADDRESS,
            data: guardian,
        },
    );
    tick(&mut rpc);
    let reject = Call::Reject { id: 1 }.encode();
    send(
        &mut rpc,
        &alice,
        1,
        ETHER,
        &Call::Submit {
            target: GOVERNANCE_ADDRESS,
            data: reject,
        },
    );
    tick(&mut rpc);
    assert_eq!(
        ok(&mut rpc, "orange_getProposal", json!(["0x2"]))["fastTrack"],
        true
    );
    // The validator's vote passes it; it executes at the end of that block.
    let voter = validator();
    let raw = voter.legacy_on(
        &Fields {
            nonce: 0,
            to: Some(GOVERNANCE_ADDRESS),
            value: 0,
            gas_limit: GAS,
            data: &Call::Vote {
                id: 2,
                support: true,
            }
            .encode(),
        },
        0,
        CHAIN_ID,
    );
    let vote = ok(&mut rpc, "eth_sendRawTransaction", json!([data(&raw)]));
    tick(&mut rpc);
    let receipt = ok(&mut rpc, "eth_getTransactionReceipt", json!([vote]));
    let block = receipt["blockNumber"].clone();
    let block_hash = receipt["blockHash"].clone();
    assert_eq!(receipt["logs"].as_array().unwrap().len(), 1);
    // `ProposalExecuted(2)` is in the block's system receipt, after the
    // vote's `Voted`, where `eth_getLogs` finds it.
    let hash = keccak256(&orange_abi::chain::system_receipt_preimage(
        &orange_rpc::methods::parse_hex(block_hash.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    ));
    let executed = orange_abi::governance::executed_log(2);
    let logs = ok(
        &mut rpc,
        "eth_getLogs",
        json!([{"fromBlock": block, "toBlock": block, "address": data(&GOVERNANCE_ADDRESS)}]),
    );
    assert_eq!(logs.as_array().unwrap().len(), 2);
    assert_eq!(logs[0]["transactionHash"], vote);
    assert_eq!(
        logs[1],
        json!({
            "address": data(&GOVERNANCE_ADDRESS),
            "topics": executed.topics.0.iter().map(|t| data(t)).collect::<Vec<_>>(),
            "data": "0x",
            "blockHash": block_hash,
            "blockNumber": block,
            "transactionHash": data(&hash),
            "transactionIndex": "0x1",
            "logIndex": "0x1",
            "removed": false,
        })
    );
    // A filter that matches only the vote leaves it out.
    let topic = data(&orange_abi::governance::event::VOTED);
    let matching = ok(
        &mut rpc,
        "eth_getLogs",
        json!([{"fromBlock": block, "toBlock": block, "topics": [topic]}]),
    );
    assert_eq!(matching.as_array().unwrap().len(), 1);
    // Its receipt reads like a transaction's; there is no transaction, and
    // the block lists its transactions' receipts alone.
    let system = ok(&mut rpc, "eth_getTransactionReceipt", json!([data(&hash)]));
    assert_eq!(
        (
            &system["status"],
            &system["to"],
            &system["from"],
            &system["gasUsed"]
        ),
        (
            &json!("0x1"),
            &json!(data(&GOVERNANCE_ADDRESS)),
            &json!(data(&[0; 20])),
            &json!("0x0")
        )
    );
    assert_eq!(system["cumulativeGasUsed"], receipt["cumulativeGasUsed"]);
    assert_eq!(system["logs"][0], logs[1]);
    assert_eq!(
        ok(&mut rpc, "eth_getTransactionByHash", json!([data(&hash)])),
        Value::Null
    );
    let receipts = ok(&mut rpc, "eth_getBlockReceipts", json!([block]));
    assert_eq!(receipts.as_array().unwrap().len(), 1);
    // The header's bloom covers the system log (spec 20 §3.5): it is the OR
    // of the vote's receipt's bloom and the system receipt's, and a client
    // that skips blocks by their bloom, filtering on the one topic only the
    // system log has, keeps this block, where `eth_getLogs` finds that log.
    let bloom = |v: &Value| -> [u8; 256] {
        orange_rpc::methods::parse_hex(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let header = bloom(&ok(&mut rpc, "eth_getBlockByNumber", json!([block, false]))["logsBloom"]);
    let ours = bloom(&receipts[0]["logsBloom"]);
    let theirs = bloom(&system["logsBloom"]);
    let or: Vec<u8> = ours.iter().zip(&theirs).map(|(a, b)| a | b).collect();
    assert_eq!(header.to_vec(), or);
    let wanted =
        orange_eth::logs_bloom(&[(&GOVERNANCE_ADDRESS, &executed.topics.0[..1])], keccak256);
    let admits = |b: &[u8; 256]| {
        b.iter()
            .zip(&wanted)
            .all(|(have, want)| have & want == *want)
    };
    assert!(admits(&header));
    assert!(admits(&theirs));
    assert!(
        !admits(&ours),
        "the vote's bloom alone would skip the block"
    );
    let only = ok(
        &mut rpc,
        "eth_getLogs",
        json!([{"fromBlock": block, "toBlock": block, "topics": [data(&executed.topics.0[0])]}]),
    );
    assert_eq!(only, json!([logs[1]]));
    // The proposal names it; the proposal it rejected is gone.
    assert_eq!(
        ok(&mut rpc, "orange_getProposal", json!(["0x2"])),
        json!({
            "id": "0x2",
            "status": "executed",
            "executedAt": block,
            "atEndOfBlock": true,
            "transactionHash": data(&hash),
        })
    );
    assert_eq!(
        ok(&mut rpc, "orange_getProposal", json!(["0x1"])),
        Value::Null
    );
    assert_eq!(ok(&mut rpc, "orange_getProposals", json!([])), json!([]));
}

#[test]
fn a_development_chain_reads_as_the_key_track() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(common::node(&alice));
    let status = ok(&mut rpc, "orange_getGovernance", json!([]));
    assert_eq!(status["mode"], "key");
    assert_eq!(status["key"], data(&[0; 20]));
    assert_eq!(status["guardian"], data(&[0; 20]));
    assert_eq!(status["params"]["votingBlocks"], "0x0");
    assert_eq!(status["proposals"], json!([]));
    assert_eq!(ok(&mut rpc, "orange_getProposals", json!([])), json!([]));
}
