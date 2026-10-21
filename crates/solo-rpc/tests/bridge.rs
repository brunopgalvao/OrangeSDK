//! The bridge relayer's methods (spec 17 §7) on a one-validator chain that
//! generates its threshold key: no certificate before the key, then a
//! certificate with its proposal and `submit` calldata, the proof of an
//! outbox slot against the anchored state root, the outbox's rejection
//! text, and the handoffs of a key that rotates every epoch.

mod common;

use common::{CHAIN_ID, ETHER, Fields, SLOT_MS, Wallet, err, kernel_module, node_key, ok};
use serde_json::{Value, json};
use solo_abi::Encode;
use solo_abi::bridge::{OUTBOX_ADDRESS, SendCall};
use solo_abi::chain::{Allocation, GenesisParams, Validator, ValidatorSet};
use solo_abi::codec::Seq;
use solo_abi::staking::{StakingParams, ValidatorKey};
use solo_abi::types::Genesis;
use solo_node::keystore::encryption_key;
use solo_node::{Node, NodeConfig, PROOF_HISTORY, validator_id};
use solo_rpc::Rpc;
use solo_rpc::methods::{data, parse_hex, parse_quantity};

fn staking_node(alice: &Wallet, epoch_blocks: u64) -> Node {
    let key = node_key();
    let staking = StakingParams {
        epoch_blocks,
        dkg_phase_blocks: 2,
        max_key_age: 2,
        unbonding_epochs: 4,
        keys: Seq(vec![ValidatorKey {
            id: validator_id(&key),
            dkg_key: encryption_key(&key).to_vec(),
        }]),
        ..StakingParams::default()
    };
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        allocations: Seq(vec![Allocation {
            address: alice.address,
            balance: 100 * ETHER,
            ..Allocation::default()
        }]),
        staking,
        ..GenesisParams::default()
    };
    let set = ValidatorSet {
        validators: Seq(vec![Validator {
            id: validator_id(&key),
            weight: 1_000,
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

fn quantity_of(v: &Value) -> u64 {
    parse_quantity(v.as_str().unwrap()).unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_relayer_gets_certificates_and_outbox_proofs() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(staking_node(&alice, 1_000));
    let mut now = 1_000;
    let mut tick = |rpc: &mut Rpc, blocks: u64| {
        for _ in 0..blocks {
            now += SLOT_MS;
            rpc.node_mut().tick(now).unwrap();
        }
    };
    tick(&mut rpc, 1);
    assert_eq!(
        ok(&mut rpc, "solo_getFinalityProof", json!(["0x1"])),
        Value::Null
    );
    // A transaction to the outbox that is no send is refused with its own text.
    let bad = alice.legacy(&Fields {
        nonce: 0,
        to: Some(OUTBOX_ADDRESS),
        value: 0,
        gas_limit: 100_000,
        data: &[1, 2, 3],
    });
    assert_eq!(
        err(&mut rpc, "eth_sendRawTransaction", json!([data(&bad)])),
        (-32000, "not a valid outbox message".to_string())
    );
    // The key is generated within the first epoch; then a message goes out.
    tick(&mut rpc, 12);
    let send = SendCall {
        dest_chain_id: 1,
        recipient: [0xAA; 20],
        payload: b"relay me".to_vec(),
    }
    .encode();
    let raw = alice.legacy(&Fields {
        nonce: 0,
        to: Some(OUTBOX_ADDRESS),
        value: 0,
        gas_limit: 200_000,
        data: &send,
    });
    ok(&mut rpc, "eth_sendRawTransaction", json!([data(&raw)]));
    tick(&mut rpc, 1);
    let sent_at = rpc.node_mut().block_number().unwrap();
    tick(&mut rpc, 3);
    let head = rpc.node_mut().finalized_height().unwrap();
    let proof = ok(
        &mut rpc,
        "solo_getFinalityProof",
        json!([format!("{head:#x}")]),
    );
    assert_eq!(quantity_of(&proof["height"]), head);
    assert_eq!(quantity_of(&proof["keyId"]), 0);
    let anchor = quantity_of(&proof["anchorHeight"]);
    assert!(anchor >= sent_at && anchor < head, "{proof}");
    assert_eq!(
        parse_hex(proof["certificate"].as_str().unwrap())
            .unwrap()
            .len(),
        97
    );
    assert_eq!(
        parse_hex(proof["signature"].as_str().unwrap())
            .unwrap()
            .len(),
        128
    );
    let calldata = parse_hex(proof["calldata"].as_str().unwrap()).unwrap();
    assert_eq!(
        calldata[..4],
        solo_bridge::abi::selector("submit(bytes,bytes)")
    );
    let header = rpc.node_mut().block_by_number(anchor).unwrap().unwrap();
    assert_eq!(proof["anchorRoot"], json!(data(&header.state_root)));
    // The outbox slot of message 1 against that root.
    let slot = ok(
        &mut rpc,
        "solo_getOutboxProof",
        json!(["0x1", format!("{anchor:#x}")]),
    );
    assert_eq!(slot["stateRoot"], proof["anchorRoot"]);
    assert_eq!(quantity_of(&slot["nonce"]), 1);
    assert!(!slot["siblings"].as_array().unwrap().is_empty());
    // Before the message there is nothing to prove; a height the node has not reached has no proof.
    let (code, message) = err(&mut rpc, "solo_getOutboxProof", json!(["0x1", "0x1"]));
    assert_eq!(
        (code, message.as_str()),
        (-32000, "the message is not committed at that height")
    );
    assert_eq!(
        ok(&mut rpc, "solo_getOutboxProof", json!(["0x1", "0x100000"])),
        Value::Null
    );
    assert_eq!(
        err(&mut rpc, "solo_getOutboxProof", json!(["0x1"])).0,
        -32602
    );
    assert_eq!(err(&mut rpc, "solo_getOutboxProof", json!([])).0, -32602);
    assert_eq!(err(&mut rpc, "solo_getFinalityProof", json!([])).0, -32602);
    // No key has rotated within the first epoch.
    assert_eq!(
        ok(&mut rpc, "solo_getRotation", json!(["0x0"])),
        Value::Null
    );
    // Nor has a height the node no longer keeps, once PROOF_HISTORY blocks have passed it.
    tick(&mut rpc, PROOF_HISTORY as u64 + 1);
    assert_eq!(
        ok(
            &mut rpc,
            "solo_getOutboxProof",
            json!(["0x1", format!("{anchor:#x}")])
        ),
        Value::Null
    );
}

#[test]
fn a_relayer_gets_the_handoffs_of_a_rotating_key() {
    // One validator in epochs of 16 blocks: its key rotates every epoch, the old key
    // handing off to the new one.
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(staking_node(&alice, 16));
    let mut now = 1_000;
    let mut rotation = Value::Null;
    for _ in 0..80 {
        now += SLOT_MS;
        rpc.node_mut().tick(now).unwrap();
        rotation = ok(&mut rpc, "solo_getRotation", json!(["0x0"]));
        if !rotation.is_null() {
            break;
        }
    }
    assert!(!rotation.is_null());
    assert_eq!(quantity_of(&rotation["from"]), 0);
    assert_eq!(quantity_of(&rotation["to"]), 1);
    assert!(quantity_of(&rotation["height"]) > 16);
    let key = parse_hex(rotation["key"].as_str().unwrap()).unwrap();
    assert_eq!(key.len(), 96);
    assert_eq!(
        parse_hex(rotation["keyEip2537"].as_str().unwrap()).unwrap(),
        solo_bridge::group_key(&key).unwrap().to_vec()
    );
    assert_eq!(
        parse_hex(rotation["signature"].as_str().unwrap())
            .unwrap()
            .len(),
        128
    );
    let calldata = parse_hex(rotation["calldata"].as_str().unwrap()).unwrap();
    assert_eq!(
        calldata[..4],
        solo_bridge::abi::selector("rotate(uint64,bytes,bytes)")
    );
    assert_eq!(
        ok(&mut rpc, "solo_getRotation", json!(["0x63"])),
        Value::Null
    );
    assert_eq!(err(&mut rpc, "solo_getRotation", json!([])).0, -32602);
}
