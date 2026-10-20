//! The outbox on a one-validator chain (spec 17 §2–§3): an account and a
//! contract send messages, each gets the next nonce, its hash lands in the
//! outbox slot of that nonce, the log names it and the value stays with the
//! outbox; a revert takes a message back; static and delegate calls,
//! malformed calls and transactions are refused; and the slot is proven
//! against the block's state root.

mod support;

use solo_abi::Encode;
use solo_abi::bridge::{
    MESSAGE_SENT, Message, NONCE_SLOT, OUTBOX_ADDRESS, SendCall, message_key, message_slot,
    send_gas,
};
use solo_abi::chain::{CallRequest, Receipt, reason};
use solo_abi::codec::Seq;
use solo_bridge::abi::{self, Value};
use solo_bridge::{Error, SlotProof, message_hash, sent_messages, slot_proof};
use solo_node::{Node, NodeConfig, SubmitError};
use support::eth::init_code;
use support::solo::{CHAIN_ID, address, create_address, genesis, kernel_module, key, tx};

const SLOT_MS: u64 = 400;
const START_MS: u64 = 1_700_000_000_000;
const ETH: u64 = 1;
const RECIPIENT: [u8; 20] = [0xAA; 20];

struct Chain {
    node: Node,
    now_ms: u64,
}

impl Chain {
    fn new(funded: &[[u8; 20]]) -> Chain {
        let validator = key(0x42);
        let config = NodeConfig {
            now_ms: START_MS,
            key: Some(validator.clone()),
            ..NodeConfig::default()
        };
        let mut node = Node::open(
            kernel_module(),
            &genesis(&[validator], funded, SLOT_MS, None),
            config,
        )
        .unwrap();
        node.start(None).unwrap();
        Chain {
            node,
            now_ms: START_MS,
        }
    }

    /// Runs `raw` in the next block and returns its receipt.
    fn run(&mut self, raw: &[u8]) -> Receipt {
        let hash = self.node.submit(raw).unwrap();
        self.now_ms += SLOT_MS;
        self.node.tick(self.now_ms).unwrap();
        self.node.receipt(&hash).unwrap().unwrap()
    }

    fn word(&mut self, slot: [u8; 32]) -> [u8; 32] {
        self.node.storage(&OUTBOX_ADDRESS, &slot).unwrap()
    }
}

/// Gas a call with `data` is charged: intrinsic gas plus `execution`, or the
/// EIP-7623 floor if that is more.
#[allow(clippy::naive_bytecount)]
fn charged(data: &[u8], execution: u64) -> u64 {
    let zeros = data.iter().filter(|b| **b == 0).count() as u64;
    let nonzero = data.len() as u64 - zeros;
    (21_000 + 4 * zeros + 16 * nonzero + execution).max(21_000 + 10 * (zeros + 4 * nonzero))
}

fn relay_call(signature: &str, dest: u64, recipient: [u8; 20], payload: &[u8]) -> Vec<u8> {
    abi::call(
        signature,
        &[
            Value::uint(u128::from(dest)),
            Value::address(&recipient),
            Value::Bytes(payload.to_vec()),
        ],
    )
}

#[test]
#[allow(clippy::too_many_lines)]
fn accounts_and_contracts_send_messages_that_state_proofs_reach() {
    let alice = key(0x11);
    let mut chain = Chain::new(&[address(&alice)]);
    chain.now_ms += SLOT_MS;
    chain.node.tick(chain.now_ms).unwrap();
    // An account sends directly, with value.
    let call = SendCall {
        dest_chain_id: ETH,
        recipient: RECIPIENT,
        payload: b"hello".to_vec(),
    };
    let data = call.encode();
    let receipt = chain.run(&tx(&alice, 0, Some(OUTBOX_ADDRESS), 5, &data, 200_000));
    assert_eq!(receipt.status, 1);
    assert_eq!(receipt.gas_used, charged(&data, send_gas(5)));
    let first = Message {
        source_chain_id: CHAIN_ID,
        nonce: 1,
        sender: address(&alice),
        dest_chain_id: ETH,
        recipient: RECIPIENT,
        value: 5,
        payload: b"hello".to_vec(),
    };
    let hash = message_hash(&first);
    assert_eq!(
        sent_messages(CHAIN_ID, &receipt.logs.0),
        vec![(first.clone(), hash)]
    );
    assert_eq!(receipt.logs.0[0].topics.0[0], MESSAGE_SENT);
    assert_eq!(chain.word(NONCE_SLOT)[31], 1);
    assert_eq!(chain.word(message_slot(1)), hash);
    assert_eq!(chain.node.account(&OUTBOX_ADDRESS).unwrap().balance, 5);
    // The slot is proven against the header's state root, as the inbox checks it.
    let height = receipt.height;
    let header = chain.node.block_by_number(height).unwrap().unwrap();
    let proof = slot_proof(&mut chain.node, 1, height).unwrap().unwrap();
    assert_eq!(proof.message_hash, hash);
    assert_eq!(proof.root(), header.state_root);
    // A contract sends: the message's sender is the contract.
    let deployed = chain.run(&tx(
        &alice,
        1,
        None,
        0,
        &init_code("OutboxCaller"),
        1_000_000,
    ));
    assert_eq!(deployed.status, 1);
    let caller = create_address(&address(&alice), 1);
    assert_eq!(deployed.contract, Some(caller));
    let receipt = chain.run(&tx(
        &alice,
        2,
        Some(caller),
        7,
        &relay_call("relay(uint64,address,bytes)", ETH, RECIPIENT, &[1; 40]),
        300_000,
    ));
    assert_eq!(receipt.status, 1);
    let sent = sent_messages(CHAIN_ID, &receipt.logs.0);
    let second = Message {
        source_chain_id: CHAIN_ID,
        nonce: 2,
        sender: caller,
        dest_chain_id: ETH,
        recipient: RECIPIENT,
        value: 7,
        payload: vec![1; 40],
    };
    assert_eq!(sent, vec![(second.clone(), message_hash(&second))]);
    // The caller's own event carries the nonce `send` returned.
    let own = receipt.logs.0.iter().find(|l| l.address == caller).unwrap();
    assert_eq!(own.data[31], 2);
    assert_eq!(chain.node.account(&OUTBOX_ADDRESS).unwrap().balance, 12);
    assert_eq!(chain.node.account(&caller).unwrap().balance, 0);
    // A revert after the send takes the message back.
    let receipt = chain.run(&tx(
        &alice,
        3,
        Some(caller),
        0,
        &relay_call(
            "relayThenRevert(uint64,address,bytes)",
            ETH,
            RECIPIENT,
            b"x",
        ),
        300_000,
    ));
    assert_eq!(receipt.status, 0);
    assert!(receipt.logs.0.is_empty());
    assert_eq!(chain.word(NONCE_SLOT)[31], 2);
    assert_eq!(chain.word(message_slot(3)), [0; 32]);
    // A static call and a delegate call are refused; so is a send the outbox does not accept.
    for signature in [
        "relayStatic(uint64,address,bytes)",
        "relayDelegate(uint64,address,bytes)",
    ] {
        let nonce = chain.node.account(&address(&alice)).unwrap().nonce;
        let receipt = chain.run(&tx(
            &alice,
            nonce,
            Some(caller),
            0,
            &relay_call(signature, ETH, RECIPIENT, b"x"),
            300_000,
        ));
        assert_eq!(
            (receipt.status, receipt.logs.0.len()),
            (1, 0),
            "{signature}"
        );
    }
    let nonce = chain.node.account(&address(&alice)).unwrap().nonce;
    let receipt = chain.run(&tx(
        &alice,
        nonce,
        Some(caller),
        0,
        &relay_call("relay(uint64,address,bytes)", CHAIN_ID, RECIPIENT, b"x"),
        300_000,
    ));
    assert_eq!(receipt.status, 0);
    // Too little gas for the send: the call fails and nothing is recorded.
    let tight = data.clone();
    let receipt = chain.run(&tx(
        &alice,
        nonce + 1,
        Some(OUTBOX_ADDRESS),
        0,
        &tight,
        charged(&tight, send_gas(5)) - 1,
    ));
    assert_eq!(receipt.status, 0);
    assert_eq!(chain.word(NONCE_SLOT)[31], 2);
    // A call query sends nothing for good, and returns the nonce the send would get.
    let request = CallRequest {
        from: address(&alice),
        to: Some(OUTBOX_ADDRESS),
        value: 0,
        data: data.clone(),
        gas: 0,
        access_list: Seq(vec![]),
    };
    let result = chain.node.call(&request).unwrap();
    assert_eq!(result.output[31], 3);
    assert_eq!(chain.word(NONCE_SLOT)[31], 2);
    // The first message is still proven at its height while the node keeps that state;
    // a height before it shows it absent, and a height the node never kept has no proof.
    let head = chain.node.block_number().unwrap();
    let later = slot_proof(&mut chain.node, 1, head).unwrap().unwrap();
    assert_eq!(later.message_hash, hash);
    assert!(matches!(
        slot_proof(&mut chain.node, 1, height - 1),
        Err(Error::NotCommitted)
    ));
    assert!(slot_proof(&mut chain.node, 1, 10_000).unwrap().is_none());
    let absent = chain.node.state_proof_at(height, &message_key(2)).unwrap();
    assert!(matches!(
        SlotProof::new(2, height, [0; 32], &absent),
        Err(Error::NotCommitted)
    ));
}

#[test]
fn transactions_to_the_outbox_must_carry_an_acceptable_send() {
    let alice = key(0x11);
    let mut chain = Chain::new(&[address(&alice)]);
    let call = SendCall {
        dest_chain_id: ETH,
        recipient: RECIPIENT,
        payload: vec![],
    };
    let mut too_long = call.encode();
    too_long.push(0);
    for data in [
        vec![],
        too_long,
        SendCall {
            dest_chain_id: CHAIN_ID,
            ..call.clone()
        }
        .encode(),
        SendCall {
            dest_chain_id: 0,
            ..call.clone()
        }
        .encode(),
        SendCall {
            recipient: [0; 20],
            ..call.clone()
        }
        .encode(),
        SendCall {
            payload: vec![0; solo_abi::bridge::MAX_PAYLOAD + 1],
            ..call.clone()
        }
        .encode(),
    ] {
        let raw = tx(&alice, 0, Some(OUTBOX_ADDRESS), 0, &data, 1_000_000);
        assert!(matches!(
            chain.node.submit(&raw),
            Err(SubmitError::Rejected(reason::OUTBOX_MESSAGE))
        ));
    }
    let max = SendCall {
        payload: vec![0xEE; solo_abi::bridge::MAX_PAYLOAD],
        ..call
    }
    .encode();
    let receipt = chain.run(&tx(&alice, 0, Some(OUTBOX_ADDRESS), 0, &max, 1_000_000));
    assert_eq!(receipt.status, 1);
    assert_eq!(
        receipt.gas_used,
        charged(&max, send_gas(solo_abi::bridge::MAX_PAYLOAD))
    );
    // Without value the outbox account stays empty, and its slots count on regardless.
    assert_eq!(
        chain.node.account(&OUTBOX_ADDRESS).unwrap().to_bytes(),
        solo_abi::chain::Account::default().to_bytes()
    );
    let again = SendCall {
        dest_chain_id: ETH,
        recipient: RECIPIENT,
        payload: vec![1],
    }
    .encode();
    assert_eq!(
        chain
            .run(&tx(&alice, 1, Some(OUTBOX_ADDRESS), 0, &again, 1_000_000))
            .status,
        1
    );
    assert_eq!(
        chain
            .node
            .storage(&OUTBOX_ADDRESS, &solo_abi::bridge::NONCE_SLOT)
            .unwrap()[31],
        2
    );
}
