//! The Ethereum surface of spec 20 over JSON-RPC, checked against
//! independent implementations: every block's header hashes with alloy to
//! the hash the node serves, its transactions and receipts roots are
//! `alloy-trie`'s; set-code transactions and their views; `eth_getProof`
//! checked by a verifier written here from spec 10; and state at older
//! blocks, before and after the node prunes it.

mod common;

use alloy_consensus::{Eip658Value, Header, Receipt, ReceiptEnvelope, ReceiptWithBloom};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B64, B256, Bloom, Bytes, Log, LogData, U256};
use common::{
    COUNTER_RUNTIME, ETHER, Fields, SLOT_MS, Wallet, calldata, counter_initcode, created_address,
    err, hex, node_funding, ok, word,
};
use serde_json::{Value, json};
use solo_rpc::Rpc;
use solo_rpc::methods::{MAX_PROOF_KEYS, data, parse_hex, parse_quantity};
use std::cell::Cell;
use std::rc::Rc;
use tiny_keccak::{Hasher, Keccak};

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(data);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

fn bytes(v: &Value) -> Vec<u8> {
    parse_hex(v.as_str().unwrap()).unwrap()
}

fn fixed<const N: usize>(v: &Value) -> [u8; N] {
    bytes(v).try_into().unwrap()
}

fn number(v: &Value) -> u64 {
    parse_quantity(v.as_str().unwrap()).unwrap()
}

/// Submits each transaction and ticks until every one has a receipt.
fn mine(rpc: &mut Rpc, now: &mut u64, raws: &[Vec<u8>]) -> Vec<String> {
    let hashes: Vec<String> = raws
        .iter()
        .map(|raw| {
            ok(rpc, "eth_sendRawTransaction", json!([data(raw)]))
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    for _ in 0..20 {
        let done = hashes
            .iter()
            .all(|h| ok(rpc, "eth_getTransactionReceipt", json!([h])) != Value::Null);
        if done {
            return hashes;
        }
        *now += SLOT_MS;
        rpc.node_mut().tick(*now).unwrap();
    }
    panic!("not mined: {hashes:?}");
}

fn header(block: &Value) -> Header {
    Header {
        parent_hash: B256::from(fixed::<32>(&block["parentHash"])),
        ommers_hash: B256::from(fixed::<32>(&block["sha3Uncles"])),
        beneficiary: Address::from(fixed::<20>(&block["miner"])),
        state_root: B256::from(fixed::<32>(&block["stateRoot"])),
        transactions_root: B256::from(fixed::<32>(&block["transactionsRoot"])),
        receipts_root: B256::from(fixed::<32>(&block["receiptsRoot"])),
        logs_bloom: Bloom::from(fixed::<256>(&block["logsBloom"])),
        difficulty: U256::from(number(&block["difficulty"])),
        number: number(&block["number"]),
        gas_limit: number(&block["gasLimit"]),
        gas_used: number(&block["gasUsed"]),
        timestamp: number(&block["timestamp"]),
        extra_data: Bytes::from(bytes(&block["extraData"])),
        mix_hash: B256::from(fixed::<32>(&block["mixHash"])),
        nonce: B64::from(fixed::<8>(&block["nonce"])),
        base_fee_per_gas: Some(number(&block["baseFeePerGas"])),
        withdrawals_root: Some(B256::from(fixed::<32>(&block["withdrawalsRoot"]))),
        blob_gas_used: Some(number(&block["blobGasUsed"])),
        excess_blob_gas: Some(number(&block["excessBlobGas"])),
        parent_beacon_block_root: Some(B256::from(fixed::<32>(&block["parentBeaconBlockRoot"]))),
        requests_hash: Some(B256::from(fixed::<32>(&block["requestsHash"]))),
    }
}

fn envelope(receipt: &Value) -> ReceiptEnvelope {
    let logs = receipt["logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| Log {
            address: Address::from(fixed::<20>(&l["address"])),
            data: LogData::new_unchecked(
                l["topics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|t| B256::from(fixed::<32>(t)))
                    .collect(),
                Bytes::from(bytes(&l["data"])),
            ),
        })
        .collect();
    let inner = Receipt {
        status: Eip658Value::Eip658(receipt["status"] == "0x1"),
        cumulative_gas_used: number(&receipt["cumulativeGasUsed"]),
        logs,
    };
    let r = ReceiptWithBloom::from(inner);
    match number(&receipt["type"]) {
        0 => ReceiptEnvelope::Legacy(r),
        1 => ReceiptEnvelope::Eip2930(r),
        2 => ReceiptEnvelope::Eip1559(r),
        _ => ReceiptEnvelope::Eip7702(r),
    }
}

/// Checks block `n` against alloy: its hash, its tries, its bloom and its
/// parent link, zero for the genesis block; returns how many transactions
/// it has.
fn verify_block(rpc: &mut Rpc, n: u64) -> usize {
    let block = ok(
        rpc,
        "eth_getBlockByNumber",
        json!([format!("{n:#x}"), false]),
    );
    let h = header(&block);
    assert_eq!(h.hash_slow().0, fixed::<32>(&block["hash"]), "block {n}");
    assert_eq!(
        block,
        ok(rpc, "eth_getBlockByHash", json!([block["hash"], false]))
    );
    let raws: Vec<Vec<u8>> = block["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| rpc.node_mut().transaction(&fixed(t)).unwrap().unwrap())
        .collect();
    assert_eq!(
        alloy_trie::root::ordered_trie_root_encoded(&raws),
        h.transactions_root,
        "block {n}"
    );
    let receipts: Vec<ReceiptEnvelope> =
        ok(rpc, "eth_getBlockReceipts", json!([format!("{n:#x}")]))
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                let e = envelope(r);
                assert_eq!(e.logs_bloom().0.0, fixed::<256>(&r["logsBloom"]));
                e
            })
            .collect();
    let root =
        alloy_trie::root::ordered_trie_root_with_encoder(&receipts, |r, buf| r.encode_2718(buf));
    assert_eq!(root, h.receipts_root, "block {n}");
    let mut bloom = Bloom::default();
    for r in &receipts {
        bloom.accrue_bloom(r.logs_bloom());
    }
    assert_eq!(bloom, h.logs_bloom);
    let parent = if n == 0 {
        [0; 32]
    } else {
        fixed(
            &ok(
                rpc,
                "eth_getBlockByNumber",
                json!([format!("{:#x}", n - 1), false]),
            )["hash"],
        )
    };
    assert_eq!(h.parent_hash.0, parent);
    // The size is the block's RLP: the header, the transactions, no ommers, no withdrawals.
    let mut encoded_txs = Vec::new();
    for raw in &raws {
        if raw[0] < 0x80 {
            alloy_rlp::Encodable::encode(&Bytes::from(raw.clone()), &mut encoded_txs);
        } else {
            encoded_txs.extend_from_slice(raw);
        }
    }
    let header_len = alloy_rlp::Encodable::length(&h);
    let txs_len = alloy_rlp::length_of_length(encoded_txs.len()) + encoded_txs.len();
    let payload = header_len + txs_len + 2;
    assert_eq!(
        usize::try_from(number(&block["size"])).unwrap(),
        alloy_rlp::length_of_length(payload) + payload
    );
    raws.len()
}

#[test]
#[allow(clippy::too_many_lines)]
fn blocks_carry_ethereum_headers_and_patricia_roots() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut rpc = Rpc::new(node_funding(&[&alice, &bob]));
    let mut now = 1_000;
    let counter = created_address(&alice.address, 0);
    let create = Fields {
        nonce: 0,
        to: None,
        value: 0,
        gas_limit: 1_000_000,
        data: &counter_initcode(5),
    };
    mine(&mut rpc, &mut now, &[alice.legacy(&create)]);
    // Every type in one block: legacy, access list, dynamic fee and set code,
    // most of them emitting a log.
    let increment = calldata("increment(uint256)", &[2]);
    let at = |nonce| Fields {
        nonce,
        to: Some(counter),
        value: 0,
        gas_limit: 200_000,
        data: &increment,
    };
    let auth = bob.authorization(common::CHAIN_ID, counter, 1);
    // Bob delegates to the counter and calls himself: the counter's code
    // runs over his storage.
    let read = calldata("count()", &[]);
    let to_self = Fields {
        nonce: 0,
        to: Some(bob.address),
        value: 0,
        gas_limit: 200_000,
        data: &read,
    };
    let hashes = mine(
        &mut rpc,
        &mut now,
        &[
            alice.legacy(&at(1)),
            alice.access_list_tx(&at(2), &[(counter, vec![word(0)])]),
            alice.dynamic(&at(3), 2 * common::GAS_PRICE, common::GAS_PRICE, &[]),
            bob.set_code(&to_self, 2 * common::GAS_PRICE, common::GAS_PRICE, &[auth]),
        ],
    );
    let head = rpc.node_mut().block_number().unwrap();
    let mut total = 0;
    // The genesis block verifies as every other does (spec 20 §3.1).
    for n in 0..=head {
        total += verify_block(&mut rpc, n);
    }
    assert_eq!(total, 5);
    // The set-code transaction and its receipt.
    let tx = ok(&mut rpc, "eth_getTransactionByHash", json!([hashes[3]]));
    assert_eq!(tx["type"], "0x4");
    let auths = tx["authorizationList"].as_array().unwrap();
    assert_eq!(auths.len(), 1);
    assert_eq!(auths[0]["address"], data(&counter));
    assert_eq!(auths[0]["chainId"], format!("{:#x}", common::CHAIN_ID));
    assert_eq!(auths[0]["nonce"], "0x1");
    assert!(auths[0]["yParity"] == "0x0" || auths[0]["yParity"] == "0x1");
    assert_eq!(tx["maxFeePerGas"], format!("{:#x}", 2 * common::GAS_PRICE));
    let receipt = ok(&mut rpc, "eth_getTransactionReceipt", json!([hashes[3]]));
    assert_eq!(
        (receipt["type"].clone(), receipt["status"].clone()),
        (json!("0x4"), json!("0x1"))
    );
    let designator = [&[0xEF, 0x01, 0x00][..], &counter].concat();
    assert_eq!(
        ok(&mut rpc, "eth_getCode", json!([data(&bob.address)])),
        data(&designator)
    );
    // The counter's code now runs at Bob's address too, over Bob's storage.
    let count = json!({ "to": data(&bob.address), "input": data(&calldata("count()", &[])) });
    assert_eq!(ok(&mut rpc, "eth_call", json!([count])), data(&word(0)));
    // The genesis block has a header, whose hash is its hash (spec 20 §3.1),
    // committing to the genesis state.
    let genesis = ok(&mut rpc, "eth_getBlockByNumber", json!(["0x0", false]));
    assert_eq!(
        header(&genesis).hash_slow().0,
        fixed::<32>(&genesis["hash"])
    );
    assert_ne!(genesis["hash"], data(&[0; 32]));
    assert_eq!(genesis["parentHash"], data(&[0; 32]));
    assert_eq!(
        genesis["transactionsRoot"],
        data(&solo_eth::mpt::EMPTY_ROOT)
    );
    assert_eq!(genesis["stateRoot"], data(&rpc.node().genesis_state_root()));
    assert_ne!(genesis["stateRoot"], data(&[0; 32]));
    // Block 1's parent hash names it as any block's hash names its block:
    // by hash, for receipts and logs, and as a state method's block
    // parameter, directly or as an EIP-1898 object (spec 20 §5.2).
    let zero = genesis["hash"].clone();
    let first = ok(&mut rpc, "eth_getBlockByNumber", json!(["0x1", false]));
    assert_eq!(first["parentHash"], zero);
    // The zero hash names no block.
    assert_eq!(
        ok(
            &mut rpc,
            "eth_getBlockByHash",
            json!([data(&[0; 32]), false])
        ),
        Value::Null
    );
    assert_eq!(
        ok(&mut rpc, "eth_getBlockByHash", json!([zero, false])),
        genesis
    );
    assert_eq!(
        ok(&mut rpc, "eth_getBlockReceipts", json!([zero])),
        json!([])
    );
    assert_eq!(
        ok(&mut rpc, "eth_getLogs", json!([{ "blockHash": zero }])),
        json!([])
    );
    let allocation = format!("{:#x}", 100 * ETHER);
    for block in [json!(zero), json!({ "blockHash": zero })] {
        assert_eq!(
            ok(
                &mut rpc,
                "eth_getBalance",
                json!([data(&alice.address), block])
            ),
            allocation
        );
    }
}

#[test]
fn calls_and_estimates_take_an_authorization_list() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut rpc = Rpc::new(node_funding(&[&alice, &bob]));
    let mut now = 1_000;
    let counter = created_address(&alice.address, 0);
    let create = Fields {
        nonce: 0,
        to: None,
        value: 0,
        gas_limit: 1_000_000,
        data: &counter_initcode(5),
    };
    mine(&mut rpc, &mut now, &[alice.legacy(&create)]);
    // Bob's authorization, as a wallet would pass it to eth_estimateGas
    // before sending: the counter's code runs at Bob's address.
    let raw = bob.authorization(common::CHAIN_ID, counter, 1);
    let item = solo_rlp::decode(&raw).unwrap();
    let fields = item.list().unwrap();
    let quantity = |i: usize| {
        let b = fields[i].bytes().unwrap();
        if b.is_empty() {
            "0x0".to_owned()
        } else {
            format!("0x{}", &data(b)[2..].trim_start_matches('0'))
        }
    };
    let auth = json!({
        "chainId": quantity(0),
        "address": data(&counter),
        "nonce": quantity(2),
        "yParity": quantity(3),
        "r": data(fields[4].bytes().unwrap()),
        "s": data(fields[5].bytes().unwrap()),
    });
    let increment = data(&calldata("increment(uint256)", &[3]));
    let call = json!({ "from": data(&bob.address), "to": data(&bob.address), "input": increment, "authorizationList": [auth] });
    // Bob's slot 0 starts at zero: the counter returns the delta.
    assert_eq!(ok(&mut rpc, "eth_call", json!([call])), data(&word(3)));
    let plain = json!({ "from": data(&bob.address), "to": data(&counter), "input": increment });
    // Without refunds an estimate is exactly the gas used. An authorization
    // that is skipped (another chain's) still costs its 25 000 of
    // intrinsic gas, and nothing else.
    let without = number(&ok(&mut rpc, "eth_estimateGas", json!([plain])));
    let mut elsewhere = auth.clone();
    elsewhere["chainId"] = json!("0x3e7");
    let mut skipped = plain.clone();
    skipped["authorizationList"] = json!([elsewhere]);
    assert_eq!(
        number(&ok(&mut rpc, "eth_estimateGas", json!([skipped]))),
        without + 25_000
    );
    // Bob's own authorization costs the same 25 000, and the counter's
    // SSTORE sets his slot 0 from zero (22 100, cold) where the plain call
    // reset the counter's (5 000). Bob's account exists, so 12 500 comes
    // back as a refund, which a gas limit must still cover: the call
    // succeeds with exactly that much gas and fails with one less, and the
    // estimate lands within its 1.5% above.
    let needed = without + 25_000 + 22_100 - 5_000;
    let limited = |gas: u64| {
        let mut call = call.clone();
        call["gas"] = json!(format!("{gas:#x}"));
        json!([call])
    };
    assert_eq!(ok(&mut rpc, "eth_call", limited(needed)), data(&word(3)));
    assert_eq!(
        err(&mut rpc, "eth_call", limited(needed - 1)),
        (
            -32000,
            "execution halted: out of gas or an exceptional halt".to_owned()
        )
    );
    let with = number(&ok(&mut rpc, "eth_estimateGas", json!([call])));
    assert!(
        (needed..=needed + needed * 15 / 1000).contains(&with),
        "{with} {needed}"
    );
    // `v` stands for `yParity`; a missing field or a bad list is refused.
    let mut with_v = auth.clone();
    with_v["v"] = with_v["yParity"].take();
    with_v.as_object_mut().unwrap().remove("yParity");
    let call_v = json!({ "from": data(&bob.address), "to": data(&bob.address), "input": increment, "authorizationList": [with_v] });
    assert_eq!(ok(&mut rpc, "eth_call", json!([call_v])), data(&word(3)));
    let mut missing = auth.clone();
    missing.as_object_mut().unwrap().remove("r");
    for bad in [
        json!([missing]),
        json!("nope"),
        json!([1]),
        json!([{ "chainId": "0x1", "address": data(&counter), "nonce": "0x0", "yParity": "0x100", "r": "0x1", "s": "0x1" }]),
    ] {
        let call = json!({ "to": data(&bob.address), "authorizationList": bad });
        assert_eq!(err(&mut rpc, "eth_call", json!([call])).0, -32602, "{bad}");
    }
    // Code reads are unchanged: nothing was sent.
    assert_eq!(
        ok(&mut rpc, "eth_getCode", json!([data(&bob.address)])),
        "0x"
    );
    assert_eq!(
        ok(&mut rpc, "eth_getCode", json!([data(&counter)])),
        data(&hex(COUNTER_RUNTIME))
    );
}

/// A spec 10 §5.3 verifier written from the spec: the value hash of a
/// present key, `Some(None)` for an absent one, `None` for a rejected proof.
#[allow(clippy::option_option)]
fn verify(root: &[u8; 32], key: &[u8], elements: &[Value]) -> Option<Option<[u8; 32]>> {
    let (terminal, siblings) = elements.split_last()?;
    let siblings: Vec<[u8; 32]> = siblings.iter().map(fixed::<32>).collect();
    let path = keccak(key);
    let bit = |p: &[u8; 32], i: usize| p[i / 8] >> (7 - i % 8) & 1 == 1;
    let terminal = bytes(terminal);
    let (mut h, outcome) = match terminal.as_slice() {
        [0x00] => ([0; 32], None),
        [0x01, rest @ ..] if rest.len() == 64 => {
            let q: [u8; 32] = rest[..32].try_into().unwrap();
            let w: [u8; 32] = rest[32..].try_into().unwrap();
            if (0..siblings.len()).any(|i| bit(&q, i) != bit(&path, i)) {
                return None;
            }
            (
                keccak(&[&[0x00][..], &q, &w].concat()),
                (q == path).then_some(w),
            )
        }
        _ => return None,
    };
    for i in (0..siblings.len()).rev() {
        h = if bit(&path, i) {
            keccak(&[&[0x01][..], &siblings[i], &h].concat())
        } else {
            keccak(&[&[0x01][..], &h, &siblings[i]].concat())
        };
    }
    (h == *root).then_some(outcome)
}

#[test]
#[allow(clippy::too_many_lines)]
fn get_proof_verifies_independently_at_every_kept_height() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node_funding(&[&alice]));
    let mut now = 1_000;
    let counter = created_address(&alice.address, 0);
    let create = Fields {
        nonce: 0,
        to: None,
        value: 0,
        gas_limit: 1_000_000,
        data: &counter_initcode(5),
    };
    mine(&mut rpc, &mut now, &[alice.legacy(&create)]);
    let deployed = rpc.node_mut().block_number().unwrap();
    let increment = calldata("increment(uint256)", &[2]);
    let inc = Fields {
        nonce: 1,
        to: Some(counter),
        value: 0,
        gas_limit: 200_000,
        data: &increment,
    };
    mine(&mut rpc, &mut now, &[alice.legacy(&inc)]);
    let head = rpc.node_mut().block_number().unwrap();
    let c = data(&counter);
    let check = |rpc: &mut Rpc, block: Value, height: u64, count: u64| {
        let proof = ok(rpc, "eth_getProof", json!([c, ["0x0", "0x05"], block]));
        assert_eq!(proof["proofFormat"], "solo-binary-trie-v0");
        let root = fixed::<32>(&proof["stateRoot"]);
        assert_eq!(proof["storageHash"], proof["stateRoot"]);
        // The account: its entry's value is the encoded record, whose fields
        // the response spells out.
        let key = [&b"acct/"[..], &counter].concat();
        assert_eq!(bytes(&proof["accountKey"]), key);
        let value = bytes(&proof["accountValue"]);
        assert_eq!(
            verify(&root, &key, proof["accountProof"].as_array().unwrap()),
            Some(Some(keccak(&value)))
        );
        assert_eq!(value.len(), 56);
        assert_eq!(u128::from_le_bytes(value[..16].try_into().unwrap()), 0);
        assert_eq!(
            u64::from_le_bytes(value[16..24].try_into().unwrap()),
            number(&proof["nonce"])
        );
        assert_eq!(value[24..], keccak(&hex(COUNTER_RUNTIME)));
        assert_eq!(bytes(&proof["codeHash"]), value[24..]);
        // Slot 0 holds the count; slot 5 is empty and proven absent.
        let slots = proof["storageProof"].as_array().unwrap();
        assert_eq!(slots[0]["key"], "0x0");
        assert_eq!(number(&slots[0]["value"]), count);
        let slot_key = [&b"slot/"[..], &counter, &word(0)].concat();
        assert_eq!(
            verify(&root, &slot_key, slots[0]["proof"].as_array().unwrap()),
            Some(Some(keccak(&word(count))))
        );
        assert_eq!(slots[1]["key"], "0x05");
        assert_eq!(slots[1]["value"], "0x0");
        let empty_key = [&b"slot/"[..], &counter, &word(5)].concat();
        assert_eq!(
            verify(&root, &empty_key, slots[1]["proof"].as_array().unwrap()),
            Some(None)
        );
        // The proof is against the block's header.
        let header = ok(
            rpc,
            "eth_getBlockByNumber",
            json!([format!("{height:#x}"), false]),
        );
        assert_eq!(header["stateRoot"], proof["stateRoot"]);
        // A tampered sibling or value does not verify.
        let mut forged = proof["accountProof"].as_array().unwrap().clone();
        forged[0] = json!(data(&[7; 32]));
        assert_eq!(verify(&root, &key, &forged), None);
    };
    check(&mut rpc, json!("latest"), head, 7);
    check(&mut rpc, json!(format!("{deployed:#x}")), deployed, 5);
    // An account that does not exist is proven absent, with zero fields.
    let nobody = ok(
        &mut rpc,
        "eth_getProof",
        json!([data(&[0x99; 20]), [], "latest"]),
    );
    let key = [&b"acct/"[..], &[0x99; 20]].concat();
    let root = fixed::<32>(&nobody["stateRoot"]);
    assert_eq!(
        verify(&root, &key, nobody["accountProof"].as_array().unwrap()),
        Some(None)
    );
    assert_eq!(
        (
            nobody["balance"].clone(),
            nobody["nonce"].clone(),
            nobody["accountValue"].clone()
        ),
        (json!("0x0"), json!("0x0"), json!("0x"))
    );
    assert_eq!(nobody["codeHash"], data(&keccak(&[])));
    // The genesis state proves against the root block 0 carries: Alice's
    // allocation, and no counter yet.
    let genesis = ok(
        &mut rpc,
        "eth_getProof",
        json!([data(&alice.address), [], "earliest"]),
    );
    let root =
        fixed::<32>(&ok(&mut rpc, "eth_getBlockByNumber", json!(["0x0", false]))["stateRoot"]);
    assert_eq!(fixed::<32>(&genesis["stateRoot"]), root);
    assert_eq!(genesis["balance"], format!("{:#x}", 100 * ETHER));
    let key = [&b"acct/"[..], &alice.address].concat();
    assert_eq!(
        verify(&root, &key, genesis["accountProof"].as_array().unwrap()),
        Some(Some(keccak(&bytes(&genesis["accountValue"]))))
    );
    let before = ok(&mut rpc, "eth_getProof", json!([c, ["0x0"], "0x0"]));
    assert_eq!(before["accountValue"], "0x");
    assert_eq!(before["storageProof"][0]["value"], "0x0");
    // Parameters.
    assert_eq!(err(&mut rpc, "eth_getProof", json!([c])).0, -32602);
    assert_eq!(
        err(&mut rpc, "eth_getProof", json!([c, ["0xzz"]])).0,
        -32602
    );
    assert_eq!(
        err(
            &mut rpc,
            "eth_getProof",
            json!([c, [], format!("{:#x}", head + 1)])
        )
        .1,
        "header not found"
    );
    // Once the node has pruned a height, its proofs go with its state.
    rpc.node_mut().state_history = 2;
    mine(
        &mut rpc,
        &mut now,
        &[alice.legacy(&Fields { nonce: 2, ..inc })],
    );
    mine(
        &mut rpc,
        &mut now,
        &[alice.legacy(&Fields { nonce: 3, ..inc })],
    );
    let (code, message) = err(
        &mut rpc,
        "eth_getProof",
        json!([c, [], format!("{deployed:#x}")]),
    );
    assert_eq!(code, -32000);
    assert!(message.starts_with("missing trie node "), "{message}");
    let oldest = rpc.node().oldest_state();
    assert!(
        message.ends_with(&format!("the node keeps the state from block {oldest}")),
        "{message}"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn get_proof_hands_the_node_its_work_between_keys_and_caps_them() {
    let alice = Wallet::new(1);
    let mut rpc = Rpc::new(node_funding(&[&alice]));
    let mut now = 1_000;
    let counter = created_address(&alice.address, 0);
    let create = Fields {
        nonce: 0,
        to: None,
        value: 0,
        gas_limit: 1_000_000,
        data: &counter_initcode(5),
    };
    mine(&mut rpc, &mut now, &[alice.legacy(&create)]);
    let height = rpc.node_mut().block_number().unwrap();
    // Each time the node gets the thread back it mines a block that
    // increments the counter, so the head moves during the request.
    let increment = calldata("increment(uint256)", &[1]);
    let raws: Vec<Vec<u8>> = (1..=4)
        .map(|nonce| {
            alice.legacy(&Fields {
                nonce,
                to: Some(counter),
                value: 0,
                gas_limit: 200_000,
                data: &increment,
            })
        })
        .collect();
    let turns = Rc::new(Cell::new(0usize));
    let seen = Rc::clone(&turns);
    let clock = Rc::new(Cell::new(now));
    rpc.set_background(Box::new(move |node| {
        let hash = node.submit(&raws[seen.get()]).unwrap();
        seen.set(seen.get() + 1);
        while node.receipt(&hash).unwrap().is_none() {
            clock.set(clock.get() + SLOT_MS);
            node.tick(clock.get()).unwrap();
        }
    }));
    let c = data(&counter);
    let proof = ok(
        &mut rpc,
        "eth_getProof",
        json!([c, ["0x0", "0x5", "0x0"], "latest"]),
    );
    assert_eq!(turns.get(), 3);
    assert_eq!(rpc.node_mut().block_number().unwrap(), height + 3);
    // The answer is still the head the request named: its root, and slot
    // values that match their proofs against it.
    let block = ok(
        &mut rpc,
        "eth_getBlockByNumber",
        json!([format!("{height:#x}"), false]),
    );
    assert_eq!(proof["stateRoot"], block["stateRoot"]);
    let root = fixed::<32>(&proof["stateRoot"]);
    for (entry, (slot, value)) in
        proof["storageProof"]
            .as_array()
            .unwrap()
            .iter()
            .zip([(0, 5), (5, 0), (0, 5)])
    {
        assert_eq!(number(&entry["value"]), value);
        let key = [&b"slot/"[..], &counter, &word(slot)].concat();
        let expected = (value != 0).then(|| keccak(&word(value)));
        assert_eq!(
            verify(&root, &key, entry["proof"].as_array().unwrap()),
            Some(expected)
        );
    }
    // A block that the background work executes can prune the height: the
    // request then fails as for any pruned height.
    rpc.node_mut().state_history = 1;
    let latest = rpc.node_mut().block_number().unwrap();
    let (code, message) = err(&mut rpc, "eth_getProof", json!([c, ["0x0"], "latest"]));
    assert_eq!(code, -32000);
    let oldest = rpc.node().oldest_state();
    assert_eq!(oldest, latest + 1);
    assert!(message.starts_with("missing trie node "), "{message}");
    assert!(
        message.ends_with(&format!(
            "state of block {latest} is not available, the node keeps the state from block {oldest}"
        )),
        "{message}"
    );
    // At most MAX_PROOF_KEYS keys, each handing the node its work.
    let quiet = Rc::new(Cell::new(0usize));
    let count = Rc::clone(&quiet);
    rpc.set_background(Box::new(move |_| count.set(count.get() + 1)));
    let keys: Vec<String> = (0..=MAX_PROOF_KEYS).map(|k| format!("{k:#x}")).collect();
    let (code, message) = err(&mut rpc, "eth_getProof", json!([c, keys, "latest"]));
    assert_eq!(
        (code, message),
        (
            -32602,
            format!(
                "too many storage keys: {}, the limit is {MAX_PROOF_KEYS}",
                MAX_PROOF_KEYS + 1
            )
        )
    );
    assert_eq!(quiet.get(), 0);
    let proof = ok(
        &mut rpc,
        "eth_getProof",
        json!([c, keys[..MAX_PROOF_KEYS], "latest"]),
    );
    assert_eq!(quiet.get(), MAX_PROOF_KEYS);
    assert_eq!(
        proof["storageProof"].as_array().unwrap().len(),
        MAX_PROOF_KEYS
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn state_methods_answer_at_older_blocks_until_pruned() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut rpc = Rpc::new(node_funding(&[&alice]));
    let mut now = 1_000;
    let mut seen = Vec::new();
    for nonce in 0..4 {
        mine(
            &mut rpc,
            &mut now,
            &[alice.transfer(nonce, bob.address, ETHER, 21_000)],
        );
        let height = rpc.node_mut().block_number().unwrap();
        let hash = ok(
            &mut rpc,
            "eth_getBlockByNumber",
            json!([format!("{height:#x}"), false]),
        )["hash"]
            .clone();
        seen.push((height, hash, u128::from(nonce + 1) * ETHER));
    }
    let b = data(&bob.address);
    let a = data(&alice.address);
    for (height, hash, balance) in &seen {
        let expected = format!("{balance:#x}");
        for block in [
            json!(format!("{height:#x}")),
            hash.clone(),
            json!({ "blockHash": hash }),
            json!({ "blockNumber": format!("{height:#x}") }),
        ] {
            assert_eq!(ok(&mut rpc, "eth_getBalance", json!([b, block])), expected);
        }
        let nonce = ok(
            &mut rpc,
            "eth_getTransactionCount",
            json!([a, format!("{height:#x}")]),
        );
        assert_eq!(u128::from(number(&nonce)) * ETHER, *balance);
        // A call at a block runs in that block: NUMBER is its height.
        let number_call = json!({ "input": "0x4360005260206000f3" });
        assert_eq!(
            ok(
                &mut rpc,
                "eth_call",
                json!([number_call, format!("{height:#x}")])
            ),
            data(&word(*height))
        );
        assert_eq!(
            number(&ok(
                &mut rpc,
                "eth_estimateGas",
                json!([{ "from": a, "to": b, "value": "0x1" }, format!("{height:#x}")])
            )),
            21_000
        );
    }
    // The genesis state is kept: Bob had nothing, and Alice could not send
    // more than her allocation.
    assert_eq!(
        ok(&mut rpc, "eth_getBalance", json!([b, "earliest"])),
        "0x0"
    );
    assert_eq!(ok(&mut rpc, "eth_getCode", json!([b, "0x0"])), "0x");
    assert_eq!(
        ok(&mut rpc, "eth_getStorageAt", json!([b, "0x0", "0x0"])),
        data(&[0; 32])
    );
    let too_much = json!({ "from": a, "to": b, "value": format!("{:#x}", 101 * ETHER) });
    assert!(
        err(&mut rpc, "eth_call", json!([too_much, "earliest"]))
            .1
            .starts_with("insufficient funds")
    );
    // Pruned heights are refused as a pruned geth node refuses them.
    rpc.node_mut().state_history = 2;
    mine(
        &mut rpc,
        &mut now,
        &[alice.transfer(4, bob.address, ETHER, 21_000)],
    );
    let oldest = rpc.node().oldest_state();
    let (first, _, _) = &seen[0];
    let (code, message) = err(
        &mut rpc,
        "eth_getBalance",
        json!([b, format!("{first:#x}")]),
    );
    assert_eq!(code, -32000);
    let root = ok(
        &mut rpc,
        "eth_getBlockByNumber",
        json!([format!("{first:#x}"), false]),
    )["stateRoot"]
        .clone();
    assert_eq!(
        message,
        format!(
            "missing trie node {} (path ) state of block {first} is not available, the node keeps the state from block {oldest}",
            &root.as_str().unwrap()[2..]
        )
    );
    assert!(
        err(&mut rpc, "eth_getBalance", json!([b, "earliest"]))
            .1
            .starts_with("missing trie node ")
    );
    let head = rpc.node_mut().block_number().unwrap();
    assert_eq!(oldest, head - 1);
    assert_eq!(
        ok(&mut rpc, "eth_getBalance", json!([b, format!("{head:#x}")])),
        format!("{:#x}", 5 * ETHER)
    );
}

/// Every state and block method's answer at every height the node keeps.
fn answers_at_every_height(rpc: &mut Rpc, alice: &Wallet, counter: &[u8; 20]) -> Vec<Value> {
    let head = number(&ok(rpc, "eth_blockNumber", json!([])));
    let (a, c) = (data(&alice.address), data(counter));
    let mut all = vec![json!(head)];
    for height in 0..=head {
        let at = json!(format!("{height:#x}"));
        all.extend([
            ok(rpc, "eth_getBlockByNumber", json!([at, true])),
            ok(rpc, "eth_getBlockReceipts", json!([at])),
            ok(rpc, "eth_getBalance", json!([a, at])),
            ok(rpc, "eth_getTransactionCount", json!([a, at])),
            ok(rpc, "eth_getCode", json!([c, at])),
            ok(rpc, "eth_getStorageAt", json!([c, "0x0", at])),
            ok(rpc, "eth_getProof", json!([c, ["0x0", "0x05"], at])),
            ok(rpc, "eth_getProof", json!([a, [], at])),
            ok(
                rpc,
                "eth_call",
                json!([{"to": c, "data": data(&calldata("count()", &[]))}, at]),
            ),
        ]);
    }
    all.push(ok(
        rpc,
        "eth_getLogs",
        json!([{"fromBlock": "0x0", "toBlock": "latest"}]),
    ));
    all
}

#[test]
fn a_node_restarted_over_its_chain_store_answers_every_method_as_before() {
    let dir = solo_scratch::Scratch::new("rpc-restart", "store");
    let alice = Wallet::new(1);
    let config = |persisted| solo_node::NodeConfig {
        now_ms: 1_000,
        key: Some(common::node_key()),
        persisted,
        store: solo_node::StoreConfig::Disk(dir.to_path_buf()),
        ..solo_node::NodeConfig::default()
    };
    let genesis = common::genesis(&alice);
    let mut node = solo_node::Node::open(
        &common::kernel_module(),
        &genesis,
        config(std::collections::BTreeMap::default()),
    )
    .unwrap();
    node.start(None).unwrap();
    let mut rpc = Rpc::new(node);
    let mut now = 1_000;
    let counter = created_address(&alice.address, 0);
    let create = Fields {
        nonce: 0,
        to: None,
        value: 0,
        gas_limit: 1_000_000,
        data: &counter_initcode(5),
    };
    mine(&mut rpc, &mut now, &[alice.legacy(&create)]);
    let increment = calldata("increment(uint256)", &[2]);
    let inc = Fields {
        nonce: 1,
        to: Some(counter),
        value: 0,
        gas_limit: 200_000,
        data: &increment,
    };
    mine(&mut rpc, &mut now, &[alice.legacy(&inc)]);
    mine(
        &mut rpc,
        &mut now,
        &[alice.transfer(2, [9; 20], ETHER, 21_000)],
    );
    let before = answers_at_every_height(&mut rpc, &alice, &counter);
    let persisted = rpc.node().persisted();
    let resumed = rpc.node().persisted_driver_state.clone();
    drop(rpc);
    // Reopened over the same directory: the same answer to every question,
    // at every height, before the driver starts and after, with nothing
    // executed again.
    let node =
        solo_node::Node::open(&common::kernel_module(), &genesis, config(persisted)).unwrap();
    let mut rpc = Rpc::new(node);
    assert_eq!(answers_at_every_height(&mut rpc, &alice, &counter), before);
    rpc.node_mut().start(resumed).unwrap();
    assert!(rpc.node().executed.is_empty());
    assert_eq!(answers_at_every_height(&mut rpc, &alice, &counter), before);
}
