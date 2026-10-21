//! Block headers, receipts and Merkle-Patricia roots against independent
//! implementations: alloy's header encoding and hash, alloy's receipt
//! envelopes and `alloy-trie`'s ordered roots, and a mainnet block.

use alloy_consensus::{Eip658Value, Header as AlloyHeader, Receipt as AlloyReceipt, ReceiptEnvelope, ReceiptWithBloom};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B64, B256, Bloom, Bytes, Log as AlloyLog, LogData, U256};
use solo_abi::chain::{BlockHeader, Log, Receipt};
use solo_abi::codec::Seq;
use solo_eth::header::{EMPTY_OMMERS_HASH, EMPTY_REQUESTS_HASH, Header, accrue, block_hash, receipt_bloom, receipt_envelope};
use solo_eth::mpt::{EMPTY_ROOT, ordered_root};
use tiny_keccak::{Hasher, Keccak};

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(data);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

fn sha256_empty() -> [u8; 32] {
    use k256::sha2::{Digest, Sha256};
    Sha256::digest([]).into()
}

fn alloy_header(header: &Header) -> AlloyHeader {
    AlloyHeader {
        parent_hash: B256::from(header.parent_hash),
        ommers_hash: B256::from(header.ommers_hash),
        beneficiary: Address::from(header.beneficiary),
        state_root: B256::from(header.state_root),
        transactions_root: B256::from(header.transactions_root),
        receipts_root: B256::from(header.receipts_root),
        logs_bloom: Bloom::from(header.logs_bloom),
        difficulty: U256::from(header.difficulty),
        number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data: Bytes::from(header.extra_data.clone()),
        mix_hash: B256::from(header.mix_hash),
        nonce: B64::from(header.nonce),
        base_fee_per_gas: Some(header.base_fee_per_gas),
        withdrawals_root: Some(B256::from(header.withdrawals_root)),
        blob_gas_used: Some(header.blob_gas_used),
        excess_blob_gas: Some(header.excess_blob_gas),
        parent_beacon_block_root: Some(B256::from(header.parent_beacon_block_root)),
        requests_hash: Some(B256::from(header.requests_hash)),
        ..AlloyHeader::default()
    }
}

#[test]
fn constants_are_the_hashes_they_name() {
    assert_eq!(keccak(&[0xC0]), EMPTY_OMMERS_HASH);
    assert_eq!(sha256_empty(), EMPTY_REQUESTS_HASH);
}

#[test]
fn solo_header_matches_alloy() {
    let block = BlockHeader {
        height: 77,
        parent_hash: [1; 32],
        timestamp_ms: 1_760_000_123_456,
        state_root: [2; 32],
        receipts_root: [3; 32],
        tx_hashes: Seq(vec![[4; 32]]),
        gas_used: 42_000,
        transactions_root: [5; 32],
        logs_bloom: vec![6; 256],
        gas_limit: 30_000_000,
        base_fee: 7,
        beneficiary: [8; 20],
    };
    let header = Header::of(&block);
    assert_eq!(header.timestamp, 1_760_000_123);
    assert_eq!(header.number, 77);
    assert_eq!(header.withdrawals_root, EMPTY_ROOT);
    let theirs = alloy_header(&header);
    assert_eq!(block_hash(&block, keccak), theirs.hash_slow().0);
    let mut encoded = Vec::new();
    alloy_rlp::Encodable::encode(&theirs, &mut encoded);
    assert_eq!(header.rlp(), encoded);
    // A record whose bloom is not 256 bytes (a template) has an empty bloom.
    let template = BlockHeader { logs_bloom: Vec::new(), ..block };
    assert_eq!(Header::of(&template).logs_bloom, [0; 256]);
}

fn hex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn quantity(v: &serde_json::Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn fixed<const N: usize>(v: &serde_json::Value) -> [u8; N] {
    hex(v.as_str().unwrap()).try_into().unwrap()
}

/// Ethereum mainnet block 23 000 003 (2025-07-24, Prague; 89 transactions of
/// every type 0 to 4), committed with its raw transactions and receipts as
/// the JSON-RPC returned them: its header hashes to its hash, and its
/// transactions and receipts roots are the tries built here.
#[test]
fn mainnet_block_hashes_and_roots() {
    let vector: serde_json::Value = serde_json::from_str(include_str!("vectors/mainnet-23000003.json")).unwrap();
    let j = &vector["header"];
    let header = Header {
        parent_hash: fixed(&j["parentHash"]),
        ommers_hash: fixed(&j["sha3Uncles"]),
        beneficiary: fixed(&j["miner"]),
        state_root: fixed(&j["stateRoot"]),
        transactions_root: fixed(&j["transactionsRoot"]),
        receipts_root: fixed(&j["receiptsRoot"]),
        logs_bloom: fixed(&j["logsBloom"]),
        difficulty: u128::from(quantity(&j["difficulty"])),
        number: quantity(&j["number"]),
        gas_limit: quantity(&j["gasLimit"]),
        gas_used: quantity(&j["gasUsed"]),
        timestamp: quantity(&j["timestamp"]),
        extra_data: hex(j["extraData"].as_str().unwrap()),
        mix_hash: fixed(&j["mixHash"]),
        nonce: fixed(&j["nonce"]),
        base_fee_per_gas: quantity(&j["baseFeePerGas"]),
        withdrawals_root: fixed(&j["withdrawalsRoot"]),
        blob_gas_used: quantity(&j["blobGasUsed"]),
        excess_blob_gas: quantity(&j["excessBlobGas"]),
        parent_beacon_block_root: fixed(&j["parentBeaconBlockRoot"]),
        requests_hash: fixed(&j["requestsHash"]),
    };
    assert_eq!(header.number, 23_000_003);
    assert_eq!(header.hash(keccak), fixed::<32>(&j["hash"]));
    assert_eq!(header.ommers_hash, EMPTY_OMMERS_HASH);
    assert_eq!(header.requests_hash, EMPTY_REQUESTS_HASH);
    let raws: Vec<Vec<u8>> = vector["transactions"].as_array().unwrap().iter().map(|t| hex(t.as_str().unwrap())).collect();
    assert_eq!(raws.len(), 89);
    assert_eq!(ordered_root(&raws, keccak), header.transactions_root);
    // Every transaction but the blob ones decodes, set-code ones included.
    let mut set_code = 0;
    for raw in &raws {
        match raw[0] {
            3 => assert_eq!(solo_eth::decode(raw), Err(solo_eth::Error::Unsupported)),
            t => {
                let tx = solo_eth::decode(raw).unwrap();
                assert_eq!(tx.tx_type, if t >= 0x7F { 0 } else { t });
                set_code += usize::from(tx.tx_type == 4);
            }
        }
    }
    assert!(set_code > 0);
    let mut block_bloom = [0u8; 256];
    let receipts: Vec<Vec<u8>> = vector["receipts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let logs = r["logs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| Log { address: fixed(&l["address"]), topics: Seq(l["topics"].as_array().unwrap().iter().map(fixed).collect()), data: hex(l["data"].as_str().unwrap()) })
                .collect();
            let receipt = Receipt {
                tx_type: u8::try_from(quantity(&r["type"])).unwrap(),
                status: u8::try_from(quantity(&r["status"])).unwrap(),
                cumulative_gas_used: quantity(&r["cumulativeGasUsed"]),
                logs: Seq(logs),
                ..Receipt::default()
            };
            let bloom = receipt_bloom(&receipt, keccak);
            accrue(&mut block_bloom, &bloom);
            receipt_envelope(&receipt, &bloom)
        })
        .collect();
    assert_eq!(ordered_root(&receipts, keccak), header.receipts_root);
    assert_eq!(block_bloom, header.logs_bloom);
}

fn log(address: u8, topics: &[u8], data: &[u8]) -> Log {
    Log { address: [address; 20], topics: Seq(topics.iter().map(|t| [*t; 32]).collect()), data: data.to_vec() }
}

fn alloy_receipt(receipt: &Receipt) -> ReceiptEnvelope {
    let logs = receipt
        .logs
        .0
        .iter()
        .map(|l| AlloyLog {
            address: Address::from(l.address),
            data: LogData::new_unchecked(l.topics.0.iter().map(|t| B256::from(*t)).collect(), Bytes::from(l.data.clone())),
        })
        .collect();
    let inner = AlloyReceipt { status: Eip658Value::Eip658(receipt.status == 1), cumulative_gas_used: receipt.cumulative_gas_used, logs };
    let with_bloom = ReceiptWithBloom::from(inner);
    match receipt.tx_type {
        0 => ReceiptEnvelope::Legacy(with_bloom),
        1 => ReceiptEnvelope::Eip2930(with_bloom),
        2 => ReceiptEnvelope::Eip1559(with_bloom),
        _ => ReceiptEnvelope::Eip7702(with_bloom),
    }
}

#[test]
fn receipts_and_their_root_match_alloy() {
    let receipts: Vec<Receipt> = [(0u8, 1u8, 21_000u64, vec![]), (2, 0, 50_000, vec![log(1, &[2], &[3; 40])]), (4, 1, 90_000, vec![log(4, &[], &[]), log(5, &[6, 7, 8], &[9])]), (1, 1, 120_000, vec![])]
        .into_iter()
        .map(|(tx_type, status, cumulative_gas_used, logs)| Receipt { tx_type, status, cumulative_gas_used, logs: Seq(logs), ..Receipt::default() })
        .collect();
    let mut block_bloom = [0u8; 256];
    let mut ours = Vec::new();
    let mut theirs = Vec::new();
    for receipt in &receipts {
        let bloom = receipt_bloom(receipt, keccak);
        let envelope = alloy_receipt(receipt);
        assert_eq!(bloom, envelope.logs_bloom().0.0);
        let encoded = receipt_envelope(receipt, &bloom);
        assert_eq!(encoded, envelope.encoded_2718());
        accrue(&mut block_bloom, &bloom);
        ours.push(encoded);
        theirs.push(envelope);
    }
    assert_eq!(ordered_root(&ours, keccak), alloy_trie::root::ordered_trie_root_with_encoder(&theirs, |r, buf| r.encode_2718(buf)).0);
    let bits: u32 = block_bloom.iter().map(|b| b.count_ones()).sum();
    assert!(bits > 0);
}

#[test]
fn ordered_roots_match_alloy_trie_at_every_size() {
    // Sizes that cross the single-byte keys (0x01..0x7f), the 0x80 key of
    // index 128 and the two-byte keys after it.
    for n in [0usize, 1, 2, 3, 16, 17, 127, 128, 129, 300] {
        let values: Vec<Vec<u8>> = (0..n).map(|i| vec![(i % 251) as u8; 1 + i % 40]).collect();
        let expected = alloy_trie::root::ordered_trie_root_encoded(&values);
        assert_eq!(ordered_root(&values, keccak), expected.0, "{n} items");
    }
}
