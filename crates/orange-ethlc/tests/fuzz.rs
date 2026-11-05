//! Seeded fuzzing of what the bridge from Ethereum decodes from relayers
//! (spec 18): the SSZ light-client containers, delivery calldata, and
//! Merkle-Patricia proofs. Mutated bytes never panic a decoder, whatever
//! one accepts re-encodes to exactly its input, and a proof with any node
//! changed never verifies to another value. See `orange-fuzz` for the long
//! mode.

use std::collections::BTreeMap;

use orange_ethlc::abi::{Delivery, decode_bytes_call, encode_bytes_call};
use orange_ethlc::beacon::{Bootstrap, ExecutionPayloadHeader, LightClientHeader, Update};
use orange_ethlc::inbox::Message;
use orange_ethlc::mpt;
use orange_ethlc::testing::{Account, Chain, EthState, Native, keccak256};
use orange_fuzz::evolve;

/// Committee size of the generated chain: small, so containers are short.
const SIZE: u32 = 8;

fn ssz<T: PartialEq + std::fmt::Debug>(
    name: &str,
    cases: u64,
    seeds: Vec<Vec<u8>>,
    decode: impl Fn(&[u8]) -> Option<T>,
    encode: impl Fn(&T) -> Vec<u8>,
) {
    ssz_with(name, cases, seeds, decode, encode, |_, _| false);
}

/// [`ssz`], where `other(input, encoding)` names the other encodings the
/// spec accepts on purpose.
fn ssz_with<T: PartialEq + std::fmt::Debug>(
    name: &str,
    cases: u64,
    seeds: Vec<Vec<u8>>,
    decode: impl Fn(&[u8]) -> Option<T>,
    encode: impl Fn(&T) -> Vec<u8>,
    other: impl Fn(&[u8], &[u8]) -> bool,
) {
    let accepted = evolve(name, cases, seeds, |bytes| {
        let Some(value) = decode(bytes) else {
            return false;
        };
        let again = encode(&value);
        if again != bytes && other(bytes, &again) {
            assert_eq!(decode(&again).as_ref(), Some(&value));
            return true;
        }
        let at = again.iter().zip(bytes).position(|(a, b)| a != b);
        assert!(
            again == bytes,
            "{name}: input of {} bytes re-encodes to {} bytes, first difference at {at:?}: {:02x?}",
            bytes.len(),
            again.len(),
            &bytes[at.unwrap_or(0).saturating_sub(8)..(at.unwrap_or(0) + 8).min(bytes.len())]
        );
        true
    });
    assert!(accepted > 0, "{name}");
}

#[test]
fn light_client_containers_decode_only_canonical_bytes() {
    let chain = Chain::minimal(SIZE);
    let size = SIZE as usize;
    let finalized = chain.header(16, [3; 32], [4; 32]);
    let with_next = chain.update(40, &finalized, true, 41, 6);
    let without = chain.update(40, &finalized, false, 41, 6);
    let header = chain.header(9, [1; 32], [2; 32]);
    ssz(
        "ethlc-header",
        1_500,
        vec![header.encode()],
        |b| LightClientHeader::decode(b).ok(),
        LightClientHeader::encode,
    );
    ssz(
        "ethlc-execution",
        1_500,
        vec![
            header.execution.encode(),
            ExecutionPayloadHeader::default().encode(),
        ],
        |b| ExecutionPayloadHeader::decode(b).ok(),
        ExecutionPayloadHeader::encode,
    );
    // An update with a zero committee branch does not read its committee
    // field (spec 18 §3), so any bytes there re-encode as zeros.
    let committee = 4 + 48 * size + 48;
    ssz_with(
        "ethlc-update",
        1_500,
        vec![with_next.encode_update(size), without.encode_update(size)],
        |b| Update::decode_update(b, size).ok(),
        |u| u.encode_update(size),
        move |input, encoding| {
            input.len() == encoding.len()
                && input[..4] == encoding[..4]
                && input[committee..] == encoding[committee..]
                && encoding[4..committee].iter().all(|b| *b == 0)
        },
    );
    ssz(
        "ethlc-finality-update",
        1_500,
        vec![without.encode_finality_update()],
        |b| Update::decode_finality_update(b, size).ok(),
        Update::encode_finality_update,
    );
    ssz(
        "ethlc-bootstrap",
        1_000,
        vec![chain.bootstrap(8, [5; 32]).encode()],
        |b| Bootstrap::decode(b, size).ok(),
        Bootstrap::encode,
    );
}

#[test]
fn delivery_calldata_decodes_only_canonical_bytes() {
    let selector = [1, 2, 3, 4];
    let delivery = Delivery {
        anchor: [9; 32],
        message: Message {
            nonce: 3,
            sender: [0x11; 20],
            recipient: [0x22; 20],
            gas_limit: 100_000,
            payload: vec![7; 40],
        },
        account_proof: vec![vec![1; 33], vec![2; 5]],
        storage_proof: vec![vec![], vec![3; 64]],
    };
    let empty = Delivery {
        account_proof: Vec::new(),
        storage_proof: Vec::new(),
        message: Message {
            payload: Vec::new(),
            ..delivery.message.clone()
        },
        ..delivery.clone()
    };
    ssz(
        "ethlc-delivery",
        3_000,
        vec![delivery.encode(selector), empty.encode(selector)],
        |b| Delivery::decode(b).map(|d| (b[..4].to_vec(), d)),
        |(sel, d)| d.encode(sel.as_slice().try_into().unwrap()),
    );
    ssz(
        "ethlc-bytes-call",
        2_000,
        vec![
            encode_bytes_call(selector, &[]),
            encode_bytes_call(selector, &[5; 70]),
        ],
        |b| decode_bytes_call(b).map(|data| (b[..4].to_vec(), data)),
        |(sel, data)| encode_bytes_call(sel.as_slice().try_into().unwrap(), data),
    );
}

#[test]
fn forged_patricia_proofs_never_verify_to_another_value() {
    let mut state = EthState {
        accounts: BTreeMap::new(),
    };
    for i in 0..24u8 {
        let mut account = Account {
            nonce: u64::from(i),
            balance: u128::from(i) * 1_000,
            ..Account::default()
        };
        for s in 0..i % 5 {
            account.storage.insert([s; 32], [i ^ s; 32]);
        }
        state.accounts.insert([i; 20], account);
    }
    let root = state.root();
    let c = Native;
    orange_fuzz::run("ethlc-mpt-forgery", 400, |r| {
        let address = [u8::try_from(r.below(30)).unwrap(); 20];
        let present = state.accounts.contains_key(&address);
        let key = keccak256(&address);
        let honest = if present {
            state.proof(&address, &[0; 32]).0
        } else {
            state.proof(&[0; 20], &[0; 32]).0
        };
        let truth = mpt::verify(&c, &root, &key, &honest);
        if present {
            assert!(matches!(truth, Ok(Some(_))));
        }
        let mut forged = honest.clone();
        match r.below(4) {
            0 => {
                let i = r.index(forged.len());
                forged[i] = r.mutate(&forged[i]);
            }
            1 => {
                forged.pop();
            }
            2 => forged.push(r.bytes(40)),
            _ => {
                let i = r.index(forged.len());
                let dup = forged[i].clone();
                forged.insert(i, dup);
            }
        }
        if forged != honest
            && let Ok(answer) = mpt::verify(&c, &root, &key, &forged)
        {
            assert_eq!(
                Ok(answer),
                truth,
                "a forged proof verified to another value"
            );
        }
    });
}
