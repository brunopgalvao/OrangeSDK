//! Seeded differential fuzzing of transaction decoding against alloy:
//! signed transactions of every accepted type, mutated byte by byte and
//! field by field (a well-formed RLP tree with one leaf or list changed),
//! never panic the decoder; every transaction it accepts, alloy accepts with
//! the same fields and the same signature hash; and every one alloy accepts
//! that it refuses is refused for a documented reason. See `solo-fuzz` for
//! the long mode.

use alloy_consensus::{
    SignableTransaction, Transaction, TxEip1559, TxEip2930, TxEip7702, TxEnvelope, TxLegacy,
};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_eips::eip2930::{AccessList, AccessListItem};
use alloy_eips::eip7702::Authorization as AlloyAuthorization;
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256};
use solo_eth::{Error, decode};
use solo_fuzz::{Rng, evolve};
use solo_rlp::{Item, encode_bytes, encode_item, encode_list};
use tiny_keccak::{Hasher, Keccak};

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(data);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// A fixed low-`s` signature: decoding does not recover, so any valid
/// values do.
fn signature(parity: bool) -> Signature {
    Signature::new(U256::from(0x1234_5678u64), U256::from(0x9ABCu64), parity)
}

fn access_list() -> AccessList {
    AccessList(vec![AccessListItem {
        address: Address::from([0x55; 20]),
        storage_keys: vec![B256::from([1; 32]), B256::from([2; 32])],
    }])
}

/// One transaction of every accepted type, as `eth_sendRawTransaction`
/// carries it.
fn seeds() -> Vec<Vec<u8>> {
    let to = TxKind::Call(Address::from([0x44; 20]));
    let input = Bytes::from(vec![0, 1, 2, 3, 0xFF]);
    let legacy = |chain_id| TxLegacy {
        chain_id,
        nonce: 7,
        gas_price: 1_000_000_007,
        gas_limit: 21_000,
        to,
        value: U256::from(99),
        input: input.clone(),
    };
    let auth = AlloyAuthorization {
        chain_id: U256::from(1337),
        address: Address::from([0xAA; 20]),
        nonce: 5,
    }
    .into_signed(signature(true));
    vec![
        legacy(Some(1337))
            .into_signed(signature(false))
            .encoded_2718(),
        legacy(None).into_signed(signature(true)).encoded_2718(),
        TxLegacy {
            to: TxKind::Create,
            ..legacy(Some(1))
        }
        .into_signed(signature(false))
        .encoded_2718(),
        TxEip2930 {
            chain_id: 1337,
            nonce: 1,
            gas_price: 5,
            gas_limit: 50_000,
            to,
            value: U256::from(1),
            access_list: access_list(),
            input: input.clone(),
        }
        .into_signed(signature(true))
        .encoded_2718(),
        TxEip1559 {
            chain_id: 1337,
            nonce: 2,
            gas_limit: 60_000,
            max_fee_per_gas: 30,
            max_priority_fee_per_gas: 2,
            to: TxKind::Create,
            value: U256::ZERO,
            access_list: AccessList::default(),
            input: input.clone(),
        }
        .into_signed(signature(false))
        .encoded_2718(),
        TxEip7702 {
            chain_id: 1337,
            nonce: 3,
            gas_limit: 100_000,
            max_fee_per_gas: 30,
            max_priority_fee_per_gas: 2,
            to: Address::from([0x44; 20]),
            value: U256::from(9),
            access_list: access_list(),
            authorization_list: vec![auth.clone(), auth],
            input,
        }
        .into_signed(signature(true))
        .encoded_2718(),
    ]
}

/// A leaf replaced, or a list item dropped, duplicated or wrapped.
fn mutate_tree(r: &mut Rng, item: &mut Item<'static>) {
    match item {
        Item::List(items) if !items.is_empty() && r.chance(3, 4) => {
            let i = r.index(items.len());
            match r.below(6) {
                0 => {
                    items.remove(i);
                }
                1 => {
                    let copy = items[i].clone();
                    items.insert(i, copy);
                }
                2 => items[i] = Item::List(vec![items[i].clone()]),
                _ => mutate_tree(r, &mut items[i]),
            }
        }
        _ => {
            let leaf: &'static [u8] = match r.below(9) {
                0 => &[],
                1 => &[0],
                2 => &[0, 1],
                3 => &[0x7F],
                4 => &[0x80],
                5 => &[0xFF; 20],
                6 => &[0xFF; 32],
                7 => &[1; 33],
                _ => &[0xFF; 17],
            };
            *item = if r.chance(1, 8) {
                Item::List(Vec::new())
            } else {
                Item::Bytes(leaf)
            };
        }
    }
}

/// `raw` with one field changed, the RLP kept well formed.
fn mutate_fields(r: &mut Rng, raw: &[u8]) -> Vec<u8> {
    let (prefix, body) = match raw.first() {
        Some(t) if *t < 0x80 => (Some(*t), &raw[1..]),
        _ => (None, raw),
    };
    // The tree borrows the input; leak a copy so it outlives this call (the
    // test process is short-lived and the inputs are small).
    let body: &'static [u8] = Box::leak(body.to_vec().into_boxed_slice());
    let Ok(mut item) = solo_rlp::decode(body) else {
        return r.mutate(raw);
    };
    mutate_tree(r, &mut item);
    let mut out: Vec<u8> = prefix.into_iter().collect();
    encode_item(&item, &mut out);
    out
}

fn alloy(raw: &[u8]) -> Option<TxEnvelope> {
    let mut buf = raw;
    let env = TxEnvelope::decode_2718(&mut buf).ok()?;
    buf.is_empty().then_some(env)
}

/// Why alloy may take a transaction this decoder refuses (spec 20 §2):
/// a blob or unknown type, a signature with `r` or `s` zero or `s` high or
/// a legacy `v` that is neither 27, 28 nor EIP-155, and amounts above what
/// a `u128` holds. And alloy reads some bytes that are not the canonical
/// EIP-2718 encoding of what it decodes (a first byte of `0x80..=0xBF`, which
/// is neither a type nor a list prefix, as a type byte; a list prefix before
/// a typed transaction), which this decoder refuses as malformed.
fn documented_refusal(raw: &[u8], err: Error, theirs: &TxEnvelope) -> bool {
    if err == Error::Malformed && theirs.encoded_2718() != raw {
        return true;
    }
    let sig = theirs.signature();
    // Half the secp256k1 group order.
    let half = U256::from_be_slice(&[
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B,
        0x20, 0xA0,
    ]);
    match err {
        Error::Unsupported => theirs.is_eip4844(),
        Error::BadSignature => sig.r().is_zero() || sig.s().is_zero() || sig.s() > half,
        Error::Malformed => {
            theirs.value() > U256::from(u128::MAX)
                || (theirs.is_eip7702() && theirs.authorization_list().is_some_and(<[_]>::is_empty))
        }
    }
}

fn agree(raw: &[u8]) -> bool {
    let ours = decode(raw);
    let theirs = alloy(raw);
    match (&ours, &theirs) {
        (Ok(tx), Some(env)) => {
            assert_eq!(tx.nonce, env.nonce());
            assert_eq!(tx.gas_limit, env.gas_limit());
            assert_eq!(U256::from(tx.value), env.value());
            assert_eq!(tx.input, env.input().to_vec());
            assert_eq!(tx.to, env.to().map(|a| a.0.0));
            assert_eq!(tx.chain_id, env.chain_id());
            assert_eq!(tx.tx_type, u8::from(env.tx_type()));
            assert_eq!(keccak(&tx.signing_payload), env.signature_hash().0);
            assert_eq!(
                tx.access_list.len(),
                env.access_list().map_or(0, |l| l.0.len())
            );
            true
        }
        (Ok(tx), None) => panic!("only this decoder accepts {raw:02x?}: {tx:?}"),
        (Err(e), Some(env)) => {
            assert!(
                documented_refusal(raw, *e, env),
                "{e:?} refuses what alloy takes: {raw:02x?} {env:?}"
            );
            false
        }
        (Err(_), None) => false,
    }
}

#[test]
fn every_seed_decodes_the_same_on_both_sides() {
    for raw in seeds() {
        assert!(agree(&raw), "{raw:02x?}");
    }
}

#[test]
fn mutated_transaction_bytes_decode_as_alloy_decodes_them() {
    let accepted = evolve("eth-tx-bytes", 1_500, seeds(), agree);
    assert!(accepted > 100, "{accepted}");
}

#[test]
fn mutated_transaction_fields_decode_as_alloy_decodes_them() {
    let seeds = seeds();
    let mut accepted = 0u32;
    solo_fuzz::run("eth-tx-tree", 1_500, |r| {
        let mut raw = r.pick(&seeds).clone();
        for _ in 0..=r.below(3) {
            raw = mutate_fields(r, &raw);
        }
        accepted += u32::from(agree(&raw));
    });
    assert!(accepted > 50, "{accepted}");
    // A leaf of a list nested past the limit is refused, not a crash.
    let mut deep = Vec::new();
    encode_bytes(&[1], &mut deep);
    for _ in 0..40_000 {
        let mut out = Vec::new();
        encode_list(&deep, &mut out);
        deep = out;
    }
    assert_eq!(decode(&[&[2u8][..], &deep].concat()), Err(Error::Malformed));
}
