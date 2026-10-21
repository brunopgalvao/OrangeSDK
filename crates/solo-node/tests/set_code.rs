//! EIP-7702 set-code transactions end to end (spec 20 §2): across simulated
//! validators an account delegates to a contract and calls itself, runs the
//! contract's code in its own context, and keeps sending as a delegated
//! account; authorizations that name no authority, or the wrong chain, are
//! skipped; the pool holds one transaction of a delegated account at a time;
//! and every node agrees on the headers that record it.

mod support;

use solo_abi::Encode;
use solo_abi::chain::{Allocation, GenesisParams, reason};
use solo_abi::codec::Seq;
use solo_abi::types::Genesis;
use solo_host::hash::keccak256;
use solo_node::mempool::PoolError;
use solo_node::{NodeConfig, Sim, SubmitError};
use solo_rlp::{encode_bytes, encode_list, encode_uint};
use support::{CHAIN_ID, ETHER, SLOT_MS, Wallet, include, keys, v1};

/// `slot0 += 1; slot1 = CALLER; LOG1(topic ADDRESS)`: what the delegated
/// account runs, in its own storage.
const DELEGATE_CODE: [u8; 17] = [
    0x5F, 0x54, 0x60, 0x01, 0x01, 0x5F, 0x55, // slot0 += 1
    0x33, 0x60, 0x01, 0x55, // slot1 = CALLER
    0x30, 0x5F, 0x5F, 0xA1, // LOG1(0, 0, ADDRESS)
    0x00, 0x00,
];
const DELEGATE: [u8; 20] = [0xDE; 20];

fn strip(b: &[u8]) -> Vec<u8> {
    b[b.iter().take_while(|x| **x == 0).count()..].to_vec()
}

/// A signed authorization of `authority` for `address` at `nonce`, as an RLP
/// list item.
fn authorization(authority: &Wallet, chain_id: u64, address: [u8; 20], nonce: u64) -> Vec<u8> {
    signed_authorization(authority, chain_id, address, nonce, None)
}

/// As [`authorization`], its y parity replaced by `parity` when given: a
/// parity other than 0 and 1 names no authority.
fn signed_authorization(
    authority: &Wallet,
    chain_id: u64,
    address: [u8; 20],
    nonce: u64,
    parity: Option<u8>,
) -> Vec<u8> {
    let mut body = Vec::new();
    encode_uint(u128::from(chain_id), &mut body);
    encode_bytes(&address, &mut body);
    encode_uint(u128::from(nonce), &mut body);
    let mut message = vec![0x05];
    encode_list(&body, &mut message);
    let (sig, rid) = authority
        .key
        .sign_prehash_recoverable(&keccak256(&message))
        .unwrap();
    encode_uint(u128::from(parity.unwrap_or(rid.to_byte())), &mut body);
    encode_bytes(&strip(&sig.r().to_bytes()), &mut body);
    encode_bytes(&strip(&sig.s().to_bytes()), &mut body);
    let mut out = Vec::new();
    encode_list(&body, &mut out);
    out
}

/// A set-code transaction of `sender` to `to` carrying the encoded `auths`.
fn set_code_tx(
    sender: &Wallet,
    nonce: u64,
    to: [u8; 20],
    auths: &[Vec<u8>],
    data: &[u8],
) -> Vec<u8> {
    let mut fields = Vec::new();
    for n in [u128::from(CHAIN_ID), u128::from(nonce), 0, 0, 200_000] {
        encode_uint(n, &mut fields);
    }
    encode_bytes(&to, &mut fields);
    encode_uint(0, &mut fields);
    encode_bytes(data, &mut fields);
    encode_list(&[], &mut fields);
    encode_list(&auths.concat(), &mut fields);
    let mut unsigned = vec![0x04];
    encode_list(&fields, &mut unsigned);
    let (sig, rid) = sender
        .key
        .sign_prehash_recoverable(&keccak256(&unsigned))
        .unwrap();
    encode_uint(u128::from(rid.to_byte()), &mut fields);
    encode_bytes(&strip(&sig.r().to_bytes()), &mut fields);
    encode_bytes(&strip(&sig.s().to_bytes()), &mut fields);
    let mut out = vec![0x04];
    encode_list(&fields, &mut out);
    out
}

fn designator(address: [u8; 20]) -> Vec<u8> {
    [&[0xEF, 0x01, 0x00][..], &address].concat()
}

fn word(n: u8) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[31] = n;
    w
}

fn address_word(address: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(address);
    w
}

fn genesis(validators: &[k256::ecdsa::SigningKey], funded: &[[u8; 20]]) -> Genesis {
    let mut allocations: Vec<Allocation> = funded
        .iter()
        .map(|a| Allocation {
            address: *a,
            balance: 100 * ETHER,
            ..Allocation::default()
        })
        .collect();
    allocations.push(Allocation {
        address: DELEGATE,
        code: DELEGATE_CODE.to_vec(),
        nonce: 1,
        ..Allocation::default()
    });
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 100,
        allocations: Seq(allocations),
        ..GenesisParams::default()
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: Sim::validator_set(validators).to_bytes(),
    }
}

#[test]
fn an_account_delegates_and_calls_itself_across_validators() {
    let alice = Wallet::new(0x71);
    let bob = Wallet::new(0x72);
    let carol = Wallet::new(0x73);
    let validators = keys(3);
    let genesis = genesis(&validators, &[alice.address]);
    let template = NodeConfig {
        now_ms: 1_000,
        ..NodeConfig::default()
    };
    let mut sim = Sim::new(v1(), &genesis, &validators, 1, &template, 20).unwrap();
    // Alice authorizes the delegate for herself (at her nonce after this
    // transaction's), Bob for himself, Carol for another chain, and Dave
    // with a parity that names no authority; then calls herself.
    let dave = Wallet::new(0x76);
    let auths = [
        authorization(&alice, CHAIN_ID, DELEGATE, 1),
        authorization(&bob, 0, DELEGATE, 0),
        authorization(&carol, CHAIN_ID + 1, DELEGATE, 0),
        signed_authorization(&dave, CHAIN_ID, DELEGATE, 0, Some(2)),
    ];
    let first = set_code_tx(&alice, 0, alice.address, &auths, &[]);
    let hash = sim.submit(0, &first).unwrap();
    assert!(
        sim.run_until(60 * SLOT_MS, |s| s
            .nodes
            .iter_mut()
            .all(|n| n.receipt(&hash).unwrap().is_some()))
            .unwrap()
    );
    let observer = sim.nodes.len() - 1;
    let node = &mut sim.nodes[observer];
    let receipt = node.receipt(&hash).unwrap().unwrap();
    assert_eq!((receipt.status, receipt.tx_type), (1, 4));
    // The delegate's code ran in Alice's context, Alice its caller.
    assert_eq!(receipt.logs.0.len(), 1);
    assert_eq!(receipt.logs.0[0].address, alice.address);
    assert_eq!(
        receipt.logs.0[0].topics.0,
        vec![address_word(&alice.address)]
    );
    assert_eq!(node.code(&alice.address).unwrap(), designator(DELEGATE));
    assert_eq!(node.code(&bob.address).unwrap(), designator(DELEGATE));
    assert!(
        node.code(&carol.address).unwrap().is_empty(),
        "another chain's authorization is skipped"
    );
    assert!(
        node.code(&dave.address).unwrap().is_empty(),
        "an authorization that names no authority is skipped"
    );
    assert_eq!(node.account(&dave.address).unwrap().nonce, 0);
    assert_eq!(node.storage(&alice.address, &word(0)).unwrap(), word(1));
    assert_eq!(
        node.storage(&alice.address, &word(1)).unwrap(),
        address_word(&alice.address)
    );
    // Her nonce moved for the transaction and for her authorization; Bob's for his.
    assert_eq!(node.account(&alice.address).unwrap().nonce, 2);
    assert_eq!(node.account(&bob.address).unwrap().nonce, 1);
    // Intrinsic gas: 21 000 plus 25 000 for each of the four authorizations,
    // skipped ones included. The delegate's code: a cold SLOAD (2 100), an
    // SSTORE from zero to the slot it warmed (20 000), one to a cold slot
    // (22 100), LOG1 with no data (750) and 21 for its pushes, ADD, CALLER
    // and ADDRESS. Less a refund of 12 500 for each authority that existed:
    // Alice; Bob had no account, Carol and Dave were skipped.
    let code = 2_100 + 20_000 + 22_100 + 750 + 21;
    assert_eq!(receipt.gas_used, 21_000 + 4 * 25_000 + code - 12_500);
    // A delegated account still sends (EIP-3607 allows a designator), and a
    // call to it runs the delegate again.
    let again = alice.tx(2, alice.address, 0, 100_000, &[]);
    let hash = sim.submit(1, &again).unwrap();
    assert!(
        sim.run_until(60 * SLOT_MS, |s| s
            .nodes
            .iter_mut()
            .all(|n| n.receipt(&hash).unwrap().is_some()))
            .unwrap()
    );
    let node = &mut sim.nodes[observer];
    assert_eq!(node.receipt(&hash).unwrap().unwrap().status, 1);
    assert_eq!(node.storage(&alice.address, &word(0)).unwrap(), word(2));
    // Calling Bob runs the delegate in Bob's storage, Alice the caller.
    let call_bob = alice.tx(3, bob.address, 0, 100_000, &[]);
    let hash = sim.submit(2, &call_bob).unwrap();
    assert!(
        sim.run_until(60 * SLOT_MS, |s| s
            .nodes
            .iter_mut()
            .all(|n| n.receipt(&hash).unwrap().is_some()))
            .unwrap()
    );
    let node = &mut sim.nodes[observer];
    assert_eq!(
        node.storage(&bob.address, &word(1)).unwrap(),
        address_word(&alice.address)
    );
    // Every node recorded the same blocks, under the same Ethereum hashes.
    let height = node.block_number().unwrap();
    let hashes: Vec<_> = sim
        .nodes
        .iter_mut()
        .map(|n| {
            let header = n.block_by_number(height).unwrap().unwrap();
            solo_eth::header::block_hash(&header, keccak256)
        })
        .collect();
    assert!(hashes.iter().all(|h| *h == hashes[0]));
    let executed = sim.nodes[0]
        .executed
        .iter()
        .find(|(h, _)| *h == height)
        .unwrap()
        .1;
    assert_eq!(executed, hashes[0]);
}

#[test]
fn a_delegated_account_may_have_one_transaction_in_the_pool() {
    let alice = Wallet::new(0x74);
    let bob = Wallet::new(0x75);
    let validators = keys(1);
    let genesis = genesis(&validators, &[alice.address, bob.address]);
    let mut node = solo_node::Node::open(
        v1(),
        &genesis,
        NodeConfig {
            key: Some(validators[0].clone()),
            now_ms: 1_000,
            ..NodeConfig::default()
        },
    )
    .unwrap();
    node.start(None).unwrap();
    // Before delegating, Alice may queue several.
    assert!(
        node.submit(&alice.tx(0, bob.address, 1, 21_000, &[]))
            .is_ok()
    );
    assert!(
        node.submit(&alice.tx(1, bob.address, 1, 21_000, &[]))
            .is_ok()
    );
    let receipt = include(&mut node, &alice.tx(2, bob.address, 1, 21_000, &[]));
    assert_eq!(receipt.status, 1);
    // A set-code transaction naming Bob as authority while Bob has two
    // transactions waiting is refused; with one waiting it is admitted.
    assert!(
        node.submit(&bob.tx(0, alice.address, 1, 21_000, &[]))
            .is_ok()
    );
    assert!(
        node.submit(&bob.tx(5, alice.address, 1, 21_000, &[]))
            .is_ok()
    );
    let delegate_bob = set_code_tx(
        &alice,
        3,
        alice.address,
        &[authorization(&bob, CHAIN_ID, DELEGATE, 1)],
        &[],
    );
    assert_eq!(
        node.submit(&delegate_bob),
        Err(SubmitError::Pool(PoolError::AuthorityReserved))
    );
    // Alice delegates herself.
    let receipt = include(
        &mut node,
        &set_code_tx(
            &alice,
            3,
            alice.address,
            &[authorization(&alice, CHAIN_ID, DELEGATE, 4)],
            &[],
        ),
    );
    assert_eq!(receipt.status, 1);
    assert_eq!(node.code(&alice.address).unwrap(), designator(DELEGATE));
    // Now one in flight at a time; a replacement of it is still allowed.
    let one = alice.tx(5, bob.address, 1, 21_000, &[]);
    assert!(node.submit(&one).is_ok());
    assert_eq!(
        node.submit(&alice.tx(6, bob.address, 1, 21_000, &[])),
        Err(SubmitError::Pool(PoolError::InflightLimit))
    );
    assert_eq!(
        PoolError::InflightLimit.to_string(),
        "in-flight transaction limit reached for delegated accounts"
    );
    assert_eq!(
        PoolError::AuthorityReserved.to_string(),
        "authority already reserved"
    );
    // A set-code transaction that does not decode is refused for it.
    assert_eq!(
        node.submit(&[0x04, 0xC0]),
        Err(SubmitError::Rejected(reason::MALFORMED))
    );
}
