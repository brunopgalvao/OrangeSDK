//! A single node running the reference kernel end to end: genesis, signed
//! Ethereum legacy transfers through the mempool, blocks per slot,
//! receipts, queries, rejection reasons, and restart from persisted state.

use k256::ecdsa::SigningKey;
use solo_abi::Encode;
use solo_abi::chain::consensus::{propose_timer, timeout_timer};
use solo_abi::chain::{Allocation, GenesisParams, reason};
use solo_abi::codec::Seq;
use solo_abi::types::Genesis;
use solo_host::hash::keccak256;
use solo_node::{Node, NodeConfig, Sim, SubmitError};
use solo_recompile::{Input, Options, recompile};
use solo_rlp::{encode_bytes, encode_list, encode_uint};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 400;
const ETHER: u128 = 1_000_000_000_000_000_000;

fn kernel_module() -> Vec<u8> {
    recompile(&Input::load(KERNEL).unwrap(), &Options::default()).unwrap()
}

struct Wallet {
    key: SigningKey,
    address: [u8; 20],
}

impl Wallet {
    fn new(seed: u8) -> Wallet {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let digest = keccak256(&point.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&digest[12..]);
        Wallet { key, address }
    }

    /// An EIP-155 legacy transfer. `chain_id` of `None` signs pre-155 (v = 27/28).
    #[allow(clippy::too_many_arguments)]
    fn transfer(
        &self,
        nonce: u64,
        to: [u8; 20],
        value: u128,
        gas_price: u128,
        gas_limit: u64,
        chain_id: Option<u64>,
        data: &[u8],
    ) -> Vec<u8> {
        let fields = |out: &mut Vec<u8>| {
            encode_uint(u128::from(nonce), out);
            encode_uint(gas_price, out);
            encode_uint(u128::from(gas_limit), out);
            encode_bytes(&to, out);
            encode_uint(value, out);
            encode_bytes(data, out);
        };
        let mut unsigned = Vec::new();
        fields(&mut unsigned);
        if let Some(id) = chain_id {
            encode_uint(u128::from(id), &mut unsigned);
            encode_uint(0, &mut unsigned);
            encode_uint(0, &mut unsigned);
        }
        let mut list = Vec::new();
        encode_list(&unsigned, &mut list);
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(&keccak256(&list))
            .unwrap();
        let v = match chain_id {
            Some(id) => id * 2 + 35 + u64::from(rid.to_byte()),
            None => 27 + u64::from(rid.to_byte()),
        };
        let mut signed = Vec::new();
        fields(&mut signed);
        encode_uint(u128::from(v), &mut signed);
        let r = sig.r().to_bytes();
        let s = sig.s().to_bytes();
        encode_bytes(strip(&r), &mut signed);
        encode_bytes(strip(&s), &mut signed);
        let mut out = Vec::new();
        encode_list(&signed, &mut out);
        out
    }
}

fn strip(b: &[u8]) -> &[u8] {
    let skip = b.iter().take_while(|x| **x == 0).count();
    &b[skip..]
}

fn genesis(alice: &Wallet) -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        allocations: Seq(vec![Allocation {
            address: alice.address,
            balance: 100 * ETHER,
        }]),
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: Sim::validator_set(&[node_key()]).to_bytes(),
    }
}

/// The node's consensus key: the single validator of these chains.
fn node_key() -> SigningKey {
    SigningKey::from_slice(&[0x42; 32]).unwrap()
}

/// A validator node started at `now_ms`, resuming `state` if given.
fn node_at(alice: &Wallet, now_ms: u64, state: Option<Vec<u8>>) -> Node {
    let config = NodeConfig {
        now_ms,
        key: Some(node_key()),
        ..NodeConfig::default()
    };
    let mut node =
        Node::open(&kernel_module(), &genesis(alice), config).expect("kernel loads and inits");
    node.start(state).unwrap();
    node
}

fn node(alice: &Wallet) -> Node {
    node_at(alice, 1_000, None)
}

#[test]
fn genesis_state_and_queries() {
    let alice = Wallet::new(1);
    let mut node = node(&alice);
    assert_eq!(node.chain_id().unwrap(), CHAIN_ID);
    assert_eq!(node.block_number().unwrap(), 0);
    assert_eq!(node.finalized_height().unwrap(), 0);
    assert_eq!(node.account(&alice.address).unwrap().balance, 100 * ETHER);
    assert_eq!(node.account(&[9; 20]).unwrap().balance, 0);
    assert!(node.block_by_number(1).unwrap().is_none());
    assert!(node.block_by_hash(&[0; 32]).unwrap().is_none());
    assert!(node.receipt(&[0; 32]).unwrap().is_none());
    assert!(node.transaction(&[0; 32]).unwrap().is_none());
    assert_eq!(node.query("no_such_method", &[]).unwrap().status, 3);
    assert_eq!(node.query("account", &[1, 2]).unwrap().status, 2);
    // Started armed the view timeout and the leader's proposal time, one slot out.
    assert_eq!(
        node.timers(),
        vec![
            (timeout_timer(1), 1_000 + 3 * SLOT_MS),
            (propose_timer(1), 1_000 + SLOT_MS)
        ]
    );
    assert!(node.persisted_driver_state.is_some());
    assert!(node.mempool().is_empty());
    assert!(node.logs().is_empty());
    assert!(node.take_outbound().is_empty());
    assert_eq!(
        node.validator_id(),
        Some(solo_node::validator_id(&node_key()))
    );
    assert_eq!(node.now_ms(), 1_000);
}

#[test]
fn transfers_make_blocks() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut node = node(&alice);
    let gas_price = 1_000_000_000u128;
    let raw = alice.transfer(
        0,
        bob.address,
        5 * ETHER,
        gas_price,
        21_000,
        Some(CHAIN_ID),
        &[],
    );
    let hash = node.submit(&raw).expect("admitted");
    assert_eq!(hash, keccak256(&raw));
    assert_eq!(node.mempool().len(), 1);
    assert_eq!(
        node.submit(&raw).unwrap(),
        hash,
        "resubmitting is idempotent"
    );
    assert_eq!(node.mempool().len(), 1);
    // Nothing happens before the slot timer.
    node.tick(1_200).unwrap();
    assert_eq!(node.block_number().unwrap(), 0);
    // The slot fires: take mempool, execute, finalize, re-arm.
    node.tick(1_000 + SLOT_MS).unwrap();
    assert_eq!(node.block_number().unwrap(), 1);
    assert_eq!(node.finalized_height().unwrap(), 1);
    assert_eq!(node.executed.len(), 1);
    assert_eq!(node.finalized, vec![1]);
    assert!(node.mempool().is_empty());
    assert_eq!(
        node.timers(),
        vec![
            (timeout_timer(2), 1_000 + 4 * SLOT_MS),
            (propose_timer(2), 1_000 + 2 * SLOT_MS)
        ]
    );
    assert_eq!(node.metrics, vec![(b"blocks".to_vec(), 1)]);
    // The single validator proposed, voted, and finalized on its own.
    let outbound = node.take_outbound();
    assert_eq!(outbound.len(), 3, "{outbound:?}");
    let fee = 21_000 * gas_price;
    assert_eq!(node.account(&bob.address).unwrap().balance, 5 * ETHER);
    let a = node.account(&alice.address).unwrap();
    assert_eq!(a.balance, 100 * ETHER - 5 * ETHER - fee);
    assert_eq!(a.nonce, 1);
    let header = node.block_by_number(1).unwrap().expect("block 1");
    assert_eq!(header.height, 1);
    assert_eq!(header.parent_hash, [0; 32]);
    assert_eq!(header.timestamp_ms, 1_000 + SLOT_MS);
    assert_eq!(header.tx_hashes.0, vec![hash]);
    assert_eq!(header.gas_used, 21_000);
    assert_ne!(header.state_root, [0; 32]);
    let block_hash = node.executed[0].1;
    assert_eq!(block_hash, keccak256(&header.to_bytes()));
    assert_eq!(node.block_by_hash(&block_hash).unwrap(), Some(header));
    let receipt = node.receipt(&hash).unwrap().expect("receipt");
    assert_eq!(receipt.status, 1);
    assert_eq!(receipt.from, alice.address);
    assert_eq!(receipt.to, bob.address);
    assert_eq!(receipt.value, 5 * ETHER);
    assert_eq!((receipt.height, receipt.index), (1, 0));
    assert_eq!(node.transaction(&hash).unwrap(), Some(raw));
    // An empty slot still produces an empty block linked to the previous one.
    node.tick(1_000 + 2 * SLOT_MS).unwrap();
    let header2 = node.block_by_number(2).unwrap().unwrap();
    assert_eq!(header2.parent_hash, block_hash);
    assert!(header2.tx_hashes.0.is_empty());
    assert_eq!(node.block_number().unwrap(), 2);
    // Bob pays Alice back with a pre-EIP-155 signature and a higher gas limit; priority ordering holds.
    let raw2 = bob.transfer(0, alice.address, ETHER, gas_price, 50_000, None, &[]);
    let raw3 = alice.transfer(
        1,
        bob.address,
        ETHER,
        2 * gas_price,
        21_000,
        Some(CHAIN_ID),
        &[],
    );
    node.submit(&raw2).unwrap();
    node.submit(&raw3).unwrap();
    node.tick(1_000 + 3 * SLOT_MS).unwrap();
    let header3 = node.block_by_number(3).unwrap().unwrap();
    assert_eq!(
        header3.tx_hashes.0,
        vec![keccak256(&raw3), keccak256(&raw2)],
        "higher gas price first"
    );
    assert_eq!(
        node.account(&bob.address).unwrap().balance,
        5 * ETHER - ETHER - fee + ETHER
    );
    assert_eq!(node.account(&bob.address).unwrap().nonce, 1);
}

#[test]
fn rejections() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let poor = Wallet::new(3);
    let mut node = node(&alice);
    let gp = 1_000_000_000u128;
    let cases: Vec<(Vec<u8>, u32)> = vec![
        (
            alice.transfer(1, bob.address, ETHER, gp, 21_000, Some(CHAIN_ID), &[]),
            reason::BAD_NONCE,
        ),
        (
            poor.transfer(0, bob.address, ETHER, gp, 21_000, Some(CHAIN_ID), &[]),
            reason::INSUFFICIENT_FUNDS,
        ),
        (
            alice.transfer(0, bob.address, ETHER, gp, 20_999, Some(CHAIN_ID), &[]),
            reason::GAS_TOO_LOW,
        ),
        (
            alice.transfer(0, bob.address, ETHER, gp, 21_000, Some(CHAIN_ID + 1), &[]),
            reason::WRONG_CHAIN,
        ),
        (
            alice.transfer(0, bob.address, ETHER, gp, 21_000, Some(CHAIN_ID), &[1]),
            reason::UNSUPPORTED,
        ),
        (
            alice.transfer(
                0,
                bob.address,
                1_000 * ETHER,
                gp,
                21_000,
                Some(CHAIN_ID),
                &[],
            ),
            reason::INSUFFICIENT_FUNDS,
        ),
        (vec![0xC0], reason::MALFORMED),
        (b"garbage".to_vec(), reason::MALFORMED),
    ];
    for (raw, expected) in cases {
        assert_eq!(node.submit(&raw), Err(SubmitError::Rejected(expected)));
    }
    // A tampered signature fails recovery or recovers a stranger with no funds.
    let mut raw = alice.transfer(0, bob.address, ETHER, gp, 21_000, Some(CHAIN_ID), &[]);
    let n = raw.len();
    raw[n - 1] ^= 1;
    assert!(
        matches!(node.submit(&raw), Err(SubmitError::Rejected(r)) if r == reason::BAD_SIGNATURE || r == reason::INSUFFICIENT_FUNDS)
    );
    // A bad v value.
    let mut fields = Vec::new();
    for _ in 0..6 {
        encode_uint(0, &mut fields);
    }
    encode_uint(5, &mut fields);
    encode_bytes(&[1; 32], &mut fields);
    encode_bytes(&[1; 32], &mut fields);
    let mut list = Vec::new();
    encode_list(&fields, &mut list);
    assert_eq!(
        node.submit(&list),
        Err(SubmitError::Rejected(reason::UNSUPPORTED)),
        "zero-length recipient"
    );
    assert!(node.mempool().is_empty());
    assert_eq!(node.block_number().unwrap(), 0);
    // A block containing a transaction that became invalid gets a failed receipt, not a halt:
    // two transfers that are each admissible alone but only one can pay.
    let whale = Wallet::new(4);
    let mut node2 = Node::new(
        &kernel_module(),
        &{
            let mut g = genesis(&alice);
            let params = GenesisParams {
                slot_ms: SLOT_MS,
                max_txs: 8,
                allocations: Seq(vec![Allocation {
                    address: whale.address,
                    balance: ETHER + 21_000 * gp,
                }]),
            };
            g.params = params.to_bytes();
            g
        },
        1_000,
    )
    .unwrap();
    node2.start(None).unwrap();
    let t1 = whale.transfer(0, bob.address, ETHER, gp, 21_000, Some(CHAIN_ID), &[]);
    let t2 = whale.transfer(1, bob.address, ETHER, gp, 21_000, Some(CHAIN_ID), &[]);
    node2.submit(&t1).unwrap();
    assert_eq!(
        node2.submit(&t2),
        Err(SubmitError::Rejected(reason::BAD_NONCE)),
        "mempool validation is against state"
    );
}

#[test]
fn restart_resumes_from_persisted_state() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut node = node(&alice);
    node.submit(&alice.transfer(0, bob.address, ETHER, 1, 21_000, Some(CHAIN_ID), &[]))
        .unwrap();
    node.tick(1_000 + SLOT_MS).unwrap();
    assert_eq!(node.block_number().unwrap(), 1);
    let state = node.persisted_driver_state.clone().unwrap();
    assert_eq!(node.driver_state().unwrap(), state);
    // A fresh node over the same genesis (state is in memory, so blocks are gone) resumes the
    // driver at height 2; its slot is long overdue, so it proposes on start.
    let mut fresh = node_at(&alice, 5_000, Some(state));
    assert_eq!(fresh.executed.len(), 1);
    assert_eq!(fresh.executed[0].0, 2, "continues at the next height");
    assert_eq!(
        fresh.timers(),
        vec![
            (timeout_timer(3), 5_000 + 3 * SLOT_MS),
            (propose_timer(3), 5_000 + SLOT_MS)
        ]
    );
    fresh.tick(5_000 + SLOT_MS).unwrap();
    assert_eq!(fresh.executed.len(), 2);
    // Garbage persisted state is ignored and the driver starts from scratch.
    let mut again = node_at(&alice, 7_000, Some(vec![1, 2, 3]));
    again.tick(7_000 + SLOT_MS).unwrap();
    assert_eq!(again.executed[0].0, 1);
}

#[test]
fn node_errors() {
    let alice = Wallet::new(1);
    assert!(matches!(
        Node::new(b"not a module", &genesis(&alice), 0),
        Err(solo_node::NodeError::Load(_))
    ));
    // A genesis whose params do not decode makes kernel_init trap.
    let mut bad = genesis(&alice);
    bad.params = vec![0xFF];
    let err = Node::new(&kernel_module(), &bad, 0).err().unwrap();
    assert!(
        matches!(
            err,
            solo_node::NodeError::Kernel {
                export: "kernel_init",
                ..
            }
        ),
        "{err}"
    );
    assert!(err.to_string().contains("kernel_init"));
    // Starving kernel calls of gas turns every call into a kernel error.
    let mut node = node(&alice);
    node.kernel_gas = 0;
    assert!(matches!(
        node.block_number(),
        Err(solo_node::NodeError::Kernel {
            export: "kernel_query",
            ..
        })
    ));
    assert!(
        solo_node::NodeError::Decode("x")
            .to_string()
            .contains("undecodable")
    );
    assert!(
        solo_node::NodeError::Load(solo_host::LoadError::Invalid(
            solo_vm::module::ValidationError::BadMagic
        ))
        .to_string()
        .contains("load")
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn effects_injected_by_hand() {
    use solo_abi::types::Effect;
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut node = node(&alice);
    // Cancelling the view's timers stops block production until re-armed.
    for timer_id in [timeout_timer(1), propose_timer(1)] {
        assert_eq!(
            node.apply_effect(Effect::CancelTimer { timer_id }).unwrap(),
            None
        );
    }
    assert!(node.timers().is_empty());
    node.tick(10_000).unwrap();
    assert_eq!(node.block_number().unwrap(), 0);
    // Two transactions in the pool; a take that fits only one leaves the other.
    let t1 = alice.transfer(0, bob.address, 1, 1, 21_000, Some(CHAIN_ID), &[]);
    let t2 = alice.transfer(0, bob.address, 2, 2, 21_000, Some(CHAIN_ID), &[]);
    let h1 = node.submit(&t1).unwrap();
    let h2 = node.submit(&t2).unwrap();
    assert_eq!(node.mempool().len(), 2);
    let taken = node
        .apply_effect(Effect::MempoolTake {
            max_bytes: u32::try_from(t2.len()).unwrap(),
            max_gas: 0,
        })
        .unwrap();
    assert_eq!(
        taken,
        Some(solo_abi::types::Input::MempoolContents {
            txs: Seq(vec![t2.clone()])
        }),
        "higher priority first"
    );
    assert_eq!(node.mempool().len(), 1);
    assert_eq!(node.mempool()[0].hash, h1);
    // Rejection drops a pending transaction; an unknown hash is a no-op.
    assert_eq!(
        node.apply_effect(Effect::MempoolReject {
            tx_hash: h2,
            reason: 1
        })
        .unwrap(),
        None
    );
    assert_eq!(
        node.apply_effect(Effect::MempoolReject {
            tx_hash: h1,
            reason: 1
        })
        .unwrap(),
        None
    );
    assert!(node.mempool().is_empty());
    // Network effects are queued for the transport.
    assert!(node.take_outbound().is_empty());
    for effect in [
        Effect::Send {
            peer: [1; 32],
            topic: 0,
            payload: vec![],
        },
        Effect::Broadcast {
            topic: 0,
            payload: vec![],
        },
        Effect::Disseminate {
            blob_id: [1; 32],
            payload: vec![],
        },
        Effect::Request {
            peer: [1; 32],
            request_id: 1,
            payload: vec![],
        },
        Effect::Respond {
            request_id: 1,
            payload: vec![],
        },
        Effect::PeerScore {
            peer: [1; 32],
            delta: 1,
        },
        Effect::MempoolAdmit { tx_hash: h1 },
    ] {
        assert_eq!(node.apply_effect(effect).unwrap(), None);
    }
    let queued = node.take_outbound();
    assert_eq!(queued.len(), 6, "{queued:?}");
    assert!(matches!(
        queued[0],
        solo_node::Outbound::Send { topic: 0, .. }
    ));
    assert!(matches!(
        queued[5],
        solo_node::Outbound::PeerScore { delta: 1, .. }
    ));
    // A block whose header does not decode is a node error, not a kernel call.
    let bad = Effect::ExecuteBlock {
        block: solo_abi::types::Block {
            header: vec![1],
            txs: Seq(vec![]),
            participation: vec![],
        },
    };
    assert!(matches!(
        node.apply_effect(bad),
        Err(solo_node::NodeError::Decode("block header"))
    ));
    // Metrics and timers can be injected too.
    assert_eq!(
        node.apply_effect(Effect::Metric {
            name: b"m".to_vec(),
            value: 3
        })
        .unwrap(),
        None
    );
    assert_eq!(node.metrics.last(), Some(&(b"m".to_vec(), 3)));
    assert_eq!(
        node.apply_effect(Effect::SetTimer {
            timer_id: propose_timer(1),
            deadline_ms: 20_000
        })
        .unwrap(),
        None
    );
    node.tick(20_000).unwrap();
    assert_eq!(
        node.block_number().unwrap(),
        1,
        "an empty block once re-armed"
    );
}
