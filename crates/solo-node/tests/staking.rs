//! The validator lifecycle over the simulated network (spec 15, spec 08):
//! epochs that change the set as validators bond and unbond, quorums
//! weighed by stake, an equivocator slashed once and excluded, and the
//! threshold key: a DKG that completes and switches certificates to BLS,
//! resharing that keeps the group key across a set change, a DKG that
//! survives a misbehaving dealer, and a node that syncs across an epoch
//! boundary on BLS certificates.

use k256::ecdsa::SigningKey;
use solo_abi::chain::consensus::{
    KIND_FINALIZE, KIND_PROPOSE, KIND_VOTE, TOPIC, leader, signing_preimage,
};
use solo_abi::chain::{
    Allocation, Certificate, ConsensusMessage, GenesisParams, Proposal, Signature, SyncResponse,
    Validator, ValidatorSet, reason,
};
use solo_abi::codec::Seq;
use solo_abi::staking::{
    DkgEnvelope, DkgRequest, DkgRun, GWEI, KIND_DKG, KeystoreRequest, PartialShare,
    STAKING_ADDRESS, StakingAction, StakingParams, StakingStatus, ValidatorKey, certificate_bytes,
    certificate_message, envelope, event, first_view, keys as skeys, query, selector, view_epoch,
};
use solo_abi::types::{Genesis, Input};
use solo_abi::{Decode, Encode};
use solo_host::hash::keccak256;
use solo_node::keystore::{Keystore, encryption_key};
use solo_node::{Node, NodeConfig, Sim, SubmitError, validator_id};
use solo_rlp::{encode_bytes, encode_list, encode_uint};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 200;
const ETHER: u128 = 1_000_000_000_000_000_000;
/// Stake of an equal-weight genesis validator, in gwei.
const STAKE: u64 = 1_000;

fn kernel_module() -> &'static [u8] {
    static MODULE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    MODULE.get_or_init(|| {
        solo_recompile::recompile(
            &solo_recompile::Input::load(KERNEL).unwrap(),
            &solo_recompile::Options::default(),
        )
        .unwrap()
    })
}

fn at(now_ms: u64) -> NodeConfig {
    NodeConfig {
        now_ms,
        ..NodeConfig::default()
    }
}

fn keys(n: u8) -> Vec<SigningKey> {
    (1..=n)
        .map(|i| SigningKey::from_slice(&[0x30 + i; 32]).unwrap())
        .collect()
}

fn address(key: &SigningKey) -> [u8; 20] {
    validator_id(key)[12..].try_into().unwrap()
}

/// A chain whose genesis set is `members` with `weights` (stake in gwei),
/// every key funded and registered with its encryption key at genesis.
fn genesis(
    keys: &[SigningKey],
    members: &[usize],
    weights: &[u64],
    staking: &StakingParams,
) -> Genesis {
    let allocations = keys
        .iter()
        .map(|k| Allocation {
            address: address(k),
            balance: 100 * ETHER,
            ..Allocation::default()
        })
        .collect();
    let set = ValidatorSet {
        validators: Seq(members
            .iter()
            .zip(weights)
            .map(|(&i, &weight)| Validator {
                id: validator_id(&keys[i]),
                weight,
            })
            .collect()),
    };
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 8,
        allocations: Seq(allocations),
        staking: StakingParams {
            keys: Seq(keys
                .iter()
                .map(|k| ValidatorKey {
                    id: validator_id(k),
                    dkg_key: encryption_key(k).to_vec(),
                })
                .collect()),
            ..staking.clone()
        },
        ..GenesisParams::default()
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: set.to_bytes(),
    }
}

fn staking(epoch_blocks: u64, dkg_phase_blocks: u64) -> StakingParams {
    StakingParams {
        epoch_blocks,
        unbonding_epochs: 0,
        min_stake: 0,
        max_validators: 0,
        dkg_phase_blocks,
        keys: Seq(vec![]),
    }
}

/// A legacy EIP-155 transaction from `key` to `to`.
fn tx(key: &SigningKey, nonce: u64, to: [u8; 20], value: u128, data: &[u8]) -> Vec<u8> {
    let fields = |out: &mut Vec<u8>| {
        encode_uint(u128::from(nonce), out);
        encode_uint(1_000_000_000, out);
        encode_uint(200_000, out);
        encode_bytes(&to, out);
        encode_uint(value, out);
        encode_bytes(data, out);
    };
    let mut unsigned = Vec::new();
    fields(&mut unsigned);
    encode_uint(u128::from(CHAIN_ID), &mut unsigned);
    encode_uint(0, &mut unsigned);
    encode_uint(0, &mut unsigned);
    let mut list = Vec::new();
    encode_list(&unsigned, &mut list);
    let (sig, rid) = key.sign_prehash_recoverable(&keccak256(&list)).unwrap();
    let v = CHAIN_ID * 2 + 35 + u64::from(rid.to_byte());
    let mut signed = Vec::new();
    fields(&mut signed);
    encode_uint(u128::from(v), &mut signed);
    let strip = |b: &[u8]| -> Vec<u8> {
        let skip = b.iter().take_while(|x| **x == 0).count();
        b[skip..].to_vec()
    };
    encode_bytes(&strip(&sig.r().to_bytes()), &mut signed);
    encode_bytes(&strip(&sig.s().to_bytes()), &mut signed);
    let mut out = Vec::new();
    encode_list(&signed, &mut out);
    out
}

fn action(key: &SigningKey, nonce: u64, value: u128, action: &StakingAction) -> Vec<u8> {
    tx(key, nonce, STAKING_ADDRESS, value, &action.encode())
}

fn status(node: &mut Node) -> StakingStatus {
    let r = node.query(query::STAKING, &[]).unwrap();
    assert_eq!(r.status, 0);
    StakingStatus::from_bytes(&r.body).unwrap()
}

fn set_of(node: &mut Node, epoch: u64) -> Option<Vec<[u8; 32]>> {
    let r = node.query(query::STAKING_SET, &epoch.to_bytes()).unwrap();
    (r.status == 0).then(|| {
        ValidatorSet::from_bytes(&r.body)
            .unwrap()
            .validators
            .0
            .iter()
            .map(|v| v.id)
            .collect()
    })
}

fn record_of(node: &mut Node, key: &SigningKey) -> solo_abi::staking::StakeRecord {
    let id = validator_id(key);
    status(node)
        .records
        .0
        .into_iter()
        .find(|e| e.id == id)
        .unwrap()
        .record
}

fn registered(node: &mut Node, key: &SigningKey) -> bool {
    let id = validator_id(key);
    status(node).records.0.iter().any(|e| e.id == id)
}

fn balance(node: &mut Node, address: [u8; 20]) -> u128 {
    node.account(&address).unwrap().balance
}

#[test]
fn selectors_and_events_are_the_solidity_ones() {
    let sel = |sig: &str| -> [u8; 4] { keccak256(sig.as_bytes())[..4].try_into().unwrap() };
    assert_eq!(sel("register(bytes)"), selector::REGISTER);
    assert_eq!(sel("bond()"), selector::BOND);
    assert_eq!(sel("unbond(uint256)"), selector::UNBOND);
    assert_eq!(sel("withdraw()"), selector::WITHDRAW);
    assert_eq!(keccak256(b"Registered(address,bytes32)"), event::REGISTERED);
    assert_eq!(keccak256(b"Bonded(address,uint256)"), event::BONDED);
    assert_eq!(
        keccak256(b"Unbonded(address,uint256,uint64)"),
        event::UNBONDED
    );
    assert_eq!(keccak256(b"Withdrawn(address,uint256)"), event::WITHDRAWN);
    // The certificate helpers of the ABI are the ones of solo-bls.
    let message = solo_abi::staking::certificate_message(CHAIN_ID, 3, &[7; 32]);
    assert_eq!(
        message,
        solo_bls::certificate::message(CHAIN_ID, 3, &[7; 32]).to_vec()
    );
    assert_eq!(
        solo_abi::staking::DST_SIGNATURE,
        solo_bls::sig::DST_SIGNATURE
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn epochs_change_the_set_as_validators_bond_and_unbond() {
    let keys = keys(5);
    let kernel = kernel_module();
    let genesis = genesis(&keys, &[0, 1, 2, 3], &[STAKE; 4], &staking(16, 0));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    let joiner = &keys[4];
    let leaver = &keys[3];
    // Genesis registers the set's stake, held by the staking address.
    let s = status(&mut sim.nodes[0]);
    assert_eq!((s.epoch, s.params.epoch_blocks), (0, 16));
    assert_eq!(s.records.0.len(), 4);
    assert_eq!(
        balance(&mut sim.nodes[0], STAKING_ADDRESS),
        4 * u128::from(STAKE) * GWEI
    );
    assert_eq!(set_of(&mut sim.nodes[0], 1), None);
    // Nothing but a staking action can run at the staking address.
    let plain = tx(joiner, 0, STAKING_ADDRESS, 1, &[]);
    assert_eq!(
        sim.submit(4, &plain),
        Err(SubmitError::Rejected(reason::STAKING_ACTION))
    );
    for bad in [
        // Bonding before registering, unbonding stake it does not have, withdrawing nothing.
        action(joiner, 0, GWEI, &StakingAction::Bond),
        action(joiner, 0, 0, &StakingAction::Unbond { amount: GWEI }),
        action(joiner, 0, 0, &StakingAction::Withdraw),
        // A key that is not a point, and value sent along with a registration.
        action(
            joiner,
            0,
            0,
            &StakingAction::Register {
                dkg_key: vec![0x80; 48],
            },
        ),
        action(
            joiner,
            0,
            1,
            &StakingAction::Register {
                dkg_key: encryption_key(joiner).to_vec(),
            },
        ),
        // A first registration bonds at least the minimum stake (here one gwei), so
        // registration slots cost stake (spec 15 §3.3).
        action(
            joiner,
            0,
            0,
            &StakingAction::Register {
                dkg_key: encryption_key(joiner).to_vec(),
            },
        ),
    ] {
        assert_eq!(
            sim.submit(4, &bad),
            Err(SubmitError::Rejected(reason::STAKING_ACTION))
        );
    }
    // The joiner registers with the stake of a genesis validator and bonds as much again,
    // twice that in all; the leaver unbonds everything; a genesis validator bonds more.
    let stake = 2 * u128::from(STAKE) * GWEI;
    let register = StakingAction::Register {
        dkg_key: encryption_key(joiner).to_vec(),
    };
    let registration = action(joiner, 0, stake / 2, &register);
    sim.submit(4, &registration).unwrap();
    // Bonding is admitted once the registration has run.
    assert!(
        sim.run_until(20 * SLOT_MS, |s| registered(&mut s.nodes[4], joiner))
            .unwrap()
    );
    assert_eq!(record_of(&mut sim.nodes[4], joiner).stake, stake / 2);
    let topics: Vec<[u8; 32]> = sim.nodes[4]
        .receipt(&keccak256(&registration))
        .unwrap()
        .unwrap()
        .logs
        .0
        .iter()
        .map(|l| l.topics.0[0])
        .collect();
    assert_eq!(topics, [event::REGISTERED, event::BONDED]);
    // A registered validator replacing its key sends no value.
    assert_eq!(
        sim.submit(4, &action(joiner, 1, GWEI, &register)),
        Err(SubmitError::Rejected(reason::STAKING_ACTION))
    );
    sim.submit(4, &action(joiner, 1, stake / 2, &StakingAction::Bond))
        .unwrap();
    let unbond = StakingAction::Unbond {
        amount: u128::from(STAKE) * GWEI,
    };
    sim.submit(3, &action(leaver, 0, 0, &unbond)).unwrap();
    sim.submit(0, &action(&keys[0], 0, GWEI, &StakingAction::Bond))
        .unwrap();
    let staked = sim
        .run_until(20 * SLOT_MS, |s| {
            let r = record_of(&mut s.nodes[0], &keys[4]);
            r.stake == stake && record_of(&mut s.nodes[0], &keys[3]).unbonding > 0
        })
        .unwrap();
    assert!(staked);
    let leaving = record_of(&mut sim.nodes[0], leaver);
    assert_eq!((leaving.stake, leaving.release_epoch), (0, 1));
    assert_eq!(
        record_of(&mut sim.nodes[0], &keys[0]).stake,
        u128::from(STAKE) * GWEI + GWEI
    );
    // Withdrawing before the release epoch cannot run.
    assert_eq!(
        sim.submit(3, &action(leaver, 1, 0, &StakingAction::Withdraw)),
        Err(SubmitError::Rejected(reason::STAKING_ACTION))
    );
    // The staking address keeps all of it, and the logs say what happened.
    let receipt_logs =
        |node: &mut Node, raw: &[u8]| node.receipt(&keccak256(raw)).unwrap().unwrap().logs.0;
    let logs = receipt_logs(
        &mut sim.nodes[0],
        &action(joiner, 1, stake / 2, &StakingAction::Bond),
    );
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].address, STAKING_ADDRESS);
    assert_eq!(logs[0].topics.0[0], solo_abi::staking::event::BONDED);
    // At the end of epoch 0 the next set is decided: the joiner in, the leaver out.
    let decided = sim
        .run_until(40 * SLOT_MS, |s| set_of(&mut s.nodes[0], 1).is_some())
        .unwrap();
    assert!(decided);
    let next = set_of(&mut sim.nodes[0], 1).unwrap();
    let ids = |list: &[usize]| {
        list.iter()
            .map(|&i| validator_id(&keys[i]))
            .collect::<Vec<_>>()
    };
    assert_eq!(next, ids(&[0, 1, 2, 4]));
    // Epoch 1 runs in its own views, and the joiner votes in them: blocks of epoch 1 carry
    // certificates its finalize vote is part of.
    let voting = sim
        .run_until(40 * SLOT_MS, |s| {
            s.nodes[4]
                .simplex_state()
                .is_some_and(|st| st.view >= first_view(1) && st.me == Some(3))
                && s.nodes
                    .iter_mut()
                    .all(|n| n.finalized_height().unwrap() >= 20)
        })
        .unwrap();
    assert!(voting, "{:?}", sim.finalized_heights().unwrap());
    assert_eq!(sim.nodes[3].simplex_state().unwrap().me, None);
    let certified = (17..=20).any(|h| {
        let cert = finalize_certificate(&sim.nodes[0], h);
        cert.view >= first_view(1) && cert.votes.0.iter().any(|v| v.validator == 3)
    });
    assert!(certified);
    // The leaver withdraws once its stake is released.
    let before = balance(&mut sim.nodes[0], address(leaver));
    let withdraw = action(leaver, 1, 0, &StakingAction::Withdraw);
    sim.submit(3, &withdraw).unwrap();
    let paid = sim
        .run_until(40 * SLOT_MS, |s| {
            s.nodes[0].receipt(&keccak256(&withdraw)).unwrap().is_some()
        })
        .unwrap();
    assert!(paid);
    let fee = sim.nodes[0]
        .receipt(&keccak256(&withdraw))
        .unwrap()
        .unwrap()
        .gas_used
        * 1_000_000_000;
    assert_eq!(
        balance(&mut sim.nodes[0], address(leaver)),
        before + u128::from(STAKE) * GWEI - u128::from(fee)
    );
    // Holding nothing, the leaver gives up its registration slot at the next epoch end;
    // the others keep theirs.
    let freed = sim
        .run_until(60 * SLOT_MS, |s| !registered(&mut s.nodes[0], leaver))
        .unwrap();
    assert!(freed);
    assert_eq!(status(&mut sim.nodes[0]).records.0.len(), 4);
    assert_agreement(&sim);
}

/// The finalize certificate node `node` keeps for `height`.
fn finalize_certificate(node: &Node, height: u64) -> solo_abi::chain::Certificate {
    let mut k = b"cert/".to_vec();
    k.extend_from_slice(&height.to_le_bytes());
    solo_abi::chain::Certificate::from_bytes(&node.persisted()[&k]).unwrap()
}

fn assert_agreement(sim: &Sim) {
    let longest = sim
        .nodes
        .iter()
        .map(|n| n.executed.clone())
        .max_by_key(Vec::len)
        .unwrap();
    for (i, n) in sim.nodes.iter().enumerate() {
        assert_eq!(
            &longest[..n.executed.len()],
            n.executed.as_slice(),
            "node {i}"
        );
    }
}

#[test]
fn quorums_weigh_stake() {
    // Four validators with 40, 30, 20 and 10 percent of the stake; no epochs.
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(
        &keys,
        &[0, 1, 2, 3],
        &[40, 30, 20, 10],
        &StakingParams::default(),
    );
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    assert!(
        sim.run_until(20 * SLOT_MS, |s| s.nodes[0].finalized.len() >= 3)
            .unwrap()
    );
    // Without the largest validator, three of four (60%) cannot finalize: they time out
    // and stay in their view, which needs a timeout quorum they cannot form either.
    sim.crash(0);
    let stuck = |s: &mut Sim| (1..4).all(|i| s.nodes[i].simplex_state().unwrap().timed_out);
    assert!(sim.run_until(40 * SLOT_MS, stuck).unwrap());
    let heights = sim.finalized_heights().unwrap();
    let views: Vec<u64> = (1..4)
        .map(|i| sim.nodes[i].simplex_state().unwrap().view)
        .collect();
    sim.advance(20 * SLOT_MS).unwrap();
    assert_eq!(sim.finalized_heights().unwrap()[1..], heights[1..]);
    assert_eq!(
        (1..4)
            .map(|i| sim.nodes[i].simplex_state().unwrap().view)
            .collect::<Vec<_>>(),
        views
    );
    // The largest validator back, and the two smallest gone: two of four (70%) finalize.
    sim.revive(0, kernel, &genesis).unwrap();
    sim.crash(2);
    sim.crash(3);
    let target = heights[1] + 3;
    let resumed = sim
        .run_until(80 * SLOT_MS, |s| {
            [0, 1]
                .iter()
                .all(|&i| s.nodes[i].finalized_height().unwrap() >= target)
        })
        .unwrap();
    assert!(resumed, "{:?}", sim.finalized_heights().unwrap());
    // The largest alone (40%) cannot.
    sim.crash(1);
    assert!(
        sim.run_until(40 * SLOT_MS, |s| s.nodes[0]
            .simplex_state()
            .unwrap()
            .timed_out)
            .unwrap()
    );
    let alone = sim.nodes[0].finalized_height().unwrap();
    sim.advance(20 * SLOT_MS).unwrap();
    assert_eq!(sim.nodes[0].finalized_height().unwrap(), alone);
}

/// `kind(view, hash)` signed with `key`.
fn signed(key: &SigningKey, kind: u8, view: u64, hash: [u8; 32]) -> Signature {
    let digest = keccak256(&signing_preimage(kind, CHAIN_ID, view, &hash));
    Signature(solo_node::sign_recoverable(key, &digest).unwrap())
}

#[test]
fn an_equivocator_is_slashed_once_and_excluded() {
    // Five equal validators; the fifth has no node, and its key signs what the test wants.
    let keys = keys(5);
    let kernel = kernel_module();
    let genesis = genesis(&keys, &[0, 1, 2, 3, 4], &[STAKE; 5], &staking(16, 0));
    let mut sim = Sim::new(kernel, &genesis, &keys[..4], 0, &at(10_000), 20).unwrap();
    assert!(
        sim.run_until(20 * SLOT_MS, |s| s.nodes[0].finalized.len() >= 2)
            .unwrap()
    );
    let byzantine = validator_id(&keys[4]);
    let ahead = sim.nodes[0].simplex_state().unwrap().view + 40;
    // Three offences: two block votes in each of two views, and two finalize votes.
    for (kind, view, hashes) in [
        (KIND_VOTE, ahead, [[1; 32], [2; 32]]),
        (KIND_VOTE, ahead + 1, [[1; 32], [2; 32]]),
        (KIND_FINALIZE, ahead, [[3; 32], [4; 32]]),
    ] {
        for hash in hashes {
            let signature = signed(&keys[4], kind, view, hash);
            let m = if kind == KIND_VOTE {
                ConsensusMessage::Vote {
                    view,
                    hash,
                    signature,
                }
            } else {
                ConsensusMessage::Finalize {
                    view,
                    hash,
                    signature,
                }
            };
            sim.nodes[0]
                .deliver(byzantine, TOPIC, m.to_bytes())
                .unwrap();
        }
    }
    let zero_before = balance(&mut sim.nodes[0], [0; 20]);
    let recorded = sim
        .run_until(40 * SLOT_MS, |s| {
            (0..4).all(|i| s.nodes[i].evidence(0).unwrap().len() == 3)
        })
        .unwrap();
    assert!(recorded);
    // One slash for all three offences: a tenth of the stake burned, and the validator jailed.
    let r = record_of(&mut sim.nodes[1], &keys[4]);
    assert!(r.jailed);
    assert_eq!(r.stake, u128::from(STAKE) * GWEI * 9 / 10);
    assert_eq!(
        balance(&mut sim.nodes[1], STAKING_ADDRESS),
        u128::from(STAKE) * GWEI * 49 / 10
    );
    assert!(balance(&mut sim.nodes[1], [0; 20]) >= zero_before + u128::from(STAKE) * GWEI / 10);
    // A jailed validator can no longer bond or re-register, and the next set leaves it out.
    let rebond = action(&keys[4], 0, GWEI, &StakingAction::Bond);
    assert_eq!(
        sim.submit(0, &rebond),
        Err(SubmitError::Rejected(reason::STAKING_ACTION))
    );
    let reregister = action(
        &keys[4],
        0,
        0,
        &StakingAction::Register {
            dkg_key: encryption_key(&keys[4]).to_vec(),
        },
    );
    assert_eq!(
        sim.submit(0, &reregister),
        Err(SubmitError::Rejected(reason::STAKING_ACTION))
    );
    let decided = sim
        .run_until(60 * SLOT_MS, |s| set_of(&mut s.nodes[0], 1).is_some())
        .unwrap();
    assert!(decided);
    let next = set_of(&mut sim.nodes[0], 1).unwrap();
    assert_eq!(next.len(), 4);
    assert!(!next.contains(&byzantine));
    assert_eq!(record_of(&mut sim.nodes[0], &keys[4]).stake, r.stake);
}

/// Waits until every live node in `nodes` has adopted a key set with id `id`.
fn adopted(sim: &mut Sim, nodes: &[usize], id: u64) -> bool {
    nodes
        .iter()
        .all(|&i| status(&mut sim.nodes[i]).active.is_some_and(|k| k.id == id))
}

/// The certificates node `node` passed to `FinalizeBlock`, as the kernel recorded them,
/// read back through the driver's persisted tables.
fn bls_certificate(node: &Node, height: u64) -> Option<Vec<u8>> {
    let mut k = b"bcert/".to_vec();
    k.extend_from_slice(&height.to_le_bytes());
    node.persisted().get(&k).cloned()
}

fn verifies(group_key: &[u8], cert: &[u8]) -> bool {
    let key = solo_bls::PublicKey::from_bytes(group_key.try_into().unwrap()).unwrap();
    solo_bls::Certificate::from_bytes(cert)
        .unwrap()
        .verify(CHAIN_ID, &key)
}

#[test]
#[allow(clippy::too_many_lines)]
fn threshold_keys_across_epochs() {
    // Four genesis validators, a fifth key that joins in epoch 1 while the fourth leaves,
    // and an observer that is offline until the end.
    let keys = keys(5);
    let kernel = kernel_module();
    let genesis = genesis(&keys, &[0, 1, 2, 3], &[STAKE; 4], &staking(24, 4));
    let mut sim = Sim::new(kernel, &genesis, &keys, 1, &at(10_000), 20).unwrap();
    sim.crash(5);
    // Epoch 0's DKG: four dealers, threshold 3, the key adopted in its confirmation phase.
    let done = sim
        .run_until(80 * SLOT_MS, |s| adopted(s, &[0, 1, 2, 3, 4], 0))
        .unwrap();
    assert!(done, "{:?}", sim.finalized_heights().unwrap());
    let s = status(&mut sim.nodes[0]);
    let first = s.active.unwrap();
    assert_eq!((first.threshold(), first.shareholders.0.len()), (3, 4));
    assert_eq!(s.group_key, first.key_set[..96].to_vec());
    let group_key = s.group_key.clone();
    // Certificates switch to BLS: once the key is active every finalized block gets one
    // (89 bytes, spec 12 §7) that verifies under the group key.
    let start = sim.nodes[0].finalized_height().unwrap() + 1;
    let switched = sim
        .run_until(40 * SLOT_MS, |s| {
            (0..4).all(|i| bls_certificate(&s.nodes[i], start + 1).is_some())
        })
        .unwrap();
    assert!(switched);
    for h in [start, start + 1] {
        let cert = bls_certificate(&sim.nodes[0], h).unwrap();
        assert_eq!(cert.len(), 89);
        assert!(verifies(&group_key, &cert));
    }
    // A set change: the fifth key registers with its stake, the fourth unbonds.
    let register = StakingAction::Register {
        dkg_key: encryption_key(&keys[4]).to_vec(),
    };
    sim.submit(4, &action(&keys[4], 0, u128::from(STAKE) * GWEI, &register))
        .unwrap();
    sim.submit(
        3,
        &action(
            &keys[3],
            0,
            0,
            &StakingAction::Unbond {
                amount: u128::from(STAKE) * GWEI,
            },
        ),
    )
    .unwrap();
    // Epoch 1 reshares among the new set; the departed validator still deals its share.
    let reshared = sim
        .run_until(160 * SLOT_MS, |s| adopted(s, &[0, 1, 2, 3, 4], 1))
        .unwrap();
    assert!(reshared, "{:?}", sim.finalized_heights().unwrap());
    let s = status(&mut sim.nodes[4]);
    let second = s.active.unwrap();
    let ids: Vec<[u8; 32]> = [0, 1, 2, 4]
        .iter()
        .map(|&i| validator_id(&keys[i]))
        .collect();
    assert_eq!(second.shareholders.0, ids);
    assert_ne!(second.key_set, first.key_set);
    // The group key is the same, so certificates of the new set verify under it.
    assert_eq!(s.group_key, group_key);
    assert_eq!(&second.key_set[..96], group_key.as_slice());
    let run = DkgRun::from_bytes(
        &sim.nodes[0]
            .state_get(&[skeys::RUN, &1u64.to_be_bytes()].concat())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(run.previous, Some(0));
    let later = sim.nodes[4].finalized_height().unwrap() + 2;
    assert!(
        sim.run_until(40 * SLOT_MS, |s| bls_certificate(&s.nodes[4], later)
            .is_some())
            .unwrap()
    );
    assert!(verifies(
        &group_key,
        &bls_certificate(&sim.nodes[4], later).unwrap()
    ));
    // The observer comes back with nothing and syncs from genesis across the epoch
    // boundary: once it has executed the block that adopted the key, the threshold
    // certificates of the responses are what it verifies.
    sim.revive_from_scratch(5, kernel, &genesis).unwrap();
    let head = sim.nodes[0].finalized_height().unwrap();
    let synced = sim
        .run_until(120 * SLOT_MS, |s| {
            s.nodes[5].finalized_height().unwrap() >= head
        })
        .unwrap();
    assert!(synced, "{:?}", sim.finalized_heights().unwrap());
    assert!(status(&mut sim.nodes[5]).epoch >= 1);
    let by_threshold: Vec<u64> = (25..=head)
        .filter(|&h| bls_certificate(&sim.nodes[5], h).is_some())
        .collect();
    assert!(!by_threshold.is_empty());
    for h in by_threshold {
        assert!(verifies(
            &group_key,
            &bls_certificate(&sim.nodes[5], h).unwrap()
        ));
    }
    assert_agreement(&sim);
}

#[test]
fn a_dkg_with_a_misbehaving_dealer_still_completes() {
    // Five validators; the fifth has no node: the test deals for it, badly, and never
    // answers the complaints.
    let keys = keys(5);
    let kernel = kernel_module();
    let genesis = genesis(&keys, &[0, 1, 2, 3, 4], &[STAKE; 5], &staking(24, 4));
    let mut sim = Sim::new(kernel, &genesis, &keys[..4], 0, &at(10_000), 20).unwrap();
    let run = DkgRun::from_bytes(
        &sim.nodes[0]
            .state_get(&[skeys::RUN, &0u64.to_be_bytes()].concat())
            .unwrap(),
    )
    .unwrap();
    assert_eq!((run.threshold, run.dealers.0.len()), (4, 5));
    let recipients = run
        .keys
        .0
        .iter()
        .map(|k| {
            solo_bls::dkg::EncryptionKey::from_bytes(k.as_slice().try_into().unwrap()).unwrap()
        })
        .collect();
    let config = solo_bls::dkg::Config {
        session: run.session,
        threshold: run.threshold,
        dealers: 5,
        recipients,
        previous: None,
    };
    let dealer = solo_bls::dkg::Dealer {
        index: 5,
        seed: [9; 32],
        share: None,
    };
    let (_, dealing) = solo_bls::dkg::Dkg::new(config, Some(dealer), None).unwrap();
    let Some(solo_bls::dkg::Message::Dealing(mut dealing)) = dealing else {
        panic!("a dealing")
    };
    // Recipient 1's share is off by one.
    dealing.shares[0][31] ^= 1;
    let body = solo_bls::dkg::Message::Dealing(dealing).to_bytes();
    let body_hash = keccak256(&DkgEnvelope::signed_hash_preimage(envelope::MESSAGE, &body));
    let digest = keccak256(&signing_preimage(KIND_DKG, CHAIN_ID, 0, &body_hash));
    let env = DkgEnvelope {
        epoch: 0,
        kind: envelope::MESSAGE,
        body,
        signature: Signature(solo_node::sign_recoverable(&keys[4], &digest).unwrap()),
    };
    let m = ConsensusMessage::Dkg {
        envelope: env.to_bytes(),
    };
    for i in 0..4 {
        sim.nodes[i]
            .deliver(validator_id(&keys[4]), TOPIC, m.to_bytes())
            .unwrap();
    }
    let done = sim
        .run_until(80 * SLOT_MS, |s| adopted(s, &[0, 1, 2, 3], 0))
        .unwrap();
    assert!(done, "{:?}", sim.finalized_heights().unwrap());
    let message = |phase: u8, index: u32| {
        sim.nodes[0].state_get(
            &[
                skeys::MESSAGE,
                &0u64.to_be_bytes(),
                &[phase],
                &index.to_be_bytes(),
            ]
            .concat(),
        )
    };
    // The bad dealing went on chain, recipient 1 complained, nobody justified.
    assert!(message(0, 5).is_some());
    assert!(message(1, 1).is_some());
    assert!(message(2, 5).is_none());
    // The key the four honest dealers made signs: all four shareholders' partials combine.
    let s = status(&mut sim.nodes[2]);
    let start = sim.nodes[2].finalized_height().unwrap() + 1;
    assert!(
        sim.run_until(40 * SLOT_MS, |s| bls_certificate(&s.nodes[2], start)
            .is_some())
            .unwrap()
    );
    assert!(verifies(
        &s.group_key,
        &bls_certificate(&sim.nodes[2], start).unwrap()
    ));
}

#[test]
fn a_genesis_listing_an_invalid_encryption_key_does_not_start() {
    // The second key is listed but not in the set: its key is checked all the same.
    let keys = keys(2);
    let good = genesis(&keys, &[0], &[STAKE], &staking(16, 0));
    assert!(Node::new(kernel_module(), &good, 0).is_ok());
    let mut params = GenesisParams::from_bytes(&good.params).unwrap();
    params.staking.keys.0[1].dkg_key = vec![0x80; 48];
    let bad = Genesis {
        params: params.to_bytes(),
        ..good
    };
    assert!(Node::new(kernel_module(), &bad, 0).is_err());
}

/// The validator ids of `keys`.
fn ids_of(keys: &[SigningKey]) -> Vec<[u8; 32]> {
    keys.iter().map(validator_id).collect()
}

/// A peer that is no node of the simulation.
const STRANGER: [u8; 32] = [0xAB; 32];

/// The entries of the driver table `key` of `node`, as the driver keeps them.
fn persisted_entries(node: &Node, key: &[u8]) -> Vec<Vec<u8>> {
    node.persisted()
        .get(key)
        .map(|raw| Seq::<Vec<u8>>::from_bytes(raw).unwrap().0)
        .unwrap_or_default()
}

#[test]
fn a_flood_of_dkg_envelopes_does_not_stop_the_dkg() {
    // Four validators and a funded outsider. Before any block, every validator gets 64
    // envelopes nobody signed, for an epoch far ahead, and 64 that the outsider signed,
    // each claiming dealer 1 of epoch 0's run.
    let keys = keys(5);
    let kernel = kernel_module();
    let genesis = genesis(&keys, &[0, 1, 2, 3], &[STAKE; 4], &staking(24, 4));
    let mut sim = Sim::new(kernel, &genesis, &keys[..4], 0, &at(10_000), 20).unwrap();
    let run = DkgRun::from_bytes(
        &sim.nodes[0]
            .state_get(&[skeys::RUN, &0u64.to_be_bytes()].concat())
            .unwrap(),
    )
    .unwrap();
    let mut flood = Vec::new();
    for j in 0..64u64 {
        flood.push(DkgEnvelope {
            epoch: u64::MAX - j,
            kind: envelope::MESSAGE,
            body: vec![0; 40],
            signature: Signature([0; 65]),
        });
        let mut body = vec![0u8];
        body.extend_from_slice(&run.session);
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&j.to_le_bytes());
        let body_hash = keccak256(&DkgEnvelope::signed_hash_preimage(envelope::MESSAGE, &body));
        let digest = keccak256(&signing_preimage(KIND_DKG, CHAIN_ID, 0, &body_hash));
        flood.push(DkgEnvelope {
            epoch: 0,
            kind: envelope::MESSAGE,
            body,
            signature: Signature(solo_node::sign_recoverable(&keys[4], &digest).unwrap()),
        });
    }
    for i in 0..4 {
        for env in &flood {
            let m = ConsensusMessage::Dkg {
                envelope: env.to_bytes(),
            };
            sim.nodes[i].deliver(STRANGER, TOPIC, m.to_bytes()).unwrap();
        }
    }
    // None of it is kept: whatever the pools hold, a participant of the run signed.
    let members = ids_of(&keys[..4]);
    for i in 0..4 {
        let pool = persisted_entries(&sim.nodes[i], b"dkg/pool");
        assert!(pool.len() <= 4);
        assert!(
            pool.iter()
                .all(|e| members.iter().any(|id| e[..32] == id[..]))
        );
    }
    let done = sim
        .run_until(80 * SLOT_MS, |s| adopted(s, &[0, 1, 2, 3], 0))
        .unwrap();
    assert!(done, "{:?}", sim.finalized_heights().unwrap());
}

#[test]
fn a_flood_of_messages_for_later_epochs_neither_fills_the_buffer_nor_holds_up_sync() {
    // Four validators in epochs of 8 blocks, and a funded outsider.
    let keys = keys(5);
    let kernel = kernel_module();
    let genesis = genesis(&keys, &[0, 1, 2, 3], &[STAKE; 4], &staking(8, 0));
    let mut sim = Sim::new(kernel, &genesis, &keys[..4], 0, &at(10_000), 20).unwrap();
    assert!(
        sim.run_until(20 * SLOT_MS, |s| s.nodes[0].finalized.len() >= 2)
            .unwrap()
    );
    // The first validator is down for two epochs.
    sim.crash(0);
    let ahead = sim
        .run_until(80 * SLOT_MS, |s| {
            (1..4).all(|i| s.nodes[i].finalized_height().unwrap() >= 20)
        })
        .unwrap();
    assert!(ahead, "{:?}", sim.finalized_heights().unwrap());
    // It comes back to a stranger's flood, which reaches it first: votes nobody signed
    // for views far ahead, and votes the outsider signed for the next epoch's views.
    sim.revive(0, kernel, &genesis).unwrap();
    for j in 0..64u64 {
        let junk = ConsensusMessage::Vote {
            view: u64::MAX - j,
            hash: [1; 32],
            signature: Signature([0; 65]),
        };
        let view = first_view(1) + j;
        let outsider = ConsensusMessage::Vote {
            view,
            hash: [1; 32],
            signature: signed(&keys[4], KIND_VOTE, view, [1; 32]),
        };
        for m in [junk, outsider] {
            sim.nodes[0].deliver(STRANGER, TOPIC, m.to_bytes()).unwrap();
        }
    }
    assert!(persisted_entries(&sim.nodes[0], b"simplex/future").is_empty());
    // It still catches up: messages the validators signed send its sync requests to them.
    let target = sim.nodes[1].finalized_height().unwrap();
    let caught_up = sim
        .run_until(120 * SLOT_MS, |s| {
            s.nodes[0].finalized_height().unwrap() >= target
        })
        .unwrap();
    assert!(caught_up, "{:?}", sim.finalized_heights().unwrap());
    let kept = persisted_entries(&sim.nodes[0], b"simplex/future");
    assert!(kept.iter().all(|e| e[..32] != STRANGER));
    assert_agreement(&sim);
}

#[test]
#[allow(clippy::too_many_lines)]
fn shareholders_with_little_stake_cannot_certify_blocks_to_a_syncing_node() {
    // One validator holds nearly all the stake and three a gwei each, and an observer
    // follows. The three small ones hold three of the four shares: the threshold.
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, &[0, 1, 2, 3], &[1_000_000, 1, 1, 1], &staking(24, 4));
    let mut sim = Sim::new(kernel, &genesis, &keys, 1, &at(10_000), 20).unwrap();
    let done = sim
        .run_until(80 * SLOT_MS, |s| adopted(s, &[0, 1, 2, 3, 4], 0))
        .unwrap();
    assert!(done, "{:?}", sim.finalized_heights().unwrap());
    let s = status(&mut sim.nodes[4]);
    let record = s.active.unwrap();
    assert_eq!((record.threshold(), record.shareholders.0.len()), (3, 4));
    // The observer stops, and the test speaks to it as a peer.
    sim.crash(4);
    let st = sim.nodes[4].simplex_state().unwrap();
    let fin = st.finalized_height;
    let fake = Proposal {
        view: st.view,
        height: fin + 1,
        parent: finalized_hash(&sim.nodes[4], fin),
        timestamp_ms: st.tip_timestamp_ms + 1,
        txs: Seq(vec![]),
        evidence: Seq(vec![]),
        dkg: Seq(vec![]),
    };
    let hash = keccak256(&fake.to_bytes());
    // The three replay the run from chain state in their own keystores and sign the fake
    // block; their partials combine into a certificate that verifies under the group key.
    let run = DkgRun::from_bytes(
        &sim.nodes[4]
            .state_get(&[skeys::RUN, &0u64.to_be_bytes()].concat())
            .unwrap(),
    )
    .unwrap();
    let transcript: Vec<Vec<u8>> = sim.nodes[4]
        .state_scan(&[skeys::MESSAGE, &0u64.to_be_bytes()].concat())
        .into_iter()
        .map(|(_, v)| v)
        .collect();
    let message = certificate_message(CHAIN_ID, fake.height, &hash);
    let partials = (1..4u32)
        .map(|index| {
            let key = &keys[index as usize];
            let mut store = Keystore::default();
            let replay = KeystoreRequest::Dkg(DkgRequest {
                key_set: 0,
                session: run.session,
                threshold: run.threshold,
                dealers: u32::try_from(run.dealers.0.len()).unwrap(),
                recipients: run.keys.clone(),
                recipient: index + 1,
                transcript: Seq(transcript.clone()),
                upto: 3,
                ..DkgRequest::default()
            });
            store.handle(Some(key), &replay.to_bytes()).unwrap();
            let sign = KeystoreRequest::Sign {
                key_set: 0,
                message: message.clone(),
            };
            PartialShare {
                key_set: 0,
                index: index + 1,
                signature: store.handle(Some(key), &sign.to_bytes()).unwrap(),
            }
        })
        .collect();
    let combine = KeystoreRequest::Combine {
        key_set: record.key_set.clone(),
        message,
        partials: Seq(partials),
    };
    let signature = Keystore::default()
        .handle(None, &combine.to_bytes())
        .unwrap();
    let forged = certificate_bytes(fake.height, &hash, &signature);
    assert!(verifies(&s.group_key, &forged));
    // A proposal far above its tip, signed by the view's leader, makes the observer ask
    // the test for blocks.
    let set = set_of(&mut sim.nodes[4], view_epoch(st.view)).unwrap();
    let proposer = set[leader(st.view, set.len())];
    let proposer_key = keys.iter().find(|k| validator_id(k) == proposer).unwrap();
    let trigger = Proposal {
        height: st.tip_height + 5,
        parent: [1; 32],
        ..fake.clone()
    };
    let signature = signed(
        proposer_key,
        KIND_PROPOSE,
        st.view,
        keccak256(&trigger.to_bytes()),
    );
    let m = ConsensusMessage::Propose {
        proposal: trigger,
        signature,
    };
    sim.nodes[4].deliver(STRANGER, TOPIC, m.to_bytes()).unwrap();
    let st = sim.nodes[4].simplex_state().unwrap();
    assert!(st.sync_pending);
    // The answer: the fake block, an empty vote list, and the forged certificate.
    let response = SyncResponse {
        finalized_height: fin + 1,
        proposals: Seq(vec![fake]),
        certificate: Some(Certificate {
            kind: KIND_FINALIZE,
            view: st.view,
            hash,
            votes: Seq(vec![]),
        }),
        threshold: forged,
    };
    let executed = sim.nodes[4].executed.len();
    sim.nodes[4]
        .step(Input::Response {
            request_id: st.sync_request_id,
            payload: response.to_bytes(),
        })
        .unwrap();
    // The observer finalizes nothing: a full node always checks the stake behind the votes.
    assert_eq!(sim.nodes[4].simplex_state().unwrap().finalized_height, fin);
    assert_eq!(sim.nodes[4].executed.len(), executed);
    let mut next_key = b"final/".to_vec();
    next_key.extend_from_slice(&(fin + 1).to_le_bytes());
    assert!(!sim.nodes[4].persisted().contains_key(&next_key));
}

/// The hash of the block node `node` finalized at `height`.
fn finalized_hash(node: &Node, height: u64) -> [u8; 32] {
    let mut k = b"final/".to_vec();
    k.extend_from_slice(&height.to_le_bytes());
    <[u8; 32]>::from_bytes(&node.persisted()[&k]).unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn an_epoch_end_finalized_by_a_suffix_and_a_restarted_shareholder() {
    // Four validators, three with nodes: every quorum, and every threshold certificate
    // (three of four shares), needs all three.
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, &[0, 1, 2, 3], &[STAKE; 4], &staking(24, 4));
    let mut sim = Sim::new(kernel, &genesis, &keys[..3], 0, &at(10_000), 20).unwrap();
    let done = sim
        .run_until(80 * SLOT_MS, |s| adopted(s, &[0, 1, 2], 0))
        .unwrap();
    assert!(done, "{:?}", sim.finalized_heights().unwrap());
    // The last block of an epoch a few blocks on.
    let end = (sim.nodes[0].finalized_height().unwrap() + 4).div_ceil(24) * 24;
    // The third node goes down right after its block vote for that block: the others
    // notarize it, but its finalize quorum never forms.
    let voted = sim
        .run_until(200 * SLOT_MS, |s| {
            s.nodes[2]
                .simplex_state()
                .is_some_and(|st| st.voted && st.tip_height + 1 == end)
        })
        .unwrap();
    assert!(voted, "{:?}", sim.finalized_heights().unwrap());
    let view = sim.nodes[2].simplex_state().unwrap().view;
    sim.crash(2);
    let notarized = sim
        .run_until(20 * SLOT_MS, |s| {
            (0..2).all(|i| s.nodes[i].simplex_state().unwrap().view > view)
        })
        .unwrap();
    assert!(notarized);
    // Their finalize votes are lost on the way to it.
    sim.advance(5 * sim.latency_ms).unwrap();
    // It comes back with its chain state but an empty keystore. The block is finalized by
    // an empty suffix proposal of the old epoch, then the next epoch runs.
    sim.revive(2, kernel, &genesis).unwrap();
    let moved_on = sim
        .run_until(200 * SLOT_MS, |s| {
            (0..3).all(|i| s.nodes[i].finalized_height().unwrap() >= end + 3)
        })
        .unwrap();
    assert!(moved_on, "{:?}", sim.finalized_heights().unwrap());
    let epoch = view_epoch(view);
    for (i, node) in sim.nodes.iter().enumerate() {
        let block = finalized_hash(node, end);
        let cert = finalize_certificate(node, end);
        // Finalized by a quorum for another proposal of the old epoch: the suffix.
        assert_ne!(cert.hash, block, "node {i}");
        assert_eq!(view_epoch(cert.view), epoch, "node {i}");
        // The suffix was never executed: the next block extends the last one.
        assert_ne!(finalized_hash(node, end + 1), cert.hash, "node {i}");
        let heights: Vec<u64> = node.executed.iter().map(|e| e.0).collect();
        assert!(heights.windows(2).all(|w| w[1] == w[0] + 1), "node {i}");
        // A suffix-finalized block has the vote certificate, not a threshold one.
        assert!(bls_certificate(node, end).is_none(), "node {i}");
    }
    // Threshold certificates resume, and each needs the restarted node's partial: it
    // installed its share again from the run on chain.
    let resumed = sim
        .run_until(40 * SLOT_MS, |s| {
            (0..3).all(|i| bls_certificate(&s.nodes[i], end + 3).is_some())
        })
        .unwrap();
    assert!(resumed);
    let group_key = status(&mut sim.nodes[2]).group_key;
    assert!(verifies(
        &group_key,
        &bls_certificate(&sim.nodes[0], end + 3).unwrap()
    ));
    assert_agreement(&sim);
}
