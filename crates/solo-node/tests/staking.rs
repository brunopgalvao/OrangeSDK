//! The validator lifecycle over the simulated network (spec 15, spec 08):
//! epochs that change the set as validators bond and unbond, quorums
//! weighed by stake, an equivocator slashed once and excluded, and the
//! threshold key: a DKG that completes and switches certificates to BLS,
//! a fresh key each epoch that the old key hands off to, a failed DKG that
//! keeps the active key, a DKG that survives a misbehaving dealer, a node
//! that syncs across a rotation on BLS certificates, and shareholders
//! slashed once for partial signatures no honest shareholder makes.

use k256::ecdsa::SigningKey;
use solo_abi::chain::consensus::{
    KIND_FINALIZE, KIND_PROPOSE, KIND_VOTE, TOPIC, leader, signing_preimage,
};
use solo_abi::chain::{
    Allocation, BlockHeader, Certificate, ConsensusMessage, GenesisParams, Proposal, Signature,
    SyncResponse, Validator, ValidatorSet, reason,
};
use solo_abi::codec::Seq;
use solo_abi::rotation::{
    self, Handoff, RotationCertificate, ThresholdEvidence,
    certificate_bytes as certificate_bytes_v2, certificate_message as certificate_message_v2,
    offence, rotation_message,
};
use solo_abi::staking::{
    DkgEnvelope, DkgRequest, DkgRun, GWEI, KIND_DKG, KeySetRecord, KeystoreRequest, PartialShare,
    STAKING_ADDRESS, StakingAction, StakingParams, StakingStatus, ValidatorKey, envelope, event,
    first_view, keys as skeys, query, selector, view_epoch,
};
use solo_abi::types::{Block, Effect, Genesis, Input};
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

/// Staking in epochs of `epoch_blocks`; with threshold keys, a key age of 2
/// and the shortest unbonding period it allows (spec 15 §6.7).
fn staking(epoch_blocks: u64, dkg_phase_blocks: u64) -> StakingParams {
    StakingParams {
        epoch_blocks,
        unbonding_epochs: if dkg_phase_blocks == 0 { 0 } else { 4 },
        min_stake: 0,
        max_validators: 0,
        dkg_phase_blocks,
        max_key_age: 2,
        keys: Seq(vec![]),
    }
}

/// A legacy EIP-155 transaction from `key` to `to`.
fn tx(key: &SigningKey, nonce: u64, to: [u8; 20], value: u128, data: &[u8]) -> Vec<u8> {
    tx_with_gas(key, nonce, to, value, data, 200_000)
}

/// [`tx`] with gas limit `gas`.
fn tx_with_gas(
    key: &SigningKey,
    nonce: u64,
    to: [u8; 20],
    value: u128,
    data: &[u8],
    gas: u64,
) -> Vec<u8> {
    let fields = |out: &mut Vec<u8>| {
        encode_uint(u128::from(nonce), out);
        encode_uint(1_000_000_000, out);
        encode_uint(u128::from(gas), out);
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
    assert_eq!(sel("report(bytes)"), selector::REPORT);
    assert_eq!(
        keccak256(b"Reported(address,uint8,uint64)"),
        event::REPORTED
    );
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
    // And so are the version-2 message and the rotation message.
    assert_eq!(
        certificate_message_v2(CHAIN_ID, 2, 3, &[7; 32]),
        solo_bls::certificate::message_v2(CHAIN_ID, 2, 3, &[7; 32]).to_vec()
    );
    let pk = solo_bls::SecretKey::generate(&[1; 32], b"")
        .unwrap()
        .public_key();
    assert_eq!(
        rotation_message(CHAIN_ID, 4, &pk.to_bytes()),
        solo_bls::certificate::rotation_message(CHAIN_ID, 4, &pk).to_vec()
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
fn validators_restarted_from_their_tables_replay_their_own_chain() {
    // Epochs of 8 blocks with a threshold key, well into epoch 2: the views
    // carry an epoch that no fresh chain state knows (spec 08 §3a).
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, &[0, 1, 2, 3], &[1, 1, 1, 1], &staking(8, 2));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    let past = |s: &mut Sim| {
        s.nodes
            .iter_mut()
            .all(|n| n.finalized_height().unwrap() >= 18)
    };
    assert!(sim.run_until(300 * SLOT_MS, past).unwrap());
    let heights = sim.finalized_heights().unwrap();
    let executed: Vec<Vec<(u64, [u8; 32])>> =
        sim.nodes.iter().map(|n| n.executed.clone()).collect();
    let views: Vec<u64> = sim
        .nodes
        .iter()
        .map(|n| n.simplex_state().unwrap().view)
        .collect();
    // Every validator stops, so no peer holds the chain for any other; each
    // comes back with its tables, re-executes its own finalized chain at
    // once and is back in the view it left (spec 08 §7).
    for i in 0..4 {
        sim.crash(i);
    }
    sim.advance(5 * SLOT_MS).unwrap();
    for i in 0..4 {
        sim.revive(i, kernel, &genesis).unwrap();
        let node = &mut sim.nodes[i];
        assert_eq!(node.finalized_height().unwrap(), heights[i], "node {i}");
        assert_eq!(node.executed, executed[i], "node {i}");
        assert_eq!(node.simplex_state().unwrap().view, views[i], "node {i}");
    }
    // They go on finalizing together, nobody having voted twice.
    let target = heights.iter().max().unwrap() + 3;
    let resumed = sim
        .run_until(60 * SLOT_MS, |s| {
            s.finalized_heights().unwrap().iter().all(|h| *h >= target)
        })
        .unwrap();
    let after: Vec<(u64, u64, bool, bool, Option<u32>)> = sim
        .nodes
        .iter()
        .map(|n| {
            let s = n.simplex_state().unwrap();
            (s.view, s.tip_height, s.voted, s.timed_out, s.me)
        })
        .collect();
    assert!(
        resumed,
        "{:?} from {heights:?}, views {views:?}, now {after:?}",
        sim.finalized_heights().unwrap()
    );
    for node in &sim.nodes {
        assert!(
            !node
                .metrics
                .iter()
                .any(|(name, _)| name == b"equivocations"),
            "an equivocation was recorded"
        );
    }
    let shortest = sim.nodes.iter().map(|n| n.executed.len()).min().unwrap();
    for node in &sim.nodes[1..] {
        assert_eq!(node.executed[..shortest], sim.nodes[0].executed[..shortest]);
    }
}

#[test]
fn a_lone_validator_comes_back_from_its_tables_past_the_first_epoch() {
    // One validator in epochs of 8 blocks: nobody holds the chain but
    // itself, and past epoch 0 its view is in an epoch no fresh chain state
    // knows, so without its tables it could never propose again.
    let keys = keys(1);
    let kernel = kernel_module();
    let genesis = genesis(&keys, &[0], &[STAKE], &staking(8, 0));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    let past = |s: &mut Sim| s.nodes[0].finalized_height().unwrap() >= 10;
    assert!(sim.run_until(60 * SLOT_MS, past).unwrap());
    let height = sim.nodes[0].finalized_height().unwrap();
    let state = sim.nodes[0].simplex_state().unwrap();
    assert_eq!(view_epoch(state.view), 1);
    let tables = sim.nodes[0].persisted();
    let executed = sim.nodes[0].executed.clone();
    sim.crash(0);
    sim.advance(5 * SLOT_MS).unwrap();
    sim.revive(0, kernel, &genesis).unwrap();
    assert_eq!(sim.nodes[0].executed[..executed.len()], executed[..]);
    assert!(sim.nodes[0].simplex_state().unwrap().view >= state.view);
    // Back in its view's epoch it is the leader again and proposes at once,
    // not after the view timeout of three slots (spec 08 §3, §7).
    let resumed = sim
        .run_until(2 * SLOT_MS, |s| {
            s.nodes[0].finalized_height().unwrap() > height
        })
        .unwrap();
    assert!(resumed, "{:?}", sim.nodes[0].simplex_state());
    // A replay that a restart cut short goes on to where it was headed: a
    // state record behind its tables re-executes up to the target the
    // tables still hold; without the target, what the record says.
    let mut cut = state;
    cut.finalized_height = 3;
    let replayed = |tables: std::collections::BTreeMap<Vec<u8>, Vec<u8>>| {
        let config = NodeConfig {
            persisted: tables,
            ..at(1_000_000)
        };
        let mut node = Node::open(kernel, &genesis, config).unwrap();
        node.start(Some(cut.to_bytes())).unwrap();
        node.executed.len()
    };
    let mut headed = tables.clone();
    headed.insert(b"simplex/replay".to_vec(), height.to_bytes());
    assert_eq!(replayed(headed), usize::try_from(height).unwrap());
    assert_eq!(replayed(tables), 3);
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
#[allow(clippy::too_many_lines)]
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
    // Validator 1's account delegates behind the offender-to-be (spec 15
    // §10.1): a delegation's stake is slashed with the validator's own.
    let delegator = keys[1].clone();
    let delegated = 1_000 * GWEI;
    let delegation = action(
        &delegator,
        0,
        delegated,
        &StakingAction::Delegate {
            validator: address(&keys[4]),
        },
    );
    let hash = sim.submit(0, &delegation).unwrap();
    assert!(
        sim.run_until(40 * SLOT_MS, |s| s.nodes[0]
            .receipt(&hash)
            .unwrap()
            .is_some())
            .unwrap()
    );
    assert_eq!(record_of(&mut sim.nodes[0], &keys[4]).delegated, delegated);
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
    // One slash for all three offences: a tenth of the stake burned, the
    // delegation's tenth with it, and the validator jailed.
    let r = record_of(&mut sim.nodes[1], &keys[4]);
    assert!(r.jailed);
    assert_eq!(r.stake, u128::from(STAKE) * GWEI * 9 / 10);
    assert_eq!(r.delegated, delegated * 9 / 10);
    let delegations = {
        let r = sim.nodes[1]
            .query(query::DELEGATIONS, &address(&delegator))
            .unwrap();
        Seq::<solo_abi::staking::DelegationEntry>::from_bytes(&r.body)
            .unwrap()
            .0
    };
    assert_eq!(delegations.len(), 1);
    assert_eq!(delegations[0].delegation.stake, delegated * 9 / 10);
    // The staking address holds the stakes left and the reward pool, which
    // the delegation's priority fee filled (spec 15 §10.2).
    let pool = status(&mut sim.nodes[1]).pool;
    assert_eq!(
        balance(&mut sim.nodes[1], STAKING_ADDRESS),
        u128::from(STAKE) * GWEI * 49 / 10 + delegated * 9 / 10 + pool
    );
    assert!(
        balance(&mut sim.nodes[1], [0; 20])
            >= zero_before + u128::from(STAKE) * GWEI / 10 + delegated / 10
    );
    // Still in epoch 0, whose end pays the pool out: everyone's balance now.
    assert!(sim.nodes[1].block_number().unwrap() < 16);
    assert!(pool > 0);
    let before: Vec<u128> = keys
        .iter()
        .map(|k| balance(&mut sim.nodes[1], address(k)))
        .collect();
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
    // The pool of epoch 0 went to the four members that were not jailed, a
    // quarter each, their weights being equal (spec 15 §10.2): the jailed
    // member and the delegation behind it got nothing, though it was in
    // the set of epoch 0 all along.
    let share = pool / 4;
    for (i, k) in keys.iter().enumerate().take(4) {
        assert_eq!(
            balance(&mut sim.nodes[1], address(k)),
            before[i] + share,
            "validator {i}"
        );
    }
    assert_eq!(balance(&mut sim.nodes[1], address(&keys[4])), before[4]);
    assert_eq!(status(&mut sim.nodes[1]).pool, pool - 4 * share);
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

/// The key set with id `id` that `node`'s chain adopted.
fn key_set(node: &Node, id: u64) -> Option<KeySetRecord> {
    node.state_get(&[skeys::KEY_SET, &id.to_be_bytes()].concat())
        .map(|b| KeySetRecord::from_bytes(&b).unwrap())
}

fn public_key(record: &KeySetRecord) -> solo_bls::PublicKey {
    solo_bls::PublicKey::from_bytes(record.key_set[..96].try_into().unwrap()).unwrap()
}

/// Whether `cert` is a version-2 certificate (97 bytes, spec 12 §7) that
/// verifies under the group key of the key set it names.
fn verifies(node: &Node, cert: &[u8]) -> bool {
    let c = solo_bls::certificate::CertificateV2::from_bytes(cert).unwrap();
    c.verify(CHAIN_ID, &public_key(&key_set(node, c.key_id).unwrap()))
}

/// The key set id a version-2 certificate names.
fn key_id_of(cert: &[u8]) -> u64 {
    solo_bls::certificate::CertificateV2::from_bytes(cert)
        .unwrap()
        .key_id
}

/// The handoff out of key set `from` that `node`'s chain recorded.
fn handoff(node: &mut Node, from: u64) -> Option<Handoff> {
    let r = node
        .query(rotation::query::HANDOFF, &from.to_bytes())
        .unwrap();
    (r.status == 0).then(|| Handoff::from_bytes(&r.body).unwrap())
}

/// A chain-state `u64` of key set `id` under `prefix`.
fn height_of(node: &Node, prefix: &[u8], id: u64) -> Option<u64> {
    node.state_get(&[prefix, &id.to_be_bytes()].concat())
        .map(|b| u64::from_bytes(&b).unwrap())
}

/// Validator `key`'s partial signature over `message` with its first share
/// of key set `id`, its keystore having replayed the run from `node`'s chain
/// state.
fn partial_of(node: &Node, key: &SigningKey, id: u64, message: &[u8]) -> PartialShare {
    partials_of(node, key, id, message).swap_remove(0)
}

/// Validator `key`'s partial signatures over `message` with every share it
/// holds of key set `id` (none when it holds none), its keystore having
/// replayed the run from `node`'s chain state.
fn partials_of(node: &Node, key: &SigningKey, id: u64, message: &[u8]) -> Vec<PartialShare> {
    let run = DkgRun::from_bytes(
        &node
            .state_get(&[skeys::RUN, &id.to_be_bytes()].concat())
            .unwrap(),
    )
    .unwrap();
    let transcript: Vec<Vec<u8>> = node
        .state_scan(&[skeys::MESSAGE, &id.to_be_bytes()].concat())
        .into_iter()
        .map(|(_, v)| v)
        .collect();
    let Some(position) = run
        .recipients
        .0
        .iter()
        .position(|r| *r == validator_id(key))
    else {
        return Vec::new();
    };
    let mut store = Keystore::default();
    let replay = KeystoreRequest::WeightedDkg {
        request: DkgRequest {
            key_set: id,
            session: run.session,
            threshold: run.threshold,
            dealers: u32::try_from(run.dealers.0.len()).unwrap(),
            recipients: run.keys.clone(),
            recipient: u32::try_from(position + 1).unwrap(),
            transcript: Seq(transcript),
            upto: 3,
            ..DkgRequest::default()
        },
        shares: run.shares.clone(),
    };
    store.handle(Some(key), &replay.to_bytes()).unwrap();
    let sign = KeystoreRequest::SignAll {
        key_set: id,
        message: message.to_vec(),
    };
    Seq::<PartialShare>::from_bytes(&store.handle(Some(key), &sign.to_bytes()).unwrap())
        .unwrap()
        .0
}

#[test]
#[allow(clippy::too_many_lines)]
fn threshold_keys_rotate_across_epochs() {
    // Four genesis validators, a fifth key that joins in epoch 1 while the fourth leaves,
    // and an observer that is offline until the end.
    let keys = keys(5);
    let kernel = kernel_module();
    let genesis = genesis(&keys, &[0, 1, 2, 3], &[STAKE; 4], &staking(24, 4));
    let mut sim = Sim::new(kernel, &genesis, &keys, 1, &at(10_000), 20).unwrap();
    sim.crash(5);
    // Epoch 0's DKG: four dealers with equal stake, four shares each and a threshold of
    // 11 shares, that is three validators; the key is adopted in its confirmation phase
    // and active at once, as the first key needs no handoff.
    let done = sim
        .run_until(80 * SLOT_MS, |s| adopted(s, &[0, 1, 2, 3, 4], 0))
        .unwrap();
    assert!(done, "{:?}", sim.finalized_heights().unwrap());
    let s = status(&mut sim.nodes[0]);
    let first = s.active.unwrap();
    assert_eq!((first.threshold(), first.shareholders.0.len()), (11, 16));
    assert_eq!(s.group_key, first.key_set[..96].to_vec());
    // Certificates switch to BLS: once the key is active every finalized block gets a
    // version-2 certificate (97 bytes, spec 12 §7) naming key set 0.
    let start = sim.nodes[0].finalized_height().unwrap() + 1;
    let switched = sim
        .run_until(40 * SLOT_MS, |s| {
            (0..4).all(|i| bls_certificate(&s.nodes[i], start + 1).is_some())
        })
        .unwrap();
    assert!(switched);
    for h in [start, start + 1] {
        let cert = bls_certificate(&sim.nodes[0], h).unwrap();
        assert_eq!((cert.len(), key_id_of(&cert)), (97, 0));
        assert!(verifies(&sim.nodes[0], &cert));
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
    // Epoch 1 generates a fresh key among the new set, and key 0 hands off to it.
    let rotated = sim
        .run_until(160 * SLOT_MS, |s| adopted(s, &[0, 1, 2, 3, 4], 1))
        .unwrap();
    assert!(rotated, "{:?}", sim.finalized_heights().unwrap());
    let s = status(&mut sim.nodes[4]);
    let second = s.active.unwrap();
    let ids: Vec<[u8; 32]> = [0, 1, 2, 4]
        .iter()
        .map(|&i| validator_id(&keys[i]))
        .collect();
    let holders: Vec<[u8; 32]> = ids
        .iter()
        .flat_map(|id| std::iter::repeat_n(*id, 4))
        .collect();
    assert_eq!(second.shareholders.0, holders);
    assert_ne!(second.key_set[..96], first.key_set[..96]);
    assert_eq!(s.group_key, second.key_set[..96].to_vec());
    let run = DkgRun::from_bytes(
        &sim.nodes[0]
            .state_get(&[skeys::RUN, &1u64.to_be_bytes()].concat())
            .unwrap(),
    )
    .unwrap();
    assert_eq!((run.previous, &run.dealers.0), (None, &ids));
    // The handoff is key 0's group signature over the rotation message to key set 1.
    let h = handoff(&mut sim.nodes[0], 0).unwrap();
    assert_eq!(
        (h.from, h.to, h.key.as_slice()),
        (0, 1, &second.key_set[..96])
    );
    let signature =
        solo_bls::Signature::from_bytes(&h.signature.clone().try_into().unwrap()).unwrap();
    assert!(public_key(&first).verify(&h.message(CHAIN_ID), &signature));
    assert_eq!(
        height_of(&sim.nodes[0], rotation::keys::REPLACED, 0),
        Some(h.height)
    );
    assert_eq!(
        height_of(&sim.nodes[0], rotation::keys::ACTIVATED, 1),
        Some(h.height)
    );
    assert!(handoff(&mut sim.nodes[0], 1).is_none());
    // Certificates now name key set 1 and verify under its key, not key 0's.
    let later = sim.nodes[4].finalized_height().unwrap() + 2;
    assert!(
        sim.run_until(40 * SLOT_MS, |s| bls_certificate(&s.nodes[4], later)
            .is_some())
            .unwrap()
    );
    let cert = bls_certificate(&sim.nodes[4], later).unwrap();
    assert_eq!(key_id_of(&cert), 1);
    assert!(verifies(&sim.nodes[4], &cert));
    let c = solo_bls::certificate::CertificateV2::from_bytes(&cert).unwrap();
    assert!(!c.verify(CHAIN_ID, &public_key(&first)));
    // The observer comes back with nothing, two sync batches after the handoff, and syncs
    // from genesis across the rotation: the threshold certificates it keeps verify under
    // the key set they name, key 0's before the handoff and key 1's after.
    let past = h.height + 34;
    assert!(
        sim.run_until(120 * SLOT_MS, |s| s.nodes[0].finalized_height().unwrap()
            >= past)
            .unwrap()
    );
    sim.revive_from_scratch(5, kernel, &genesis).unwrap();
    let head = sim.nodes[0].finalized_height().unwrap();
    let synced = sim
        .run_until(120 * SLOT_MS, |s| {
            s.nodes[5].finalized_height().unwrap() >= head
        })
        .unwrap();
    assert!(synced, "{:?}", sim.finalized_heights().unwrap());
    assert!(status(&mut sim.nodes[5]).epoch >= 1);
    let by_threshold: Vec<u64> = (1..=head)
        .filter(|&h| bls_certificate(&sim.nodes[5], h).is_some())
        .collect();
    assert!(!by_threshold.is_empty());
    let mut named = std::collections::BTreeSet::new();
    for height in by_threshold {
        let cert = bls_certificate(&sim.nodes[5], height).unwrap();
        assert!(verifies(&sim.nodes[5], &cert));
        named.insert(key_id_of(&cert));
    }
    assert!(named.contains(&0) && named.contains(&1), "{named:?}");
    assert_agreement(&sim);
    // Honest rotation produced no evidence and slashed no one.
    assert_eq!(evidence_count(&mut sim.nodes[0]), 0);
    assert!(!record_of(&mut sim.nodes[0], &keys[1]).jailed);
    // A valid partial of key 0 over a proposal anchored below the handoff is honest, so
    // it is no evidence of a stale key: key 0 was still in force at that anchor.
    let early = Proposal {
        height: h.height + 1,
        anchor_height: h.height - 1,
        anchor_root: sim.nodes[0]
            .block_by_number(h.height - 1)
            .unwrap()
            .unwrap()
            .state_root,
        ..Proposal::default()
    };
    let subject = early.to_bytes();
    let message = certificate_message_v2(CHAIN_ID, 0, early.height, &keccak256(&subject));
    let p = partial_of(&sim.nodes[0], &keys[1], 0, &message);
    assert!(share_verifies(
        &first.public_shares.0[p.index as usize - 1],
        &message,
        &p.signature
    ));
    let honest = ThresholdEvidence {
        kind: offence::STALE_KEY,
        key_set: 0,
        index: p.index,
        signature: p.signature,
        subject,
    };
    let refused = action(
        &keys[2],
        0,
        0,
        &StakingAction::Report {
            evidence: honest.to_bytes(),
        },
    );
    assert_eq!(
        sim.submit(2, &refused),
        Err(SubmitError::Rejected(reason::STAKING_ACTION))
    );
    // A partial of key 0 over a proposal anchored at or after the handoff is slashable:
    // its shareholders had all moved to key set 1 by then (spec 15 §5.1).
    let fake = Proposal {
        height: h.height + 2,
        anchor_height: h.height,
        anchor_root: sim.nodes[0]
            .block_by_number(h.height)
            .unwrap()
            .unwrap()
            .state_root,
        ..Proposal::default()
    };
    let subject = fake.to_bytes();
    let message = certificate_message_v2(CHAIN_ID, 0, fake.height, &keccak256(&subject));
    let p = partial_of(&sim.nodes[0], &keys[1], 0, &message);
    let evidence = ThresholdEvidence {
        kind: offence::STALE_KEY,
        key_set: 0,
        index: p.index,
        signature: p.signature,
        subject,
    };
    let report = action(
        &keys[2],
        0,
        0,
        &StakingAction::Report {
            evidence: evidence.to_bytes(),
        },
    );
    let hash = sim.submit(2, &report).unwrap();
    assert!(
        sim.run_until(40 * SLOT_MS, |s| s.nodes[0]
            .receipt(&hash)
            .unwrap()
            .is_some())
            .unwrap()
    );
    let receipt = sim.nodes[0].receipt(&hash).unwrap().unwrap();
    assert_eq!(receipt.status, 1);
    let log = &receipt.logs.0[0];
    assert_eq!(
        (log.topics.0[0], &log.topics.0[1][12..]),
        (event::REPORTED, &address(&keys[1])[..])
    );
    // `Reported(offender, kind, key_set)`: kind 2, key set 0.
    let mut kind = [0u8; 32];
    kind[31] = offence::STALE_KEY;
    assert_eq!(log.data, [kind, [0u8; 32]].concat());
    assert!(record_of(&mut sim.nodes[0], &keys[1]).jailed);
    assert_eq!(evidence_count(&mut sim.nodes[0]), 1);
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
    assert_eq!((run.threshold, run.dealers.0.len()), (14, 5));
    assert_eq!(run.shares.0, [4; 5]);
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
        shares: run.shares.0.clone(),
        weights: run.shares.0.clone(),
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
    let start = sim.nodes[2].finalized_height().unwrap() + 1;
    assert!(
        sim.run_until(40 * SLOT_MS, |s| bls_certificate(&s.nodes[2], start)
            .is_some())
            .unwrap()
    );
    assert!(verifies(
        &sim.nodes[2],
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
fn seats_without_two_thirds_of_the_stake_cannot_certify_and_sync_wants_votes() {
    // One validator holds 70% of the stake and three 10% each, and an observer follows.
    // The three small ones hold three of the four seats, the old threshold of three
    // shareholders, but 30% of the stake: shares follow stake (spec 15 §6.1), one each
    // of Q = 16, against a threshold of 11 that the large one alone reaches.
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(
        &keys,
        &[0, 1, 2, 3],
        &[7 * STAKE, STAKE, STAKE, STAKE],
        &staking(24, 4),
    );
    let mut sim = Sim::new(kernel, &genesis, &keys, 1, &at(10_000), 20).unwrap();
    let done = sim
        .run_until(80 * SLOT_MS, |s| adopted(s, &[0, 1, 2, 3, 4], 0))
        .unwrap();
    assert!(done, "{:?}", sim.finalized_heights().unwrap());
    let s = status(&mut sim.nodes[4]);
    let record = s.active.unwrap();
    assert_eq!((record.threshold(), record.shareholders.0.len()), (11, 14));
    let holders: Vec<[u8; 32]> = [(0, 11), (1, 1), (2, 1), (3, 1)]
        .iter()
        .flat_map(|&(i, m)| std::iter::repeat_n(validator_id(&keys[i]), m))
        .collect();
    assert_eq!(record.shareholders.0, holders);
    // The observer stops, and the test speaks to it as a peer.
    sim.crash(4);
    let st = sim.nodes[4].simplex_state().unwrap();
    let fin = st.finalized_height;
    let fake = Proposal {
        view: st.view,
        height: fin + 1,
        parent: finalized_hash(&sim.nodes[4], fin),
        timestamp_ms: st.tip_timestamp_ms + 1,
        anchor_height: 0,
        anchor_root: [0; 32],
        txs: Seq(vec![]),
        evidence: Seq(vec![]),
        dkg: Seq(vec![]),
    };
    let hash = keccak256(&fake.to_bytes());
    // The three small ones replay the run from chain state in their own keystores and
    // sign the fake block: three partials, which combine into nothing.
    let message = certificate_message_v2(CHAIN_ID, 0, fake.height, &hash);
    let combine = |partials: Vec<PartialShare>| {
        let request = KeystoreRequest::Combine {
            key_set: record.key_set.clone(),
            message: message.clone(),
            partials: Seq(partials),
        };
        Keystore::default().handle(None, &request.to_bytes())
    };
    let small: Vec<PartialShare> = (1..4)
        .flat_map(|i| partials_of(&sim.nodes[4], &keys[i], 0, &message))
        .collect();
    assert_eq!(small.len(), 3);
    assert_eq!(combine(small.clone()), None);
    // The large one, with 70% of the stake, holds the threshold alone; with the small
    // ones' partials besides, the certificate is the same.
    let large = partials_of(&sim.nodes[4], &keys[0], 0, &message);
    assert_eq!(large.len(), 11);
    assert_eq!(combine(large[..10].to_vec()), None);
    let signature = combine(large.clone()).unwrap();
    assert_eq!(combine([small, large].concat()), Some(signature.clone()));
    let forged = certificate_bytes_v2(0, fake.height, &hash, &signature);
    assert!(verifies(&sim.nodes[4], &forged));
    // Even so, a full node syncs on votes, not on a threshold certificate (spec 08 §7a).
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
    // (11 of 16 shares, three validators), needs all three.
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
    assert!(verifies(
        &sim.nodes[2],
        &bls_certificate(&sim.nodes[0], end + 3).unwrap()
    ));
    assert_agreement(&sim);
}

#[test]
fn threshold_keys_need_an_unbonding_period_past_the_key_age() {
    // A key age of 2 epochs needs at least 4 epochs of unbonding: the age, one epoch of
    // handoff latency and one in which evidence about the last trusted anchor lands.
    let keys = keys(1);
    let ok = genesis(&keys, &[0], &[STAKE], &staking(16, 2));
    assert!(Node::new(kernel_module(), &ok, 0).is_ok());
    let with = |age: u64, unbonding: u64, phase: u64| {
        let mut params = GenesisParams::from_bytes(&ok.params).unwrap();
        params.staking.max_key_age = age;
        params.staking.unbonding_epochs = unbonding;
        params.staking.dkg_phase_blocks = phase;
        Genesis {
            params: params.to_bytes(),
            ..ok.clone()
        }
    };
    for (age, unbonding) in [(0, 4), (2, 3), (3, 4)] {
        assert!(
            Node::new(kernel_module(), &with(age, unbonding, 2), 0).is_err(),
            "{age} {unbonding}"
        );
    }
    assert!(Node::new(kernel_module(), &with(3, 5, 2), 0).is_ok());
    // Without threshold keys neither matters.
    assert!(Node::new(kernel_module(), &with(0, 0, 0), 0).is_ok());
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_failed_dkg_keeps_the_active_key() {
    // Two validators hold nearly all the stake and two very little; all four hold shares.
    let keys = keys(4);
    let kernel = kernel_module();
    // Weights 5 : 5 : 2 : 2 deal shares 5, 5, 2 and 2 of Q = 16 (W = 14, rounded down),
    // threshold 11: the two large ones hold 71% of the stake, enough to finalize, but
    // only 10 shares, the cost of rounding (spec 15 §6.8).
    let weights = [500_000, 500_000, 200_000, 200_000];
    let genesis = genesis(&keys, &[0, 1, 2, 3], &weights, &staking(24, 4));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    let done = sim
        .run_until(80 * SLOT_MS, |s| adopted(s, &[0, 1, 2, 3], 0))
        .unwrap();
    assert!(done, "{:?}", sim.finalized_heights().unwrap());
    // The two small ones go down before epoch 1's dealings. The two large dealers weigh
    // 10, below the threshold of 11, so epoch 1's run makes no key, while the two large
    // ones keep finalizing.
    sim.crash(2);
    sim.crash(3);
    let dealt = sim
        .run_until(200 * SLOT_MS, |s| {
            (0..2).all(|i| s.nodes[i].finalized_height().unwrap() >= 30)
        })
        .unwrap();
    assert!(dealt, "{:?}", sim.finalized_heights().unwrap());
    let dealings = sim.nodes[0]
        .state_scan(&[skeys::MESSAGE, &1u64.to_be_bytes(), &[0]].concat())
        .len();
    assert_eq!(dealings, 2);
    // They come back; epoch 1 ends without a key set 1, and key 0 is still active.
    sim.revive(2, kernel, &genesis).unwrap();
    sim.revive(3, kernel, &genesis).unwrap();
    let ended = sim
        .run_until(200 * SLOT_MS, |s| {
            (0..4).all(|i| s.nodes[i].finalized_height().unwrap() >= 49)
        })
        .unwrap();
    assert!(ended, "{:?}", sim.finalized_heights().unwrap());
    assert!(key_set(&sim.nodes[0], 1).is_none());
    assert_eq!(status(&mut sim.nodes[0]).active.unwrap().id, 0);
    assert!(handoff(&mut sim.nodes[0], 0).is_none());
    // A later run makes a key, and key 0, still active, hands off to it.
    let handed = sim
        .run_until(400 * SLOT_MS, |s| handoff(&mut s.nodes[0], 0).is_some())
        .unwrap();
    assert!(handed, "{:?}", sim.finalized_heights().unwrap());
    let h = handoff(&mut sim.nodes[0], 0).unwrap();
    assert!(h.to >= 2, "{h:?}");
    assert!(key_set(&sim.nodes[0], 1).is_none());
    assert_eq!(status(&mut sim.nodes[0]).active.unwrap().id, h.to);
    assert_agreement(&sim);
}

/// `env` signed by `key` as a DKG envelope (spec 15 §6.2).
fn envelope_of(key: &SigningKey, epoch: u64, kind: u8, body: Vec<u8>) -> ConsensusMessage {
    let body_hash = keccak256(&DkgEnvelope::signed_hash_preimage(kind, &body));
    let digest = keccak256(&signing_preimage(KIND_DKG, CHAIN_ID, epoch, &body_hash));
    let env = DkgEnvelope {
        epoch,
        kind,
        body,
        signature: Signature(solo_node::sign_recoverable(key, &digest).unwrap()),
    };
    ConsensusMessage::Dkg {
        envelope: env.to_bytes(),
    }
}

/// Whether `signature` (48 bytes) verifies over `message` under the public
/// share `share` (96 bytes), as the kernel checks a partial.
fn share_verifies(share: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let key = solo_bls::PublicKey::from_bytes(share.try_into().unwrap()).unwrap();
    let signature = solo_bls::Signature::from_bytes(signature.try_into().unwrap()).unwrap();
    key.verify(message, &signature)
}

fn evidence_count(node: &mut Node) -> usize {
    let r = node
        .query(rotation::query::THRESHOLD_EVIDENCE, &0u64.to_bytes())
        .unwrap();
    Seq::<ThresholdEvidence>::from_bytes(&r.body)
        .unwrap()
        .0
        .len()
}

#[test]
#[allow(clippy::too_many_lines)]
fn threshold_misbehaviour_is_slashed_once() {
    // Four validators with nodes and a funded outsider who reports.
    let keys = keys(5);
    let kernel = kernel_module();
    let genesis = genesis(&keys, &[0, 1, 2, 3], &[STAKE; 4], &staking(24, 4));
    let mut sim = Sim::new(kernel, &genesis, &keys[..4], 0, &at(10_000), 20).unwrap();
    let done = sim
        .run_until(80 * SLOT_MS, |s| adopted(s, &[0, 1, 2, 3], 0))
        .unwrap();
    assert!(done, "{:?}", sim.finalized_heights().unwrap());
    // Validator 3's partial over a proposal whose anchor root is not the root the chain
    // executed at height 2.
    let fake = Proposal {
        height: 40,
        anchor_height: 2,
        anchor_root: [0x66; 32],
        ..Proposal::default()
    };
    let subject = fake.to_bytes();
    let message = certificate_message_v2(CHAIN_ID, 0, fake.height, &keccak256(&subject));
    let p = partial_of(&sim.nodes[0], &keys[3], 0, &message);
    let evidence = ThresholdEvidence {
        kind: offence::ANCHOR,
        key_set: 0,
        index: p.index,
        signature: p.signature,
        subject,
    };
    let before = record_of(&mut sim.nodes[0], &keys[3]);
    let pot = balance(&mut sim.nodes[0], STAKING_ADDRESS);
    let report = |nonce: u64, evidence: &ThresholdEvidence| {
        action(
            &keys[4],
            nonce,
            0,
            &StakingAction::Report {
                evidence: evidence.to_bytes(),
            },
        )
    };
    // Evidence that shows nothing cannot run: validator 3's partial, valid under its
    // share, over the same proposal with the root the chain executed.
    let mut proposal = fake.clone();
    proposal.anchor_root = sim.nodes[0].block_by_number(2).unwrap().unwrap().state_root;
    let subject = proposal.to_bytes();
    let message = certificate_message_v2(CHAIN_ID, 0, proposal.height, &keccak256(&subject));
    let valid = partial_of(&sim.nodes[0], &keys[3], 0, &message);
    let share = &key_set(&sim.nodes[0], 0).unwrap().public_shares.0[valid.index as usize - 1];
    assert!(share_verifies(share, &message, &valid.signature));
    let honest = ThresholdEvidence {
        kind: offence::ANCHOR,
        key_set: 0,
        index: valid.index,
        signature: valid.signature,
        subject,
    };
    assert_eq!(
        sim.submit(0, &report(0, &honest)),
        Err(SubmitError::Rejected(reason::STAKING_ACTION))
    );
    // Reported in a transaction to the staking address, it slashes and jails validator 3.
    let hash = sim.submit(0, &report(0, &evidence)).unwrap();
    assert!(
        sim.run_until(40 * SLOT_MS, |s| s.nodes[0]
            .receipt(&hash)
            .unwrap()
            .is_some())
            .unwrap()
    );
    let receipt = sim.nodes[0].receipt(&hash).unwrap().unwrap();
    assert_eq!(receipt.status, 1);
    assert!(receipt.gas_used > rotation::REPORT_GAS + 21_000);
    let log = &receipt.logs.0[0];
    assert_eq!(
        (log.address, log.topics.0[0], &log.topics.0[1][12..]),
        (STAKING_ADDRESS, event::REPORTED, &address(&keys[3])[..])
    );
    assert_eq!(log.data, [[0u8; 32], [0u8; 32]].concat());
    let after = record_of(&mut sim.nodes[0], &keys[3]);
    assert!(after.jailed);
    assert_eq!(after.stake, before.stake - before.stake / 10);
    // The staking address lost the burned tenth and gained the reward pool:
    // the report's priority fee, `REPORT_GAS` included (spec 15 §10.2).
    let pool = status(&mut sim.nodes[0]).pool;
    assert_eq!(pool, u128::from(receipt.gas_used) * 1_000_000_000);
    assert_eq!(
        balance(&mut sim.nodes[0], STAKING_ADDRESS),
        pot - before.stake / 10 + pool
    );
    assert_eq!(evidence_count(&mut sim.nodes[0]), 1);
    // Once: the same offence cannot be reported again.
    assert_eq!(
        sim.submit(0, &report(1, &evidence)),
        Err(SubmitError::Rejected(reason::STAKING_ACTION))
    );
    // Validator 2 signs a rotation to key set 0 with another group key than the one the
    // chain adopted, and sends it as a rotation share: the nodes see it is evidence,
    // put it in their proposals, and the chain slashes validator 2.
    let wrong = key_set(&sim.nodes[0], 0).unwrap().public_shares.0[0].clone();
    let p = partial_of(
        &sim.nodes[0],
        &keys[2],
        0,
        &rotation_message(CHAIN_ID, 0, &wrong),
    );
    let share = solo_abi::rotation::RotationShare {
        to: 0,
        key: wrong.clone(),
        partials: Seq(partials_of(
            &sim.nodes[0],
            &keys[2],
            0,
            &rotation_message(CHAIN_ID, 0, &wrong),
        )),
    };
    let m = envelope_of(&keys[2], 0, envelope::ROTATION_SHARE, share.to_bytes());
    for i in 0..4 {
        sim.nodes[i]
            .deliver(validator_id(&keys[2]), TOPIC, m.to_bytes())
            .unwrap();
    }
    let slashed = sim
        .run_until(40 * SLOT_MS, |s| {
            record_of(&mut s.nodes[0], &keys[2]).jailed
        })
        .unwrap();
    assert!(slashed);
    assert_eq!(evidence_count(&mut sim.nodes[0]), 2);
    // Neither offence is recorded or punished again, by transaction or in a proposal.
    let rotation_evidence = ThresholdEvidence {
        kind: offence::ROTATION,
        key_set: 0,
        index: p.index,
        signature: p.signature,
        subject: [&0u64.to_be_bytes()[..], &wrong].concat(),
    };
    assert_eq!(
        sim.submit(0, &report(1, &rotation_evidence)),
        Err(SubmitError::Rejected(reason::STAKING_ACTION))
    );
    let epoch = status(&mut sim.nodes[0]).epoch;
    let again = envelope_of(&keys[0], epoch, envelope::EVIDENCE, evidence.to_bytes());
    for i in 0..4 {
        sim.nodes[i]
            .deliver(validator_id(&keys[0]), TOPIC, again.to_bytes())
            .unwrap();
    }
    let height = sim.nodes[0].finalized_height().unwrap();
    assert!(
        sim.run_until(40 * SLOT_MS, |s| s.nodes[0].finalized_height().unwrap()
            >= height + 4)
            .unwrap()
    );
    assert_eq!(evidence_count(&mut sim.nodes[0]), 2);
    assert_eq!(record_of(&mut sim.nodes[0], &keys[3]).stake, after.stake);
    assert_agreement(&sim);
}

#[test]
fn checks_that_need_a_pairing_spend_a_block_budget() {
    // A leader puts staking transactions that fail a pairing check into its proposal:
    // they use no gas, but each costs every node a pairing, so they draw on a budget of
    // the block gas limit (spec 15 §3.3). Here the check is register's key check.
    let keys = keys(2);
    let genesis = genesis(&keys, &[0], &[STAKE], &staking(16, 0));
    let mut node = Node::open(kernel_module(), &genesis, at(10_000)).unwrap();
    let bad = |variant: u8| {
        let register = StakingAction::Register {
            dkg_key: vec![0x80 | variant; 48],
        };
        tx_with_gas(
            &keys[1],
            0,
            STAKING_ADDRESS,
            0,
            &register.encode(),
            15_000_000,
        )
    };
    let rekey = |nonce: u64, to: &SigningKey| {
        let register = StakingAction::Register {
            dkg_key: encryption_key(to).to_vec(),
        };
        action(&keys[0], nonce, 0, &register)
    };
    let execute = |node: &mut Node, height: u64, txs: Vec<Vec<u8>>| {
        let header = BlockHeader {
            height,
            timestamp_ms: 10_000 + height * SLOT_MS,
            ..BlockHeader::default()
        };
        node.apply_effect(Effect::ExecuteBlock {
            block: Block {
                header: header.to_bytes(),
                txs: Seq(txs),
                participation: Vec::new(),
            },
        })
        .unwrap();
        // The running sum never reaches committed state.
        assert!(node.state_get(b"stake/pairing_gas").is_none());
    };
    let receipt = |node: &mut Node, raw: &[u8]| node.receipt(&keccak256(raw)).unwrap().unwrap();
    // Half the budget spent on a failing check leaves room for a valid one.
    let first = rekey(0, &keys[1]);
    execute(&mut node, 1, vec![bad(1), first.clone()]);
    assert_eq!(receipt(&mut node, &bad(1)).gas_used, 0);
    assert_eq!(receipt(&mut node, &first).status, 1);
    assert_eq!(
        record_of(&mut node, &keys[0]).dkg_key,
        encryption_key(&keys[1]).to_vec()
    );
    // The whole budget spent: the valid one after it cannot run, and nothing changes.
    let second = rekey(1, &keys[0]);
    execute(&mut node, 2, vec![bad(2), bad(3), second.clone()]);
    let r = receipt(&mut node, &second);
    assert_eq!((r.status, r.gas_used), (0, 0));
    assert_eq!(
        record_of(&mut node, &keys[0]).dkg_key,
        encryption_key(&keys[1]).to_vec()
    );
    // The budget is per block: alone in the next block it runs.
    execute(&mut node, 3, vec![second.clone()]);
    assert_eq!(receipt(&mut node, &second).status, 1);
    assert_eq!(
        record_of(&mut node, &keys[0]).dkg_key,
        encryption_key(&keys[0]).to_vec()
    );
}

/// The newest adopted key set's id in `node`'s chain state.
fn newest_adopted(node: &Node) -> u64 {
    u64::from_bytes(&node.state_get(rotation::keys::ADOPTED).unwrap()).unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_key_hands_off_only_once_its_shareholders_sign_and_only_to_the_newest_key() {
    // Four genesis validators hold key 0. Two of them unbond and two newcomers take their
    // seats in epoch 1, then the two leavers stop their nodes.
    let keys = keys(6);
    let kernel = kernel_module();
    let genesis = genesis(&keys, &[0, 1, 2, 3], &[STAKE; 4], &staking(24, 4));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    let done = sim
        .run_until(80 * SLOT_MS, |s| adopted(s, &[0, 1, 2, 3, 4, 5], 0))
        .unwrap();
    assert!(done, "{:?}", sim.finalized_heights().unwrap());
    for i in [4, 5] {
        let register = StakingAction::Register {
            dkg_key: encryption_key(&keys[i]).to_vec(),
        };
        sim.submit(i, &action(&keys[i], 0, u128::from(STAKE) * GWEI, &register))
            .unwrap();
    }
    for i in [2, 3] {
        let unbond = StakingAction::Unbond {
            amount: u128::from(STAKE) * GWEI,
        };
        sim.submit(i, &action(&keys[i], 0, 0, &unbond)).unwrap();
    }
    let next = sim
        .run_until(160 * SLOT_MS, |s| {
            s.nodes[0].finalized_height().unwrap() >= 25
        })
        .unwrap();
    assert!(next, "{:?}", sim.finalized_heights().unwrap());
    let mut set = set_of(&mut sim.nodes[0], 1).unwrap();
    set.sort_unstable();
    let mut newcomers = ids_of(&[
        keys[0].clone(),
        keys[1].clone(),
        keys[4].clone(),
        keys[5].clone(),
    ]);
    newcomers.sort_unstable();
    assert_eq!(set, newcomers);
    sim.crash(2);
    sim.crash(3);
    // Epochs 1 and 2 each adopt a fresh key among the new set, but only two of key 0's
    // four shareholders are left to sign a handoff, 8 shares below its threshold of 11: key 0
    // stays active, whichever newer key is the target.
    let stalled = sim
        .run_until(400 * SLOT_MS, |s| key_set(&s.nodes[0], 2).is_some())
        .unwrap();
    assert!(stalled, "{:?}", sim.finalized_heights().unwrap());
    let height = sim.nodes[0].finalized_height().unwrap();
    assert!(
        sim.run_until(40 * SLOT_MS, |s| s.nodes[0].finalized_height().unwrap()
            >= height + 4)
            .unwrap()
    );
    assert!(key_set(&sim.nodes[0], 1).is_some());
    assert_eq!(status(&mut sim.nodes[0]).active.unwrap().id, 0);
    assert!(handoff(&mut sim.nodes[0], 0).is_none());
    assert!(newest_adopted(&sim.nodes[0]) >= 2);
    // A handoff from key 0 to key set 1, validly signed by three of its shareholders, is
    // never recorded: key set 1 was superseded before its handoff, and the active key
    // only ever moves to the newest adopted key (spec 15 §6.6).
    let older = key_set(&sim.nodes[0], 1).unwrap();
    let message = rotation_message(CHAIN_ID, 1, &older.key_set[..96]);
    let partials = (0..3)
        .flat_map(|i| partials_of(&sim.nodes[0], &keys[i], 0, &message))
        .collect();
    let combine = KeystoreRequest::Combine {
        key_set: key_set(&sim.nodes[0], 0).unwrap().key_set,
        message: message.clone(),
        partials: Seq(partials),
    };
    let signature = Keystore::default()
        .handle(None, &combine.to_bytes())
        .unwrap();
    let first = key_set(&sim.nodes[0], 0).unwrap();
    let point = solo_bls::Signature::from_bytes(&signature.clone().try_into().unwrap()).unwrap();
    assert!(public_key(&first).verify(&message, &point));
    let certificate = RotationCertificate {
        from: 0,
        to: 1,
        signature,
    };
    let epoch = status(&mut sim.nodes[0]).epoch;
    let m = envelope_of(&keys[0], epoch, envelope::HANDOFF, certificate.to_bytes());
    for i in [0, 1, 4, 5] {
        sim.nodes[i]
            .deliver(validator_id(&keys[0]), TOPIC, m.to_bytes())
            .unwrap();
    }
    let height = sim.nodes[0].finalized_height().unwrap();
    assert!(
        sim.run_until(40 * SLOT_MS, |s| s.nodes[0].finalized_height().unwrap()
            >= height + 4)
            .unwrap()
    );
    assert!(handoff(&mut sim.nodes[0], 0).is_none());
    assert_eq!(status(&mut sim.nodes[0]).active.unwrap().id, 0);
    assert!(height_of(&sim.nodes[0], rotation::keys::ACTIVATED, 1).is_none());
    // The leavers come back and sign: key 0 hands off to the newest adopted key, and key
    // set 1 is never activated.
    sim.revive(2, kernel, &genesis).unwrap();
    sim.revive(3, kernel, &genesis).unwrap();
    let handed = sim
        .run_until(400 * SLOT_MS, |s| handoff(&mut s.nodes[0], 0).is_some())
        .unwrap();
    assert!(handed, "{:?}", sim.finalized_heights().unwrap());
    let h = handoff(&mut sim.nodes[0], 0).unwrap();
    assert!(h.to >= 2, "{h:?}");
    assert_eq!(
        height_of(&sim.nodes[0], rotation::keys::ACTIVATED, h.to),
        Some(h.height)
    );
    assert!(height_of(&sim.nodes[0], rotation::keys::ACTIVATED, 1).is_none());
    assert_eq!(status(&mut sim.nodes[0]).active.unwrap().id, h.to);
    assert_agreement(&sim);
}

#[test]
#[allow(clippy::too_many_lines)]
fn shares_follow_stake_across_an_epoch_transition() {
    // Four validators with equal stake; during epoch 0 validator 0 bonds six times its
    // stake more and validator 1 twice, so epoch 1 weighs 7 : 3 : 1 : 1.
    let keys = keys(4);
    let kernel = kernel_module();
    let genesis = genesis(&keys, &[0, 1, 2, 3], &[STAKE; 4], &staking(24, 4));
    let mut sim = Sim::new(kernel, &genesis, &keys, 0, &at(10_000), 20).unwrap();
    // Key set 0, equal stakes: four shares each of Q = 16, threshold 11, so any three
    // validators sign and no two do.
    let done = sim
        .run_until(80 * SLOT_MS, |s| adopted(s, &[0, 1, 2, 3], 0))
        .unwrap();
    assert!(done, "{:?}", sim.finalized_heights().unwrap());
    let first = key_set(&sim.nodes[0], 0).unwrap();
    assert_eq!((first.threshold(), first.shareholders.0.len()), (11, 16));
    let run = |node: &Node, id: u64| {
        DkgRun::from_bytes(
            &node
                .state_get(&[skeys::RUN, &id.to_be_bytes()].concat())
                .unwrap(),
        )
        .unwrap()
    };
    let first_run = run(&sim.nodes[0], 0);
    assert_eq!((first_run.threshold, first_run.shares.0), (11, vec![4; 4]));
    for (i, times) in [(0, 6), (1, 2)] {
        let value = u128::from(STAKE) * GWEI * times;
        sim.submit(i, &action(&keys[i], 0, value, &StakingAction::Bond))
            .unwrap();
    }
    // Epoch 1's run deals by the new weights, W = 12: 16·7/12, 16·3/12 and 16/12 rounded
    // down, 9, 4, 1 and 1 of the 15 shares, against the threshold of 11 for Q = 16.
    let rotated = sim
        .run_until(160 * SLOT_MS, |s| adopted(s, &[0, 1, 2, 3], 1))
        .unwrap();
    assert!(rotated, "{:?}", sim.finalized_heights().unwrap());
    let r = sim.nodes[0]
        .query(query::STAKING_SET, &1u64.to_bytes())
        .unwrap();
    let weights: Vec<u64> = ValidatorSet::from_bytes(&r.body)
        .unwrap()
        .validators
        .0
        .iter()
        .map(|v| v.weight)
        .collect();
    assert_eq!(weights, [7 * STAKE, 3 * STAKE, STAKE, STAKE]);
    let second_run = run(&sim.nodes[0], 1);
    assert_eq!(
        (second_run.threshold, second_run.shares.0.clone()),
        (11, vec![9, 4, 1, 1])
    );
    let second = key_set(&sim.nodes[0], 1).unwrap();
    let holders: Vec<[u8; 32]> = [(0, 9), (1, 4), (2, 1), (3, 1)]
        .iter()
        .flat_map(|&(i, m)| std::iter::repeat_n(validator_id(&keys[i]), m))
        .collect();
    assert_eq!(second.shareholders.0, holders);
    assert_eq!(second.public_shares.0.len(), 15);
    // Key 0, dealt equally, handed off to the skewed key 1, and certificates follow it.
    let h = handoff(&mut sim.nodes[0], 0).unwrap();
    assert_eq!((h.from, h.to), (0, 1));
    let later = sim.nodes[0].finalized_height().unwrap() + 2;
    assert!(
        sim.run_until(40 * SLOT_MS, |s| bls_certificate(&s.nodes[0], later)
            .is_some())
            .unwrap()
    );
    let cert = bls_certificate(&sim.nodes[0], later).unwrap();
    assert_eq!(key_id_of(&cert), 1);
    assert!(verifies(&sim.nodes[0], &cert));
    // Which validators can sign with key 1: exactly the sets with more than two thirds
    // of epoch 1's stake. Validators 0 and 2 hold exactly two thirds and fall short.
    let message = certificate_message_v2(CHAIN_ID, 1, 99, &[7; 32]);
    let partials: Vec<Vec<PartialShare>> = (0..4)
        .map(|i| partials_of(&sim.nodes[0], &keys[i], 1, &message))
        .collect();
    assert_eq!(
        partials.iter().map(Vec::len).collect::<Vec<_>>(),
        [9, 4, 1, 1]
    );
    for mask in 1u32..16 {
        let members: Vec<usize> = (0..4).filter(|i| mask & (1 << i) != 0).collect();
        let stake: u64 = members.iter().map(|&i| weights[i]).sum();
        let request = KeystoreRequest::Combine {
            key_set: second.key_set.clone(),
            message: message.clone(),
            partials: Seq(members.iter().flat_map(|&i| partials[i].clone()).collect()),
        };
        let signed = Keystore::default()
            .handle(None, &request.to_bytes())
            .is_some();
        assert_eq!(signed, 3 * stake > 2 * 12 * STAKE, "{members:?}");
    }
    // Validator 3, a twelfth of the stake, stops: blocks and certificates go on.
    sim.crash(3);
    let resumed = sim.nodes[0].finalized_height().unwrap() + 3;
    assert!(
        sim.run_until(60 * SLOT_MS, |s| bls_certificate(&s.nodes[0], resumed)
            .is_some())
            .unwrap()
    );
    assert_eq!(evidence_count(&mut sim.nodes[0]), 0);
}
