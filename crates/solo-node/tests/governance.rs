//! Two-track governance end to end (spec 13 §9), over four validators whose
//! stakes differ: under the key the genesis key acts alone; it switches the
//! chain to the stake track and becomes the guardian; from then on
//! validators propose and vote by stake, a passed proposal waits out its
//! timelock and anyone executes it (a module install, a bridge parameter,
//! governance's own rules), one fails short of quorum and loses its
//! deposit, one fails with quorum and gets it back, the guardian vetoes one
//! and pauses the inbox at once, a pause passes on the fast track in the
//! vote that reaches a majority, a passed proposal nobody executes expires,
//! and a proposal upgrades the kernel across the network. On one node: the
//! bounds, the gas, a failing action, a fast-track cancel of a pending
//! upgrade, the genesis checks, and the selectors and topics.

mod support;

use k256::ecdsa::SigningKey;
use solo_abi::bridge_in::{BridgeInParams, InboxLimits, LIGHT_CLIENT_ADDRESS, VERIFIER_ADDRESS};
use solo_abi::chain::{
    Allocation, CallRequest, CallResult, GenesisParams, Receipt, UpgradeParams, Validator,
    ValidatorSet, call_status, reason,
};
use solo_abi::codec::Seq;
use solo_abi::governance::{
    self as gov, Ballot, Call, DelegatorBallot, GOVERNANCE_ADDRESS, GOVERNANCE_GAS,
    GovernanceParams, GovernanceStatus, MAX_CALL_GAS, MAX_OPEN_PROPOSALS, MAX_PROPOSAL_DATA,
    Proposal, ProposalView, event, mode, selector, status,
};
use solo_abi::modules::{self, INSTALLED_TOPIC, Install, MODULE_ADDRESS, capability};
use solo_abi::staking::{GWEI, STAKING_ADDRESS, StakingAction, StakingParams};
use solo_abi::types::Genesis;
use solo_abi::{Decode, Encode};
use solo_ethlc::abi;
use solo_ethlc::testing::Chain;
use solo_host::hash::keccak256;
use solo_node::{Node, NodeConfig, NodeError, Sim, SubmitError, Switch};
use solo_upgrade::action::proposed_log;
use solo_upgrade::{Action, query};
use solo_vm::status::Termination;
use support::{
    CHAIN_ID, ETHER, SLOT_MS, STAGE_GAS, Wallet, alice, governance, include, keys, run_until,
    stage_actions, tiny_kernel, v1, v2,
};

const COUNTER_ELF: &[u8] = include_bytes!("fixtures/counter.elf");
const LIGHT_CLIENT_ELF: &[u8] = include_bytes!("fixtures/eth-light-client.elf");
const VERIFIER_ELF: &[u8] = include_bytes!("fixtures/eth-message-verifier.elf");

/// Blocks a proposal takes votes for: room for a vote per block from each
/// of the four validators, and one changing its mind.
const VOTING: u64 = 6;
const TIMELOCK: u64 = 2;
const QUORUM: u64 = 5_000;
const DEPOSIT: u128 = ETHER;
/// Gas of a governance call: the intrinsic gas and the surcharge.
const GAS: u64 = 200_000;
/// The weights of the four validators: a total of 10.
const WEIGHTS: [u64; 4] = [5, 3, 1, 1];

fn module(elf: &[u8]) -> Vec<u8> {
    solo_recompile::recompile(
        &solo_recompile::Input::load(elf).unwrap(),
        &solo_recompile::Options::default(),
    )
    .unwrap()
}

/// The bridge of spec 18 on a synthetic beacon chain, so the inbox's
/// verifier exists to be paused.
fn bridge() -> BridgeInParams {
    let chain = Chain::minimal(32);
    BridgeInParams {
        light_client: module(LIGHT_CLIENT_ELF),
        verifier: module(VERIFIER_ELF),
        config: chain.config.clone(),
        bootstrap: chain.bootstrap(8, [3; 32]).encode(),
        outbox: [0xAA; 20],
        limits: InboxLimits {
            delay: 3,
            window: 3600,
            max_messages: 2,
        },
    }
}

/// Governance rules under `m`.
fn rules(m: u8) -> GovernanceParams {
    GovernanceParams {
        mode: m,
        voting_blocks: VOTING,
        timelock_blocks: TIMELOCK,
        quorum_bps: QUORUM,
        deposit: DEPOSIT,
    }
}

/// A chain of `validators` with `weights`, Alice funded, the test
/// governance key, and governance `rules`.
fn genesis(
    validators: &[SigningKey],
    weights: &[u64],
    rules: GovernanceParams,
    bridge: Option<BridgeInParams>,
) -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 16,
        allocations: Seq(vec![Allocation {
            address: alice().address,
            balance: 100 * ETHER,
            ..Allocation::default()
        }]),
        upgrades: UpgradeParams {
            governance: governance().address,
            min_delay: 2,
            epoch_blocks: 0,
        },
        bridge_in: bridge.unwrap_or_default(),
        governance: rules,
        ..GenesisParams::default()
    };
    let set = ValidatorSet {
        validators: Seq(validators
            .iter()
            .zip(weights)
            .map(|(k, &weight)| Validator {
                id: solo_node::validator_id(k),
                weight,
            })
            .collect()),
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: set.to_bytes(),
    }
}

/// An account that tracks its nonce.
struct Sender {
    wallet: Wallet,
    nonce: u64,
}

impl Sender {
    fn new(wallet: Wallet) -> Sender {
        Sender { wallet, nonce: 0 }
    }

    fn tx(&mut self, to: [u8; 20], value: u128, gas: u64, data: &[u8]) -> Vec<u8> {
        self.nonce += 1;
        self.wallet.tx(self.nonce - 1, to, value, gas, data)
    }

    /// A governance call carrying `value`.
    fn call(&mut self, call: &Call, value: u128) -> Vec<u8> {
        let gas = if matches!(call, Call::Submit { .. }) {
            STAGE_GAS
        } else {
            GAS
        };
        self.tx(GOVERNANCE_ADDRESS, value, gas, &call.encode())
    }

    /// The same call without using up a nonce: for transactions admission refuses.
    fn peek(&self, call: &Call, value: u128) -> Vec<u8> {
        self.wallet.tx(
            self.nonce,
            GOVERNANCE_ADDRESS,
            value,
            STAGE_GAS,
            &call.encode(),
        )
    }

    fn address(&self) -> [u8; 20] {
        self.wallet.address
    }
}

fn submit(target: [u8; 20], data: &[u8]) -> Call {
    Call::Submit {
        target,
        data: data.to_vec(),
    }
}

fn vote(id: u64, support: bool) -> Call {
    Call::Vote { id, support }
}

fn gov_status(node: &mut Node) -> GovernanceStatus {
    let r = node.query(gov::query::GOVERNANCE, &[]).unwrap();
    assert_eq!(r.status, 0);
    GovernanceStatus::from_bytes(&r.body).unwrap()
}

fn view(node: &mut Node, id: u64) -> Option<ProposalView> {
    let r = node.query(gov::query::PROPOSAL, &id.to_bytes()).unwrap();
    (r.status == 0).then(|| ProposalView::from_bytes(&r.body).unwrap())
}

fn balance(node: &mut Node, address: [u8; 20]) -> u128 {
    node.account(&address).unwrap().balance
}

fn call(node: &mut Node, from: [u8; 20], to: [u8; 20], data: &[u8]) -> CallResult {
    node.call(&CallRequest {
        from,
        to: Some(to),
        data: data.to_vec(),
        gas: 1_000_000,
        ..CallRequest::default()
    })
    .unwrap()
}

/// The verifier's `paused()`.
fn paused(node: &mut Node) -> bool {
    let out = call(node, alice().address, VERIFIER_ADDRESS, &abi::PAUSED).output;
    out == abi::word(1)
}

/// Submits `raw` to node 0 (gossip takes it to the others) and runs the
/// network until every node has executed it.
fn sim_include(sim: &mut Sim, raw: &[u8]) -> Receipt {
    let hash = sim.submit(0, raw).expect("admitted");
    let reached = sim
        .run_until(60 * SLOT_MS, |s| {
            s.nodes
                .iter_mut()
                .all(|n| n.receipt(&hash).unwrap().is_some())
        })
        .unwrap();
    assert!(reached, "transaction not executed everywhere");
    sim.nodes[0].receipt(&hash).unwrap().unwrap()
}

/// Runs the network until node 0 has executed block `height`.
fn sim_reach(sim: &mut Sim, height: u64) {
    let reached = sim
        .run_until(200 * SLOT_MS, |s| {
            s.nodes[0].block_number().unwrap() >= height
        })
        .unwrap();
    assert!(reached, "height {height} not reached");
}

fn refused() -> Result<[u8; 32], SubmitError> {
    Err(SubmitError::Rejected(reason::SYSTEM_ACTION))
}

/// Every node executed the same blocks.
fn assert_agreement(sim: &mut Sim) {
    let height = sim
        .nodes
        .iter_mut()
        .map(|n| n.block_number().unwrap())
        .min()
        .unwrap();
    let roots: Vec<_> = sim
        .nodes
        .iter_mut()
        .map(|n| n.block_by_number(height).unwrap().unwrap().state_root)
        .collect();
    assert!(roots.windows(2).all(|w| w[0] == w[1]), "{roots:?}");
}

/// The proposal record `submit` at `height` makes under the test rules.
fn expected(
    id: u64,
    proposer: [u8; 20],
    deposit: u128,
    target: [u8; 20],
    data: &[u8],
    height: u64,
) -> Proposal {
    let voting_end = height + VOTING;
    Proposal {
        id,
        proposer,
        deposit,
        target,
        data: data.to_vec(),
        submitted_at: height,
        voting_end,
        executable_at: voting_end + TIMELOCK + 1,
        expires_at: voting_end + TIMELOCK + VOTING,
        fast_track: false,
        status: status::VOTING,
        yes: 0,
        no: 0,
        total: 0,
        value: 0,
        gas: 0,
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_key_switches_the_chain_to_stake_governance_and_proposals_decide() {
    let validators = keys(4);
    let genesis = genesis(&validators, &WEIGHTS, rules(mode::KEY), Some(bridge()));
    let template = NodeConfig {
        now_ms: 10_000,
        ..NodeConfig::default()
    };
    let mut sim = Sim::new(v1(), &genesis, &validators, 0, &template, 30).unwrap();
    let mut key = Sender::new(governance());
    let mut alice = Sender::new(alice());
    let mut guardian = Sender::new(Wallet::new(0x61));
    let mut val: Vec<Sender> = validators
        .iter()
        .map(|k| Sender::new(Wallet::from_key(k.clone())))
        .collect();
    let guardian_action = Call::SetGuardian {
        guardian: guardian.address(),
    }
    .encode();

    // Under the key: nothing is open, nobody is guardian, and the calls of
    // the stake track, a submission by anyone but the key and an action no
    // proposal may carry are refused; a gas limit below the surcharge is
    // refused as the gas shortfall it is.
    let s = gov_status(&mut sim.nodes[0]);
    assert_eq!(
        (s.mode, s.key, s.guardian, s.next_id, s.proposals.0.len()),
        (mode::KEY, key.address(), [0; 20], 1, 0)
    );
    assert_eq!(s.params, rules(mode::KEY));
    let too_little = key.wallet.tx(
        0,
        GOVERNANCE_ADDRESS,
        0,
        60_000,
        &submit(GOVERNANCE_ADDRESS, &guardian_action).encode(),
    );
    assert_eq!(
        sim.submit(0, &too_little),
        Err(SubmitError::Rejected(reason::GAS_TOO_LOW))
    );
    for raw in [
        val[0].peek(&vote(1, true), 0),
        alice.peek(&Call::Execute { id: 1 }, 0),
        key.peek(&Call::Veto { id: 1 }, 0),
        key.peek(
            &Call::Pause {
                target: VERIFIER_ADDRESS,
            },
            0,
        ),
        alice.peek(&submit(GOVERNANCE_ADDRESS, &guardian_action), DEPOSIT),
        val[0].peek(&submit(GOVERNANCE_ADDRESS, &guardian_action), 0),
        key.peek(&submit(alice.address(), &abi::PAUSE), 0),
        key.peek(
            &submit(GOVERNANCE_ADDRESS, &Action::Signal { features: 1 }.encode()),
            0,
        ),
        key.peek(&submit(GOVERNANCE_ADDRESS, &guardian_action), 1),
    ] {
        assert_eq!(sim.submit(0, &raw), refused());
    }
    // The key names the guardian ahead of the switch and pauses, then
    // unpauses, the inbox at once, each a submission executed on the spot.
    let r = sim_include(
        &mut sim,
        &key.call(&submit(GOVERNANCE_ADDRESS, &guardian_action), 0),
    );
    assert_eq!(r.status, 1);
    assert_eq!(
        r.logs.0,
        vec![
            gov::enacted_log(&key.address(), &GOVERNANCE_ADDRESS, &guardian_action),
            gov::guardian_log(&guardian.address()),
        ]
    );
    assert_eq!(
        gov_status(&mut sim.nodes[0]).guardian,
        [0; 20],
        "no guardian under the key"
    );
    assert!(!paused(&mut sim.nodes[0]));
    let r = sim_include(
        &mut sim,
        &key.call(&submit(VERIFIER_ADDRESS, &abi::PAUSE), 0),
    );
    assert_eq!((r.status, r.gas_used > GOVERNANCE_GAS), (1, true));
    assert_eq!(
        r.logs.0,
        vec![gov::enacted_log(
            &key.address(),
            &VERIFIER_ADDRESS,
            &abi::PAUSE
        )]
    );
    assert!(paused(&mut sim.nodes[0]));
    let r = sim_include(
        &mut sim,
        &key.call(&submit(VERIFIER_ADDRESS, &abi::UNPAUSE), 0),
    );
    assert_eq!(r.status, 1);
    assert!(!paused(&mut sim.nodes[0]));
    // A submission whose action fails reverts: an unknown mode, and a
    // module action the verifier rejects. (The light client's actions run
    // in `bridge_in.rs`, on a chain whose feature gate 1 is active.)
    for data in [
        Call::SetMode { mode: 2 }.encode(),
        Call::SetMode { mode: mode::KEY }.encode(),
    ] {
        let r = sim_include(&mut sim, &key.call(&submit(GOVERNANCE_ADDRESS, &data), 0));
        assert_eq!((r.status, r.logs.0.len()), (0, 0), "{data:?}");
    }
    let r = sim_include(
        &mut sim,
        &key.call(
            &submit(
                VERIFIER_ADDRESS,
                &[abi::SET_RATE_LIMIT.as_slice(), &[1]].concat(),
            ),
            0,
        ),
    );
    assert_eq!((r.status, r.logs.0.len()), (0, 0));
    assert_eq!(gov_status(&mut sim.nodes[0]).mode, mode::KEY);

    // The switch: a proposal that passes under the key.
    let switch = Call::SetMode { mode: mode::STAKE }.encode();
    let r = sim_include(&mut sim, &key.call(&submit(GOVERNANCE_ADDRESS, &switch), 0));
    assert_eq!(r.status, 1);
    assert_eq!(
        r.logs.0,
        vec![
            gov::enacted_log(&key.address(), &GOVERNANCE_ADDRESS, &switch),
            gov::mode_log(mode::STAKE),
        ]
    );
    let s = gov_status(&mut sim.nodes[0]);
    assert_eq!((s.mode, s.guardian), (mode::STAKE, guardian.address()));
    assert_eq!(
        s.params,
        rules(mode::STAKE),
        "the rules read under the new mode"
    );
    // Irreversible, and the key's direct powers are gone: it neither
    // stages, proposes, cancels nor installs, and its submissions need the
    // deposit like anyone's; nobody proposes a mode.
    let counter = module(COUNTER_ELF);
    let counter_hash = keccak256(&counter);
    let stage = stage_actions(&counter);
    assert_eq!(stage.len(), 1);
    let install = Install {
        target: [0x48; 20],
        code_hash: counter_hash,
        capabilities: capability::HOOKS,
        init: 9u64.to_le_bytes().to_vec(),
    };
    let far = sim.nodes[0].block_number().unwrap() + 100;
    for raw in [
        key.wallet.action(key.nonce, &stage[0]),
        key.wallet.action(
            key.nonce,
            &Action::Propose {
                code_hash: counter_hash,
                activation_height: far,
                required_gates: 0,
            },
        ),
        key.wallet.action(
            key.nonce,
            &Action::Cancel {
                code_hash: counter_hash,
            },
        ),
        key.wallet
            .tx(key.nonce, MODULE_ADDRESS, 0, STAGE_GAS, &install.encode()),
        key.peek(
            &submit(
                GOVERNANCE_ADDRESS,
                &Call::SetMode { mode: mode::KEY }.encode(),
            ),
            0,
        ),
        key.peek(&submit(GOVERNANCE_ADDRESS, &guardian_action), 0),
        val[0].peek(&submit(GOVERNANCE_ADDRESS, &switch), 0),
        val[0].peek(
            &submit(
                GOVERNANCE_ADDRESS,
                &Call::SetMode { mode: mode::KEY }.encode(),
            ),
            0,
        ),
        alice.peek(&submit(GOVERNANCE_ADDRESS, &switch), DEPOSIT),
    ] {
        assert_eq!(sim.submit(0, &raw), refused());
    }
    // The key's own call to a bridge module is nobody's now: the modules
    // take governance from the governance address.
    let r = call(
        &mut sim.nodes[0],
        key.address(),
        VERIFIER_ADDRESS,
        &abi::PAUSE,
    );
    assert_eq!(
        (r.status, r.output),
        (call_status::REVERT, abi::encode(abi::NOT_GOVERNANCE, &[]))
    );
    // Validators stage code now; the key cannot.
    assert_eq!(
        sim_include(
            &mut sim,
            &val[0].tx(GOVERNANCE_ADDRESS, 0, STAGE_GAS, &stage[0].encode())
        )
        .status,
        1
    );

    // Proposal 1: Alice, no validator, proposes the module install with the
    // deposit; validators vote by stake; it passes, waits out the timelock,
    // and Alice executes it.
    let install_data = install.encode();
    for raw in [
        alice.peek(&submit(MODULE_ADDRESS, &install_data), 0),
        alice.peek(&submit(MODULE_ADDRESS, &install_data), DEPOSIT + 1),
        val[0].peek(&submit(MODULE_ADDRESS, &install_data), DEPOSIT),
        alice.peek(&submit(MODULE_ADDRESS, b"junk"), DEPOSIT),
        alice.peek(
            &submit(VERIFIER_ADDRESS, &vec![0xAB; MAX_PROPOSAL_DATA + 1]),
            DEPOSIT,
        ),
    ] {
        assert_eq!(sim.submit(0, &raw), refused());
    }
    let r = sim_include(
        &mut sim,
        &alice.call(&submit(MODULE_ADDRESS, &install_data), DEPOSIT),
    );
    assert_eq!(r.status, 1);
    let p1 = expected(
        1,
        alice.address(),
        DEPOSIT,
        MODULE_ADDRESS,
        &install_data,
        r.height,
    );
    assert_eq!(r.logs.0, vec![gov::submitted_log(&p1)]);
    let shown = view(&mut sim.nodes[0], 1).unwrap();
    assert_eq!(shown.proposal, p1);
    assert_eq!(
        (shown.yes, shown.no, shown.total, shown.votes.0.len()),
        (0, 0, 10, 0)
    );
    assert_eq!(
        balance(&mut sim.nodes[0], alice.address()),
        100 * ETHER - DEPOSIT
    );
    assert_eq!(balance(&mut sim.nodes[0], GOVERNANCE_ADDRESS), DEPOSIT);
    let s = gov_status(&mut sim.nodes[0]);
    assert_eq!((s.next_id, s.proposals.0.len()), (2, 1));
    // Only validators vote, only on open proposals; a vote may change.
    for raw in [
        alice.peek(&vote(1, true), 0),
        key.peek(&vote(1, true), 0),
        val[3].peek(&vote(9, true), 0),
        val[3].peek(&vote(1, true), 1),
        alice.peek(&Call::Execute { id: 1 }, 0),
    ] {
        assert_eq!(sim.submit(0, &raw), refused());
    }
    let r = sim_include(&mut sim, &val[0].call(&vote(1, true), 0));
    assert_eq!(r.status, 1);
    assert_eq!(
        r.logs.0,
        vec![gov::voted_log(1, &val[0].address(), true, 5)]
    );
    assert_eq!(
        sim_include(&mut sim, &val[1].call(&vote(1, true), 0)).status,
        1
    );
    assert_eq!(
        sim_include(&mut sim, &val[2].call(&vote(1, false), 0)).status,
        1
    );
    let shown = view(&mut sim.nodes[0], 1).unwrap();
    assert_eq!((shown.yes, shown.no, shown.total), (8, 1, 10));
    assert_eq!(
        shown.votes.0,
        vec![
            gov::Ballot {
                validator: solo_node::validator_id(&validators[0]),
                support: true,
                weight: 5
            },
            gov::Ballot {
                validator: solo_node::validator_id(&validators[1]),
                support: true,
                weight: 3
            },
            gov::Ballot {
                validator: solo_node::validator_id(&validators[2]),
                support: false,
                weight: 1
            },
        ]
    );
    assert_eq!(
        sim_include(&mut sim, &val[2].call(&vote(1, true), 0)).status,
        1
    );
    let shown = view(&mut sim.nodes[0], 1).unwrap();
    assert_eq!((shown.yes, shown.no, shown.votes.0.len()), (9, 0, 3));
    // Voting ends: tallied, passed, and closed to votes and still to execution.
    sim_reach(&mut sim, p1.voting_end + 1);
    let shown = view(&mut sim.nodes[0], 1).unwrap();
    assert_eq!(
        (
            shown.proposal.status,
            shown.proposal.yes,
            shown.proposal.no,
            shown.proposal.total
        ),
        (status::PASSED, 9, 0, 10)
    );
    for raw in [
        val[3].peek(&vote(1, true), 0),
        alice.peek(&Call::Execute { id: 1 }, 0),
    ] {
        assert_eq!(sim.submit(0, &raw), refused());
    }
    sim_reach(&mut sim, p1.executable_at - 1);
    let r = sim_include(&mut sim, &alice.call(&Call::Execute { id: 1 }, 0));
    assert_eq!((r.status, r.logs.0.len()), (1, 2));
    assert_eq!(r.logs.0[0], gov::executed_log(1));
    assert_eq!(r.logs.0[1].address, MODULE_ADDRESS);
    assert_eq!(r.logs.0[1].topics.0[0], INSTALLED_TOPIC);
    assert!(r.height >= p1.executable_at && r.height <= p1.expires_at);
    assert_eq!(
        sim.nodes[0]
            .query(modules::query::MODULE, &install.target.to_bytes())
            .unwrap()
            .status,
        0
    );
    assert_eq!(view(&mut sim.nodes[0], 1), None);
    assert_eq!(balance(&mut sim.nodes[0], alice.address()), 100 * ETHER);
    assert_eq!(balance(&mut sim.nodes[0], GOVERNANCE_ADDRESS), 0);
    // Never twice.
    assert_eq!(
        sim.submit(0, &alice.peek(&Call::Execute { id: 1 }, 0)),
        refused()
    );

    // Proposal 2 fails with quorum: the deposit comes back. Proposal 3
    // fails short of quorum: the deposit is burned.
    let limit = solo_ethlc::verifier::set_rate_limit_call(3600, 3);
    let r = sim_include(
        &mut sim,
        &alice.call(&submit(VERIFIER_ADDRESS, &limit), DEPOSIT),
    );
    assert_eq!((r.status, view(&mut sim.nodes[0], 2).is_some()), (1, true));
    let p2_end = r.height + VOTING;
    assert_eq!(
        sim_include(&mut sim, &val[0].call(&vote(2, true), 0)).status,
        1
    );
    assert_eq!(
        sim_include(&mut sim, &val[1].call(&vote(2, false), 0)).status,
        1
    );
    let r = sim_include(
        &mut sim,
        &alice.call(&submit(VERIFIER_ADDRESS, &limit), DEPOSIT),
    );
    assert_eq!(r.status, 1);
    let p3_end = r.height + VOTING;
    assert_eq!(
        sim_include(&mut sim, &val[2].call(&vote(3, true), 0)).status,
        1
    );
    assert_eq!(
        sim_include(&mut sim, &val[3].call(&vote(3, true), 0)).status,
        1
    );
    assert_eq!(
        balance(&mut sim.nodes[0], alice.address()),
        100 * ETHER - 2 * DEPOSIT
    );
    sim_reach(&mut sim, p3_end.max(p2_end) + 1);
    assert_eq!(
        (view(&mut sim.nodes[0], 2), view(&mut sim.nodes[0], 3)),
        (None, None)
    );
    assert_eq!(
        balance(&mut sim.nodes[0], alice.address()),
        100 * ETHER - DEPOSIT
    );
    assert_eq!(balance(&mut sim.nodes[0], [0; 20]), DEPOSIT);
    assert_eq!(balance(&mut sim.nodes[0], GOVERNANCE_ADDRESS), 0);
    let r = call(
        &mut sim.nodes[0],
        alice.address(),
        VERIFIER_ADDRESS,
        &abi::RATE_LIMIT,
    );
    assert_eq!(
        r.output,
        [abi::word(3600), abi::word(2)].concat(),
        "unchanged"
    );

    // Proposal 4, the rate limit again, passes and the guardian vetoes it
    // during the timelock. (A proposal that names a guardian it could not:
    // `the_validators_replace_a_guardian_that_vetoes`.)
    let r = sim_include(&mut sim, &val[0].call(&submit(VERIFIER_ADDRESS, &limit), 0));
    assert_eq!(r.status, 1);
    let p4 = expected(4, val[0].address(), 0, VERIFIER_ADDRESS, &limit, r.height);
    assert_eq!(view(&mut sim.nodes[0], 4).unwrap().proposal, p4);
    assert_eq!(
        sim_include(&mut sim, &val[0].call(&vote(4, true), 0)).status,
        1
    );
    sim_reach(&mut sim, p4.voting_end + 1);
    assert_eq!(
        view(&mut sim.nodes[0], 4).unwrap().proposal.status,
        status::PASSED
    );
    for raw in [
        alice.peek(&Call::Veto { id: 4 }, 0),
        key.peek(&Call::Veto { id: 4 }, 0),
        guardian.peek(&Call::Veto { id: 9 }, 0),
    ] {
        assert_eq!(sim.submit(0, &raw), refused());
    }
    let r = sim_include(&mut sim, &guardian.call(&Call::Veto { id: 4 }, 0));
    assert_eq!((r.status, r.logs.0), (1, vec![gov::vetoed_log(4)]));
    assert_eq!(view(&mut sim.nodes[0], 4), None);
    assert_eq!(gov_status(&mut sim.nodes[0]).guardian, guardian.address());
    sim_reach(&mut sim, p4.executable_at);
    assert_eq!(
        sim.submit(0, &alice.peek(&Call::Execute { id: 4 }, 0)),
        refused()
    );

    // Proposal 5 pauses the inbox on the fast track: it executes at the end
    // of the block whose votes take yes past half of all stake, half itself
    // not enough.
    let r = sim_include(
        &mut sim,
        &val[1].call(&submit(VERIFIER_ADDRESS, &abi::PAUSE), 0),
    );
    assert_eq!(r.status, 1);
    let shown = view(&mut sim.nodes[0], 5).unwrap();
    assert_eq!(
        (
            shown.proposal.fast_track,
            shown.proposal.executable_at,
            shown.proposal.expires_at
        ),
        (true, 0, r.height + VOTING)
    );
    assert_eq!(
        sim_include(&mut sim, &val[2].call(&vote(5, true), 0)).status,
        1
    );
    assert_eq!(
        sim_include(&mut sim, &val[3].call(&vote(5, true), 0)).status,
        1
    );
    assert_eq!(
        sim_include(&mut sim, &val[1].call(&vote(5, true), 0)).status,
        1
    );
    assert_eq!(view(&mut sim.nodes[0], 5).unwrap().yes, 5);
    assert!(!paused(&mut sim.nodes[0]));
    let r = sim_include(&mut sim, &val[0].call(&vote(5, true), 0));
    assert_eq!(r.status, 1);
    assert_eq!(
        r.logs.0,
        vec![gov::voted_log(5, &val[0].address(), true, 5)]
    );
    assert!(paused(&mut sim.nodes[0]));
    assert_eq!(view(&mut sim.nodes[0], 5), None);
    // Unpausing takes the normal track; anyone executes.
    let r = sim_include(
        &mut sim,
        &val[0].call(&submit(VERIFIER_ADDRESS, &abi::UNPAUSE), 0),
    );
    let p6 = expected(
        6,
        val[0].address(),
        0,
        VERIFIER_ADDRESS,
        &abi::UNPAUSE,
        r.height,
    );
    assert_eq!(
        sim_include(&mut sim, &val[0].call(&vote(6, true), 0)).status,
        1
    );
    assert_eq!(
        sim_include(&mut sim, &val[1].call(&vote(6, true), 0)).status,
        1
    );
    sim_reach(&mut sim, p6.executable_at - 1);
    let r = sim_include(&mut sim, &val[3].call(&Call::Execute { id: 6 }, 0));
    assert_eq!((r.status, r.logs.0), (1, vec![gov::executed_log(6)]));
    assert!(!paused(&mut sim.nodes[0]));
    // The guardian pauses at once, and nothing else.
    for raw in [
        alice.peek(
            &Call::Pause {
                target: VERIFIER_ADDRESS,
            },
            0,
        ),
        guardian.peek(
            &Call::Pause {
                target: LIGHT_CLIENT_ADDRESS,
            },
            0,
        ),
        guardian.peek(&submit(VERIFIER_ADDRESS, &abi::UNPAUSE), 0),
    ] {
        assert_eq!(sim.submit(0, &raw), refused());
    }
    let r = sim_include(
        &mut sim,
        &guardian.call(
            &Call::Pause {
                target: VERIFIER_ADDRESS,
            },
            0,
        ),
    );
    assert_eq!(r.status, 1);
    assert_eq!(
        r.logs.0,
        vec![gov::enacted_log(
            &guardian.address(),
            &VERIFIER_ADDRESS,
            &abi::PAUSE
        )]
    );
    assert!(paused(&mut sim.nodes[0]));

    // Proposal 7 changes the rules: shorter votes, no timelock, a smaller
    // quorum and no deposit, so only validators propose from then on.
    let new_rules = Call::SetParams {
        voting_blocks: 2,
        timelock_blocks: 0,
        quorum_bps: 3_000,
        deposit: 0,
    };
    let r = sim_include(
        &mut sim,
        &val[0].call(&submit(GOVERNANCE_ADDRESS, &new_rules.encode()), 0),
    );
    let p7 = expected(
        7,
        val[0].address(),
        0,
        GOVERNANCE_ADDRESS,
        &new_rules.encode(),
        r.height,
    );
    assert_eq!(
        sim_include(&mut sim, &val[0].call(&vote(7, true), 0)).status,
        1
    );
    sim_reach(&mut sim, p7.executable_at - 1);
    let r = sim_include(&mut sim, &val[0].call(&Call::Execute { id: 7 }, 0));
    let in_force = GovernanceParams {
        mode: mode::STAKE,
        voting_blocks: 2,
        timelock_blocks: 0,
        quorum_bps: 3_000,
        deposit: 0,
    };
    assert_eq!(
        (r.status, r.logs.0),
        (1, vec![gov::executed_log(7), gov::params_log(&in_force)])
    );
    assert_eq!(gov_status(&mut sim.nodes[0]).params, in_force);
    for raw in [
        alice.peek(&submit(GOVERNANCE_ADDRESS, &guardian_action), 0),
        alice.peek(&submit(GOVERNANCE_ADDRESS, &guardian_action), DEPOSIT),
    ] {
        assert_eq!(sim.submit(0, &raw), refused());
    }
    // Proposal 8 passes with 30% of the stake and nobody executes it: it expires.
    let r = sim_include(
        &mut sim,
        &val[1].call(&submit(GOVERNANCE_ADDRESS, &guardian_action), 0),
    );
    assert_eq!(r.status, 1);
    let p8 = view(&mut sim.nodes[0], 8).unwrap().proposal;
    assert_eq!(
        (p8.voting_end, p8.executable_at, p8.expires_at),
        (r.height + 2, r.height + 3, r.height + 4)
    );
    assert_eq!(
        sim_include(&mut sim, &val[1].call(&vote(8, true), 0)).status,
        1
    );
    sim_reach(&mut sim, p8.voting_end + 1);
    assert_eq!(
        view(&mut sim.nodes[0], 8).unwrap().proposal.status,
        status::PASSED
    );
    sim_reach(&mut sim, p8.expires_at + 1);
    assert_eq!(view(&mut sim.nodes[0], 8), None);
    assert_eq!(gov_status(&mut sim.nodes[0]).next_id, 9);
    // Proposal 9 sets the light client's delay. Its module needs feature
    // gate 1, which this chain never activates: the action fails when the
    // proposal executes, as a bridge call to a module that is not there
    // does (spec 13 §9.5), and the proposal is pruned all the same.
    let set_delay = abi::encode(abi::SET_DELAY, &[abi::word(11)]);
    let r = sim_include(
        &mut sim,
        &val[0].call(&submit(LIGHT_CLIENT_ADDRESS, &set_delay), 0),
    );
    assert_eq!(r.status, 1);
    assert_eq!(
        sim_include(&mut sim, &val[0].call(&vote(9, true), 0)).status,
        1
    );
    let p9 = view(&mut sim.nodes[0], 9).unwrap().proposal;
    sim_reach(&mut sim, p9.executable_at - 1);
    let r = sim_include(&mut sim, &alice.call(&Call::Execute { id: 9 }, 0));
    assert_eq!((r.status, r.logs.0.len()), (0, 0));
    assert_eq!(view(&mut sim.nodes[0], 9), None);
    assert_agreement(&mut sim);
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_proposal_upgrades_the_kernel_across_four_validators() {
    let validators = keys(4);
    // Under the stake track from genesis: the key is the guardian from the start.
    let genesis = genesis(&validators, &WEIGHTS, rules(mode::STAKE), None);
    let template = NodeConfig {
        now_ms: 10_000,
        ..NodeConfig::default()
    };
    let mut sim = Sim::new(v1(), &genesis, &validators, 0, &template, 30).unwrap();
    let key = Sender::new(governance());
    let mut alice = Sender::new(alice());
    let mut val: Vec<Sender> = validators
        .iter()
        .map(|k| Sender::new(Wallet::from_key(k.clone())))
        .collect();
    let s = gov_status(&mut sim.nodes[0]);
    assert_eq!((s.mode, s.guardian), (mode::STAKE, key.address()));
    let code = v2();
    let code_hash = keccak256(code);
    let stages = stage_actions(code);
    // The key cannot stage; validator 0 does.
    assert_eq!(sim.submit(0, &key.wallet.action(0, &stages[0])), refused());
    for action in &stages {
        let raw = val[0].tx(GOVERNANCE_ADDRESS, 0, STAGE_GAS, &action.encode());
        assert_eq!(sim_include(&mut sim, &raw).status, 1);
    }
    // The code hash is validator 0's: a byte another validator appends
    // after the last chunk, or writes over the first, changes nothing, so
    // nobody spoils what a proposal will hash. Its staker may still replace
    // a chunk of its own.
    let spoil = |index: u32| Action::Stage {
        code_hash,
        index,
        chunk: vec![0xFF],
    };
    for action in [spoil(u32::try_from(stages.len()).unwrap()), spoil(0)] {
        let raw = val[3].tx(GOVERNANCE_ADDRESS, 0, STAGE_GAS, &action.encode());
        assert_eq!(sim_include(&mut sim, &raw).status, 0);
    }
    let served = sim.nodes[0].query(query::CODE, &code_hash).unwrap();
    assert_eq!(Vec::<u8>::from_bytes(&served.body).unwrap(), code);
    let last = stages.len() - 1;
    let raw = val[0].tx(GOVERNANCE_ADDRESS, 0, STAGE_GAS, &stages[last].encode());
    assert_eq!(sim_include(&mut sim, &raw).status, 1);
    // A proposal over code that does not hash to its hash never opens: the
    // submission reverts and the deposit comes back.
    let wrong = Action::Stage {
        code_hash: [7; 32],
        index: 0,
        chunk: vec![1, 2, 3],
    };
    let raw = val[1].tx(GOVERNANCE_ADDRESS, 0, STAGE_GAS, &wrong.encode());
    assert_eq!(sim_include(&mut sim, &raw).status, 1);
    let far = sim.nodes[0].block_number().unwrap() + 100;
    let hopeless = Action::Propose {
        code_hash: [7; 32],
        activation_height: far,
        required_gates: 0,
    }
    .encode();
    let r = sim_include(
        &mut sim,
        &alice.call(&submit(GOVERNANCE_ADDRESS, &hopeless), DEPOSIT),
    );
    assert_eq!((r.status, r.logs.0.len()), (0, 0));
    assert_eq!(gov_status(&mut sim.nodes[0]).next_id, 1);
    assert_eq!(balance(&mut sim.nodes[0], alice.address()), 100 * ETHER);
    assert_eq!(balance(&mut sim.nodes[0], GOVERNANCE_ADDRESS), 0);
    // The proposal names an activation height that leaves room for the
    // vote, the timelock and the execution, plus the upgrade delay.
    let h = sim.nodes[0].block_number().unwrap() + VOTING + TIMELOCK + 1 + 2 + 12;
    let propose = Action::Propose {
        code_hash,
        activation_height: h,
        required_gates: 0,
    }
    .encode();
    let r = sim_include(
        &mut sim,
        &val[0].call(&submit(GOVERNANCE_ADDRESS, &propose), 0),
    );
    assert_eq!(r.status, 1);
    let p = expected(
        1,
        val[0].address(),
        0,
        GOVERNANCE_ADDRESS,
        &propose,
        r.height,
    );
    assert_eq!(view(&mut sim.nodes[0], 1).unwrap().proposal, p);
    // Code an open proposal names is frozen, for its staker too.
    let raw = val[0].tx(GOVERNANCE_ADDRESS, 0, STAGE_GAS, &stages[last].encode());
    assert_eq!(sim_include(&mut sim, &raw).status, 0);
    // Validators 0 and 1 carry 80% of the stake; validator 3 says no.
    assert_eq!(
        sim_include(&mut sim, &val[0].call(&vote(1, true), 0)).status,
        1
    );
    assert_eq!(
        sim_include(&mut sim, &val[1].call(&vote(1, true), 0)).status,
        1
    );
    assert_eq!(
        sim_include(&mut sim, &val[3].call(&vote(1, false), 0)).status,
        1
    );
    sim_reach(&mut sim, p.executable_at - 1);
    let shown = view(&mut sim.nodes[0], 1).unwrap().proposal;
    assert_eq!(
        (shown.status, shown.yes, shown.no, shown.total),
        (status::PASSED, 8, 1, 10)
    );
    let r = sim_include(&mut sim, &alice.call(&Call::Execute { id: 1 }, 0));
    assert_eq!(
        (r.status, r.logs.0),
        (
            1,
            vec![gov::executed_log(1), proposed_log(&code_hash, h, 0)]
        )
    );
    assert!(r.height + 2 <= h, "the delay holds");
    for (i, node) in sim.nodes.iter_mut().enumerate() {
        let pending = node.upgrade_status().unwrap().pending.unwrap();
        assert_eq!(
            (pending.code_hash, pending.activation_height),
            (code_hash, h),
            "node {i}"
        );
        assert_eq!(node.upgrades().prepared, Some(code_hash), "node {i}");
    }
    // Every validator switches at `h`; governance's state carries over.
    sim_reach(&mut sim, h + 3);
    let reached = sim
        .run_until(60 * SLOT_MS, |s| {
            s.nodes
                .iter()
                .all(|n| n.executed.last().is_some_and(|e| e.0 >= h + 3))
        })
        .unwrap();
    assert!(reached);
    for (i, node) in sim.nodes.iter_mut().enumerate() {
        assert_eq!(node.upgrades().switches.len(), 1, "node {i}");
        assert_eq!(
            Switch {
                held: 0,
                ..node.upgrades().switches[0].clone()
            },
            Switch {
                height: h,
                code_hash,
                from_version: 1,
                to_version: 2,
                held: 0,
            }
        );
        assert_eq!(node.kernel_version().unwrap(), 2);
        let s = gov_status(node);
        assert_eq!(
            (s.mode, s.guardian, s.next_id),
            (mode::STAKE, key.address(), 2)
        );
    }
    assert_agreement(&mut sim);
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_validators_replace_a_guardian_that_vetoes() {
    let validators = keys(4);
    // Under the stake track from genesis, with the bridge: the key is the guardian.
    let genesis = genesis(&validators, &WEIGHTS, rules(mode::STAKE), Some(bridge()));
    let template = NodeConfig {
        now_ms: 10_000,
        ..NodeConfig::default()
    };
    let mut sim = Sim::new(v1(), &genesis, &validators, 0, &template, 30).unwrap();
    let mut key = Sender::new(governance());
    let mut alice = Sender::new(alice());
    let mut val: Vec<Sender> = validators
        .iter()
        .map(|k| Sender::new(Wallet::from_key(k.clone())))
        .collect();
    assert_eq!(gov_status(&mut sim.nodes[0]).guardian, key.address());
    // Proposal 1 names Alice guardian, proposal 2 pauses the inbox on the
    // fast track, proposal 3 changes the rules. The guardian vetoes neither
    // of the first two, and the third at once.
    let name_alice = Call::SetGuardian {
        guardian: alice.address(),
    }
    .encode();
    let r = sim_include(
        &mut sim,
        &val[0].call(&submit(GOVERNANCE_ADDRESS, &name_alice), 0),
    );
    assert_eq!(r.status, 1);
    let p1 = expected(
        1,
        val[0].address(),
        0,
        GOVERNANCE_ADDRESS,
        &name_alice,
        r.height,
    );
    let r = sim_include(
        &mut sim,
        &val[1].call(&submit(VERIFIER_ADDRESS, &abi::PAUSE), 0),
    );
    assert_eq!(r.status, 1);
    let p2_end = r.height + VOTING;
    let new_rules = Call::SetParams {
        voting_blocks: 3,
        timelock_blocks: 1,
        quorum_bps: QUORUM,
        deposit: DEPOSIT,
    }
    .encode();
    assert_eq!(
        sim_include(
            &mut sim,
            &val[0].call(&submit(GOVERNANCE_ADDRESS, &new_rules), 0)
        )
        .status,
        1
    );
    for id in [1, 2] {
        assert_eq!(sim.submit(0, &key.peek(&Call::Veto { id }, 0)), refused());
    }
    let r = sim_include(&mut sim, &key.call(&Call::Veto { id: 3 }, 0));
    assert_eq!((r.status, r.logs.0), (1, vec![gov::vetoed_log(3)]));
    // 80% of the stake names Alice; the guardian cannot stop it while it
    // votes, nor once it has passed.
    assert_eq!(
        sim_include(&mut sim, &val[0].call(&vote(1, true), 0)).status,
        1
    );
    assert_eq!(
        sim_include(&mut sim, &val[1].call(&vote(1, true), 0)).status,
        1
    );
    sim_reach(&mut sim, p1.voting_end + 1);
    assert_eq!(
        view(&mut sim.nodes[0], 1).unwrap().proposal.status,
        status::PASSED
    );
    assert_eq!(
        sim.submit(0, &key.peek(&Call::Veto { id: 1 }, 0)),
        refused()
    );
    sim_reach(&mut sim, p1.executable_at - 1);
    let r = sim_include(&mut sim, &alice.call(&Call::Execute { id: 1 }, 0));
    assert_eq!(
        (r.status, r.logs.0),
        (
            1,
            vec![gov::executed_log(1), gov::guardian_log(&alice.address())]
        )
    );
    assert_eq!(gov_status(&mut sim.nodes[0]).guardian, alice.address());
    // The pause nobody voted for failed at its voting end.
    sim_reach(&mut sim, p2_end + 1);
    assert_eq!(view(&mut sim.nodes[0], 2), None);
    assert!(!paused(&mut sim.nodes[0]));
    // The old guardian is nobody; the new one vetoes, and governance goes
    // on: the rules change the old guardian vetoed passes.
    let r = sim_include(
        &mut sim,
        &val[0].call(&submit(GOVERNANCE_ADDRESS, &new_rules), 0),
    );
    assert_eq!(r.status, 1);
    assert_eq!(
        sim.submit(0, &key.peek(&Call::Veto { id: 4 }, 0)),
        refused()
    );
    let r = sim_include(&mut sim, &alice.call(&Call::Veto { id: 4 }, 0));
    assert_eq!((r.status, r.logs.0), (1, vec![gov::vetoed_log(4)]));
    let r = sim_include(
        &mut sim,
        &val[0].call(&submit(GOVERNANCE_ADDRESS, &new_rules), 0),
    );
    let p5 = expected(
        5,
        val[0].address(),
        0,
        GOVERNANCE_ADDRESS,
        &new_rules,
        r.height,
    );
    assert_eq!(
        sim_include(&mut sim, &val[0].call(&vote(5, true), 0)).status,
        1
    );
    assert_eq!(
        sim_include(&mut sim, &val[1].call(&vote(5, true), 0)).status,
        1
    );
    sim_reach(&mut sim, p5.executable_at - 1);
    let r = sim_include(&mut sim, &val[2].call(&Call::Execute { id: 5 }, 0));
    assert_eq!(r.status, 1);
    assert_eq!(
        gov_status(&mut sim.nodes[0]).params,
        GovernanceParams {
            mode: mode::STAKE,
            voting_blocks: 3,
            timelock_blocks: 1,
            quorum_bps: QUORUM,
            deposit: DEPOSIT,
        }
    );
    assert_agreement(&mut sim);
}

fn start(genesis: &Genesis) -> Node {
    let config = NodeConfig {
        now_ms: 1_000,
        key: Some(keys(1)[0].clone()),
        ..NodeConfig::default()
    };
    let mut node = Node::open(v1(), genesis, config).unwrap();
    node.start(None).unwrap();
    node
}

/// Runs `node` until it has executed `height`.
fn reach(node: &mut Node, height: u64) {
    run_until(node, 60, &mut |n| n.block_number().unwrap() >= height);
}

/// Rules with a voting period of `voting_blocks` and a timelock of one block.
fn single(voting_blocks: u64) -> GovernanceParams {
    GovernanceParams {
        mode: mode::STAKE,
        voting_blocks,
        timelock_blocks: 1,
        quorum_bps: QUORUM,
        deposit: DEPOSIT,
    }
}

#[test]
fn one_validator_meets_the_bounds_and_the_gas() {
    let validators = keys(1);
    let mut node = start(&genesis(&validators, &[1], single(40), None));
    let mut v0 = Sender::new(Wallet::from_key(validators[0].clone()));
    let guardian_action = Call::SetGuardian {
        guardian: [0xAB; 20],
    }
    .encode();
    // The gas of a vote is pinned: its intrinsic gas at the EIP-7623 floor
    // plus the surcharge (spec 13 §9.9).
    let r = include(
        &mut node,
        &v0.call(&submit(GOVERNANCE_ADDRESS, &guardian_action), 0),
    );
    assert_eq!(r.status, 1);
    let r = include(&mut node, &v0.call(&vote(1, true), 0));
    assert_eq!((r.status, r.gas_used), (1, 21_860 + GOVERNANCE_GAS));
    // The largest actions fit a block: a bridge action is checked by its
    // selector alone until it executes, an install decodes in full. The
    // largest submission with no zero byte in its action pays the EIP-7623
    // floor of its calldata and the surcharge (spec 13 §9.9).
    let mut big = abi::UNPAUSE.to_vec();
    big.resize(MAX_PROPOSAL_DATA, 0xFF);
    let calldata = submit(VERIFIER_ADDRESS, &big).encode();
    let r = include(
        &mut node,
        &v0.tx(GOVERNANCE_ADDRESS, 0, 3_000_000, &calldata),
    );
    assert_eq!(r.status, 1);
    #[allow(clippy::naive_bytecount)]
    let zeros = calldata.iter().filter(|b| **b == 0).count() as u64;
    let floor = 21_000 + 10 * (zeros + 4 * (calldata.len() as u64 - zeros));
    assert_eq!(r.gas_used, floor + GOVERNANCE_GAS);
    assert_eq!(r.gas_used, 1_382_960);
    assert_eq!(
        view(&mut node, 2).unwrap().proposal.data.len(),
        MAX_PROPOSAL_DATA
    );
    // An install proposal needs its code staged, so a few bytes are.
    let blob = vec![0xAB; 3];
    let staged = Action::Stage {
        code_hash: keccak256(&blob),
        index: 0,
        chunk: blob.clone(),
    };
    assert_eq!(
        include(
            &mut node,
            &v0.tx(GOVERNANCE_ADDRESS, 0, STAGE_GAS, &staged.encode())
        )
        .status,
        1
    );
    let big_install = Install {
        code_hash: keccak256(&blob),
        init: vec![7; modules::MAX_INIT_LEN],
        ..Install::default()
    }
    .encode();
    let r = include(
        &mut node,
        &v0.tx(
            GOVERNANCE_ADDRESS,
            0,
            3_000_000,
            &submit(MODULE_ADDRESS, &big_install).encode(),
        ),
    );
    assert_eq!(r.status, 1);
    assert_eq!(view(&mut node, 3).unwrap().proposal.data, big_install);
    // At most 16 proposals are open at once.
    for _ in 3..MAX_OPEN_PROPOSALS {
        assert_eq!(
            include(
                &mut node,
                &v0.call(&submit(GOVERNANCE_ADDRESS, &guardian_action), 0)
            )
            .status,
            1
        );
    }
    assert_eq!(gov_status(&mut node).proposals.0.len(), MAX_OPEN_PROPOSALS);
    assert_eq!(
        node.submit(&v0.peek(&submit(GOVERNANCE_ADDRESS, &guardian_action), 0)),
        refused()
    );
    // Unvoted, they all fail at their voting ends and the slots free up;
    // the one with the vote passed, and expires unexecuted.
    let last = gov_status(&mut node)
        .proposals
        .0
        .last()
        .unwrap()
        .proposal
        .voting_end;
    reach(&mut node, last + 1);
    let s = gov_status(&mut node);
    assert_eq!(s.proposals.0.len(), 1);
    let passed = &s.proposals.0[0].proposal;
    assert_eq!(
        (passed.id, passed.status, passed.yes, passed.total),
        (1, status::PASSED, 1, 1)
    );
    reach(&mut node, passed.expires_at + 1);
    assert_eq!(gov_status(&mut node).proposals.0.len(), 0);
    assert_eq!(
        gov_status(&mut node).guardian,
        governance().address,
        "nothing executed"
    );
    assert_eq!(gov_status(&mut node).next_id, 17);
}

#[test]
#[allow(clippy::too_many_lines)]
fn one_validator_meets_the_edge_cases() {
    let validators = keys(1);
    let mut node = start(&genesis(&validators, &[1], single(2), None));
    let mut v0 = Sender::new(Wallet::from_key(validators[0].clone()));
    let mut alice = Sender::new(alice());
    // A submission naming code that is not staged opens nothing: it
    // reverts, and the deposit it carried comes back.
    let unstaged = Install {
        target: [0x48; 20],
        code_hash: [9; 32],
        capabilities: 0,
        init: vec![],
    };
    let r = include(
        &mut node,
        &alice.call(&submit(MODULE_ADDRESS, &unstaged.encode()), DEPOSIT),
    );
    assert_eq!((r.status, r.logs.0.len()), (0, 0));
    assert_eq!(gov_status(&mut node).next_id, 1);
    assert_eq!(balance(&mut node, alice.address()), 100 * ETHER);
    // A passed proposal whose action fails (an install into the system
    // range) is executed once all the same: the receipt says so and the
    // proposal is gone.
    let tiny = tiny_kernel(&2u32.to_le_bytes(), false, None);
    let tiny_hash = keccak256(&tiny);
    for action in stage_actions(&tiny) {
        assert_eq!(
            include(
                &mut node,
                &v0.tx(GOVERNANCE_ADDRESS, 0, STAGE_GAS, &action.encode())
            )
            .status,
            1
        );
    }
    let mut system = [0u8; 20];
    system[19] = 0x42;
    let doomed = Install {
        target: system,
        code_hash: tiny_hash,
        capabilities: 0,
        init: vec![],
    };
    let r = include(
        &mut node,
        &alice.call(&submit(MODULE_ADDRESS, &doomed.encode()), DEPOSIT),
    );
    let id = 1;
    let p = view(&mut node, id).unwrap().proposal;
    assert_eq!(
        (p.voting_end, p.executable_at, p.expires_at),
        (r.height + 2, r.height + 4, r.height + 5)
    );
    assert_eq!(include(&mut node, &v0.call(&vote(id, true), 0)).status, 1);
    reach(&mut node, p.voting_end + 1);
    let r = include(&mut node, &alice.call(&Call::Execute { id }, 0));
    assert_eq!((r.status, r.logs.0.len()), (0, 0));
    assert_eq!(view(&mut node, id), None);
    assert_eq!(balance(&mut node, alice.address()), 100 * ETHER);
    assert_eq!(
        node.submit(&alice.peek(&Call::Execute { id }, 0)),
        refused()
    );
    // Rules that cannot work, no voting period or no quorum, are refused
    // when the proposal executes.
    for (id, bad_rules) in [
        (
            2,
            Call::SetParams {
                voting_blocks: 0,
                timelock_blocks: 0,
                quorum_bps: 10_001,
                deposit: 0,
            },
        ),
        (
            3,
            Call::SetParams {
                voting_blocks: 2,
                timelock_blocks: 0,
                quorum_bps: 0,
                deposit: 0,
            },
        ),
    ] {
        let r = include(
            &mut node,
            &v0.call(&submit(GOVERNANCE_ADDRESS, &bad_rules.encode()), 0),
        );
        assert_eq!(include(&mut node, &v0.call(&vote(id, true), 0)).status, 1);
        reach(&mut node, r.height + 2 + 1);
        let r = include(&mut node, &v0.call(&Call::Execute { id }, 0));
        assert_eq!(r.status, 0, "{bad_rules:?}");
        assert_eq!(gov_status(&mut node).params, single(2));
    }

    // A pending upgrade proposed by proposal, then cancelled on the fast
    // track at the end of the block whose vote reaches a majority.
    let h = node.block_number().unwrap() + 40;
    let propose = Action::Propose {
        code_hash: tiny_hash,
        activation_height: h,
        required_gates: 0,
    }
    .encode();
    let r = include(
        &mut node,
        &v0.call(&submit(GOVERNANCE_ADDRESS, &propose), 0),
    );
    let id = 4;
    assert_eq!(include(&mut node, &v0.call(&vote(id, true), 0)).status, 1);
    reach(&mut node, r.height + 2 + 1);
    let r = include(&mut node, &v0.call(&Call::Execute { id }, 0));
    assert_eq!(
        (r.status, r.logs.0),
        (
            1,
            vec![gov::executed_log(id), proposed_log(&tiny_hash, h, 0)]
        )
    );
    assert_eq!(
        node.upgrade_status().unwrap().pending.unwrap().code_hash,
        tiny_hash
    );
    let cancel = Action::Cancel {
        code_hash: tiny_hash,
    }
    .encode();
    let r = include(&mut node, &v0.call(&submit(GOVERNANCE_ADDRESS, &cancel), 0));
    let id = 5;
    assert!(view(&mut node, id).unwrap().proposal.fast_track);
    let r2 = include(&mut node, &v0.call(&vote(id, true), 0));
    assert_eq!(
        (r2.status, r2.logs.0),
        (1, vec![gov::voted_log(id, &v0.address(), true, 1)])
    );
    assert!(r2.height > r.height);
    assert_eq!(node.upgrade_status().unwrap().pending, None);
    assert_eq!(view(&mut node, id), None);
    // A fast-track proposal nobody carries fails at its voting end.
    let r = include(&mut node, &v0.call(&submit(GOVERNANCE_ADDRESS, &cancel), 0));
    assert!(view(&mut node, 6).is_some());
    reach(&mut node, r.height + 2 + 1);
    assert_eq!(view(&mut node, 6), None);
    // The governance queries refuse malformed parameters.
    assert_eq!(node.query(gov::query::PROPOSAL, &[1, 2]).unwrap().status, 2);
    assert_eq!(node.query(query::CODE, &tiny_hash).unwrap().status, 0);
}

#[test]
fn a_chain_without_a_key_has_no_guardian_until_a_proposal_names_one() {
    let validators = keys(1);
    let mut genesis = genesis(&validators, &[1], rules(mode::STAKE), None);
    let mut params = GenesisParams::from_bytes(&genesis.params).unwrap();
    params.upgrades.governance = [0; 20];
    genesis.params = params.to_bytes();
    let mut node = start(&genesis);
    let mut v0 = Sender::new(Wallet::from_key(validators[0].clone()));
    let mut guardian = Sender::new(Wallet::new(0x61));
    let s = gov_status(&mut node);
    assert_eq!((s.mode, s.key, s.guardian), (mode::STAKE, [0; 20], [0; 20]));
    let name = Call::SetGuardian {
        guardian: guardian.address(),
    }
    .encode();
    let r = include(&mut node, &v0.call(&submit(GOVERNANCE_ADDRESS, &name), 0));
    let p = expected(1, v0.address(), 0, GOVERNANCE_ADDRESS, &name, r.height);
    assert_eq!(include(&mut node, &v0.call(&vote(1, true), 0)).status, 1);
    reach(&mut node, p.voting_end + 1);
    // Nobody can veto yet.
    assert_eq!(
        node.submit(&guardian.peek(&Call::Veto { id: 1 }, 0)),
        refused()
    );
    reach(&mut node, p.executable_at - 1);
    let r = include(&mut node, &v0.call(&Call::Execute { id: 1 }, 0));
    assert_eq!(
        (r.status, r.logs.0),
        (
            1,
            vec![gov::executed_log(1), gov::guardian_log(&guardian.address())]
        )
    );
    assert_eq!(gov_status(&mut node).guardian, guardian.address());
    // Now the guardian vetoes a change of rules; and a guardian set to zero
    // is none again.
    let tweak = Call::SetParams {
        voting_blocks: VOTING,
        timelock_blocks: 1,
        quorum_bps: QUORUM,
        deposit: 0,
    }
    .encode();
    let r = include(&mut node, &v0.call(&submit(GOVERNANCE_ADDRESS, &tweak), 0));
    assert_eq!(r.status, 1);
    let r = include(&mut node, &guardian.call(&Call::Veto { id: 2 }, 0));
    assert_eq!((r.status, r.logs.0), (1, vec![gov::vetoed_log(2)]));
    let clear = Call::SetGuardian { guardian: [0; 20] }.encode();
    let r = include(&mut node, &v0.call(&submit(GOVERNANCE_ADDRESS, &clear), 0));
    let p = expected(3, v0.address(), 0, GOVERNANCE_ADDRESS, &clear, r.height);
    assert_eq!(include(&mut node, &v0.call(&vote(3, true), 0)).status, 1);
    reach(&mut node, p.executable_at - 1);
    assert_eq!(
        include(&mut node, &v0.call(&Call::Execute { id: 3 }, 0)).status,
        1
    );
    assert_eq!(gov_status(&mut node).guardian, [0; 20]);
    let r = include(&mut node, &v0.call(&submit(GOVERNANCE_ADDRESS, &name), 0));
    assert_eq!(r.status, 1);
    assert_eq!(
        node.submit(&guardian.peek(&Call::Veto { id: 4 }, 0)),
        refused()
    );
}

#[test]
fn genesis_refuses_rules_that_cannot_work() {
    let validators = keys(1);
    let trap = |rules: GovernanceParams| {
        let genesis = genesis(&validators, &[1], rules.clone(), None);
        let config = NodeConfig {
            now_ms: 1_000,
            key: Some(validators[0].clone()),
            ..NodeConfig::default()
        };
        assert_eq!(
            Node::open(v1(), &genesis, config).err(),
            Some(NodeError::Kernel {
                export: "kernel_init",
                status: Termination::Trap
            }),
            "{rules:?}"
        );
    };
    trap(GovernanceParams {
        mode: 2,
        ..rules(mode::KEY)
    });
    trap(GovernanceParams {
        quorum_bps: 10_001,
        ..rules(mode::KEY)
    });
    trap(GovernanceParams {
        voting_blocks: 0,
        ..rules(mode::STAKE)
    });
    trap(GovernanceParams {
        quorum_bps: 0,
        ..rules(mode::STAKE)
    });
    // The key track needs neither a voting period nor a quorum: `setMode`
    // checks both at the switch, and `setParams` takes no rules without them.
    let mut node = start(&genesis(
        &validators,
        &[1],
        GovernanceParams::default(),
        None,
    ));
    let mut key = Sender::new(governance());
    let switch = Call::SetMode { mode: mode::STAKE }.encode();
    let r = include(
        &mut node,
        &key.call(&submit(GOVERNANCE_ADDRESS, &switch), 0),
    );
    assert_eq!((r.status, gov_status(&mut node).mode), (0, mode::KEY));
    let no_quorum = Call::SetParams {
        voting_blocks: 1,
        timelock_blocks: 0,
        quorum_bps: 0,
        deposit: 0,
    }
    .encode();
    assert_eq!(
        include(
            &mut node,
            &key.call(&submit(GOVERNANCE_ADDRESS, &no_quorum), 0)
        )
        .status,
        0
    );
    let fix = Call::SetParams {
        voting_blocks: 1,
        timelock_blocks: 0,
        quorum_bps: 1,
        deposit: 0,
    }
    .encode();
    assert_eq!(
        include(&mut node, &key.call(&submit(GOVERNANCE_ADDRESS, &fix), 0)).status,
        1
    );
    assert_eq!(gov_status(&mut node).params.mode, mode::KEY);
    let r = include(
        &mut node,
        &key.call(&submit(GOVERNANCE_ADDRESS, &switch), 0),
    );
    assert_eq!((r.status, gov_status(&mut node).mode), (1, mode::STAKE));
    // The rules `setParams` recorded now read as the stake track's.
    assert_eq!(
        gov_status(&mut node).params,
        GovernanceParams {
            mode: mode::STAKE,
            voting_blocks: 1,
            timelock_blocks: 0,
            quorum_bps: 1,
            deposit: 0,
        }
    );
    // Under the key the module address took the key's installs; a chain
    // without a key under the key track takes nothing at all.
    let mut genesis = genesis(&validators, &[1], GovernanceParams::default(), None);
    let mut params = GenesisParams::from_bytes(&genesis.params).unwrap();
    params.upgrades.governance = [0; 20];
    genesis.params = params.to_bytes();
    let mut node = start(&genesis);
    assert_eq!(
        node.submit(&key.peek(&submit(GOVERNANCE_ADDRESS, &switch), 0)),
        refused()
    );
    assert_eq!(gov_status(&mut node).guardian, [0; 20]);
}

#[test]
fn selectors_and_topics_are_the_solidity_ones() {
    let sel = |sig: &str| -> [u8; 4] { keccak256(sig.as_bytes())[..4].try_into().unwrap() };
    assert_eq!(sel("submit(address,bytes)"), selector::SUBMIT);
    assert_eq!(sel("vote(uint64,bool)"), selector::VOTE);
    assert_eq!(sel("execute(uint64)"), selector::EXECUTE);
    assert_eq!(sel("veto(uint64)"), selector::VETO);
    assert_eq!(sel("pause(address)"), selector::PAUSE);
    assert_eq!(sel("setGuardian(address)"), selector::SET_GUARDIAN);
    assert_eq!(sel("setMode(uint8)"), selector::SET_MODE);
    assert_eq!(
        sel("setParams(uint64,uint64,uint64,uint256)"),
        selector::SET_PARAMS
    );
    assert_eq!(
        sel("submitCall(address,uint256,uint64,bytes)"),
        selector::SUBMIT_CALL
    );
    assert_eq!(sel("reject(uint64)"), selector::REJECT);
    assert_eq!(
        keccak256(b"CallExecuted(uint64,address,bool,uint64,bytes)"),
        event::CALL_EXECUTED
    );
    assert_eq!(
        keccak256(b"ProposalSubmitted(uint64,address,address,bytes,uint64)"),
        event::SUBMITTED
    );
    assert_eq!(
        keccak256(b"Voted(uint64,address,bool,uint64)"),
        event::VOTED
    );
    assert_eq!(keccak256(b"ProposalExecuted(uint64)"), event::EXECUTED);
    assert_eq!(keccak256(b"ProposalVetoed(uint64)"), event::VETOED);
    assert_eq!(keccak256(b"Enacted(address,address,bytes)"), event::ENACTED);
    assert_eq!(keccak256(b"GuardianSet(address)"), event::GUARDIAN_SET);
    assert_eq!(keccak256(b"ModeSet(uint8)"), event::MODE_SET);
    assert_eq!(
        keccak256(b"ParamsSet(uint64,uint64,uint64,uint256)"),
        event::PARAMS_SET
    );
    // The governance calls share the address with the upgrade actions and
    // no selector with them.
    for new in [
        selector::SUBMIT,
        selector::VOTE,
        selector::EXECUTE,
        selector::VETO,
        selector::PAUSE,
        selector::SET_GUARDIAN,
        selector::SET_MODE,
        selector::SET_PARAMS,
        selector::SUBMIT_CALL,
        selector::REJECT,
    ] {
        for old in [
            solo_upgrade::action::selector::STAGE,
            solo_upgrade::action::selector::PROPOSE,
            solo_upgrade::action::selector::CANCEL,
            solo_upgrade::action::selector::SIGNAL,
        ] {
            assert_ne!(new, old);
        }
    }
}

/// An account with code at a plain address: stores its first calldata word
/// in slot 0 and the value it received in slot 1, emits an empty log, and
/// reverts when the calldata is empty.
const TARGET: [u8; 20] = [0x77; 20];
const TARGET_CODE: [u8; 26] = [
    0x36, 0x15, 0x60, 0x15, 0x57, 0x60, 0x00, 0x35, 0x60, 0x00, 0x55, 0x34, 0x60, 0x01, 0x55, 0x60,
    0x00, 0x60, 0x00, 0xa0, 0x00, 0x5b, 0x60, 0x00, 0x80, 0xfd,
];

/// The intrinsic gas of `execute(id)` for an id of one non-zero byte, at
/// the EIP-7623 floor.
const EXECUTE_INTRINSIC: u64 = 21_510;

/// A chain of one validator of weight 100 (100 gwei of stake), with staking
/// on if `staking`, `funded` accounts with 100 ether each, the target, and
/// 5 ether at the governance address.
fn staked(rules: GovernanceParams, funded: &[[u8; 20]], staking: bool) -> Genesis {
    staked_with(100, rules, funded, staking)
}

/// [`staked`] with a validator of `weight`.
fn staked_with(
    weight: u64,
    rules: GovernanceParams,
    funded: &[[u8; 20]],
    staking: bool,
) -> Genesis {
    let mut g = genesis(&keys(1), &[weight], rules, None);
    let mut params = GenesisParams::from_bytes(&g.params).unwrap();
    if staking {
        params.staking = StakingParams {
            epoch_blocks: 10_000,
            unbonding_epochs: 0,
            min_stake: 0,
            max_validators: 0,
            dkg_phase_blocks: 0,
            max_key_age: 0,
            keys: Seq(vec![]),
        };
    }
    for address in funded {
        params.allocations.0.push(Allocation {
            address: *address,
            balance: 100 * ETHER,
            ..Allocation::default()
        });
    }
    params.allocations.0.push(Allocation {
        address: GOVERNANCE_ADDRESS,
        balance: 5 * ETHER,
        ..Allocation::default()
    });
    params.allocations.0.push(Allocation {
        address: TARGET,
        code: TARGET_CODE.to_vec(),
        ..Allocation::default()
    });
    g.params = params.to_bytes();
    g
}

fn slot(node: &mut Node, address: [u8; 20], index: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[31] = index;
    node.storage(&address, &key).unwrap()
}

/// The gas a governed call used, from its `CallExecuted` log.
fn call_gas(log: &solo_abi::chain::Log) -> u64 {
    u64::from_be_bytes(log.data[56..64].try_into().unwrap())
}

/// The target's empty log.
fn target_log() -> solo_abi::chain::Log {
    solo_abi::chain::Log {
        address: TARGET,
        topics: Seq(vec![]),
        data: vec![],
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn delegators_vote_and_proposals_call_any_account() {
    let validators = keys(1);
    let mut alice = Sender::new(alice());
    let mut bob = Sender::new(Wallet::new(0x62));
    let mut carol = Sender::new(Wallet::new(0x63));
    let rules = GovernanceParams {
        mode: mode::STAKE,
        voting_blocks: VOTING,
        timelock_blocks: 1,
        quorum_bps: QUORUM,
        deposit: DEPOSIT,
    };
    let mut node = start(&staked(rules, &[bob.address(), carol.address()], true));
    let mut v0 = Sender::new(Wallet::from_key(validators[0].clone()));
    let validator = v0.address();
    let delegate = |s: &mut Sender, gwei: u128| {
        s.tx(
            STAKING_ADDRESS,
            gwei * GWEI,
            200_000,
            &StakingAction::Delegate { validator }.encode(),
        )
    };
    assert_eq!(include(&mut node, &delegate(&mut alice, 60)).status, 1);
    assert_eq!(include(&mut node, &delegate(&mut bob, 40)).status, 1);

    // Proposal 1: the governance address calls the target with an ether.
    let forty_two = gov::word(42).to_vec();
    let call1 = Call::SubmitCall {
        target: TARGET,
        value: ETHER,
        gas: 100_000,
        data: forty_two.clone(),
    };
    assert_eq!(include(&mut node, &v0.call(&call1, 0)).status, 1);
    let p = view(&mut node, 1).unwrap();
    assert!(p.proposal.is_call() && !p.proposal.fast_track);
    assert_eq!(
        (p.proposal.target, p.proposal.value, p.proposal.gas),
        (TARGET, ETHER, 100_000)
    );
    assert_eq!(p.proposal.data, forty_two);
    assert_eq!((p.yes, p.no, p.total), (0, 0, 200));
    // Carol has no stake behind anyone, so no vote.
    assert_eq!(node.submit(&carol.peek(&vote(1, true), 0)), refused());
    // The validator's vote carries its own stake and its delegators'; a
    // delegator who votes takes its own with it (spec 13 §9.3).
    let r = include(&mut node, &v0.call(&vote(1, true), 0));
    assert_eq!(r.logs.0, vec![gov::voted_log(1, &validator, true, 200)]);
    let r = include(&mut node, &alice.call(&vote(1, false), 0));
    assert_eq!(
        r.logs.0,
        vec![gov::voted_log(1, &alice.address(), false, 60)]
    );
    let p = view(&mut node, 1).unwrap();
    assert_eq!((p.yes, p.no, p.total), (140, 60, 200));
    assert_eq!(
        p.votes.0,
        vec![Ballot {
            validator: solo_node::validator_id(&validators[0]),
            support: true,
            weight: 140,
        }]
    );
    assert_eq!(
        p.delegators.0,
        vec![DelegatorBallot {
            delegator: alice.address(),
            support: false,
            weight: 60,
        }]
    );
    // Bob votes no, then yes: one ballot, his latest vote.
    include(&mut node, &bob.call(&vote(1, false), 0));
    let p = view(&mut node, 1).unwrap();
    assert_eq!((p.yes, p.no), (100, 100));
    include(&mut node, &bob.call(&vote(1, true), 0));
    let p = view(&mut node, 1).unwrap();
    assert_eq!((p.yes, p.no), (140, 60));
    assert_eq!(p.delegators.0.len(), 2);
    // Alice undelegates half: stake that is unbonding votes for nobody, and
    // the whole stake shrinks with it.
    let undelegate = StakingAction::Undelegate {
        validator,
        amount: 30 * GWEI,
    }
    .encode();
    assert_eq!(
        include(
            &mut node,
            &alice.tx(STAKING_ADDRESS, 0, 200_000, &undelegate)
        )
        .status,
        1
    );
    let p = view(&mut node, 1).unwrap();
    assert_eq!((p.yes, p.no, p.total), (140, 30, 170));
    // Voting ends: passed, the tally recorded.
    reach(&mut node, p.proposal.voting_end);
    let p = view(&mut node, 1).unwrap();
    assert_eq!(
        (
            p.proposal.status,
            p.proposal.yes,
            p.proposal.no,
            p.proposal.total
        ),
        (status::PASSED, 140, 30, 170)
    );
    // `execute` needs the call's gas beside the surcharge: an estimate says
    // so, and a limit one short is refused as the shortfall it is.
    let execute = Call::Execute { id: 1 }.encode();
    let needed = EXECUTE_INTRINSIC + GOVERNANCE_GAS + 100_000;
    reach(&mut node, p.proposal.executable_at - 1);
    assert_eq!(
        call(&mut node, carol.address(), GOVERNANCE_ADDRESS, &execute).gas_used,
        needed
    );
    let short = carol
        .wallet
        .tx(carol.nonce, GOVERNANCE_ADDRESS, 0, needed - 1, &execute);
    assert_eq!(
        node.submit(&short),
        Err(SubmitError::Rejected(reason::GAS_TOO_LOW))
    );
    // Anyone executes it; the executor pays the call's gas, and the receipt
    // records what the call did.
    let r = include(&mut node, &carol.call(&Call::Execute { id: 1 }, 0));
    let used = call_gas(&r.logs.0[2]);
    // Intrinsic gas, two storage slots set from zero, and the log (spec 13 §9.9).
    assert_eq!(used, 65_753);
    assert_eq!(
        (r.status, r.gas_used),
        (1, EXECUTE_INTRINSIC + GOVERNANCE_GAS + used)
    );
    assert_eq!(
        r.logs.0,
        vec![
            gov::executed_log(1),
            target_log(),
            gov::call_executed_log(1, &TARGET, true, used, &[]),
        ]
    );
    assert_eq!(slot(&mut node, TARGET, 0), gov::word(42));
    assert_eq!(slot(&mut node, TARGET, 1), gov::word(ETHER));
    assert_eq!(balance(&mut node, TARGET), ETHER);
    assert_eq!(balance(&mut node, GOVERNANCE_ADDRESS), 4 * ETHER);
    assert_eq!(view(&mut node, 1), None);

    // Proposal 2 calls the target with no calldata, which reverts; proposal
    // 3 asks for more than the governance address holds beyond the deposits
    // of open proposals; proposal 4 is Alice's, with a deposit.
    let revert = Call::SubmitCall {
        target: TARGET,
        value: 0,
        gas: 100_000,
        data: vec![],
    };
    let greedy = Call::SubmitCall {
        target: TARGET,
        value: 4 * ETHER + 1,
        gas: 100_000,
        data: forty_two,
    };
    let r2 = include(&mut node, &v0.call(&revert, 0));
    include(&mut node, &v0.call(&vote(2, true), 0));
    let r3 = include(&mut node, &v0.call(&greedy, 0));
    include(&mut node, &v0.call(&vote(3, true), 0));
    let alice_before = balance(&mut node, alice.address());
    let guardian = Call::SetGuardian {
        guardian: [0xAB; 20],
    }
    .encode();
    assert_eq!(
        include(
            &mut node,
            &alice.call(&submit(GOVERNANCE_ADDRESS, &guardian), DEPOSIT)
        )
        .status,
        1
    );
    assert_eq!(balance(&mut node, GOVERNANCE_ADDRESS), 4 * ETHER + DEPOSIT);
    // Proposal 5 withdraws proposal 4 on the fast track: Alice's vote
    // against it is not enough to hold it, the validator's yes passes it at
    // the end of its block, and her deposit comes back.
    let reject = Call::Reject { id: 4 }.encode();
    include(&mut node, &v0.call(&submit(GOVERNANCE_ADDRESS, &reject), 0));
    assert!(view(&mut node, 5).unwrap().proposal.fast_track);
    include(&mut node, &alice.call(&vote(5, false), 0));
    assert!(view(&mut node, 5).is_some());
    let r = include(&mut node, &v0.call(&vote(5, true), 0));
    assert_eq!(r.logs.0, vec![gov::voted_log(5, &validator, true, 170)]);
    assert_eq!((view(&mut node, 4), view(&mut node, 5)), (None, None));
    assert_eq!(balance(&mut node, alice.address()), alice_before);
    assert_eq!(balance(&mut node, GOVERNANCE_ADDRESS), 4 * ETHER);
    // A call that reverts leaves nothing behind but its gas and the record
    // of its failure; the proposal is executed all the same.
    reach(&mut node, r2.height + VOTING + 1);
    let r = include(&mut node, &carol.call(&Call::Execute { id: 2 }, 0));
    let used = call_gas(&r.logs.0[1]);
    assert!(used > 21_000, "{used}");
    assert_eq!(
        (r.status, r.logs.0.clone()),
        (
            1,
            vec![
                gov::executed_log(2),
                gov::call_executed_log(2, &TARGET, false, used, &[])
            ]
        )
    );
    assert_eq!(slot(&mut node, TARGET, 0), gov::word(42));
    assert_eq!(view(&mut node, 2), None);
    // Neither can a call spend what the governance address does not hold:
    // it does not run, and uses no gas.
    reach(&mut node, r3.height + VOTING + 1);
    let r = include(&mut node, &carol.call(&Call::Execute { id: 3 }, 0));
    assert_eq!(
        (r.status, r.gas_used, r.logs.0),
        (
            1,
            EXECUTE_INTRINSIC + GOVERNANCE_GAS,
            vec![
                gov::executed_log(3),
                gov::call_executed_log(3, &TARGET, false, 0, &[])
            ]
        )
    );
    assert_eq!(balance(&mut node, GOVERNANCE_ADDRESS), 4 * ETHER);
    assert_eq!(gov_status(&mut node).proposals.0, vec![]);
}

#[test]
fn a_delegator_needs_a_share_of_the_stake_to_vote() {
    let validators = keys(1);
    let mut dave = Sender::new(Wallet::new(0x64));
    let mut erin = Sender::new(Wallet::new(0x65));
    let mut node = start(&staked_with(
        5_000,
        single(20),
        &[dave.address(), erin.address()],
        true,
    ));
    let mut v0 = Sender::new(Wallet::from_key(validators[0].clone()));
    let validator = v0.address();
    for (who, gwei) in [(&mut dave, 1u128), (&mut erin, 2)] {
        let raw = who.tx(
            STAKING_ADDRESS,
            gwei * GWEI,
            200_000,
            &StakingAction::Delegate { validator }.encode(),
        );
        assert_eq!(include(&mut node, &raw).status, 1);
    }
    let guardian = Call::SetGuardian {
        guardian: [0xAB; 20],
    }
    .encode();
    include(
        &mut node,
        &v0.call(&submit(GOVERNANCE_ADDRESS, &guardian), 0),
    );
    // 1 gwei of 5 003 is less than a 4 096th: Dave's validator speaks for him.
    assert_eq!(node.submit(&dave.peek(&vote(1, false), 0)), refused());
    let r = include(&mut node, &erin.call(&vote(1, false), 0));
    assert_eq!(r.logs.0, vec![gov::voted_log(1, &erin.address(), false, 2)]);
    let p = view(&mut node, 1).unwrap();
    assert_eq!((p.yes, p.no, p.total), (0, 2, 5_003));
}

#[test]
fn the_key_calls_any_account_at_once() {
    let mut node = start(&staked(rules(mode::KEY), &[], false));
    let mut key = Sender::new(governance());
    let seven = gov::word(7).to_vec();
    let call7 = Call::SubmitCall {
        target: TARGET,
        value: 3,
        gas: 100_000,
        data: seven.clone(),
    };
    let r = include(&mut node, &key.call(&call7, 0));
    let used = call_gas(&r.logs.0[2]);
    assert_eq!(
        r.logs.0,
        vec![
            gov::enacted_log(&key.address(), &TARGET, &seven),
            target_log(),
            gov::call_executed_log(0, &TARGET, true, used, &[]),
        ]
    );
    assert_eq!(slot(&mut node, TARGET, 0), gov::word(7));
    assert_eq!(balance(&mut node, TARGET), 3);
    // Not to a system address, not with more than the most gas a call
    // carries, and no `reject` without proposals.
    let staking = Call::SubmitCall {
        target: STAKING_ADDRESS,
        value: 0,
        gas: 100_000,
        data: vec![],
    };
    assert_eq!(node.submit(&key.peek(&staking, 0)), refused());
    let heavy = Call::SubmitCall {
        target: TARGET,
        value: 0,
        gas: MAX_CALL_GAS + 1,
        data: vec![],
    };
    let raw = key.wallet.tx(
        key.nonce,
        GOVERNANCE_ADDRESS,
        0,
        11_000_000,
        &heavy.encode(),
    );
    assert_eq!(node.submit(&raw), refused());
    let reject = submit(GOVERNANCE_ADDRESS, &Call::Reject { id: 1 }.encode());
    assert_eq!(node.submit(&key.peek(&reject, 0)), refused());
    // Only the key: a call from anyone else cannot run.
    assert_eq!(
        node.submit(&Sender::new(alice()).peek(&call7, 0)),
        refused()
    );
}

/// The kernel gas `kernel_stf_execute_block` has used so far.
fn execute_gas(node: &mut Node) -> u64 {
    node.metrics_text()
        .lines()
        .find(|l| {
            l.starts_with("solo_kernel_gas_used_total") && l.contains("kernel_stf_execute_block")
        })
        .and_then(|l| l.rsplit(' ').next())
        .map_or(0, |n| n.parse().unwrap())
}

/// Runs `node` to block `height` and returns the kernel gas of executing it.
fn gas_of_block(node: &mut Node, height: u64) -> u64 {
    reach(node, height - 1);
    let before = execute_gas(node);
    reach(node, height);
    assert_eq!(node.block_number().unwrap(), height);
    execute_gas(node) - before
}

/// Submits every transaction and runs until each has a receipt.
fn include_all(node: &mut Node, raws: &[Vec<u8>]) {
    let hashes: Vec<_> = raws.iter().map(|r| node.submit(r).unwrap()).collect();
    run_until(node, 60, &mut |n| {
        hashes.iter().all(|h| n.receipt(h).unwrap().is_some())
    });
    for h in hashes {
        assert_eq!(node.receipt(&h).unwrap().unwrap().status, 1);
    }
}

/// What the tally and the pruning of delegators' votes cost the kernel
/// (spec 19 §5.1): 64 delegators, one delegation each, vote on one
/// proposal; another proposal takes no vote. The block where each one's
/// voting ends, and the block that executes each, are measured.
///
/// `cargo test -p solo-node --test governance -- --ignored --nocapture ballots`
#[test]
#[ignore = "measurement; run explicitly"]
fn the_kernel_gas_of_delegators_ballots() {
    let validators = keys(1);
    let delegators: Vec<Sender> = (0..64u8)
        .map(|i| Sender::new(Wallet::new(0x80 + i)))
        .collect();
    let funded: Vec<[u8; 20]> = delegators.iter().map(Sender::address).collect();
    let rules = GovernanceParams {
        mode: mode::STAKE,
        voting_blocks: 12,
        timelock_blocks: 1,
        quorum_bps: QUORUM,
        deposit: DEPOSIT,
    };
    let mut genesis = staked(rules, &funded, true);
    let mut params = GenesisParams::from_bytes(&genesis.params).unwrap();
    params.max_txs = 64;
    genesis.params = params.to_bytes();
    let mut node = start(&genesis);
    let mut v0 = Sender::new(Wallet::from_key(validators[0].clone()));
    let validator = v0.address();
    let mut delegators = delegators;
    let delegations: Vec<Vec<u8>> = delegators
        .iter_mut()
        .map(|d| {
            d.tx(
                STAKING_ADDRESS,
                GWEI,
                200_000,
                &StakingAction::Delegate { validator }.encode(),
            )
        })
        .collect();
    include_all(&mut node, &delegations);
    let guardian = |b: u8| Call::SetGuardian { guardian: [b; 20] }.encode();
    let quiet = include(
        &mut node,
        &v0.call(&submit(GOVERNANCE_ADDRESS, &guardian(1)), 0),
    );
    let busy = include(
        &mut node,
        &v0.call(&submit(GOVERNANCE_ADDRESS, &guardian(2)), 0),
    );
    include(&mut node, &v0.call(&vote(1, true), 0));
    include(&mut node, &v0.call(&vote(2, true), 0));
    let votes: Vec<Vec<u8>> = delegators
        .iter_mut()
        .map(|d| d.call(&vote(2, true), 0))
        .collect();
    include_all(&mut node, &votes);
    assert_eq!(view(&mut node, 2).unwrap().delegators.0.len(), 64);
    let quiet_end = gas_of_block(&mut node, quiet.height + 12);
    let busy_end = gas_of_block(&mut node, busy.height + 12);
    let plain = gas_of_block(&mut node, busy.height + 13);
    eprintln!(
        "end of voting: no ballots {quiet_end}, 64 ballots {busy_end}, a block with neither {plain}; per ballot {}",
        (busy_end - quiet_end) / 64
    );
    assert_eq!(view(&mut node, 2).unwrap().proposal.status, status::PASSED);
    let mut executor = Sender::new(alice());
    let mut execute = |node: &mut Node, id: u64| {
        let hash = node
            .submit(&executor.call(&Call::Execute { id }, 0))
            .unwrap();
        let mut gas = 0;
        while node.receipt(&hash).unwrap().is_none() {
            let (height, before) = (node.block_number().unwrap(), execute_gas(node));
            let t = node.now_ms() + SLOT_MS;
            node.tick(t).unwrap();
            if node.block_number().unwrap() == height + 1 {
                gas = execute_gas(node) - before;
            }
        }
        gas
    };
    let quiet_execute = execute(&mut node, 1);
    let busy_execute = execute(&mut node, 2);
    eprintln!(
        "execute: no ballots {quiet_execute}, 64 ballots {busy_execute}; per ballot {}",
        (busy_execute - quiet_execute) / 64
    );
}
