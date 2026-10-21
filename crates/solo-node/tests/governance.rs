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
    self as gov, Call, GOVERNANCE_ADDRESS, GOVERNANCE_GAS, GovernanceParams, GovernanceStatus,
    MAX_OPEN_PROPOSALS, MAX_PROPOSAL_DATA, Proposal, ProposalView, event, mode, selector, status,
};
use solo_abi::modules::{self, INSTALLED_TOPIC, Install, MODULE_ADDRESS, capability};
use solo_abi::types::Genesis;
use solo_abi::{Decode, Encode};
use solo_ethlc::abi;
use solo_ethlc::testing::Chain;
use solo_host::hash::keccak256;
use solo_node::{Node, NodeConfig, NodeError, Sim, SubmitError, Switch};
use solo_upgrade::action::{cancelled_log, proposed_log};
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
    // the stake track, a submission by anyone but the key, an action no
    // proposal may carry and a gas limit below the surcharge are refused.
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
        too_little,
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
    // module action the verifier rejects.
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

    // Proposal 4 passes and the guardian vetoes it during the timelock.
    let name_alice = Call::SetGuardian {
        guardian: alice.address(),
    }
    .encode();
    let r = sim_include(
        &mut sim,
        &val[0].call(&submit(GOVERNANCE_ADDRESS, &name_alice), 0),
    );
    assert_eq!(r.status, 1);
    let p4 = expected(
        4,
        val[0].address(),
        0,
        GOVERNANCE_ADDRESS,
        &name_alice,
        r.height,
    );
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

    // Proposal 5 pauses the inbox on the fast track: it executes in the
    // vote that takes yes past half of all stake, half itself not enough.
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
        vec![
            gov::voted_log(5, &val[0].address(), true, 5),
            gov::executed_log(5)
        ]
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
    // selector alone until it executes, an install decodes in full.
    let mut big = abi::UNPAUSE.to_vec();
    big.resize(MAX_PROPOSAL_DATA, 0);
    let r = include(
        &mut node,
        &v0.tx(
            GOVERNANCE_ADDRESS,
            0,
            3_000_000,
            &submit(VERIFIER_ADDRESS, &big).encode(),
        ),
    );
    assert_eq!(r.status, 1);
    assert_eq!(
        view(&mut node, 2).unwrap().proposal.data.len(),
        MAX_PROPOSAL_DATA
    );
    let big_install = Install {
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
    // A passed proposal whose action fails is executed once all the same:
    // the receipt says so and the proposal is gone.
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
    // Rules that cannot work are refused when the proposal executes.
    let bad_rules = Call::SetParams {
        voting_blocks: 0,
        timelock_blocks: 0,
        quorum_bps: 10_001,
        deposit: 0,
    };
    let r = include(
        &mut node,
        &v0.call(&submit(GOVERNANCE_ADDRESS, &bad_rules.encode()), 0),
    );
    let id = 2;
    assert_eq!(include(&mut node, &v0.call(&vote(id, true), 0)).status, 1);
    reach(&mut node, r.height + 2 + 1);
    let r = include(&mut node, &v0.call(&Call::Execute { id }, 0));
    assert_eq!(r.status, 0);
    assert_eq!(gov_status(&mut node).params.voting_blocks, 2);

    // A pending upgrade proposed by proposal, then cancelled on the fast
    // track by the vote that reaches a majority.
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
    let id = 3;
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
    let id = 4;
    assert!(view(&mut node, id).unwrap().proposal.fast_track);
    let r2 = include(&mut node, &v0.call(&vote(id, true), 0));
    assert_eq!(
        (r2.status, r2.logs.0),
        (
            1,
            vec![
                gov::voted_log(id, &v0.address(), true, 1),
                gov::executed_log(id),
                cancelled_log(&tiny_hash)
            ]
        )
    );
    assert!(r2.height > r.height);
    assert_eq!(node.upgrade_status().unwrap().pending, None);
    assert_eq!(view(&mut node, id), None);
    // A fast-track proposal nobody carries fails at its voting end.
    let r = include(&mut node, &v0.call(&submit(GOVERNANCE_ADDRESS, &cancel), 0));
    assert!(view(&mut node, 5).is_some());
    reach(&mut node, r.height + 2 + 1);
    assert_eq!(view(&mut node, 5), None);
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
    // Now the guardian vetoes; and a guardian set to zero is none again.
    let r = include(&mut node, &v0.call(&submit(GOVERNANCE_ADDRESS, &name), 0));
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
    // The key track needs no voting period: `setMode` checks it at the switch.
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
    let fix = Call::SetParams {
        voting_blocks: 1,
        timelock_blocks: 0,
        quorum_bps: 0,
        deposit: 0,
    }
    .encode();
    assert_eq!(
        include(&mut node, &key.call(&submit(GOVERNANCE_ADDRESS, &fix), 0)).status,
        1
    );
    let r = include(
        &mut node,
        &key.call(&submit(GOVERNANCE_ADDRESS, &switch), 0),
    );
    assert_eq!((r.status, gov_status(&mut node).mode), (1, mode::STAKE));
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
