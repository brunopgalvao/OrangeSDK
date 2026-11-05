//! A token gateway on Orange owned by the chain's governance (spec 21 §5.6,
//! spec 13 §9.2): `TokenGatewayOnOrange` names the governance address as its
//! owner, nobody else can set its rate limits, and a governed call that the
//! validators pass sets one (spec 21 §6.5); under the key track the key's
//! governed call does so at once.

mod support;

use k256::ecdsa::SigningKey;
use orange_abi::chain::{CallRequest, GenesisParams, Receipt};
use orange_abi::governance::{
    self as gov, Call, GOVERNANCE_ADDRESS, GovernanceParams, ProposalView, mode, status,
};
use orange_abi::types::Genesis;
use orange_abi::{Decode, Encode};
use orange_bridge::tokens::{
    NATIVE, OrangeGatewayConfig, address_view, set_release_limit_calldata,
};
use orange_node::{Node, NodeConfig};
use support::eth::init_code;
use support::orange::{ETHER, address, create_address, genesis, kernel_module, key, tx_priced};

const SLOT_MS: u64 = 200;
const VOTING: u64 = 3;
/// The gas a governed call to the gateway is given.
const CALL_GAS: u64 = 200_000;
/// The gas limit of every transaction here: room for the governance
/// surcharge and the call's gas (spec 13 §9.9).
const TX_GAS: u64 = 5_000_000;
const GUARDIAN: [u8; 20] = [0x0B; 20];
const LIMIT: u128 = 5 * ETHER;
const WINDOW: u64 = 3_600;

/// A single validator's chain under governance `mode`, the validator also
/// the governance key, Alice funded.
fn chain(m: u8, validator: &SigningKey, alice: [u8; 20]) -> Genesis {
    let mut g = genesis(
        std::slice::from_ref(validator),
        &[alice, address(validator)],
        SLOT_MS,
        None,
    );
    let mut params = GenesisParams::from_bytes(&g.params).unwrap();
    params.upgrades.governance = address(validator);
    params.upgrades.min_delay = 1;
    params.governance = GovernanceParams {
        mode: m,
        voting_blocks: VOTING,
        timelock_blocks: 1,
        quorum_bps: 5_000,
        deposit: ETHER,
    };
    g.params = params.to_bytes();
    g
}

struct Chain {
    node: Node,
    nonces: std::collections::BTreeMap<[u8; 20], u64>,
}

impl Chain {
    fn start(genesis: &Genesis, validator: &SigningKey) -> Chain {
        let config = NodeConfig {
            now_ms: 1_000,
            key: Some(validator.clone()),
            ..NodeConfig::default()
        };
        let mut node = Node::open(kernel_module(), genesis, config).unwrap();
        node.start(None).unwrap();
        Chain {
            node,
            nonces: std::collections::BTreeMap::new(),
        }
    }

    fn reach(&mut self, height: u64) {
        for _ in 0..60 {
            if self.node.block_number().unwrap() >= height {
                return;
            }
            let t = self.node.now_ms() + SLOT_MS;
            self.node.tick(t).unwrap();
        }
        panic!("height {height} not reached");
    }

    /// Signs `data` to `to` from `from` at gas price zero and runs the
    /// chain until its receipt.
    fn send(&mut self, from: &SigningKey, to: Option<[u8; 20]>, data: &[u8]) -> Receipt {
        let nonce = self.nonces.entry(address(from)).or_insert(0);
        let raw = tx_priced(from, *nonce, to, 0, data, TX_GAS, 0);
        *nonce += 1;
        let hash = self.node.submit(&raw).expect("admitted");
        for _ in 0..20 {
            if let Some(r) = self.node.receipt(&hash).unwrap() {
                return r;
            }
            let t = self.node.now_ms() + SLOT_MS;
            self.node.tick(t).unwrap();
        }
        panic!("no receipt");
    }

    fn deploy_gateway(&mut self, from: &SigningKey) -> [u8; 20] {
        let nonce = self.nonces.get(&address(from)).copied().unwrap_or(0);
        let config = OrangeGatewayConfig::new(
            1,
            [0xE7; 20],
            GOVERNANCE_ADDRESS,
            GUARDIAN,
            "Orange",
            "ORANGE",
        );
        let mut code = init_code("TokenGatewayOnOrange");
        code.extend(config.constructor_args());
        assert_eq!(self.send(from, None, &code).status, 1);
        create_address(&address(from), nonce)
    }

    /// The release limit of the native currency: its amount and window.
    fn release_limit(&mut self, gateway: [u8; 20]) -> (u128, u64) {
        let out = self
            .node
            .call(&CallRequest {
                from: [0xEE; 20],
                to: Some(gateway),
                data: address_view("releaseLimit(address)", &NATIVE),
                gas: 1_000_000,
                ..CallRequest::default()
            })
            .unwrap()
            .output;
        (
            u128::from_be_bytes(out[16..32].try_into().unwrap()),
            u64::from_be_bytes(out[56..64].try_into().unwrap()),
        )
    }
}

fn set_limit() -> Vec<u8> {
    set_release_limit_calldata(&NATIVE, LIMIT, WINDOW)
}

fn governed(gateway: [u8; 20]) -> Vec<u8> {
    Call::SubmitCall {
        target: gateway,
        value: 0,
        gas: CALL_GAS,
        data: set_limit(),
    }
    .encode()
}

/// The `CallExecuted` log of a governed call: whether it succeeded.
fn call_succeeded(r: &Receipt) -> bool {
    let log = r
        .logs
        .0
        .iter()
        .find(|l| l.address == GOVERNANCE_ADDRESS && l.topics.0[0] == gov::event::CALL_EXECUTED)
        .expect("CallExecuted");
    log.data[31] == 1
}

#[test]
fn stake_governance_sets_a_gateway_rate_limit_by_a_governed_call() {
    let validator = key(1);
    let alice = key(0xA1);
    let mut chain = Chain::start(&chain(mode::STAKE, &validator, address(&alice)), &validator);
    let gateway = chain.deploy_gateway(&alice);
    assert_eq!(chain.release_limit(gateway), (0, 0));

    // Nobody but the owner, the governance address, sets a limit.
    let r = chain.send(&alice, Some(gateway), &set_limit());
    assert_eq!(r.status, 0);
    assert_eq!(chain.release_limit(gateway), (0, 0));

    // The validator proposes the call and votes for it; once voting ends
    // and the timelock has run, anyone executes it.
    let r = chain.send(&validator, Some(GOVERNANCE_ADDRESS), &governed(gateway));
    assert_eq!(r.status, 1);
    let vote = Call::Vote {
        id: 1,
        support: true,
    }
    .encode();
    assert_eq!(
        chain
            .send(&validator, Some(GOVERNANCE_ADDRESS), &vote)
            .status,
        1
    );
    assert_eq!(chain.release_limit(gateway), (0, 0));
    let p = gov_view(&mut chain, 1);
    assert_eq!(p.proposal.status, status::VOTING);
    chain.reach(p.proposal.executable_at);
    assert_eq!(gov_view(&mut chain, 1).proposal.status, status::PASSED);
    let execute = Call::Execute { id: 1 }.encode();
    let r = chain.send(&alice, Some(GOVERNANCE_ADDRESS), &execute);
    assert_eq!(r.status, 1);
    assert!(call_succeeded(&r), "{r:?}");
    assert_eq!(chain.release_limit(gateway), (LIMIT, WINDOW));
}

#[test]
fn the_governance_key_sets_a_gateway_rate_limit_at_once() {
    let validator = key(1);
    let alice = key(0xA1);
    let mut chain = Chain::start(&chain(mode::KEY, &validator, address(&alice)), &validator);
    let gateway = chain.deploy_gateway(&alice);
    let r = chain.send(&validator, Some(GOVERNANCE_ADDRESS), &governed(gateway));
    assert_eq!(r.status, 1);
    assert!(call_succeeded(&r), "{r:?}");
    assert_eq!(chain.release_limit(gateway), (LIMIT, WINDOW));
}

fn gov_view(chain: &mut Chain, id: u64) -> ProposalView {
    let r = chain
        .node
        .query(gov::query::PROPOSAL, &id.to_bytes())
        .unwrap();
    assert_eq!(r.status, 0);
    ProposalView::from_bytes(&r.body).unwrap()
}
