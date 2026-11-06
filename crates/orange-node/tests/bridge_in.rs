//! The Ethereum-to-OrangeSDK bridge end to end (spec 18): an `EthereumOutbox`
//! run on revm sends messages on "Ethereum"; a synthetic beacon chain whose
//! sync committee signs finalizes the state that holds them; on an OrangeSDK chain
//! simulated with `Sim`, the light client is inert until feature gate 1
//! activates, then follows the updates, and the inbox delivers each proven
//! message to its recipient contract exactly once, after the delay, within
//! the rate limit, and not while paused. A second test runs real mainnet
//! data through the kernel and pins the gas of a 512-member update.

mod support;

use orange_abi::Encode;
use orange_abi::bridge_in::{
    BridgeInParams, Fork, INBOX_ADDRESS, InboxLimits, LIGHT_CLIENT_ADDRESS, LightClientConfig,
    VERIFIER_ADDRESS,
};
use orange_abi::chain::{Allocation, CallRequest, CallResult, GenesisParams, Receipt, reason};
use orange_abi::codec::Seq;
use orange_abi::governance::{Call, GOVERNANCE_ADDRESS};
use orange_abi::types::Genesis;
use orange_ethlc::abi::{self, Delivery, word};
use orange_ethlc::beacon::Update;
use orange_ethlc::inbox::{self, Message};
use orange_ethlc::sync::Rejection;
use orange_ethlc::testing::{Chain, EthState, Evm, unhex};
use orange_ethlc::{client, verifier};
use orange_node::{Node, NodeConfig, Sim, SubmitError};
use support::{CHAIN_ID, ETHER, SLOT_MS, Wallet, alice, governance, governed, keys, v1};

const LIGHT_CLIENT_ELF: &[u8] = include_bytes!("fixtures/eth-light-client.elf");
const VERIFIER_ELF: &[u8] = include_bytes!("fixtures/eth-message-verifier.elf");
const CONTRACTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/build/");

/// The recipient contract's address on the OrangeSDK chain.
const RECIPIENT: [u8; 20] = [0x7E; 20];
const UPDATE_GAS: u64 = 3_000_000;
const DELIVER_GAS: u64 = 1_000_000;
/// The gas each message gives its recipient.
const MESSAGE_GAS: u64 = 300_000;

fn module(elf: &[u8]) -> Vec<u8> {
    orange_recompile::recompile(
        &orange_recompile::Input::load(elf).unwrap(),
        &orange_recompile::Options::default(),
    )
    .unwrap()
}

fn fixture(name: &str) -> Vec<u8> {
    unhex(&std::fs::read_to_string(format!("{CONTRACTS}{name}")).unwrap())
}

fn genesis(bridge: BridgeInParams, epoch_blocks: u64) -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 16,
        allocations: Seq(vec![
            Allocation {
                address: alice().address,
                balance: 100 * ETHER,
                ..Allocation::default()
            },
            Allocation {
                address: RECIPIENT,
                nonce: 1,
                code: fixture("EthereumMessageRecipient.bin-runtime"),
                ..Allocation::default()
            },
        ]),
        upgrades: governed(1, epoch_blocks),
        bridge_in: bridge,
        ..GenesisParams::default()
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: Sim::validator_set(&keys(1)).to_bytes(),
    }
}

/// "Ethereum": an outbox with three messages to the recipient, and the
/// state that holds them.
struct Ethereum {
    outbox: [u8; 20],
    state: EthState,
    messages: Vec<Message>,
}

fn ethereum() -> Ethereum {
    let mut evm = Evm::new();
    let mut init = fixture("EthereumOutbox.bin");
    init.extend_from_slice(&word(CHAIN_ID));
    let outbox = evm.deploy([0xD0; 20], init).unwrap();
    let mut messages = Vec::new();
    for (nonce, payload) in [b"hello orange".to_vec(), vec![0xAB; 70], b"third".to_vec()]
        .into_iter()
        .enumerate()
    {
        let message = Message {
            nonce: nonce as u64,
            sender: [0x5E; 20],
            recipient: RECIPIENT,
            gas_limit: MESSAGE_GAS,
            payload,
        };
        assert_eq!(
            evm.call([0x5E; 20], outbox, message.send_call()).unwrap(),
            word(nonce as u64)
        );
        messages.push(message);
    }
    Ethereum {
        outbox,
        state: evm.state(),
        messages,
    }
}

/// A user on the OrangeSDK chain that tracks its nonce.
struct Sender {
    wallet: Wallet,
    nonce: u64,
}

impl Sender {
    fn tx(&mut self, to: [u8; 20], gas: u64, data: &[u8]) -> Vec<u8> {
        self.nonce += 1;
        self.wallet.tx(self.nonce - 1, to, 0, gas, data)
    }
}

fn send(sim: &mut Sim, raw: &[u8]) -> Receipt {
    let hash = sim.submit(0, raw).expect("admitted");
    assert!(
        sim.run_until(20_000, |s| s.nodes[0].receipt(&hash).unwrap().is_some())
            .unwrap(),
        "no receipt"
    );
    sim.nodes[0].receipt(&hash).unwrap().unwrap()
}

fn call(node: &mut Node, to: [u8; 20], data: &[u8]) -> CallResult {
    call_with(node, to, data, 5_000_000)
}

fn call_with(node: &mut Node, to: [u8; 20], data: &[u8], gas: u64) -> CallResult {
    node.call(&CallRequest {
        from: alice().address,
        to: Some(to),
        data: data.to_vec(),
        gas,
        ..CallRequest::default()
    })
    .unwrap()
}

fn rejected(r: Rejection) -> Vec<u8> {
    abi::encode(abi::UPDATE_REJECTED, &[word(r as u64)])
}

fn delivery(eth: &Ethereum, nonce: usize, block: u64) -> Vec<u8> {
    let m = &eth.messages[nonce];
    let (account_proof, storage_proof) = eth.state.proof(
        &eth.outbox,
        &inbox::slot(&orange_ethlc::testing::Native, m.nonce),
    );
    Delivery {
        anchor: word(block),
        message: m.clone(),
        account_proof,
        storage_proof,
    }
    .encode(abi::DELIVER)
}

fn submit_update(update: &Update, finality: bool) -> Vec<u8> {
    client::submit_call(
        &if finality {
            update.encode_finality_update()
        } else {
            update.encode_update(32)
        },
        finality,
    )
}

/// The recipient's `count()`.
fn count(node: &mut Node) -> u64 {
    let out = call(node, RECIPIENT, &[0x06, 0x66, 0x1a, 0xbd]).output;
    u64::from_be_bytes(out[24..32].try_into().unwrap())
}

#[test]
#[allow(clippy::too_many_lines)]
fn messages_from_ethereum_reach_their_recipient_once() {
    let chain = Chain::minimal(32);
    let eth = ethereum();
    let limits = InboxLimits {
        delay: 3,
        window: 3600,
        max_messages: 2,
    };
    let bootstrap = chain.bootstrap(8, [3; 32]);
    let bridge = BridgeInParams {
        light_client: module(LIGHT_CLIENT_ELF),
        verifier: module(VERIFIER_ELF),
        config: chain.config.clone(),
        bootstrap: bootstrap.encode(),
        outbox: eth.outbox,
        limits,
    };
    let template = NodeConfig {
        now_ms: 10_000,
        ..NodeConfig::default()
    };
    // The deployer, the sender and the outbox: the state spec 18 §8's
    // deliveries prove against.
    assert_eq!(eth.state.accounts.len(), 3);
    let mut sim = Sim::new(v1(), &genesis(bridge, 2), &keys(1), 1, &template, 30).unwrap();
    let mut relayer = Sender {
        wallet: alice(),
        nonce: 0,
    };
    let mut gov = Sender {
        wallet: governance(),
        nonce: 0,
    };

    // The kernel placed the two native contracts and the inbox.
    let node = &mut sim.nodes[0];
    assert_eq!(node.code(&LIGHT_CLIENT_ADDRESS).unwrap().len(), 34);
    assert_eq!(node.code(&VERIFIER_ADDRESS).unwrap().len(), 34);
    assert_eq!(
        node.code(&INBOX_ADDRESS).unwrap(),
        fixture("EthereumInbox.bin-runtime")
    );

    // An update finalizing the Ethereum state that holds the messages.
    let finalized = chain.header(16, eth.state.root(), [0; 32]);
    let update = chain.update(20, &finalized, true, 21, 32);
    // Before gate 1 the light-client module cannot load: the call fails.
    let early = send(
        &mut sim,
        &relayer.tx(
            LIGHT_CLIENT_ADDRESS,
            UPDATE_GAS,
            &submit_update(&update, false),
        ),
    );
    assert_eq!((early.status, early.gas_used), (0, UPDATE_GAS));
    assert!(
        sim.run_until(60_000, |s| s.nodes[0].upgrades().active() >> 1 & 1 == 1)
            .unwrap(),
        "gate 1 never activated"
    );

    // Admission refuses updates that cannot advance the client.
    let weak = chain.update(20, &finalized, true, 21, 21);
    let raw = relayer.wallet.tx(
        relayer.nonce,
        LIGHT_CLIENT_ADDRESS,
        0,
        UPDATE_GAS,
        &submit_update(&weak, false),
    );
    assert!(matches!(
        sim.submit(0, &raw),
        Err(SubmitError::Rejected(reason::BRIDGE_UPDATE))
    ));
    let stale = chain.update(8, &chain.header(8, [3; 32], [0; 32]), false, 9, 32);
    let raw = relayer.wallet.tx(
        relayer.nonce,
        LIGHT_CLIENT_ADDRESS,
        0,
        UPDATE_GAS,
        &submit_update(&stale, true),
    );
    assert!(matches!(
        sim.submit(0, &raw),
        Err(SubmitError::Rejected(reason::BRIDGE_UPDATE))
    ));
    let raw = relayer.wallet.tx(
        relayer.nonce,
        LIGHT_CLIENT_ADDRESS,
        0,
        UPDATE_GAS,
        &[0xd1, 0x76, 0x7a, 0x4a, 1],
    );
    assert!(matches!(
        sim.submit(0, &raw),
        Err(SubmitError::Rejected(reason::BRIDGE_UPDATE))
    ));
    // A bad branch passes admission, and the light client refuses it in the block.
    let mut bad = update.clone();
    bad.finality_branch[1][0] ^= 1;
    let data = submit_update(&bad, false);
    assert_eq!(
        call(&mut sim.nodes[0], LIGHT_CLIENT_ADDRESS, &data).output,
        rejected(Rejection::BadFinalityBranch)
    );
    assert_eq!(
        send(
            &mut sim,
            &relayer.tx(LIGHT_CLIENT_ADDRESS, UPDATE_GAS, &data)
        )
        .status,
        0
    );

    // The real update is applied.
    let applied = send(
        &mut sim,
        &relayer.tx(
            LIGHT_CLIENT_ADDRESS,
            UPDATE_GAS,
            &submit_update(&update, false),
        ),
    );
    assert_eq!(applied.status, 1);
    let view = call(&mut sim.nodes[0], LIGHT_CLIENT_ADDRESS, &abi::FINALIZED).output;
    assert_eq!(
        (view[..32].to_vec(), view[128..160].to_vec()),
        (word(16).to_vec(), eth.state.root().to_vec())
    );
    let root = call(
        &mut sim.nodes[0],
        LIGHT_CLIENT_ADDRESS,
        &client::u64_call(abi::EXECUTION_ROOT, 16),
    )
    .output;
    let usable_at = u64::from_be_bytes(root[120..128].try_into().unwrap());

    // An unknown block fails in the inbox.
    let unknown = delivery(&eth, 0, 99);
    assert_eq!(
        call(&mut sim.nodes[0], INBOX_ADDRESS, &unknown).output,
        abi::encode(abi::UNKNOWN_BLOCK, &[word(99)])
    );
    // Too early: the delay has not passed (the call runs at the head block's time).
    let d0 = delivery(&eth, 0, 16);
    let head_time = |sim: &mut Sim| {
        let n = sim.nodes[0].block_number().unwrap();
        sim.nodes[0]
            .block_by_number(n)
            .unwrap()
            .unwrap()
            .timestamp_ms
            / 1000
    };
    assert!(head_time(&mut sim) < usable_at);
    assert_eq!(
        call(&mut sim.nodes[0], INBOX_ADDRESS, &d0).output,
        abi::encode(abi::TOO_EARLY, &[word(usable_at)])
    );
    assert!(sim.run_until(20_000, |s| head_time(s) > usable_at).unwrap());
    assert_eq!(
        send(&mut sim, &relayer.tx(INBOX_ADDRESS, DELIVER_GAS, &unknown)).status,
        0
    );
    // A message the outbox never stored: the real proofs of message 0,
    // with another payload or less gas for the recipient, prove nothing.
    let changes: [fn(&mut Message); 2] =
        [|m| m.payload = b"forged".to_vec(), |m| m.gas_limit = 21_000];
    for change in changes {
        let mut forged = Delivery::decode(&d0).unwrap();
        change(&mut forged.message);
        let forged = forged.encode(abi::DELIVER);
        assert_eq!(
            call(&mut sim.nodes[0], INBOX_ADDRESS, &forged).output,
            abi::encode(abi::BAD_PROOF, &[])
        );
        assert_eq!(
            send(&mut sim, &relayer.tx(INBOX_ADDRESS, DELIVER_GAS, &forged)).status,
            0
        );
    }
    // A relayer that leaves less than the message's gas for the recipient
    // gets the whole delivery undone, in a call and in a block.
    assert_eq!(
        call_with(&mut sim.nodes[0], INBOX_ADDRESS, &d0, MESSAGE_GAS).output,
        abi::encode(abi::INSUFFICIENT_GAS, &[word(MESSAGE_GAS)])
    );
    assert_eq!(
        send(&mut sim, &relayer.tx(INBOX_ADDRESS, MESSAGE_GAS, &d0)).status,
        0
    );
    assert_eq!(count(&mut sim.nodes[0]), 0);

    // Delivered: the recipient sees the message, once.
    let delivered = send(&mut sim, &relayer.tx(INBOX_ADDRESS, DELIVER_GAS, &d0));
    assert_eq!(
        (delivered.status, delivered.gas_used, applied.gas_used),
        (1, 158_029, 161_803)
    );
    assert_eq!(count(&mut sim.nodes[0]), 1);
    // The recipient had the message's gas, less its own dispatch.
    let gas = call(&mut sim.nodes[0], RECIPIENT, &[0xdc, 0x5d, 0x3a, 0x17]).output;
    let gas = u64::from_be_bytes(gas[24..32].try_into().unwrap());
    assert!((MESSAGE_GAS - 1_000..MESSAGE_GAS).contains(&gas), "{gas}");
    let payload = call(&mut sim.nodes[0], RECIPIENT, &[0x4c, 0xc2, 0xaa, 0x3c]).output;
    assert_eq!(&payload[64..76], b"hello orange");
    let sender = call(&mut sim.nodes[0], RECIPIENT, &[0x25, 0x6f, 0xec, 0x88]).output;
    assert_eq!(sender[12..], [0x5E; 20]);
    let log = delivered
        .logs
        .0
        .iter()
        .find(|l| l.address == INBOX_ADDRESS)
        .expect("MessageDelivered");
    assert_eq!(log.topics.0[1], word(0));
    assert_eq!(
        call(
            &mut sim.nodes[0],
            VERIFIER_ADDRESS,
            &client::u64_call(abi::DELIVERED, 0)
        )
        .output,
        word(1)
    );
    // A replay is refused at admission; were it included, the verifier would refuse it.
    let raw = relayer
        .wallet
        .tx(relayer.nonce, INBOX_ADDRESS, 0, DELIVER_GAS, &d0);
    assert!(matches!(
        sim.submit(0, &raw),
        Err(SubmitError::Rejected(reason::MESSAGE_DELIVERED))
    ));
    assert_eq!(
        call(&mut sim.nodes[0], INBOX_ADDRESS, &d0).output,
        abi::encode(abi::ALREADY_DELIVERED, &[word(0)])
    );

    // A recipient that reverts undoes the delivery, which can be retried.
    send(
        &mut sim,
        &relayer.tx(
            RECIPIENT,
            100_000,
            &[[0x04, 0x9d, 0xdb, 0xf8].as_slice(), &word(1)].concat(),
        ),
    );
    let d1 = delivery(&eth, 1, 16);
    assert_eq!(
        &call(&mut sim.nodes[0], INBOX_ADDRESS, &d1).output[..4],
        &abi::DELIVERY_FAILED
    );
    assert_eq!(
        send(&mut sim, &relayer.tx(INBOX_ADDRESS, DELIVER_GAS, &d1)).status,
        0
    );
    assert_eq!(
        call(
            &mut sim.nodes[0],
            VERIFIER_ADDRESS,
            &client::u64_call(abi::DELIVERED, 1)
        )
        .output,
        word(0)
    );
    send(
        &mut sim,
        &relayer.tx(
            RECIPIENT,
            100_000,
            &[[0x04, 0x9d, 0xdb, 0xf8].as_slice(), &word(0)].concat(),
        ),
    );

    // Paused by governance: deliveries are refused at admission.
    assert_eq!(
        send(
            &mut sim,
            &relayer.tx(VERIFIER_ADDRESS, 100_000, &abi::PAUSE)
        )
        .status,
        0
    );
    assert_eq!(
        send(&mut sim, &gov.tx(VERIFIER_ADDRESS, 100_000, &abi::PAUSE)).status,
        1
    );
    let raw = relayer
        .wallet
        .tx(relayer.nonce, INBOX_ADDRESS, 0, DELIVER_GAS, &d1);
    assert!(matches!(
        sim.submit(0, &raw),
        Err(SubmitError::Rejected(reason::INBOX_PAUSED))
    ));
    assert_eq!(
        call(&mut sim.nodes[0], INBOX_ADDRESS, &d1).output,
        abi::encode(abi::PAUSED_ERROR, &[])
    );
    assert_eq!(
        send(&mut sim, &gov.tx(VERIFIER_ADDRESS, 100_000, &abi::UNPAUSE)).status,
        1
    );

    // The second delivery fills the window of two; the third waits.
    assert_eq!(
        send(&mut sim, &relayer.tx(INBOX_ADDRESS, DELIVER_GAS, &d1)).status,
        1
    );
    assert_eq!(count(&mut sim.nodes[0]), 2);
    let d2 = delivery(&eth, 2, 16);
    assert_eq!(
        call(&mut sim.nodes[0], INBOX_ADDRESS, &d2).output,
        abi::encode(abi::RATE_LIMITED, &[])
    );
    assert_eq!(
        send(&mut sim, &relayer.tx(INBOX_ADDRESS, DELIVER_GAS, &d2)).status,
        0
    );
    // Governance widens the limit; then it goes through.
    assert_eq!(
        send(
            &mut sim,
            &gov.tx(
                VERIFIER_ADDRESS,
                100_000,
                &verifier::set_rate_limit_call(3600, 3)
            )
        )
        .status,
        1
    );
    assert_eq!(
        send(&mut sim, &relayer.tx(INBOX_ADDRESS, DELIVER_GAS, &d2)).status,
        1
    );
    assert_eq!(count(&mut sim.nodes[0]), 3);

    // The light client's own governance actions (spec 18 §5.1) go through
    // the governance address as actions (spec 13 §9.2), which the kernel
    // runs as the governance authority within `ACTION_GAS`: a new delay,
    // then a later checkpoint of the synthetic chain, which becomes the
    // finalized header and revokes every root stored before it. A
    // checkpoint that is no bootstrap fails the action.
    let action = |data: &[u8]| {
        Call::Submit {
            target: LIGHT_CLIENT_ADDRESS,
            data: data.to_vec(),
        }
        .encode()
    };
    let set_delay = abi::encode(abi::SET_DELAY, &[word(7)]);
    let r = send(
        &mut sim,
        &gov.tx(GOVERNANCE_ADDRESS, 200_000, &action(&set_delay)),
    );
    assert_eq!((r.status, r.logs.0.len()), (1, 1));
    assert_eq!(
        call(&mut sim.nodes[0], LIGHT_CLIENT_ADDRESS, &abi::DELAY).output,
        word(7)
    );
    let later = chain.bootstrap(72, [4; 32]);
    let checkpoint = abi::encode_bytes_call(abi::SET_CHECKPOINT, &later.encode());
    let r = send(
        &mut sim,
        &gov.tx(GOVERNANCE_ADDRESS, 300_000, &action(&checkpoint)),
    );
    assert_eq!((r.status, r.logs.0.len()), (1, 1));
    let view = call(&mut sim.nodes[0], LIGHT_CLIENT_ADDRESS, &abi::FINALIZED).output;
    assert_eq!(view[..32], word(72));
    let root = call(
        &mut sim.nodes[0],
        LIGHT_CLIENT_ADDRESS,
        &client::u64_call(abi::EXECUTION_ROOT, 16),
    )
    .output;
    assert_eq!(root[..32], [0; 32], "revoked by the new checkpoint");
    let junk = abi::encode_bytes_call(abi::SET_CHECKPOINT, &[1]);
    let r = send(
        &mut sim,
        &gov.tx(GOVERNANCE_ADDRESS, 200_000, &action(&junk)),
    );
    assert_eq!((r.status, r.logs.0.len()), (0, 0));
    let view = call(&mut sim.nodes[0], LIGHT_CLIENT_ADDRESS, &abi::FINALIZED).output;
    assert_eq!(view[..32], word(72));

    // Value is refused at admission; the observer agrees on the state.
    let raw = relayer
        .wallet
        .tx(relayer.nonce, INBOX_ADDRESS, 1, DELIVER_GAS, &d2);
    assert!(matches!(
        sim.submit(0, &raw),
        Err(SubmitError::Rejected(reason::BRIDGE_CALL))
    ));
    let height = sim.nodes[0].block_number().unwrap();
    assert!(
        sim.run_until(20_000, |s| s.nodes[1].block_number().unwrap() >= height)
            .unwrap()
    );
    let state_root = |node: &mut Node| node.block_by_number(height).unwrap().unwrap().state_root;
    let (a, b) = (state_root(&mut sim.nodes[0]), state_root(&mut sim.nodes[1]));
    assert_eq!(a, b);
}

fn mainnet_bridge() -> BridgeInParams {
    BridgeInParams {
        light_client: module(LIGHT_CLIENT_ELF),
        verifier: module(VERIFIER_ELF),
        config: LightClientConfig {
            genesis_validators_root: unhex(
                "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            )
            .try_into()
            .unwrap(),
            forks: Seq(vec![
                Fork {
                    epoch: 364_032,
                    version: [5, 0, 0, 0],
                },
                Fork {
                    epoch: 411_392,
                    version: [6, 0, 0, 0],
                },
            ]),
            sync_committee_size: 512,
            slots_per_epoch: 32,
            epochs_per_period: 256,
        },
        bootstrap: include_bytes!("../../orange-ethlc/tests/vectors/bootstrap-1888.ssz").to_vec(),
        outbox: [0xAA; 20],
        limits: InboxLimits {
            delay: 0,
            window: 3600,
            max_messages: 10,
        },
    }
}

/// Runs a single validator until gate 1 is active.
fn start_gated(genesis: &Genesis) -> Node {
    let config = NodeConfig {
        now_ms: 1_000,
        key: Some(keys(1)[0].clone()),
        ..NodeConfig::default()
    };
    let mut node = Node::open(v1(), genesis, config).unwrap();
    node.start(None).unwrap();
    support::run_until(&mut node, 40, &mut |n| n.upgrades().active() >> 1 & 1 == 1);
    node
}

#[test]
fn real_mainnet_updates_through_the_kernel() {
    let mut node = start_gated(&genesis(mainnet_bridge(), 2));
    let mut relayer = Sender {
        wallet: alice(),
        nonce: 0,
    };
    let update = client::submit_call(
        include_bytes!("../../orange-ethlc/tests/vectors/update-1888.ssz"),
        false,
    );
    let finality = client::submit_call(
        include_bytes!("../../orange-ethlc/tests/vectors/finality-15475041.ssz"),
        true,
    );
    // The finality update needs the committee the period's update carries.
    assert_eq!(
        call(&mut node, LIGHT_CLIENT_ADDRESS, &finality).output,
        rejected(Rejection::WrongPeriod)
    );
    let first = support::include(
        &mut node,
        &relayer.tx(LIGHT_CLIENT_ADDRESS, 4_000_000, &update),
    );
    let second = support::include(
        &mut node,
        &relayer.tx(LIGHT_CLIENT_ADDRESS, 4_000_000, &finality),
    );
    assert_eq!((first.status, second.status), (1, 1));
    let root = call(
        &mut node,
        LIGHT_CLIENT_ADDRESS,
        &client::u64_call(abi::EXECUTION_ROOT, 26_235_823),
    )
    .output;
    assert_eq!(
        root[..32],
        unhex("b6334d8344245c45c5665c261b743258145008ffe261f36b7bbd6a1e72fd828c")
    );
    // The gas spec 18 §8 states: a period's update with its 512 keys, and a
    // finality update.
    assert_eq!((first.gas_used, second.gas_used), (1_314_284, 332_454));
}
