//! The canonical token bridge end to end (spec 21) over both real message
//! channels. The gateways first hear from each other: the OrangeSDK-chain gateway's
//! `HELLO` crosses to Ethereum, and until it arrives the Ethereum gateway
//! takes no deposits. On "Ethereum" (revm at Osaka) Alice locks ETH and an ERC-20 in
//! `TokenGatewayOnEthereum`, which sends through `EthereumOutbox`; a
//! synthetic beacon chain finalizes that state; on an OrangeSDK chain of four
//! staking validators (simulated with `Sim`) the sync-committee light client
//! takes the update, the inbox delivers the messages with `eth_getProof`
//! proofs, and `TokenGatewayOnOrange` mints the wrapped tokens to Bob, who
//! pays Carol. Carol and Bob bridge back: the gateway burns and sends
//! through the outbox; the relayer library turns a threshold certificate
//! into a light-client submission and the outbox slots into inbox proofs,
//! and on Ethereum the gateway releases the locked tokens. Carol also locks
//! the OrangeSDK chain's own currency, which arrives on Ethereum as a wrapped token and
//! comes back. Along the way: a paused gateway and a mint over its cap make
//! deliveries fail and wait, a message from another Ethereum account than
//! the gateway is never honoured, replays are refused on both sides, a
//! fee-on-transfer token and a deposit over the lock cap are refused, and a
//! release to a recipient that refuses ETH is owed and claimed later. A
//! deposit queued on the OrangeSDK chain by its mint limit is cancelled and refunded by
//! governance, and the refund crosses back to release Alice's ETH. Then a
//! dishonest sync committee finalizes a state in which a forged mint takes
//! the nonce of Alice's next deposit: governance refunds the queued forgery,
//! the refusal tells the Ethereum gateway the nonce is spent, and Alice's
//! deposit, which can never arrive, is refunded to her; a mint of a token
//! the OrangeSDK chain does not list goes back; `OrangeInbox`'s guardian vetoes Carol's
//! deposit, anyone reports the veto to the OrangeSDK chain and Carol is refunded there.
//! Every balance at the end is exact, and minted never exceeds locked.

mod support;

use k256::ecdsa::SigningKey;
use orange_abi::Encode;
use orange_abi::bridge::Message as OrangeMessage;
use orange_abi::bridge_in::{
    BridgeInParams, INBOX_ADDRESS, InboxLimits, LIGHT_CLIENT_ADDRESS, VERIFIER_ADDRESS,
};
use orange_abi::chain::{
    Allocation, CallRequest, GenesisParams, Receipt, UpgradeParams, Validator, ValidatorSet, reason,
};
use orange_abi::codec::Seq;
use orange_abi::staking::{StakingParams, StakingStatus, ValidatorKey, query as staking_query};
use orange_abi::types::Genesis;
use orange_bridge::abi::{self, Value};
use orange_bridge::tokens::{
    EthereumGatewayConfig, NATIVE, OrangeGatewayConfig, TokenMessage, VOID, address_view,
    claim_calldata, deposit_calldata, refund_queued_calldata, refund_spent_calldata,
    report_vetoed_calldata, set_lock_cap_calldata, set_mint_cap_calldata, set_mint_limit_calldata,
    wrapped_token,
};
use orange_bridge::{
    InboxConfig, execute_calldata, group_key, light_client_v2_args, sent_messages, slot_proof,
    submission_covering, verifier_v2_args,
};
use orange_ethlc::abi::{self as ethabi, Delivery, word};
use orange_ethlc::client;
use orange_ethlc::inbox::{self, Message as EthMessage};
use orange_ethlc::testing::{Chain, EthState, Native};
use orange_node::keystore::encryption_key;
use orange_node::{NodeConfig, Sim, SubmitError, validator_id};
use orange_trie::keccak256;
use support::eth::{ETH_CHAIN_ID, Eth, Outcome, init_code, runtime_code, selector};
use support::orange::{CHAIN_ID, ETHER, address, create_address, kernel_module, key, tx_priced};

const SLOT_MS: u64 = 200;
const LIGHT_CLIENT_ELF: &[u8] =
    include_bytes!("../../orange-node/tests/fixtures/eth-light-client.elf");
const VERIFIER_ELF: &[u8] =
    include_bytes!("../../orange-node/tests/fixtures/eth-message-verifier.elf");

// Ethereum accounts.
const ETH_DEPLOYER: [u8; 20] = [0xD0; 20];
const OWNER: [u8; 20] = [0x0A; 20];
const GUARDIAN: [u8; 20] = [0x0B; 20];
const RELAYER: [u8; 20] = [0xEE; 20];
const ALICE: [u8; 20] = [0xA1; 20];
const DAVE: [u8; 20] = [0xDA; 20];
const MALLORY: [u8; 20] = [0x66; 20];

const DELAY: u64 = 600;
const MAX_KEY_AGE: u64 = 2;
/// The gas each message from Ethereum gives the gateway on the OrangeSDK chain.
const MESSAGE_GAS: u64 = 1_500_000;
const UPDATE_GAS: u64 = 3_000_000;
const DELIVER_GAS: u64 = 3_000_000;
const BIG: u128 = 1 << 100;

/// Transaction gas of the first `deposit` of ETH on Ethereum, through `EthereumOutbox`, whose
/// nonce the gateway's `HELLO` and its answer moved from zero.
const DEPOSIT_ETH_GAS: u64 = 123_972;
/// Of the first `deposit` of an ERC-20 there.
const DEPOSIT_TOKEN_GAS: u64 = 181_961;
/// Of the delivery on the OrangeSDK chain whose mint creates wrapped ETH (the inbox's proofs included).
const FIRST_MINT_GAS: u64 = 833_182;
/// Of a delivery on the OrangeSDK chain whose wrapped token exists.
const MINT_GAS: u64 = 110_104;
/// Of a withdrawal on the OrangeSDK chain: the burn and the send through the outbox.
const BURN_GAS: u64 = 120_033;
/// Of a deposit of the OrangeSDK chain's currency on the OrangeSDK chain.
const LOCK_NATIVE_GAS: u64 = 140_161;
/// Of `OrangeInbox.execute` releasing ETH through the gateway on Ethereum.
const RELEASE_GAS: u64 = 85_303;
/// Of a withdrawal on Ethereum: the burn and the send through `EthereumOutbox`.
const ETH_BURN_GAS: u64 = 108_860;
/// Of the delivery on the OrangeSDK chain that releases the OrangeSDK chain's currency.
const NATIVE_RELEASE_GAS: u64 = 100_327;
/// Of `OrangeInbox.execute` of a `REFUND` that releases ETH back to its depositor.
const REFUND_GAS: u64 = 88_289;
/// Of the delivery on the OrangeSDK chain of a `MINT` of a token the gateway does not list, which sends it back.
const BOUNCE_GAS: u64 = 165_186;
/// Of `refundSpent` on Ethereum releasing ETH whose message never arrives.
const REFUND_SPENT_GAS: u64 = 47_282;
/// Of `reportVetoed` on Ethereum, through `EthereumOutbox`.
const REPORT_GAS: u64 = 114_844;
/// Of the delivery on the OrangeSDK chain of the `SPENT` it sends.
const SPENT_GAS: u64 = 106_564;

/// The OrangeSDK side: the simulated chain and its wallets' nonces.
struct Orange {
    sim: Sim,
    nonces: std::collections::BTreeMap<[u8; 20], u64>,
}

impl Orange {
    /// Signs `data` to `to` from `from` at gas price zero, so balances stay exact, and waits
    /// for its receipt.
    fn send(
        &mut self,
        from: &SigningKey,
        to: Option<[u8; 20]>,
        value: u128,
        data: &[u8],
        gas: u64,
    ) -> Receipt {
        let raw = self.raw(from, to, value, data, gas);
        let hash = self.sim.submit(0, &raw).expect("admitted");
        assert!(
            self.sim
                .run_until(60 * SLOT_MS, |s| s.nodes[0]
                    .receipt(&hash)
                    .unwrap()
                    .is_some())
                .unwrap(),
            "no receipt"
        );
        self.sim.nodes[0].receipt(&hash).unwrap().unwrap()
    }

    fn raw(
        &mut self,
        from: &SigningKey,
        to: Option<[u8; 20]>,
        value: u128,
        data: &[u8],
        gas: u64,
    ) -> Vec<u8> {
        let nonce = self.nonces.entry(address(from)).or_insert(0);
        let raw = tx_priced(from, *nonce, to, value, data, gas, 0);
        *nonce += 1;
        raw
    }

    fn view(&mut self, to: [u8; 20], data: &[u8]) -> Vec<u8> {
        self.sim.nodes[0]
            .call(&CallRequest {
                from: [0xEE; 20],
                to: Some(to),
                data: data.to_vec(),
                gas: 5_000_000,
                ..CallRequest::default()
            })
            .unwrap()
            .output
    }

    fn u128_view(&mut self, to: [u8; 20], data: &[u8]) -> u128 {
        let out = self.view(to, data);
        u128::from_be_bytes(out[16..32].try_into().unwrap())
    }

    fn balance_of(&mut self, token: [u8; 20], account: [u8; 20]) -> u128 {
        self.u128_view(token, &address_view("balanceOf(address)", &account))
    }

    fn native(&mut self, account: [u8; 20]) -> u128 {
        self.sim.nodes[0].account(&account).unwrap().balance
    }

    fn head_time(&mut self) -> u64 {
        let n = self.sim.nodes[0].block_number().unwrap();
        self.sim.nodes[0]
            .block_by_number(n)
            .unwrap()
            .unwrap()
            .timestamp_ms
            / 1000
    }

    fn status(&mut self) -> StakingStatus {
        let r = self.sim.nodes[0]
            .query(staking_query::STAKING, &[])
            .unwrap();
        orange_abi::Decode::from_bytes(&r.body).unwrap()
    }
}

fn ok(outcome: &Outcome) {
    assert!(outcome.success, "{outcome:?}");
}

fn reverted_with(outcome: &Outcome, error: &str) {
    assert!(!outcome.success, "{error}: {outcome:?}");
    assert_eq!(outcome.output, selector(error), "{error}");
}

fn eth_u128(eth: &mut Eth, at: [u8; 20], data: &[u8]) -> u128 {
    let out = eth.view(RELAYER, at, data).output;
    u128::from_be_bytes(out[16..32].try_into().unwrap())
}

/// The messages `EthereumOutbox` at `outbox` logged in `outcome`.
fn ethereum_messages(outbox: [u8; 20], outcome: &Outcome) -> Vec<EthMessage> {
    let topic = keccak256(b"MessageSent(uint64,address,address,uint64,bytes,bytes32)");
    outcome
        .logs
        .iter()
        .filter(|l| l.address.0.0 == outbox && l.data.topics()[0].0 == topic)
        .map(|l| {
            let t = l.data.topics();
            let d = &l.data.data;
            let len = usize::try_from(u64::from_be_bytes(d[120..128].try_into().unwrap())).unwrap();
            EthMessage {
                nonce: u64::from_be_bytes(t[1].0[24..].try_into().unwrap()),
                sender: t[2].0[12..].try_into().unwrap(),
                recipient: t[3].0[12..].try_into().unwrap(),
                gas_limit: u64::from_be_bytes(d[24..32].try_into().unwrap()),
                payload: d[128..128 + len].to_vec(),
            }
        })
        .collect()
}

/// The inbox's `deliver` calldata for `message`, proven against `state` as
/// execution block `block`.
fn delivery(state: &EthState, outbox: &[u8; 20], block: u64, message: &EthMessage) -> Vec<u8> {
    let (account_proof, storage_proof) = state.proof(outbox, &inbox::slot(&Native, message.nonce));
    Delivery {
        anchor: word(block),
        message: message.clone(),
        account_proof,
        storage_proof,
    }
    .encode(ethabi::DELIVER)
}

fn genesis(
    validators: &[SigningKey],
    funded: &[[u8; 20]],
    governance: [u8; 20],
    bridge: BridgeInParams,
) -> Genesis {
    let staking = StakingParams {
        epoch_blocks: 200,
        unbonding_epochs: MAX_KEY_AGE + 2,
        min_stake: 0,
        max_validators: 0,
        dkg_phase_blocks: 4,
        max_key_age: MAX_KEY_AGE,
        keys: Seq(validators
            .iter()
            .map(|k| ValidatorKey {
                id: validator_id(k),
                dkg_key: encryption_key(k).to_vec(),
            })
            .collect()),
    };
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 16,
        allocations: Seq(funded
            .iter()
            .map(|a| Allocation {
                address: *a,
                balance: 100 * ETHER,
                ..Allocation::default()
            })
            .collect()),
        upgrades: UpgradeParams {
            governance,
            min_delay: 1,
            epoch_blocks: 2,
        },
        staking,
        bridge_in: bridge,
        ..GenesisParams::default()
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: ValidatorSet {
            validators: Seq(validators
                .iter()
                .map(|k| Validator {
                    id: validator_id(k),
                    weight: 1_000,
                })
                .collect()),
        }
        .to_bytes(),
    }
}

/// Proves `messages`, sent on the OrangeSDK chain at or before height `sent_at`, to
/// `OrangeInbox` on Ethereum: a light-client submission from a threshold
/// certificate anchoring a height at or after the sends, then each
/// message's outbox slot. Their delay runs from here.
fn prove_on_ethereum(
    orange: &mut Orange,
    eth: &mut Eth,
    contracts: ([u8; 20], [u8; 20]),
    messages: &[OrangeMessage],
    sent_at: u64,
) {
    let (light_client, orange_inbox) = contracts;
    let mut submission = None;
    for _ in 0..20 {
        let target = orange.sim.nodes[0].finalized_height().unwrap() + 2;
        assert!(
            orange
                .sim
                .run_until(40 * SLOT_MS, |s| s.nodes[0].finalized_height().unwrap()
                    >= target)
                .unwrap()
        );
        submission = submission_covering(&mut orange.sim.nodes[0], sent_at).unwrap();
        if submission.is_some() {
            break;
        }
    }
    let submission = submission.expect("a certificate anchors the sends");
    ok(&eth.call(RELAYER, light_client, &submission.calldata()));
    for m in messages {
        let proof = slot_proof(&mut orange.sim.nodes[0], m.nonce, submission.anchor_height)
            .unwrap()
            .unwrap();
        ok(&eth.call(RELAYER, orange_inbox, &proof.prove_calldata(m)));
    }
}

fn module(elf: &[u8]) -> Vec<u8> {
    orange_recompile::recompile(
        &orange_recompile::Input::load(elf).unwrap(),
        &orange_recompile::Options::default(),
    )
    .unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn tokens_cross_both_ways_over_the_verified_channels() {
    // (name, measured, pinned) of every gas figure spec 21 §8 states, checked together at the end.
    let mut gas: Vec<(&str, u64, u64)> = Vec::new();
    // OrangeSDK-chain wallets: the relayer, the gateway's deployer, owner (the governance account) and
    // guardian, and the users Bob and Carol.
    let relayer = key(0x11);
    let deployer = key(0x12);
    let governance = key(0x13);
    let guardian = key(0x14);
    let bob = key(0x15);
    let carol = key(0x16);
    let validators: Vec<SigningKey> = (1..=4).map(|i| key(0x30 + i)).collect();

    // Addresses known before anything is deployed: the outbox is the Ethereum deployer's
    // first contract and the gateway its fifth; the OrangeSDK-chain gateway is its deployer's first.
    let eth_outbox = create_address(&ETH_DEPLOYER, 0);
    let eth_gateway = create_address(&ETH_DEPLOYER, 4);
    let orange_gateway = create_address(&address(&deployer), 0);

    let beacon = Chain::minimal(32);
    let bridge = BridgeInParams {
        light_client: module(LIGHT_CLIENT_ELF),
        verifier: module(VERIFIER_ELF),
        config: beacon.config.clone(),
        bootstrap: beacon.bootstrap(8, [3; 32]).encode(),
        outbox: eth_outbox,
        limits: InboxLimits {
            delay: 3,
            window: 3_600,
            max_messages: 20,
        },
    };
    let funded: Vec<[u8; 20]> = [&relayer, &deployer, &governance, &guardian, &bob, &carol]
        .iter()
        .map(|k| address(k))
        .collect();
    let genesis = genesis(&validators, &funded, address(&governance), bridge);
    let config = NodeConfig {
        now_ms: 10_000,
        ..NodeConfig::default()
    };
    let sim = Sim::new(kernel_module(), &genesis, &validators, 0, &config, 20).unwrap();
    let mut orange = Orange {
        sim,
        nonces: std::collections::BTreeMap::new(),
    };
    // The threshold key for certificates to Ethereum, and gate 1 for the light client of Ethereum.
    assert!(
        orange
            .sim
            .run_until(120 * SLOT_MS, |s| {
                let r = s.nodes[0].query(staking_query::STAKING, &[]).unwrap();
                let st: StakingStatus = orange_abi::Decode::from_bytes(&r.body).unwrap();
                st.active.is_some() && s.nodes[0].upgrades().active() >> 1 & 1 == 1
            })
            .unwrap(),
        "no key set or gate 1"
    );
    let compressed = orange.status().group_key;

    // Ethereum: outbox, verifier, light client holding key set 0, inbox, gateway, two tokens.
    let mut eth = Eth::new();
    let mut outbox_args = vec![0u8; 24];
    outbox_args.extend_from_slice(&CHAIN_ID.to_be_bytes());
    assert_eq!(
        eth.deploy(ETH_DEPLOYER, &init_code("EthereumOutbox"), &outbox_args),
        eth_outbox
    );
    let verifier = eth.deploy(
        ETH_DEPLOYER,
        &init_code("OrangeFinalityVerifierV2"),
        &verifier_v2_args(CHAIN_ID),
    );
    let light_client = eth.deploy(
        ETH_DEPLOYER,
        &init_code("OrangeLightClientV2"),
        &light_client_v2_args(
            &verifier,
            0,
            &group_key(&compressed).unwrap(),
            200,
            MAX_KEY_AGE,
        ),
    );
    let orange_inbox = eth.deploy(
        ETH_DEPLOYER,
        &init_code("OrangeInbox"),
        &InboxConfig {
            light_client,
            first_nonce: 1,
            owner: OWNER,
            guardian: GUARDIAN,
            delay: DELAY,
            window: 3_600,
            max_messages: 20,
            max_value: BIG,
        }
        .constructor_args(),
    );
    let gateway_config = EthereumGatewayConfig {
        outbox: eth_outbox,
        inbox: orange_inbox,
        orange_chain_id: CHAIN_ID,
        orange_gateway,
        owner: OWNER,
        guardian: GUARDIAN,
        message_gas: MESSAGE_GAS,
    };
    assert_eq!(
        eth.deploy(
            ETH_DEPLOYER,
            &init_code("TokenGatewayOnEthereum"),
            &gateway_config.constructor_args()
        ),
        eth_gateway
    );
    let token_args = |name: &str, symbol: &str| {
        abi::encode(&[
            Value::Bytes(name.as_bytes().to_vec()),
            Value::Bytes(symbol.as_bytes().to_vec()),
            Value::uint(6),
        ])
    };
    let tkn = eth.deploy(
        ETH_DEPLOYER,
        &init_code("TestToken"),
        &token_args("Test Token", "TKN"),
    );
    let fee_token = eth.deploy(
        ETH_DEPLOYER,
        &init_code("TestToken"),
        &token_args("Fee Token", "FEE"),
    );
    let receiver = eth.deploy(ETH_DEPLOYER, &init_code("TestReceiver"), &[]);
    eth.fund(ALICE, 100 * ETHER);
    for token in [tkn, fee_token] {
        ok(&eth.call(
            ALICE,
            token,
            &abi::call(
                "mint(address,uint256)",
                &[Value::address(&ALICE), Value::uint(1_000_000)],
            ),
        ));
        ok(&eth.call(
            ALICE,
            token,
            &abi::call(
                "approve(address,uint256)",
                &[Value::address(&eth_gateway), Value::uint(u128::MAX)],
            ),
        ));
        ok(&eth.call(
            OWNER,
            eth_gateway,
            &set_lock_cap_calldata(&token, 1_000_000),
        ));
    }
    ok(&eth.call(
        ALICE,
        fee_token,
        &abi::call("setFee(uint256)", &[Value::uint(50)]),
    ));
    ok(&eth.call(
        OWNER,
        eth_gateway,
        &set_lock_cap_calldata(&NATIVE, 10 * ETHER),
    ));
    ok(&eth.call(
        OWNER,
        eth_gateway,
        &set_mint_cap_calldata(&NATIVE, 10 * ETHER),
    ));

    // OrangeSDK: the gateway, deployed by an ordinary transaction, governed by the governance account.
    let created = orange.send(
        &deployer,
        None,
        0,
        &[
            init_code("TokenGatewayOnOrange"),
            OrangeGatewayConfig::new(
                ETH_CHAIN_ID,
                eth_gateway,
                address(&governance),
                address(&guardian),
                "Orange",
                "ORANGE",
            )
            .constructor_args(),
        ]
        .concat(),
        5_000_000,
    );
    assert_eq!(
        (created.status, created.contract),
        (1, Some(orange_gateway))
    );
    let weth = wrapped_token(&orange_gateway, &NATIVE, &init_code("BridgedToken"));
    let wtkn = wrapped_token(&orange_gateway, &tkn, &init_code("BridgedToken"));
    for (call, gas) in [
        (set_mint_cap_calldata(&NATIVE, BIG), 100_000),
        (set_mint_cap_calldata(&tkn, 300_000), 100_000),
        (set_lock_cap_calldata(&NATIVE, 10 * ETHER), 100_000),
    ] {
        assert_eq!(
            orange
                .send(&governance, Some(orange_gateway), 0, &call, gas)
                .status,
            1
        );
    }

    // On Ethereum Alice locks 5 ETH and 700 000 TKN for Bob.
    let deposit = |eth: &mut Eth, token: [u8; 20], to: [u8; 20], amount: u128| {
        let value = if token == NATIVE { amount } else { 0 };
        eth.call_value(
            ALICE,
            eth_gateway,
            value,
            &deposit_calldata(&token, &to, amount),
        )
    };
    // But not before the Ethereum gateway has heard from its peer (spec 21 §5.7): the OrangeSDK-chain
    // gateway's constructor sent a HELLO, which crosses through the outbox, a certificate and
    // `OrangeInbox`; the Ethereum gateway answers it.
    reverted_with(
        &deposit(&mut eth, NATIVE, address(&bob), ETHER),
        "PeerUnconfirmed()",
    );
    let hellos: Vec<OrangeMessage> = sent_messages(CHAIN_ID, &created.logs.0)
        .into_iter()
        .map(|(m, _)| m)
        .collect();
    assert_eq!(hellos.len(), 1);
    assert_eq!(
        TokenMessage::decode(&hellos[0].payload),
        Some(TokenMessage::Hello { heard: false })
    );
    prove_on_ethereum(
        &mut orange,
        &mut eth,
        (light_client, orange_inbox),
        &hellos,
        created.height,
    );
    eth.advance(DELAY);
    let heard = eth.call(RELAYER, orange_inbox, &execute_calldata(&hellos[0]));
    ok(&heard);
    let answer = ethereum_messages(eth_outbox, &heard);
    assert_eq!(
        answer
            .iter()
            .map(|m| (m.nonce, TokenMessage::decode(&m.payload)))
            .collect::<Vec<_>>(),
        [(1, Some(TokenMessage::Hello { heard: true }))]
    );
    assert_eq!(
        eth_u128(&mut eth, eth_gateway, &abi::call("peerLive()", &[])),
        1
    );
    let first = deposit(&mut eth, NATIVE, address(&bob), 4 * ETHER);
    ok(&first);
    let second = deposit(&mut eth, tkn, address(&bob), 700_000);
    ok(&second);
    let third = deposit(&mut eth, NATIVE, address(&bob), ETHER);
    ok(&third);
    gas.extend([
        ("DEPOSIT_ETH_GAS", first.gas, DEPOSIT_ETH_GAS),
        ("DEPOSIT_TOKEN_GAS", second.gas, DEPOSIT_TOKEN_GAS),
    ]);
    // A fee-on-transfer token, a deposit over the cap and one while paused are refused.
    reverted_with(
        &deposit(&mut eth, fee_token, address(&bob), 1_000),
        "BalanceMismatch()",
    );
    let over = deposit(&mut eth, NATIVE, address(&bob), 6 * ETHER);
    assert_eq!(
        over.output,
        abi::call("CapExceeded(address)", &[Value::address(&NATIVE)])
    );
    ok(&eth.call(GUARDIAN, eth_gateway, &abi::call("pause()", &[])));
    reverted_with(&deposit(&mut eth, NATIVE, address(&bob), 1), "IsPaused()");
    ok(&eth.call(OWNER, eth_gateway, &abi::call("unpause()", &[])));
    // Mallory sends the OrangeSDK-chain gateway a mint of her own through the outbox.
    let forged = TokenMessage::Mint {
        origin: NATIVE,
        from: MALLORY,
        to: MALLORY,
        amount: ETHER,
        name: b"Ether".to_vec(),
        symbol: b"ETH".to_vec(),
        decimals: 18,
    };
    let forged_send = eth.call(
        MALLORY,
        eth_outbox,
        &EthMessage {
            nonce: 5,
            sender: MALLORY,
            recipient: orange_gateway,
            gas_limit: MESSAGE_GAS,
            payload: forged.encode(),
        }
        .send_call(),
    );
    ok(&forged_send);
    let to_orange: Vec<EthMessage> = [&first, &second, &third, &forged_send]
        .iter()
        .flat_map(|o| ethereum_messages(eth_outbox, o))
        .collect();
    assert_eq!(to_orange.len(), 4);
    assert_eq!(
        TokenMessage::decode(&to_orange[1].payload),
        Some(TokenMessage::Mint {
            origin: tkn,
            from: ALICE,
            to: address(&bob),
            amount: 700_000,
            name: b"Test Token".to_vec(),
            symbol: b"TKN".to_vec(),
            decimals: 6,
        })
    );

    // The beacon chain finalizes that state at execution block 16; the light client on the OrangeSDK chain
    // takes the update, and its root is usable after the delay.
    let state = eth.state();
    // The state spec 21 §8's deliveries prove against.
    assert_eq!(state.accounts.len(), 14);
    let update = beacon.update(20, &beacon.header(16, state.root(), [0; 32]), true, 21, 32);
    let applied = orange.send(
        &relayer,
        Some(LIGHT_CLIENT_ADDRESS),
        0,
        &client::submit_call(&update.encode_update(32), false),
        UPDATE_GAS,
    );
    assert_eq!(applied.status, 1);
    let root = orange.view(
        LIGHT_CLIENT_ADDRESS,
        &client::u64_call(ethabi::EXECUTION_ROOT, 16),
    );
    let usable_at = u64::from_be_bytes(root[120..128].try_into().unwrap());
    assert!(
        orange
            .sim
            .run_until(60 * SLOT_MS, |s| {
                let n = s.nodes[0].block_number().unwrap();
                s.nodes[0].block_by_number(n).unwrap().unwrap().timestamp_ms / 1000 > usable_at
            })
            .unwrap()
    );
    assert!(orange.head_time() > usable_at);
    let deliveries: Vec<Vec<u8>> = to_orange
        .iter()
        .map(|m| delivery(&state, &eth_outbox, 16, m))
        .collect();
    let delivered = |orange: &mut Orange, nonce: u64| {
        orange.view(
            VERIFIER_ADDRESS,
            &client::u64_call(ethabi::DELIVERED, nonce),
        ) == word(1)
    };

    // The guardian paused the OrangeSDK-chain gateway: the delivery fails and stays undelivered.
    let pause = abi::call("pause()", &[]);
    assert_eq!(
        orange
            .send(&guardian, Some(orange_gateway), 0, &pause, 100_000)
            .status,
        1
    );
    let r = orange.send(
        &relayer,
        Some(INBOX_ADDRESS),
        0,
        &deliveries[0],
        DELIVER_GAS,
    );
    assert_eq!(r.status, 0);
    assert!(!delivered(&mut orange, 2));
    let unpause = abi::call("unpause()", &[]);
    assert_eq!(
        orange
            .send(&governance, Some(orange_gateway), 0, &unpause, 100_000)
            .status,
        1
    );
    // Retried, it creates the wrapped ETH and mints to Bob.
    let minted = orange.send(
        &relayer,
        Some(INBOX_ADDRESS),
        0,
        &deliveries[0],
        DELIVER_GAS,
    );
    assert_eq!(minted.status, 1);
    assert!(delivered(&mut orange, 2));
    assert_eq!(orange.balance_of(weth, address(&bob)), 4 * ETHER);
    let minted_again = orange.send(
        &relayer,
        Some(INBOX_ADDRESS),
        0,
        &deliveries[2],
        DELIVER_GAS,
    );
    assert_eq!(minted_again.status, 1);
    assert_eq!(orange.balance_of(weth, address(&bob)), 5 * ETHER);
    gas.extend([
        ("FIRST_MINT_GAS", minted.gas_used, FIRST_MINT_GAS),
        ("MINT_GAS", minted_again.gas_used, MINT_GAS),
    ]);
    // Spec 21 §5.1 and §8: creating the wrapped token costs about 723 000 gas, mostly the code
    // deposit of its 2 779-byte runtime.
    assert_eq!(runtime_code("BridgedToken").len(), 2_779);
    assert_eq!((FIRST_MINT_GAS - MINT_GAS) / 1_000, 723);
    // A replay is refused at admission.
    let replay = orange.raw(
        &relayer,
        Some(INBOX_ADDRESS),
        0,
        &deliveries[0],
        DELIVER_GAS,
    );
    assert!(matches!(
        orange.sim.submit(0, &replay),
        Err(SubmitError::Rejected(reason::MESSAGE_DELIVERED))
    ));
    *orange.nonces.get_mut(&address(&relayer)).unwrap() -= 1;
    // 700 000 TKN is over the mint cap of 300 000: it waits until the owner raises the cap.
    assert_eq!(
        orange
            .send(
                &relayer,
                Some(INBOX_ADDRESS),
                0,
                &deliveries[1],
                DELIVER_GAS
            )
            .status,
        0
    );
    assert!(!delivered(&mut orange, 3));
    assert_eq!(
        orange
            .send(
                &governance,
                Some(orange_gateway),
                0,
                &set_mint_cap_calldata(&tkn, BIG),
                100_000
            )
            .status,
        1
    );
    let minted_tkn = orange.send(
        &relayer,
        Some(INBOX_ADDRESS),
        0,
        &deliveries[1],
        DELIVER_GAS,
    );
    assert_eq!(minted_tkn.status, 1);
    assert_eq!(orange.balance_of(wtkn, address(&bob)), 700_000);
    // Mallory's message is proven, but the gateway refuses its sender: nothing is minted.
    let refused = orange.send(
        &relayer,
        Some(INBOX_ADDRESS),
        0,
        &deliveries[3],
        DELIVER_GAS,
    );
    assert_eq!(refused.status, 0);
    assert!(!delivered(&mut orange, 5));
    assert_eq!(orange.balance_of(weth, MALLORY), 0);
    assert_eq!(
        orange.u128_view(weth, &abi::call("totalSupply()", &[])),
        5 * ETHER
    );

    // On the OrangeSDK chain: Bob pays Carol 200 000 TKN; Carol sends them to Alice on Ethereum; Bob sends 2 ETH
    // to a contract that refuses ETH and 1 ETH to Alice; Carol locks 3 ORANGE for Dave.
    let transfer = abi::call(
        "transfer(address,uint256)",
        &[Value::address(&address(&carol)), Value::uint(200_000)],
    );
    assert_eq!(
        orange.send(&bob, Some(wtkn), 0, &transfer, 100_000).status,
        1
    );
    let carol_before = orange.native(address(&carol));
    let mut receipts = vec![
        orange.send(
            &carol,
            Some(orange_gateway),
            0,
            &deposit_calldata(&wtkn, &ALICE, 200_000),
            300_000,
        ),
        orange.send(
            &bob,
            Some(orange_gateway),
            0,
            &deposit_calldata(&weth, &receiver, 2 * ETHER),
            300_000,
        ),
        orange.send(
            &bob,
            Some(orange_gateway),
            0,
            &deposit_calldata(&weth, &ALICE, ETHER),
            300_000,
        ),
        orange.send(
            &carol,
            Some(orange_gateway),
            3 * ETHER,
            &deposit_calldata(&NATIVE, &DAVE, 3 * ETHER),
            300_000,
        ),
    ];
    // Over the lock cap of 10 ORANGE it is refused.
    receipts.push(orange.send(
        &carol,
        Some(orange_gateway),
        8 * ETHER,
        &deposit_calldata(&NATIVE, &DAVE, 8 * ETHER),
        300_000,
    ));
    assert_eq!(
        receipts.iter().map(|r| r.status).collect::<Vec<_>>(),
        [1, 1, 1, 1, 0]
    );
    gas.extend([
        ("BURN_GAS", receipts[0].gas_used, BURN_GAS),
        ("LOCK_NATIVE_GAS", receipts[3].gas_used, LOCK_NATIVE_GAS),
    ]);
    assert_eq!(orange.native(address(&carol)), carol_before - 3 * ETHER);
    assert_eq!(orange.native(orange_gateway), 3 * ETHER);
    // Minted on the OrangeSDK chain never exceeds locked on Ethereum.
    assert_eq!(
        orange.u128_view(weth, &abi::call("totalSupply()", &[])),
        2 * ETHER
    );
    assert_eq!(
        eth_u128(
            &mut eth,
            eth_gateway,
            &address_view("locked(address)", &NATIVE)
        ),
        5 * ETHER
    );
    let to_eth: Vec<OrangeMessage> = receipts
        .iter()
        .flat_map(|r| sent_messages(CHAIN_ID, &r.logs.0))
        .map(|(m, _)| m)
        .collect();
    assert_eq!(to_eth.len(), 4);
    assert!(
        to_eth
            .iter()
            .all(|m| m.sender == orange_gateway && m.recipient == eth_gateway && m.value == 0)
    );
    let sent_at = receipts[3].height;

    // The relayer: a certificate anchoring a height at or after the sends, then the proofs.
    prove_on_ethereum(
        &mut orange,
        &mut eth,
        (light_client, orange_inbox),
        &to_eth,
        sent_at,
    );
    eth.advance(DELAY);
    let rejecting = |on: bool| abi::call("setRejecting(bool)", &[Value::uint(u128::from(on))]);
    ok(&eth.call(RELAYER, receiver, &rejecting(true)));
    let alice_eth = eth.balance(ALICE);
    for m in &to_eth {
        let executed = eth.call(RELAYER, orange_inbox, &execute_calldata(m));
        ok(&executed);
        if m.nonce == to_eth[2].nonce {
            gas.push(("RELEASE_GAS", executed.gas, RELEASE_GAS));
        }
    }
    // A replayed execution is refused.
    reverted_with(
        &eth.call(RELAYER, orange_inbox, &execute_calldata(&to_eth[0])),
        "NotPending()",
    );
    assert_eq!(eth.balance(ALICE), alice_eth + ETHER);
    assert_eq!(
        eth_u128(&mut eth, tkn, &address_view("balanceOf(address)", &ALICE)),
        1_000_000 - 700_000 + 200_000
    );
    // The release to the refusing contract is owed; once it accepts ETH anyone claims it for it.
    let owed = abi::call(
        "owed(address,address)",
        &[Value::address(&NATIVE), Value::address(&receiver)],
    );
    assert_eq!(eth_u128(&mut eth, eth_gateway, &owed), 2 * ETHER);
    reverted_with(
        &eth.call(RELAYER, eth_gateway, &claim_calldata(&NATIVE, &receiver)),
        "TransferFailed()",
    );
    ok(&eth.call(RELAYER, receiver, &rejecting(false)));
    ok(&eth.call(RELAYER, eth_gateway, &claim_calldata(&NATIVE, &receiver)));
    assert_eq!(
        eth_u128(&mut eth, receiver, &abi::call("received()", &[])),
        2 * ETHER
    );
    assert_eq!(eth_u128(&mut eth, eth_gateway, &owed), 0);
    // Dave holds 3 wrapped ORANGE on Ethereum.
    let worange = wrapped_token(&eth_gateway, &NATIVE, &init_code("BridgedToken"));
    assert_eq!(
        eth_u128(
            &mut eth,
            worange,
            &address_view("balanceOf(address)", &DAVE)
        ),
        3 * ETHER
    );

    // Dave sends 1 ORANGE back to Carol: burned on Ethereum, proven against the next finalized
    // state, released on the OrangeSDK chain from what the gateway there locked.
    let back = eth.call(
        DAVE,
        eth_gateway,
        &deposit_calldata(&worange, &address(&carol), ETHER),
    );
    ok(&back);
    let returned = ethereum_messages(eth_outbox, &back);
    assert_eq!(
        TokenMessage::decode(&returned[0].payload),
        Some(TokenMessage::Release {
            token: NATIVE,
            from: DAVE,
            to: address(&carol),
            amount: ETHER,
        })
    );
    let state = eth.state();
    let update = beacon.update(28, &beacon.header(24, state.root(), [0; 32]), false, 29, 32);
    let applied = orange.send(
        &relayer,
        Some(LIGHT_CLIENT_ADDRESS),
        0,
        &client::submit_call(&update.encode_update(32), false),
        UPDATE_GAS,
    );
    assert_eq!(applied.status, 1);
    let root = orange.view(
        LIGHT_CLIENT_ADDRESS,
        &client::u64_call(ethabi::EXECUTION_ROOT, 24),
    );
    let usable_at = u64::from_be_bytes(root[120..128].try_into().unwrap());
    assert!(
        orange
            .sim
            .run_until(60 * SLOT_MS, |s| {
                let n = s.nodes[0].block_number().unwrap();
                s.nodes[0].block_by_number(n).unwrap().unwrap().timestamp_ms / 1000 > usable_at
            })
            .unwrap()
    );
    let carol_before = orange.native(address(&carol));
    let released = orange.send(
        &relayer,
        Some(INBOX_ADDRESS),
        0,
        &delivery(&state, &eth_outbox, 24, &returned[0]),
        DELIVER_GAS,
    );
    assert_eq!(released.status, 1);
    assert_eq!(orange.native(address(&carol)), carol_before + ETHER);
    gas.extend([
        ("ETH_BURN_GAS", back.gas, ETH_BURN_GAS),
        ("NATIVE_RELEASE_GAS", released.gas_used, NATIVE_RELEASE_GAS),
    ]);

    // A refund (spec 21 §5.5b): with a mint limit on wrapped ETH, Alice's next deposit queues on
    // the OrangeSDK chain; governance, the owner there, cancels it and refunds it, and the refund crosses back
    // through the outbox, a certificate and `OrangeInbox` to the Ethereum gateway, which recorded
    // sending that very message and releases Alice's ETH to her.
    assert_eq!(
        orange
            .send(
                &governance,
                Some(orange_gateway),
                0,
                &set_mint_limit_calldata(&NATIVE, ETHER / 10, 1_000),
                100_000
            )
            .status,
        1
    );
    let alice_eth = eth.balance(ALICE);
    let refundable = deposit(&mut eth, NATIVE, address(&bob), ETHER);
    ok(&refundable);
    let refundable = ethereum_messages(eth_outbox, &refundable).remove(0);
    let state = eth.state();
    let update = beacon.update(36, &beacon.header(32, state.root(), [0; 32]), false, 37, 32);
    let applied = orange.send(
        &relayer,
        Some(LIGHT_CLIENT_ADDRESS),
        0,
        &client::submit_call(&update.encode_update(32), false),
        UPDATE_GAS,
    );
    assert_eq!(applied.status, 1);
    let root = orange.view(
        LIGHT_CLIENT_ADDRESS,
        &client::u64_call(ethabi::EXECUTION_ROOT, 32),
    );
    let usable_at = u64::from_be_bytes(root[120..128].try_into().unwrap());
    assert!(
        orange
            .sim
            .run_until(60 * SLOT_MS, |s| {
                let n = s.nodes[0].block_number().unwrap();
                s.nodes[0].block_by_number(n).unwrap().unwrap().timestamp_ms / 1000 > usable_at
            })
            .unwrap()
    );
    let queued = orange.send(
        &relayer,
        Some(INBOX_ADDRESS),
        0,
        &delivery(&state, &eth_outbox, 32, &refundable),
        DELIVER_GAS,
    );
    assert_eq!(queued.status, 1);
    assert_eq!(orange.balance_of(weth, address(&bob)), 2 * ETHER);
    assert_eq!(
        orange.u128_view(
            orange_gateway,
            &address_view("mintsQueued(address)", &NATIVE)
        ),
        ETHER
    );
    let refunding = orange.send(
        &governance,
        Some(orange_gateway),
        0,
        &refund_queued_calldata(0),
        300_000,
    );
    assert_eq!(refunding.status, 1);
    let refund: Vec<OrangeMessage> = sent_messages(CHAIN_ID, &refunding.logs.0)
        .into_iter()
        .map(|(m, _)| m)
        .collect();
    assert_eq!(
        TokenMessage::decode(&refund[0].payload),
        Some(TokenMessage::Refund {
            nonce: refundable.nonce,
            kind: 1,
            token: NATIVE,
            from: ALICE,
            to: address(&bob),
            amount: ETHER,
        })
    );
    prove_on_ethereum(
        &mut orange,
        &mut eth,
        (light_client, orange_inbox),
        &refund,
        refunding.height,
    );
    eth.advance(DELAY);
    let refunded = eth.call(RELAYER, orange_inbox, &execute_calldata(&refund[0]));
    ok(&refunded);
    gas.push(("REFUND_GAS", refunded.gas, REFUND_GAS));
    assert_eq!(eth.balance(ALICE), alice_eth);
    let sent = abi::call("sent(uint64)", &[Value::uint(u128::from(refundable.nonce))]);
    assert_eq!(eth.view(RELAYER, eth_gateway, &sent).output, [0; 32]);

    // Messages that never arrive (spec 21 §5.5c). Governance delists TKN on the OrangeSDK chain. On Ethereum
    // Alice deposits 1 ETH and 100 000 TKN for Bob; then the sync committee turns dishonest and
    // finalizes a state in which the outbox slot of her ETH deposit holds a forged mint of 1 ETH
    // to Mallory instead. On the OrangeSDK chain the forgery is delivered under Alice's nonce and queued by the
    // mint limit, and the TKN deposit, of a token the OrangeSDK chain does not list, goes back at once.
    assert_eq!(
        orange
            .send(
                &governance,
                Some(orange_gateway),
                0,
                &set_mint_cap_calldata(&tkn, 0),
                100_000
            )
            .status,
        1
    );
    let honest = deposit(&mut eth, NATIVE, address(&bob), ETHER);
    ok(&honest);
    let honest = ethereum_messages(eth_outbox, &honest).remove(0);
    let unlisted = deposit(&mut eth, tkn, address(&bob), 100_000);
    ok(&unlisted);
    let unlisted = ethereum_messages(eth_outbox, &unlisted).remove(0);
    let forged = EthMessage {
        payload: TokenMessage::Mint {
            origin: NATIVE,
            from: MALLORY,
            to: MALLORY,
            amount: ETHER,
            name: b"Ether".to_vec(),
            symbol: b"ETH".to_vec(),
            decimals: 18,
        }
        .encode(),
        ..honest.clone()
    };
    let mut forged_state = eth.state();
    forged_state
        .accounts
        .get_mut(&eth_outbox)
        .unwrap()
        .storage
        .insert(
            inbox::slot(&Native, honest.nonce),
            forged.hash(&Native, CHAIN_ID),
        );
    let submit = |orange: &mut Orange, attested: u64, block: u64, root: [u8; 32]| {
        let update = beacon.update(
            attested,
            &beacon.header(block, root, [0; 32]),
            false,
            attested + 1,
            32,
        );
        let applied = orange.send(
            &relayer,
            Some(LIGHT_CLIENT_ADDRESS),
            0,
            &client::submit_call(&update.encode_update(32), false),
            UPDATE_GAS,
        );
        assert_eq!(applied.status, 1);
        let root = orange.view(
            LIGHT_CLIENT_ADDRESS,
            &client::u64_call(ethabi::EXECUTION_ROOT, block),
        );
        let usable_at = u64::from_be_bytes(root[120..128].try_into().unwrap());
        assert!(
            orange
                .sim
                .run_until(60 * SLOT_MS, |s| {
                    let n = s.nodes[0].block_number().unwrap();
                    s.nodes[0].block_by_number(n).unwrap().unwrap().timestamp_ms / 1000 > usable_at
                })
                .unwrap()
        );
    };
    submit(&mut orange, 44, 40, forged_state.root());
    let taken = orange.send(
        &relayer,
        Some(INBOX_ADDRESS),
        0,
        &delivery(&forged_state, &eth_outbox, 40, &forged),
        DELIVER_GAS,
    );
    assert_eq!(taken.status, 1);
    assert_eq!(orange.balance_of(weth, MALLORY), 0);
    let bounced = orange.send(
        &relayer,
        Some(INBOX_ADDRESS),
        0,
        &delivery(&forged_state, &eth_outbox, 40, &unlisted),
        DELIVER_GAS,
    );
    assert_eq!(bounced.status, 1);
    gas.push(("BOUNCE_GAS", bounced.gas_used, BOUNCE_GAS));
    assert_eq!(
        orange.u128_view(wtkn, &abi::call("totalSupply()", &[])),
        500_000
    );
    // Governance refunds the forgery it cannot tell from an honest transfer; Carol locks 1 ORANGE
    // for Dave.
    let refunding = orange.send(
        &governance,
        Some(orange_gateway),
        0,
        &refund_queued_calldata(1),
        300_000,
    );
    assert_eq!(refunding.status, 1);
    let carol_before = orange.native(address(&carol));
    let vetoed = orange.send(
        &carol,
        Some(orange_gateway),
        ETHER,
        &deposit_calldata(&NATIVE, &DAVE, ETHER),
        300_000,
    );
    assert_eq!(vetoed.status, 1);
    let to_eth: Vec<OrangeMessage> = [&bounced, &refunding, &vetoed]
        .iter()
        .flat_map(|r| sent_messages(CHAIN_ID, &r.logs.0))
        .map(|(m, _)| m)
        .collect();
    assert_eq!(to_eth.len(), 3);
    assert_eq!(
        TokenMessage::decode(&to_eth[1].payload),
        Some(TokenMessage::Refund {
            nonce: honest.nonce,
            kind: 1,
            token: NATIVE,
            from: MALLORY,
            to: MALLORY,
            amount: ETHER,
        })
    );
    prove_on_ethereum(
        &mut orange,
        &mut eth,
        (light_client, orange_inbox),
        &to_eth,
        vetoed.height,
    );
    // `OrangeInbox`'s guardian vetoes Carol's deposit, which will never be delivered now.
    ok(&eth.call(
        GUARDIAN,
        orange_inbox,
        &abi::call("veto(uint64)", &[Value::uint(u128::from(to_eth[2].nonce))]),
    ));
    eth.advance(DELAY);
    // Alice's TKN comes back. The forgery's refund is refused, and it tells the Ethereum gateway
    // that Alice's nonce was spent with no effect: her ETH deposit, which can never arrive now, is
    // refunded to her.
    let alice_tkn = eth_u128(&mut eth, tkn, &address_view("balanceOf(address)", &ALICE));
    for m in &to_eth[..2] {
        ok(&eth.call(RELAYER, orange_inbox, &execute_calldata(m)));
    }
    assert_eq!(
        eth_u128(&mut eth, tkn, &address_view("balanceOf(address)", &ALICE)),
        alice_tkn + 100_000
    );
    reverted_with(
        &eth.call(RELAYER, orange_inbox, &execute_calldata(&to_eth[2])),
        "NotPending()",
    );
    let alice_eth = eth.balance(ALICE);
    let made_whole = eth.call(
        ALICE,
        eth_gateway,
        &refund_spent_calldata(honest.nonce, 1, &NATIVE, &ALICE, &address(&bob), ETHER),
    );
    ok(&made_whole);
    gas.push(("REFUND_SPENT_GAS", made_whole.gas, REFUND_SPENT_GAS));
    assert_eq!(eth.balance(ALICE), alice_eth + ETHER);
    // Anyone reports Carol's vetoed deposit to the OrangeSDK chain, through `EthereumOutbox` and the honest
    // committee's next update; her ORANGE is refunded to her there. Alice's real message is proven
    // against that state, but its nonce is spent: it is never delivered.
    let report = eth.call(
        RELAYER,
        eth_gateway,
        &report_vetoed_calldata(to_eth[2].nonce),
    );
    ok(&report);
    gas.push(("REPORT_GAS", report.gas, REPORT_GAS));
    let report_message = ethereum_messages(eth_outbox, &report).remove(0);
    assert_eq!(
        TokenMessage::decode(&report_message.payload),
        Some(TokenMessage::Spent {
            nonce: to_eth[2].nonce,
            effect: VOID,
        })
    );
    let state = eth.state();
    submit(&mut orange, 52, 48, state.root());
    let stranded = orange.raw(
        &relayer,
        Some(INBOX_ADDRESS),
        0,
        &delivery(&state, &eth_outbox, 48, &honest),
        DELIVER_GAS,
    );
    assert!(matches!(
        orange.sim.submit(0, &stranded),
        Err(SubmitError::Rejected(reason::MESSAGE_DELIVERED))
    ));
    *orange.nonces.get_mut(&address(&relayer)).unwrap() -= 1;
    let told = orange.send(
        &relayer,
        Some(INBOX_ADDRESS),
        0,
        &delivery(&state, &eth_outbox, 48, &report_message),
        DELIVER_GAS,
    );
    assert_eq!(told.status, 1);
    gas.push(("SPENT_GAS", told.gas_used, SPENT_GAS));
    let refunded = orange.send(
        &carol,
        Some(orange_gateway),
        0,
        &refund_spent_calldata(to_eth[2].nonce, 1, &NATIVE, &address(&carol), &DAVE, ETHER),
        300_000,
    );
    assert_eq!(refunded.status, 1);
    assert_eq!(orange.native(address(&carol)), carol_before);

    // Every balance is exact, and on each side what is minted is what the other side locked.
    assert_eq!(eth.balance(ALICE), 96 * ETHER);
    assert_eq!(
        eth_u128(&mut eth, tkn, &address_view("balanceOf(address)", &ALICE)),
        500_000
    );
    assert_eq!(eth.balance(eth_gateway), 2 * ETHER);
    assert_eq!(
        eth_u128(
            &mut eth,
            eth_gateway,
            &address_view("locked(address)", &NATIVE)
        ),
        2 * ETHER
    );
    assert_eq!(
        eth_u128(
            &mut eth,
            eth_gateway,
            &address_view("locked(address)", &tkn)
        ),
        500_000
    );
    assert_eq!(
        eth_u128(
            &mut eth,
            tkn,
            &address_view("balanceOf(address)", &eth_gateway)
        ),
        500_000
    );
    assert_eq!(orange.balance_of(weth, address(&bob)), 2 * ETHER);
    assert_eq!(orange.balance_of(wtkn, address(&bob)), 500_000);
    assert_eq!(orange.balance_of(wtkn, address(&carol)), 0);
    assert_eq!(
        orange.u128_view(weth, &abi::call("totalSupply()", &[])),
        2 * ETHER
    );
    assert_eq!(
        orange.u128_view(wtkn, &abi::call("totalSupply()", &[])),
        500_000
    );
    assert_eq!(orange.native(address(&carol)), 98 * ETHER);
    assert_eq!(orange.native(orange_gateway), 2 * ETHER);
    assert_eq!(
        orange.u128_view(orange_gateway, &address_view("locked(address)", &NATIVE)),
        2 * ETHER
    );
    assert_eq!(
        eth_u128(
            &mut eth,
            worange,
            &address_view("balanceOf(address)", &DAVE)
        ),
        2 * ETHER
    );
    assert_eq!(
        eth_u128(&mut eth, worange, &abi::call("totalSupply()", &[])),
        2 * ETHER
    );
    let measured: Vec<(&str, u64)> = gas.iter().map(|(n, m, _)| (*n, *m)).collect();
    let pinned: Vec<(&str, u64)> = gas.iter().map(|(n, _, p)| (*n, *p)).collect();
    assert_eq!(measured, pinned);
}
