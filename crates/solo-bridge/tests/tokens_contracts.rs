//! The token gateways of spec 21 on revm, both in one EVM with
//! `TestMessenger` standing in for both message channels: tokens of either
//! side lock, mint, burn and release; deposits of unlisted, over-cap,
//! fee-taking and reentrant tokens are refused; deliveries are refused
//! from anyone but the paired gateway through the inbox, wait while paused
//! or over a mint cap, and a release whose transfer fails is owed and
//! claimed later. A randomized run checks the value invariant after every
//! step: what a gateway holds locked is exactly what the other side has
//! minted plus what is in flight, so minted never exceeds locked. The gas
//! of deposits against the stand-in is pinned here; spec 21 §8 states the
//! gas through the real channels, which `tokens.rs` pins.

mod support;

use revm::primitives::Log;
use solo_bridge::abi::{self, Value};
use solo_bridge::tokens::{
    EthereumGatewayConfig, NATIVE, SoloGatewayConfig, TokenMessage, address_view, claim_calldata,
    claim_to_calldata, deposit_calldata, set_lock_cap_calldata, set_mint_cap_calldata,
    wrapped_token,
};
use solo_trie::keccak256;
use support::eth::{ETH_CHAIN_ID, Eth, Outcome, init_code, selector, word_u64};
use support::solo::create_address;

const SOLO_CHAIN_ID: u64 = 1337;
const DEPLOYER: [u8; 20] = [0xD0; 20];
const OWNER: [u8; 20] = [0x0A; 20];
const GUARDIAN: [u8; 20] = [0x0B; 20];
const RELAYER: [u8; 20] = [0xEE; 20];
const STRANGER: [u8; 20] = [0x5A; 20];
const ALICE: [u8; 20] = [0xA1; 20];
const BOB: [u8; 20] = [0xB0; 20];
const CAROL: [u8; 20] = [0xC0; 20];
const DAVE: [u8; 20] = [0xDA; 20];
const ETHER: u128 = 1_000_000_000_000_000_000;
const MESSAGE_GAS: u64 = 1_500_000;
const BIG: u128 = 1 << 100;

/// Gas of a `deposit` of ETH on `TokenGatewayOnEthereum`, the first one, as a transaction.
const DEPOSIT_ETH_GAS: u64 = 95_051;
/// Gas of the first `deposit` of an ERC-20 there.
const DEPOSIT_TOKEN_GAS: u64 = 135_940;
/// Gas of a `deposit` that burns a wrapped token on the other side.
const WITHDRAW_GAS: u64 = 56_024;

fn ok(outcome: &Outcome) {
    assert!(outcome.success, "{outcome:?}");
}

fn reverted_with(outcome: &Outcome, error: &str) {
    assert!(!outcome.success, "{error}: {outcome:?}");
    assert_eq!(outcome.output, selector(error), "{error}");
}

fn reverted_with_address(outcome: &Outcome, error: &str, a: &[u8; 20]) {
    assert!(!outcome.success, "{error}: {outcome:?}");
    assert_eq!(
        outcome.output,
        abi::call(error, &[Value::address(a)]),
        "{error}"
    );
}

/// A message `TestMessenger` logged and nobody delivered yet.
#[derive(Debug, Clone)]
struct Pending {
    nonce: u64,
    sender: [u8; 20],
    recipient: [u8; 20],
    payload: Vec<u8>,
}

fn sent(messenger: [u8; 20], logs: &[Log]) -> Vec<Pending> {
    let topic = keccak256(b"Sent(uint64,address,address,bytes)");
    logs.iter()
        .filter(|l| l.address.0.0 == messenger && l.data.topics()[0].0 == topic)
        .map(|l| {
            let t = l.data.topics();
            let data = &l.data.data;
            let len = usize::try_from(word_u64(&data[32..64])).unwrap();
            Pending {
                nonce: word_u64(&t[1].0),
                sender: t[2].0[12..].try_into().unwrap(),
                recipient: t[3].0[12..].try_into().unwrap(),
                payload: data[64..64 + len].to_vec(),
            }
        })
        .collect()
}

/// Both gateways, the messenger, two test tokens (one on each side) and
/// the messages in flight.
struct World {
    eth: Eth,
    messenger: [u8; 20],
    /// `TokenGatewayOnEthereum`.
    on_eth: [u8; 20],
    /// `TokenGatewayOnSolo`.
    on_solo: [u8; 20],
    /// A token of the Ethereum side.
    tkn: [u8; 20],
    /// A token of the Solo side.
    stk: [u8; 20],
    pending: Vec<Pending>,
}

impl World {
    fn new() -> World {
        let mut eth = Eth::new();
        let messenger = eth.deploy(DEPLOYER, &init_code("TestMessenger"), &[]);
        let on_solo_address = create_address(&DEPLOYER, 2);
        let on_eth = eth.deploy(
            DEPLOYER,
            &init_code("TokenGatewayOnEthereum"),
            &EthereumGatewayConfig {
                outbox: messenger,
                inbox: messenger,
                solo_chain_id: SOLO_CHAIN_ID,
                solo_gateway: on_solo_address,
                owner: OWNER,
                guardian: GUARDIAN,
                message_gas: MESSAGE_GAS,
            }
            .constructor_args(),
        );
        let on_solo = eth.deploy(
            DEPLOYER,
            &init_code("TokenGatewayOnSolo"),
            &SoloGatewayConfig {
                outbox: messenger,
                inbox: messenger,
                ..SoloGatewayConfig::new(ETH_CHAIN_ID, on_eth, OWNER, GUARDIAN, "Solo", "SOLO")
            }
            .constructor_args(),
        );
        assert_eq!(on_solo, on_solo_address);
        let tkn = deploy_token(&mut eth, "Test Token", "TKN", 6);
        let stk = deploy_token(&mut eth, "Solo Token", "STK", 18);
        let mut w = World {
            eth,
            messenger,
            on_eth,
            on_solo,
            tkn,
            stk,
            pending: Vec::new(),
        };
        for (gateway, token) in [
            (on_eth, NATIVE),
            (on_eth, tkn),
            (on_solo, NATIVE),
            (on_solo, stk),
        ] {
            ok(&w
                .eth
                .call(OWNER, gateway, &set_lock_cap_calldata(&token, BIG)));
            let other = if gateway == on_eth { on_solo } else { on_eth };
            ok(&w
                .eth
                .call(OWNER, other, &set_mint_cap_calldata(&token, BIG)));
        }
        w
    }

    /// Runs `outcome` and keeps the messages it sent.
    fn record(&mut self, outcome: Outcome) -> Outcome {
        if outcome.success {
            let messages = sent(self.messenger, &outcome.logs);
            self.pending.extend(messages);
        }
        outcome
    }

    fn deposit(
        &mut self,
        from: [u8; 20],
        gateway: [u8; 20],
        token: [u8; 20],
        to: [u8; 20],
        amount: u128,
    ) -> Outcome {
        let value = if token == NATIVE { amount } else { 0 };
        let o = self
            .eth
            .call_value(from, gateway, value, &deposit_calldata(&token, &to, amount));
        self.record(o)
    }

    fn delivery(&self, p: &Pending) -> Vec<u8> {
        if p.recipient == self.on_solo {
            abi::call(
                "toSolo(address,uint64,address,bytes)",
                &[
                    Value::address(&self.on_solo),
                    Value::uint(u128::from(p.nonce)),
                    Value::address(&p.sender),
                    Value::Bytes(p.payload.clone()),
                ],
            )
        } else {
            abi::call(
                "toEthereum(address,uint64,uint64,address,bytes)",
                &[
                    Value::address(&p.recipient),
                    Value::uint(u128::from(SOLO_CHAIN_ID)),
                    Value::uint(u128::from(p.nonce)),
                    Value::address(&p.sender),
                    Value::Bytes(p.payload.clone()),
                ],
            )
        }
    }

    /// Delivers pending message `i`; it stays pending if the delivery fails.
    fn deliver(&mut self, i: usize) -> Outcome {
        let data = self.delivery(&self.pending[i]);
        let o = self.eth.call(RELAYER, self.messenger, &data);
        if o.success {
            self.pending.remove(i);
        }
        self.record(o)
    }

    fn deliver_all(&mut self) {
        while !self.pending.is_empty() {
            ok(&self.deliver(0));
        }
    }

    fn u128_view(&mut self, at: [u8; 20], data: &[u8]) -> u128 {
        let out = self.eth.view(RELAYER, at, data).output;
        u128::from_be_bytes(out[16..32].try_into().unwrap())
    }

    fn balance_of(&mut self, token: [u8; 20], account: [u8; 20]) -> u128 {
        if token == NATIVE {
            return self.eth.balance(account);
        }
        self.u128_view(token, &address_view("balanceOf(address)", &account))
    }

    fn supply(&mut self, token: [u8; 20]) -> u128 {
        if self
            .eth
            .view(RELAYER, token, &abi::call("totalSupply()", &[]))
            .output
            .is_empty()
        {
            return 0;
        }
        self.u128_view(token, &abi::call("totalSupply()", &[]))
    }

    fn gateway_view(&mut self, gateway: [u8; 20], signature: &str, token: [u8; 20]) -> u128 {
        self.u128_view(gateway, &address_view(signature, &token))
    }

    fn owed(&mut self, gateway: [u8; 20], token: [u8; 20], recipient: [u8; 20]) -> u128 {
        let data = abi::call(
            "owed(address,address)",
            &[Value::address(&token), Value::address(&recipient)],
        );
        self.u128_view(gateway, &data)
    }

    /// The value invariant of spec 21 §6 for the token `origin` native to
    /// the side of `home`, among `recipients`: locked equals minted plus in
    /// flight, and the gateway holds what is locked plus what is owed.
    fn check(&mut self, home: [u8; 20], origin: [u8; 20], recipients: &[[u8; 20]]) {
        let away = if home == self.on_eth {
            self.on_solo
        } else {
            self.on_eth
        };
        let wrapped = wrapped_of(away, origin);
        let locked = self.gateway_view(home, "locked(address)", origin);
        let minted = self.supply(wrapped);
        let in_flight: u128 = self
            .pending
            .iter()
            .filter_map(|p| match TokenMessage::decode(&p.payload)? {
                TokenMessage::Mint {
                    origin: o, amount, ..
                } if p.sender == home && o == origin => Some(amount),
                TokenMessage::Release { token, amount, .. }
                    if p.recipient == home && token == origin =>
                {
                    Some(amount)
                }
                _ => None,
            })
            .sum();
        assert!(minted <= locked, "minted {minted} > locked {locked}");
        assert_eq!(locked, minted + in_flight);
        let owed: u128 = recipients.iter().map(|r| self.owed(home, origin, *r)).sum();
        assert_eq!(self.balance_of(origin, home), locked + owed);
    }
}

/// The wrapped token of `origin` that `gateway` creates.
fn wrapped_of(gateway: [u8; 20], origin: [u8; 20]) -> [u8; 20] {
    wrapped_token(&gateway, &origin, &init_code("BridgedToken"))
}

fn deploy_token(eth: &mut Eth, name: &str, symbol: &str, decimals: u8) -> [u8; 20] {
    eth.deploy(
        DEPLOYER,
        &init_code("TestToken"),
        &abi::encode(&[
            Value::Bytes(name.as_bytes().to_vec()),
            Value::Bytes(symbol.as_bytes().to_vec()),
            Value::uint(u128::from(decimals)),
        ]),
    )
}

fn mint_and_approve(
    eth: &mut Eth,
    token: [u8; 20],
    holder: [u8; 20],
    amount: u128,
    spender: [u8; 20],
) {
    ok(&eth.call(
        holder,
        token,
        &abi::call(
            "mint(address,uint256)",
            &[Value::address(&holder), Value::uint(amount)],
        ),
    ));
    ok(&eth.call(
        holder,
        token,
        &abi::call(
            "approve(address,uint256)",
            &[Value::address(&spender), Value::uint(u128::MAX)],
        ),
    ));
}

fn string_view(eth: &mut Eth, at: [u8; 20], signature: &str) -> Vec<u8> {
    let out = eth.view(RELAYER, at, &abi::call(signature, &[])).output;
    let len = usize::try_from(word_u64(&out[32..64])).unwrap();
    out[64..64 + len].to_vec()
}

fn transfer(to: &[u8; 20], amount: u128) -> Vec<u8> {
    abi::call(
        "transfer(address,uint256)",
        &[Value::address(to), Value::uint(amount)],
    )
}

#[test]
#[allow(clippy::too_many_lines)]
fn tokens_of_both_sides_cross_and_come_back() {
    let mut w = World::new();
    let (on_eth, on_solo, tkn, stk) = (w.on_eth, w.on_solo, w.tkn, w.stk);
    w.eth.fund(ALICE, 100 * ETHER);
    mint_and_approve(&mut w.eth, tkn, ALICE, 1_000_000, on_eth);

    // Alice locks ETH and an ERC-20 on Ethereum for Bob on Solo.
    let first = w.deposit(ALICE, on_eth, NATIVE, BOB, 5 * ETHER);
    ok(&first);
    let second = w.deposit(ALICE, on_eth, tkn, BOB, 700_000);
    ok(&second);
    assert_eq!(
        (first.gas, second.gas),
        (DEPOSIT_ETH_GAS, DEPOSIT_TOKEN_GAS)
    );
    assert_eq!(w.pending.len(), 2);
    assert_eq!(
        TokenMessage::decode(&w.pending[1].payload),
        Some(TokenMessage::Mint {
            origin: tkn,
            from: ALICE,
            to: BOB,
            amount: 700_000,
            name: b"Test Token".to_vec(),
            symbol: b"TKN".to_vec(),
            decimals: 6,
        })
    );
    assert_eq!(w.eth.balance(on_eth), 5 * ETHER);
    assert_eq!(w.gateway_view(on_eth, "locked(address)", tkn), 700_000);
    // Delivered on Solo, each creates its wrapped token at the address anyone computes.
    w.deliver_all();
    let (weth, wtkn) = (wrapped_of(on_solo, NATIVE), wrapped_of(on_solo, tkn));
    let wrapped = w.eth.view(
        RELAYER,
        on_solo,
        &address_view("wrappedToken(address)", &tkn),
    );
    assert_eq!(wrapped.output[12..], wtkn);
    assert_eq!(w.balance_of(weth, BOB), 5 * ETHER);
    assert_eq!(w.balance_of(wtkn, BOB), 700_000);
    assert_eq!(string_view(&mut w.eth, weth, "symbol()"), b"ETH");
    assert_eq!(string_view(&mut w.eth, wtkn, "name()"), b"Test Token");
    assert_eq!(w.u128_view(wtkn, &abi::call("decimals()", &[])), 6);
    assert_eq!(
        w.eth
            .view(RELAYER, wtkn, &abi::call("origin()", &[]))
            .output[12..],
        tkn
    );

    // Bob pays Carol; Carol and Bob bridge back to Alice.
    ok(&w.eth.call(BOB, wtkn, &transfer(&CAROL, 400_000)));
    let back = w.deposit(CAROL, on_solo, wtkn, ALICE, 400_000);
    ok(&back);
    assert_eq!(back.gas, WITHDRAW_GAS);
    ok(&w.deposit(BOB, on_solo, weth, ALICE, 2 * ETHER));
    assert_eq!(w.supply(wtkn), 300_000);
    w.check(on_eth, tkn, &[ALICE]);
    w.deliver_all();
    assert_eq!(w.eth.balance(ALICE), 97 * ETHER);
    assert_eq!(w.balance_of(tkn, ALICE), 700_000);
    assert_eq!(w.gateway_view(on_eth, "locked(address)", tkn), 300_000);
    assert_eq!(w.eth.balance(on_eth), 3 * ETHER);

    // The other way: Carol locks Solo's currency and a Solo token for Dave on Ethereum.
    w.eth.fund(CAROL, 10 * ETHER);
    mint_and_approve(&mut w.eth, stk, CAROL, 50, on_solo);
    ok(&w.deposit(CAROL, on_solo, NATIVE, DAVE, 4 * ETHER));
    ok(&w.deposit(CAROL, on_solo, stk, DAVE, 50));
    w.deliver_all();
    let (wsolo, wstk) = (wrapped_of(on_eth, NATIVE), wrapped_of(on_eth, stk));
    assert_eq!(string_view(&mut w.eth, wsolo, "name()"), b"Solo");
    assert_eq!(w.balance_of(wsolo, DAVE), 4 * ETHER);
    assert_eq!(w.balance_of(wstk, DAVE), 50);
    ok(&w.deposit(DAVE, on_eth, wsolo, CAROL, ETHER));
    ok(&w.deposit(DAVE, on_eth, wstk, CAROL, 20));
    w.deliver_all();
    assert_eq!(w.eth.balance(CAROL), 7 * ETHER);
    assert_eq!(w.balance_of(stk, CAROL), 20);
    for (home, origin) in [
        (on_eth, NATIVE),
        (on_eth, tkn),
        (on_solo, NATIVE),
        (on_solo, stk),
    ] {
        w.check(home, origin, &[]);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn deposits_refuse_what_cannot_be_bridged_one_for_one() {
    let mut w = World::new();
    let (on_eth, on_solo, tkn) = (w.on_eth, w.on_solo, w.tkn);
    w.eth.fund(ALICE, 100 * ETHER);
    mint_and_approve(&mut w.eth, tkn, ALICE, 1_000, on_eth);
    let deposit = |w: &mut World, token: [u8; 20], to: [u8; 20], amount: u128, value: u128| {
        w.eth
            .call_value(ALICE, on_eth, value, &deposit_calldata(&token, &to, amount))
    };
    reverted_with(&deposit(&mut w, NATIVE, [0; 20], 1, 1), "ZeroAddress()");
    reverted_with(&deposit(&mut w, NATIVE, BOB, 0, 0), "ZeroAmount()");
    reverted_with(&deposit(&mut w, NATIVE, BOB, 2, 1), "WrongValue()");
    reverted_with(&deposit(&mut w, tkn, BOB, 2, 1), "WrongValue()");
    // A token nobody listed, and one over its cap.
    let other = deploy_token(&mut w.eth, "Other", "OTH", 18);
    mint_and_approve(&mut w.eth, other, ALICE, 1_000, on_eth);
    reverted_with_address(
        &deposit(&mut w, other, BOB, 1, 0),
        "CapExceeded(address)",
        &other,
    );
    ok(&w.eth.call(OWNER, on_eth, &set_lock_cap_calldata(&tkn, 100)));
    ok(&deposit(&mut w, tkn, BOB, 60, 0));
    reverted_with_address(
        &deposit(&mut w, tkn, BOB, 41, 0),
        "CapExceeded(address)",
        &tkn,
    );
    ok(&deposit(&mut w, tkn, BOB, 40, 0));
    ok(&w.eth.call(OWNER, on_eth, &set_lock_cap_calldata(&tkn, BIG)));
    // A fee-on-transfer token would lock less than it mints: refused.
    let fee = abi::call("setFee(uint256)", &[Value::uint(100)]);
    ok(&w.eth.call(ALICE, tkn, &fee));
    reverted_with(&deposit(&mut w, tkn, BOB, 100, 0), "BalanceMismatch()");
    ok(&w
        .eth
        .call(ALICE, tkn, &abi::call("setFee(uint256)", &[Value::uint(0)])));
    // A token that reverts, and one that re-enters the gateway from transferFrom.
    let failing = |on: bool| abi::call("setFailing(bool)", &[Value::uint(u128::from(on))]);
    ok(&w.eth.call(ALICE, tkn, &failing(true)));
    reverted_with(&deposit(&mut w, tkn, BOB, 1, 0), "TransferFailed()");
    ok(&w.eth.call(ALICE, tkn, &failing(false)));
    let hook = abi::call(
        "setHook(address,bytes)",
        &[
            Value::address(&on_eth),
            Value::Bytes(deposit_calldata(&tkn, &BOB, 1)),
        ],
    );
    ok(&w.eth.call(ALICE, tkn, &hook));
    ok(&deposit(&mut w, tkn, BOB, 1, 0));
    assert_eq!(w.u128_view(tkn, &abi::call("hookSucceeded()", &[])), 0);
    let result = w
        .eth
        .view(RELAYER, tkn, &abi::call("hookResult()", &[]))
        .output;
    assert_eq!(result[64..68], selector("Reentrant()")[..]);
    assert_eq!(w.gateway_view(on_eth, "locked(address)", tkn), 101);
    let unhook = abi::call(
        "setHook(address,bytes)",
        &[Value::address(&[0; 20]), Value::Bytes(vec![])],
    );
    ok(&w.eth.call(ALICE, tkn, &unhook));
    // Paused by the guardian: nothing deposits until the owner unpauses.
    reverted_with(
        &w.eth.call(STRANGER, on_eth, &abi::call("pause()", &[])),
        "NotGuardian()",
    );
    ok(&w.eth.call(GUARDIAN, on_eth, &abi::call("pause()", &[])));
    reverted_with(&deposit(&mut w, NATIVE, BOB, 1, 1), "IsPaused()");
    reverted_with(
        &w.eth.call(GUARDIAN, on_eth, &abi::call("unpause()", &[])),
        "NotOwner()",
    );
    ok(&w.eth.call(OWNER, on_eth, &abi::call("unpause()", &[])));
    // A wrapped token deposits only without value, and only what the caller holds.
    let o = deposit(&mut w, NATIVE, BOB, 10, 10);
    w.record(o);
    w.deliver_all();
    let weth = wrapped_of(on_solo, NATIVE);
    w.eth.fund(BOB, ETHER);
    let burn = |w: &mut World, amount: u128, value: u128| {
        w.eth.call_value(
            BOB,
            on_solo,
            value,
            &deposit_calldata(&weth, &ALICE, amount),
        )
    };
    reverted_with(&burn(&mut w, 1, 1), "WrongValue()");
    reverted_with(&burn(&mut w, 11, 0), "InsufficientBalance()");
    // Only the gateway mints and burns its tokens, and initializes them once.
    for call in [
        abi::call(
            "mint(address,uint256)",
            &[Value::address(&BOB), Value::uint(1)],
        ),
        abi::call(
            "burn(address,uint256)",
            &[Value::address(&BOB), Value::uint(1)],
        ),
        abi::call(
            "initialize(address,string,string,uint8)",
            &[
                Value::address(&BOB),
                Value::Bytes(vec![]),
                Value::Bytes(vec![]),
                Value::uint(0),
            ],
        ),
    ] {
        reverted_with(&w.eth.call(BOB, weth, &call), "NotGateway()");
    }
    // Metadata longer than 64 bytes is cut.
    let long = deploy_token(&mut w.eth, &"N".repeat(70), "L", 0);
    mint_and_approve(&mut w.eth, long, ALICE, 5, on_eth);
    ok(&w.eth.call(OWNER, on_eth, &set_lock_cap_calldata(&long, 5)));
    let o = deposit(&mut w, long, BOB, 5, 0);
    w.record(o);
    let Some(TokenMessage::Mint { name, decimals, .. }) =
        TokenMessage::decode(&w.pending.last().unwrap().payload)
    else {
        panic!("a mint");
    };
    assert_eq!((name.len(), decimals), (64, 0));
}

#[test]
#[allow(clippy::too_many_lines)]
fn deliveries_count_only_from_the_paired_gateway_and_failed_releases_are_owed() {
    let mut w = World::new();
    let (on_eth, on_solo, tkn) = (w.on_eth, w.on_solo, w.tkn);
    w.eth.fund(ALICE, 100 * ETHER);
    mint_and_approve(&mut w.eth, tkn, ALICE, 1_000, on_eth);
    ok(&w.deposit(ALICE, on_eth, NATIVE, BOB, 10 * ETHER));
    let message = w.pending[0].clone();
    // Not through the inbox, from another sender, or naming another chain: refused.
    let on_solo_call = |nonce: u64, sender: [u8; 20], payload: &[u8]| {
        abi::call(
            "onEthereumMessage(uint64,address,bytes)",
            &[
                Value::uint(u128::from(nonce)),
                Value::address(&sender),
                Value::Bytes(payload.to_vec()),
            ],
        )
    };
    reverted_with(
        &w.eth.call(
            STRANGER,
            on_solo,
            &on_solo_call(0, on_eth, &message.payload),
        ),
        "NotInbox()",
    );
    let mut forged = message.clone();
    forged.sender = STRANGER;
    let data = w.delivery(&forged);
    reverted_with(
        &w.eth.call(RELAYER, w.messenger, &data),
        "NotRemoteGateway()",
    );
    let mut unknown = message.clone();
    unknown.payload[31] = 9;
    let data = w.delivery(&unknown);
    reverted_with(&w.eth.call(RELAYER, w.messenger, &data), "UnknownMessage()");
    // Over the mint cap the delivery fails and waits; the owner raises the cap and it goes through.
    ok(&w
        .eth
        .call(OWNER, on_solo, &set_mint_cap_calldata(&NATIVE, ETHER)));
    reverted_with_address(&w.deliver(0), "CapExceeded(address)", &NATIVE);
    ok(&w.eth.call(GUARDIAN, on_solo, &abi::call("pause()", &[])));
    ok(&w
        .eth
        .call(OWNER, on_solo, &set_mint_cap_calldata(&NATIVE, BIG)));
    reverted_with(&w.deliver(0), "IsPaused()");
    ok(&w.eth.call(OWNER, on_solo, &abi::call("unpause()", &[])));
    ok(&w.deliver(0));
    let weth = wrapped_of(on_solo, NATIVE);

    // On Ethereum: the inbox, the Solo chain and the paired sender are checked, and no value.
    let on_eth_call = |chain: u64, sender: [u8; 20], value: u128, payload: &[u8]| {
        abi::call(
            "onSoloMessage(uint64,uint64,address,uint256,bytes)",
            &[
                Value::uint(u128::from(chain)),
                Value::uint(1),
                Value::address(&sender),
                Value::uint(value),
                Value::Bytes(payload.to_vec()),
            ],
        )
    };
    let release = TokenMessage::Release {
        token: NATIVE,
        from: BOB,
        to: CAROL,
        amount: ETHER,
    }
    .encode();
    reverted_with(
        &w.eth.call(
            STRANGER,
            on_eth,
            &on_eth_call(SOLO_CHAIN_ID, on_solo, 0, &release),
        ),
        "NotInbox()",
    );
    // The owner can point the gateway at a successor inbox; here, at an account the test speaks for.
    reverted_with(
        &w.eth.call(
            STRANGER,
            on_eth,
            &address_view("setInbox(address)", &RELAYER),
        ),
        "NotOwner()",
    );
    ok(&w
        .eth
        .call(OWNER, on_eth, &address_view("setInbox(address)", &RELAYER)));
    reverted_with(
        &w.eth.call(
            RELAYER,
            on_eth,
            &on_eth_call(SOLO_CHAIN_ID + 1, on_solo, 0, &release),
        ),
        "WrongChain()",
    );
    reverted_with(
        &w.eth.call(
            RELAYER,
            on_eth,
            &on_eth_call(SOLO_CHAIN_ID, STRANGER, 0, &release),
        ),
        "NotRemoteGateway()",
    );
    reverted_with(
        &w.eth.call(
            RELAYER,
            on_eth,
            &on_eth_call(SOLO_CHAIN_ID, on_solo, 1, &release),
        ),
        "WrongValue()",
    );
    ok(&w.eth.call(
        OWNER,
        on_eth,
        &address_view("setInbox(address)", &w.messenger),
    ));

    // A recipient that refuses ETH: the release is owed, the message delivered.
    let receiver = w.eth.deploy(DEPLOYER, &init_code("TestReceiver"), &[]);
    let rejecting = |on: bool| abi::call("setRejecting(bool)", &[Value::uint(u128::from(on))]);
    ok(&w.eth.call(STRANGER, receiver, &rejecting(true)));
    ok(&w.deposit(BOB, on_solo, weth, receiver, 3 * ETHER));
    // Too little gas for the transfer: the delivery fails rather than leaving it owed.
    let data = w.delivery(&w.pending[0].clone());
    reverted_with(
        &w.eth.call_gas(RELAYER, w.messenger, &data, 150_000),
        "InsufficientGas()",
    );
    let delivered = w.deliver(0);
    ok(&delivered);
    let failed = keccak256(b"ReleaseFailed(uint64,address,address,address,uint256)");
    assert!(
        delivered
            .logs
            .iter()
            .any(|l| l.data.topics()[0].0 == failed)
    );
    assert_eq!(w.owed(on_eth, NATIVE, receiver), 3 * ETHER);
    w.check(on_eth, NATIVE, &[receiver]);
    // Claims fail while it still refuses, and succeed for anyone once it accepts.
    reverted_with(
        &w.eth
            .call(STRANGER, on_eth, &claim_calldata(&NATIVE, &receiver)),
        "TransferFailed()",
    );
    reverted_with(
        &w.eth.call(STRANGER, on_eth, &claim_calldata(&NATIVE, &BOB)),
        "NothingOwed()",
    );
    ok(&w.eth.call(GUARDIAN, on_eth, &abi::call("pause()", &[])));
    reverted_with(
        &w.eth
            .call(STRANGER, on_eth, &claim_calldata(&NATIVE, &receiver)),
        "IsPaused()",
    );
    ok(&w.eth.call(OWNER, on_eth, &abi::call("unpause()", &[])));
    ok(&w.eth.call(STRANGER, receiver, &rejecting(false)));
    ok(&w
        .eth
        .call(STRANGER, on_eth, &claim_calldata(&NATIVE, &receiver)));
    assert_eq!(
        w.u128_view(receiver, &abi::call("received()", &[])),
        3 * ETHER
    );
    assert_eq!(w.owed(on_eth, NATIVE, receiver), 0);

    // A token whose transfer fails: owed to Bob, who claims it to Carol.
    ok(&w.deposit(ALICE, on_eth, tkn, BOB, 500));
    w.deliver_all();
    let wtkn = wrapped_of(on_solo, tkn);
    ok(&w.eth.call(
        ALICE,
        tkn,
        &abi::call("setFailing(bool)", &[Value::uint(1)]),
    ));
    ok(&w.deposit(BOB, on_solo, wtkn, BOB, 200));
    ok(&w.deliver(0));
    assert_eq!(w.owed(on_eth, tkn, BOB), 200);
    w.check(on_eth, tkn, &[BOB]);
    ok(&w.eth.call(
        ALICE,
        tkn,
        &abi::call("setFailing(bool)", &[Value::uint(0)]),
    ));
    reverted_with(
        &w.eth.call(BOB, on_eth, &claim_to_calldata(&tkn, &[0; 20])),
        "ZeroAddress()",
    );
    ok(&w.eth.call(BOB, on_eth, &claim_to_calldata(&tkn, &CAROL)));
    assert_eq!(w.balance_of(tkn, CAROL), 200);
    w.check(on_eth, tkn, &[BOB]);
}

#[test]
fn the_owner_governs_and_the_constructors_check_their_arguments() {
    let mut w = World::new();
    let on_eth = w.on_eth;
    for call in [
        set_lock_cap_calldata(&NATIVE, 1),
        set_mint_cap_calldata(&NATIVE, 1),
        address_view("setGuardian(address)", &STRANGER),
        address_view("transferOwnership(address)", &STRANGER),
        abi::call("setMessageGas(uint64)", &[Value::uint(1_000_000)]),
    ] {
        reverted_with(&w.eth.call(STRANGER, on_eth, &call), "NotOwner()");
    }
    for zero in [
        "setGuardian(address)",
        "transferOwnership(address)",
        "setInbox(address)",
    ] {
        reverted_with(
            &w.eth.call(OWNER, on_eth, &address_view(zero, &[0; 20])),
            "ZeroAddress()",
        );
    }
    let set_gas = |gas: u128| abi::call("setMessageGas(uint64)", &[Value::uint(gas)]);
    reverted_with(
        &w.eth.call(OWNER, on_eth, &set_gas(999_999)),
        "MessageGasTooLow()",
    );
    ok(&w.eth.call(OWNER, on_eth, &set_gas(1_000_000)));
    assert_eq!(
        w.u128_view(on_eth, &abi::call("messageGas()", &[])),
        1_000_000
    );
    ok(&w.eth.call(
        OWNER,
        on_eth,
        &address_view("setGuardian(address)", &STRANGER),
    ));
    ok(&w.eth.call(STRANGER, on_eth, &abi::call("pause()", &[])));
    ok(&w.eth.call(
        OWNER,
        on_eth,
        &address_view("transferOwnership(address)", &STRANGER),
    ));
    ok(&w.eth.call(STRANGER, on_eth, &abi::call("unpause()", &[])));
    reverted_with(
        &w.eth.call(OWNER, on_eth, &abi::call("unpause()", &[])),
        "NotOwner()",
    );
    let config = EthereumGatewayConfig {
        outbox: w.messenger,
        inbox: w.messenger,
        solo_chain_id: SOLO_CHAIN_ID,
        solo_gateway: w.on_solo,
        owner: OWNER,
        guardian: GUARDIAN,
        message_gas: MESSAGE_GAS,
    };
    let (o, _) = w.eth.try_deploy(
        DEPLOYER,
        &init_code("TokenGatewayOnEthereum"),
        &EthereumGatewayConfig {
            message_gas: 999_999,
            ..config.clone()
        }
        .constructor_args(),
    );
    reverted_with(&o, "MessageGasTooLow()");
    for broken in [
        EthereumGatewayConfig {
            outbox: [0; 20],
            ..config.clone()
        },
        EthereumGatewayConfig {
            inbox: [0; 20],
            ..config.clone()
        },
        EthereumGatewayConfig {
            solo_gateway: [0; 20],
            ..config.clone()
        },
        EthereumGatewayConfig {
            owner: [0; 20],
            ..config.clone()
        },
        EthereumGatewayConfig {
            guardian: [0; 20],
            ..config.clone()
        },
    ] {
        let (o, _) = w.eth.try_deploy(
            DEPLOYER,
            &init_code("TokenGatewayOnEthereum"),
            &broken.constructor_args(),
        );
        reverted_with(&o, "ZeroAddress()");
    }
    let solo = SoloGatewayConfig::new(ETH_CHAIN_ID, on_eth, OWNER, GUARDIAN, "Solo", "SOLO");
    for broken in [
        SoloGatewayConfig {
            outbox: [0; 20],
            ..solo.clone()
        },
        SoloGatewayConfig {
            inbox: [0; 20],
            ..solo.clone()
        },
    ] {
        let (o, _) = w.eth.try_deploy(
            DEPLOYER,
            &init_code("TokenGatewayOnSolo"),
            &broken.constructor_args(),
        );
        reverted_with(&o, "ZeroAddress()");
    }
}

/// A deterministic generator for the randomized run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[usize::try_from(self.below(items.len() as u64)).unwrap()]
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn locked_always_covers_what_is_minted() {
    let mut w = World::new();
    let (on_eth, on_solo, tkn, stk) = (w.on_eth, w.on_solo, w.tkn, w.stk);
    let receiver = w.eth.deploy(DEPLOYER, &init_code("TestReceiver"), &[]);
    let eth_users = [ALICE, BOB];
    let solo_users = [CAROL, DAVE];
    let recipients_eth = [ALICE, BOB, receiver];
    let recipients_solo = [CAROL, DAVE, receiver];
    for u in eth_users {
        w.eth.fund(u, 1_000 * ETHER);
        mint_and_approve(&mut w.eth, tkn, u, 1_000_000, on_eth);
    }
    for u in solo_users {
        w.eth.fund(u, 1_000 * ETHER);
        mint_and_approve(&mut w.eth, stk, u, 1_000_000, on_solo);
    }
    let homes = [
        (on_eth, NATIVE),
        (on_eth, tkn),
        (on_solo, NATIVE),
        (on_solo, stk),
    ];
    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    let mut delivered = 0;
    for _ in 0..600 {
        let op = rng.below(12);
        let amount =
            u128::from(rng.below(5_000) + 1) * if rng.below(2) == 0 { 1 } else { ETHER / 1_000 };
        match op {
            0..=1 => {
                let token = rng.pick(&[NATIVE, tkn]);
                let (from, to) = (rng.pick(&eth_users), rng.pick(&recipients_solo));
                w.deposit(from, on_eth, token, to, amount);
            }
            2 => {
                let token = rng.pick(&[NATIVE, stk]);
                let (from, to) = (rng.pick(&solo_users), rng.pick(&recipients_eth));
                w.deposit(from, on_solo, token, to, amount);
            }
            3 => {
                let origin = rng.pick(&[NATIVE, tkn]);
                let wrapped = wrapped_of(on_solo, origin);
                let (from, to) = (rng.pick(&solo_users), rng.pick(&recipients_eth));
                if w.supply(wrapped) > 0 {
                    let held = w.balance_of(wrapped, from).min(amount);
                    if held > 0 {
                        w.deposit(from, on_solo, wrapped, to, held);
                    }
                }
            }
            4 => {
                let origin = rng.pick(&[NATIVE, stk]);
                let wrapped = wrapped_of(on_eth, origin);
                let (from, to) = (rng.pick(&eth_users), rng.pick(&recipients_solo));
                if w.supply(wrapped) > 0 {
                    let held = w.balance_of(wrapped, from).min(amount);
                    if held > 0 {
                        w.deposit(from, on_eth, wrapped, to, held);
                    }
                }
            }
            5..=8 if !w.pending.is_empty() => {
                let i = usize::try_from(rng.below(w.pending.len() as u64)).unwrap();
                if w.deliver(i).success {
                    delivered += 1;
                }
            }
            9 => {
                let gateway = rng.pick(&[on_eth, on_solo]);
                let call = if rng.below(4) == 0 {
                    "pause()"
                } else {
                    "unpause()"
                };
                ok(&w.eth.call(OWNER, gateway, &abi::call(call, &[])));
            }
            10 => {
                let on = u128::from(rng.below(2));
                ok(&w.eth.call(
                    STRANGER,
                    receiver,
                    &abi::call("setRejecting(bool)", &[Value::uint(on)]),
                ));
                let (gateway, token) = rng.pick(&homes);
                w.eth
                    .call(STRANGER, gateway, &claim_calldata(&token, &receiver));
            }
            _ => {
                let (gateway, token) = rng.pick(&homes);
                let other = if gateway == on_eth { on_solo } else { on_eth };
                let cap = if rng.below(4) == 0 { amount * 3 } else { BIG };
                if rng.below(2) == 0 {
                    ok(&w
                        .eth
                        .call(OWNER, gateway, &set_lock_cap_calldata(&token, cap)));
                } else {
                    ok(&w
                        .eth
                        .call(OWNER, other, &set_mint_cap_calldata(&token, cap)));
                }
            }
        }
        for (home, origin) in homes {
            let recipients = if home == on_eth {
                &recipients_eth
            } else {
                &recipients_solo
            };
            w.check(home, origin, recipients);
        }
    }
    assert!(delivered > 50, "{delivered}");
    // Unpause, lift the caps, deliver everything, bridge everything back and claim what is owed:
    // every original balance is whole again and nothing stays locked or minted.
    for (gateway, token) in homes {
        let other = if gateway == on_eth { on_solo } else { on_eth };
        ok(&w.eth.call(OWNER, gateway, &abi::call("unpause()", &[])));
        ok(&w
            .eth
            .call(OWNER, gateway, &set_lock_cap_calldata(&token, BIG)));
        ok(&w
            .eth
            .call(OWNER, other, &set_mint_cap_calldata(&token, BIG)));
    }
    ok(&w.eth.call(
        STRANGER,
        receiver,
        &abi::call("setRejecting(bool)", &[Value::uint(0)]),
    ));
    w.deliver_all();
    for (home, origin) in homes {
        let away = if home == on_eth { on_solo } else { on_eth };
        let wrapped = wrapped_of(away, origin);
        let holders: Vec<[u8; 20]> = if home == on_eth {
            recipients_solo.to_vec()
        } else {
            recipients_eth.to_vec()
        };
        for holder in holders {
            let held = if w.supply(wrapped) > 0 {
                w.balance_of(wrapped, holder)
            } else {
                0
            };
            if held > 0 && holder != receiver {
                ok(&w.deposit(holder, away, wrapped, holder, held));
            }
        }
    }
    w.deliver_all();
    for (home, origin) in homes {
        let recipients = if home == on_eth {
            &recipients_eth
        } else {
            &recipients_solo
        };
        for r in recipients {
            if w.owed(home, origin, *r) > 0 {
                ok(&w.eth.call(STRANGER, home, &claim_calldata(&origin, r)));
            }
        }
        w.check(home, origin, recipients);
    }
    // What the test receiver holds of wrapped tokens it cannot bridge back is all that stays locked.
    for (home, origin) in homes {
        let away = if home == on_eth { on_solo } else { on_eth };
        let wrapped = wrapped_of(away, origin);
        let stuck = if w.supply(wrapped) > 0 {
            w.balance_of(wrapped, receiver)
        } else {
            0
        };
        assert_eq!(w.gateway_view(home, "locked(address)", origin), stuck);
        assert_eq!(w.supply(wrapped), stuck);
    }
}
