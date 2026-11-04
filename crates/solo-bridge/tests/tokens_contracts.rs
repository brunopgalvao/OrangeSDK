//! The token gateways of spec 21 on revm, both in one EVM with
//! `TestMessenger` standing in for both message channels: tokens of either
//! side lock, mint, burn and release; deposits of unlisted, over-cap,
//! fee-taking and reentrant tokens are refused; deliveries are refused
//! from anyone but the paired gateway through the inbox, wait while paused
//! or over a mint cap, and a release whose transfer fails is owed and
//! claimed later; mints and releases over their rate limit wait in a queue
//! until it allows them, one of them frozen or cancelled without stopping
//! the rest, a cancelled one refunded to its sender only if its home
//! gateway really sent it, and no gateway takes deposits before a message
//! of its peer proves the peer exists. Honest messages that never arrive,
//! their nonce taken by a forgery or vetoed in `SoloInbox`, are refunded or
//! sent again once the receiving side reports the nonce spent, and a mint of
//! a token the receiving side does not list goes back. A randomized run
//! checks the value invariant after every step: what a gateway holds locked
//! is exactly what the other side has minted plus what is in flight, queued
//! or stranded, plus what owners cancelled out of the queue without a
//! refund, so minted never exceeds locked, whatever forged messages the
//! channels deliver. The gas
//! of deposits against the stand-in is pinned here; spec 21 §8 states the
//! gas through the real channels, which `tokens.rs` pins.

mod support;

use revm::primitives::Log;
use solo_abi::bridge::Message as SoloMessage;
use solo_bridge::abi::{self, Value};
use solo_bridge::tokens::{
    EthereumGatewayConfig, NATIVE, SoloGatewayConfig, TokenMessage, VOID, address_view,
    cancel_queued_calldata, claim_calldata, claim_to_calldata, deposit_calldata,
    execute_queued_calldata, freeze_queued_calldata, identity, refund_queued_calldata,
    refund_spent_calldata, report_delivered_calldata, report_vetoed_calldata,
    resend_spent_calldata, set_lock_cap_calldata, set_mint_cap_calldata, set_mint_limit_calldata,
    set_release_limit_calldata, unfreeze_queued_calldata, wrapped_token,
};
use solo_trie::keccak256;
use std::collections::{BTreeMap, BTreeSet};
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

/// Gas of a `deposit` of ETH on `TokenGatewayOnEthereum`, the first one, as a transaction. The
/// stand-in's nonce is no longer zero: the gateways' `HELLO`s came first.
const DEPOSIT_ETH_GAS: u64 = 100_631;
/// Gas of the first `deposit` of an ERC-20 there.
const DEPOSIT_TOKEN_GAS: u64 = 158_620;
/// Gas of a `deposit` that burns a wrapped token on the other side.
const WITHDRAW_GAS: u64 = 78_611;
/// Gas of the guardian's `freezeQueued` of a queued transfer (spec 21 §8).
const FREEZE_GAS: u64 = 32_525;
/// Gas of the owner's `cancelQueued` of a queued mint under a mint limit.
const CANCEL_MINT_GAS: u64 = 51_124;
/// Gas of the owner's `cancelQueued` of a queued release under a release limit.
const CANCEL_RELEASE_GAS: u64 = 53_112;
/// Gas of the owner's `refundQueued` of a queued mint under a mint limit: the
/// cancellation, and the `REFUND` sent through the stand-in and recorded.
const REFUND_MINT_GAS: u64 = 79_786;
/// Gas of the owner's `refundQueued` of a queued release under a release limit.
const REFUND_RELEASE_GAS: u64 = 85_699;

fn ok(outcome: &Outcome) {
    assert!(outcome.success, "{outcome:?}");
}

/// Whether `outcome` logged the event `signature`.
fn logged(outcome: &Outcome, signature: &str) -> bool {
    let topic = keccak256(signature.as_bytes());
    outcome.logs.iter().any(|l| l.data.topics()[0].0 == topic)
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

/// The transfers gateways queued, as `(gateway, id, ready at)`.
fn queued_in(logs: &[Log]) -> Vec<([u8; 20], u64, u64)> {
    let topic = keccak256(b"Queued(uint256,uint64,uint8,address,address,uint256,uint64)");
    logs.iter()
        .filter(|l| l.data.topics()[0].0 == topic)
        .map(|l| {
            let id = word_u64(&l.data.topics()[1].0);
            (l.address.0.0, id, word_u64(&l.data.data[4 * 32..5 * 32]))
        })
        .collect()
}

/// The `HELLO` a gateway sends when it is deployed (spec 21 §5.7).
fn hello(heard: bool) -> Vec<u8> {
    TokenMessage::Hello { heard }.encode()
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
    /// Transfers queued and not executed yet: `(gateway, id, ready at)`.
    queued: Vec<([u8; 20], u64, u64)>,
    /// What owners cancelled out of the queue of honest transfers without a
    /// refund, by the token's home gateway and the token: it stays locked
    /// there.
    retired: BTreeMap<([u8; 20], [u8; 20]), u128>,
    /// Queued transfers that forged messages made, as `(gateway, id)`.
    forged_entries: BTreeSet<([u8; 20], u64)>,
    /// What forged transfers still queued took, by the token's home gateway
    /// and the token: a forged mint's amount queued away from home, a
    /// forged release's taken out of `locked` at home.
    forged_out: BTreeMap<([u8; 20], [u8; 20]), u128>,
    /// The nonces of forged messages, whose refunds the home gateway refuses.
    forged_nonces: BTreeSet<u64>,
    /// Honest messages that will never arrive, a forgery having taken their
    /// nonce or the inbox having vetoed them, until their sender refunds or
    /// sends them again (spec 21 §5.5c): what they carry is still held as
    /// it was in flight.
    stranded: Vec<Pending>,
}

impl World {
    /// Both gateways, each having heard from the other, with every token
    /// listed.
    fn new() -> World {
        let mut w = World::unconfirmed();
        w.handshake();
        w
    }

    /// Delivers the two `HELLO`s the constructors sent, and the answers.
    fn handshake(&mut self) {
        let (on_eth, on_solo) = (self.on_eth, self.on_solo);
        self.pending.push(Pending {
            nonce: 0,
            sender: on_eth,
            recipient: on_solo,
            payload: hello(false),
        });
        self.pending.push(Pending {
            nonce: 1,
            sender: on_solo,
            recipient: on_eth,
            payload: hello(false),
        });
        self.deliver_all();
    }

    /// Both gateways, deployed and listing every token, before any message
    /// between them is delivered.
    fn unconfirmed() -> World {
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
            queued: Vec::new(),
            retired: BTreeMap::new(),
            forged_entries: BTreeSet::new(),
            forged_out: BTreeMap::new(),
            forged_nonces: BTreeSet::new(),
            stranded: Vec::new(),
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
            self.queued.extend(queued_in(&outcome.logs));
        }
        outcome
    }

    /// Executes queued transfer `i` of [`World::queued`]; it stays queued
    /// if that fails.
    fn execute(&mut self, i: usize) -> Outcome {
        let (gateway, id, _) = self.queued[i];
        let o = self
            .eth
            .call(STRANGER, gateway, &execute_queued_calldata(id));
        if o.success {
            self.queued.remove(i);
        }
        self.record(o)
    }

    /// Queued transfer `id` at `gateway`: its kind, token, amount, whether
    /// a refund queued it, and its message's nonce.
    fn queued_entry(&mut self, gateway: [u8; 20], id: u64) -> Entry {
        let out = self
            .eth
            .view(
                RELAYER,
                gateway,
                &abi::call("queued(uint256)", &[Value::uint(u128::from(id))]),
            )
            .output;
        Entry {
            kind: word_u64(&out[32..64]),
            token: out[12..32].try_into().unwrap(),
            amount: u128::from_be_bytes(out[8 * 32 + 16..9 * 32].try_into().unwrap()),
            refund: word_u64(&out[3 * 32..4 * 32]) == 1,
            nonce: word_u64(&out[4 * 32..5 * 32]),
        }
    }

    /// The home gateway of the token of a queued transfer of `kind` at
    /// `gateway`: a mint's token is at home on the other side, a release's
    /// here.
    fn home_of(&self, gateway: [u8; 20], kind: u64) -> [u8; 20] {
        match (kind, gateway == self.on_eth) {
            (1, true) | (2, false) => self.on_solo,
            _ => self.on_eth,
        }
    }

    /// The owner cancels queued transfer `i` of [`World::queued`]: what an
    /// honest one carried stays locked at the token's home, and a forged one
    /// is gone.
    fn cancel(&mut self, i: usize) -> Outcome {
        let (gateway, id, _) = self.queued[i];
        let e = self.queued_entry(gateway, id);
        let o = self.eth.call(OWNER, gateway, &cancel_queued_calldata(id));
        if o.success {
            self.queued.remove(i);
            let home = self.home_of(gateway, e.kind);
            if self.forged_entries.remove(&(gateway, id)) {
                *self.forged_out.get_mut(&(home, e.token)).unwrap() -= e.amount;
            } else {
                *self.retired.entry((home, e.token)).or_default() += e.amount;
            }
        }
        o
    }

    /// The owner cancels queued transfer `i` of [`World::queued`] and
    /// refunds it: an honest one's value is in flight back to its sender,
    /// and a forged one is gone, its refund to be refused.
    fn refund(&mut self, i: usize) -> Outcome {
        let (gateway, id, _) = self.queued[i];
        let e = self.queued_entry(gateway, id);
        let o = self.eth.call(OWNER, gateway, &refund_queued_calldata(id));
        if o.success {
            self.queued.remove(i);
            if self.forged_entries.remove(&(gateway, id)) {
                let home = self.home_of(gateway, e.kind);
                *self.forged_out.get_mut(&(home, e.token)).unwrap() -= e.amount;
            }
        }
        self.record(o)
    }

    /// Delivers a message the paired gateway never sent, as a channel that
    /// failed would: it is not in flight. What it queues is counted as
    /// forged until the owner cancels or refunds it.
    fn forge(&mut self, p: &Pending) -> Outcome {
        let data = self.delivery(p);
        let o = self.eth.call(RELAYER, self.messenger, &data);
        let before = self.queued.len();
        let o = self.record(o);
        if o.success {
            self.forged_nonces.insert(p.nonce);
        }
        let added: Vec<_> = self.queued.iter().skip(before).copied().collect();
        for (gateway, id, _) in added {
            let e = self.queued_entry(gateway, id);
            let home = self.home_of(gateway, e.kind);
            self.forged_entries.insert((gateway, id));
            *self.forged_out.entry((home, e.token)).or_default() += e.amount;
        }
        o
    }

    /// Takes pending message `i` out of flight: a forgery is about to take
    /// its nonce, or the inbox vetoes it, so it never arrives.
    fn strand(&mut self, i: usize) -> Pending {
        let p = self.pending.remove(i);
        self.stranded.push(p.clone());
        p
    }

    /// `SoloInbox`'s guardian vetoes pending message `i`, sent from Solo.
    fn veto(&mut self, i: usize) -> Pending {
        let p = self.strand(i);
        assert_eq!(p.recipient, self.on_eth);
        let data = abi::call("veto(uint64)", &[Value::uint(u128::from(p.nonce))]);
        ok(&self.eth.call(GUARDIAN, self.messenger, &data));
        p
    }

    /// Anyone reports to the gateway on Solo that its message `nonce` was
    /// vetoed, or, with `delivered`, what the inbox delivered with it.
    fn report(&mut self, nonce: u64, delivered: Option<&Pending>) -> Outcome {
        let data = match delivered {
            None => report_vetoed_calldata(nonce),
            Some(p) => report_delivered_calldata(&SoloMessage {
                nonce: p.nonce,
                sender: p.sender,
                recipient: p.recipient,
                payload: p.payload.clone(),
                ..SoloMessage::default()
            }),
        };
        let o = self.eth.call(STRANGER, self.on_eth, &data);
        self.record(o)
    }

    /// Anyone asks the sender of stranded message `i` to refund it, or, for
    /// a `REFUND` or `SPENT`, to send it again.
    fn unstrand(&mut self, i: usize) -> Outcome {
        let p = self.stranded[i].clone();
        let data = match TokenMessage::decode(&p.payload).unwrap() {
            TokenMessage::Mint {
                origin,
                from,
                to,
                amount,
                ..
            } => refund_spent_calldata(p.nonce, 1, &origin, &from, &to, amount),
            TokenMessage::Release {
                token,
                from,
                to,
                amount,
            } => refund_spent_calldata(p.nonce, 2, &token, &from, &to, amount),
            _ => resend_spent_calldata(p.nonce, &p.payload),
        };
        let o = self.eth.call(STRANGER, p.sender, &data);
        if o.success {
            self.stranded.remove(i);
        }
        self.record(o)
    }

    /// What `gateway` was told spent its message `nonce`.
    fn spent(&mut self, gateway: [u8; 20], nonce: u64) -> [u8; 32] {
        let data = abi::call("spent(uint64)", &[Value::uint(u128::from(nonce))]);
        self.eth
            .view(RELAYER, gateway, &data)
            .output
            .try_into()
            .unwrap()
    }

    /// Lets time pass until every queued transfer is ready and executes them.
    fn execute_all(&mut self) {
        let last = self.queued.iter().map(|q| q.2).max().unwrap_or(0);
        self.eth.advance(last.saturating_sub(self.eth.timestamp()));
        while !self.queued.is_empty() {
            ok(&self.execute(0));
        }
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

    /// What `gateway` recorded of the message it sent with `nonce`.
    fn sent(&mut self, gateway: [u8; 20], nonce: u64) -> [u8; 32] {
        let data = abi::call("sent(uint64)", &[Value::uint(u128::from(nonce))]);
        self.eth
            .view(RELAYER, gateway, &data)
            .output
            .try_into()
            .unwrap()
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

    /// What `messages` carry of the token `origin` native to the side of
    /// `home`: mints leaving home, releases coming home, and honest refunds.
    fn carried(&self, messages: &[Pending], home: [u8; 20], origin: [u8; 20]) -> u128 {
        messages
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
                // An honest refund of a mint comes home to be released; of a
                // release, it leaves home to be minted again.
                TokenMessage::Refund {
                    nonce,
                    kind,
                    token,
                    amount,
                    ..
                } if token == origin
                    && !self.forged_nonces.contains(&nonce)
                    && ((kind == 1 && p.recipient == home) || (kind == 2 && p.sender == home)) =>
                {
                    Some(amount)
                }
                _ => None,
            })
            .sum()
    }

    /// What stranded messages carry of `origin`, native to the side of `home`.
    fn stranded_amount(&self, home: [u8; 20], origin: [u8; 20]) -> u128 {
        self.carried(&self.stranded, home, origin)
    }

    /// The value invariant of spec 21 §6 for the token `origin` native to
    /// the side of `home`, among `recipients`: locked equals minted plus in
    /// flight plus queued to be minted, and the gateway holds what is
    /// locked plus what is owed plus what is queued to be released.
    fn check(&mut self, home: [u8; 20], origin: [u8; 20], recipients: &[[u8; 20]]) {
        let away = if home == self.on_eth {
            self.on_solo
        } else {
            self.on_eth
        };
        let wrapped = wrapped_of(away, origin);
        let locked = self.gateway_view(home, "locked(address)", origin);
        let minted = self.supply(wrapped);
        // A stranded message's value is held as it was in flight, until its
        // sender refunds or sends it again.
        let in_flight =
            self.carried(&self.pending, home, origin) + self.carried(&self.stranded, home, origin);
        let mints_queued = self.gateway_view(away, "mintsQueued(address)", origin);
        let releases_queued = self.gateway_view(home, "releasesQueued(address)", origin);
        let retired = self.retired.get(&(home, origin)).copied().unwrap_or(0);
        // What forged transfers still queued took counts on the locked side:
        // their owner cancels or refunds them, and both restore it.
        let forged = self.forged_out.get(&(home, origin)).copied().unwrap_or(0);
        assert!(
            minted <= locked + forged,
            "minted {minted} > locked {locked}"
        );
        assert_eq!(locked + forged, minted + in_flight + mints_queued + retired);
        let owed: u128 = recipients.iter().map(|r| self.owed(home, origin, *r)).sum();
        assert_eq!(
            self.balance_of(origin, home),
            locked + owed + releases_queued
        );
    }
}

/// A queued transfer as the gateway's `queued(id)` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    kind: u64,
    token: [u8; 20],
    amount: u128,
    refund: bool,
    nonce: u64,
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
    // The whole first word names the kind: one that only ends in a kind's byte is unknown too.
    for byte in [30, 0] {
        let mut unknown = message.clone();
        unknown.payload[byte] = if byte == 0 { 0x80 } else { 1 };
        let data = w.delivery(&unknown);
        reverted_with(&w.eth.call(RELAYER, w.messenger, &data), "UnknownMessage()");
    }
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
#[allow(clippy::too_many_lines)]
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

#[test]
fn no_gateway_takes_deposits_before_its_peer_is_heard_from() {
    let mut w = World::unconfirmed();
    let (on_eth, on_solo) = (w.on_eth, w.on_solo);
    w.eth.fund(ALICE, 10 * ETHER);
    let peer_live =
        |w: &mut World, gateway: [u8; 20]| w.u128_view(gateway, &abi::call("peerLive()", &[]));
    // Listed, but neither has heard from the other: deposits are refused,
    // so nothing is locked for a peer that may not exist.
    assert_eq!(
        (peer_live(&mut w, on_eth), peer_live(&mut w, on_solo)),
        (0, 0)
    );
    reverted_with(
        &w.deposit(ALICE, on_eth, NATIVE, BOB, ETHER),
        "PeerUnconfirmed()",
    );
    reverted_with(
        &w.deposit(ALICE, on_solo, NATIVE, BOB, ETHER),
        "PeerUnconfirmed()",
    );
    // The Solo gateway's HELLO was executed on Ethereum before the gateway
    // there existed, and is gone; the owner may send another until the peer
    // answers, nobody else.
    reverted_with(
        &w.eth.call(STRANGER, on_solo, &abi::call("hello()", &[])),
        "NotOwner()",
    );
    let again = w.eth.call(OWNER, on_solo, &abi::call("hello()", &[]));
    let again = w.record(again);
    ok(&again);
    assert_eq!(w.pending.len(), 1);
    assert_eq!(w.pending[0].payload, hello(false));
    w.pending.clear();
    // The Ethereum gateway's HELLO reaches the Solo gateway, which now
    // takes deposits and answers; the answer, which says it has heard,
    // gets no answer of its own.
    w.pending.push(Pending {
        nonce: 0,
        sender: on_eth,
        recipient: on_solo,
        payload: hello(false),
    });
    let delivered = w.deliver(0);
    ok(&delivered);
    let confirmed = keccak256(b"PeerConfirmed()");
    assert!(
        delivered
            .logs
            .iter()
            .any(|l| l.data.topics()[0].0 == confirmed)
    );
    assert_eq!(peer_live(&mut w, on_solo), 1);
    assert_eq!(w.pending.len(), 1);
    assert_eq!(
        TokenMessage::decode(&w.pending[0].payload),
        Some(TokenMessage::Hello { heard: true })
    );
    reverted_with(
        &w.eth.call(OWNER, on_solo, &abi::call("hello()", &[])),
        "AlreadyConfirmed()",
    );
    reverted_with(
        &w.deposit(ALICE, on_eth, NATIVE, BOB, ETHER),
        "PeerUnconfirmed()",
    );
    ok(&w.deposit(ALICE, on_solo, NATIVE, BOB, ETHER));
    w.deliver_all();
    assert_eq!(peer_live(&mut w, on_eth), 1);
    assert!(w.pending.is_empty());
    ok(&w.deposit(ALICE, on_eth, NATIVE, BOB, ETHER));
    w.deliver_all();
    assert_eq!(w.balance_of(wrapped_of(on_solo, NATIVE), BOB), ETHER);
    assert_eq!(w.balance_of(wrapped_of(on_eth, NATIVE), BOB), ETHER);
    // Any message of the peer proves it: a gateway that hears a mint first
    // takes deposits too.
    let mut fresh = World::unconfirmed();
    fresh.eth.fund(ALICE, 10 * ETHER);
    let mint = TokenMessage::Mint {
        origin: NATIVE,
        from: ALICE,
        to: BOB,
        amount: 1,
        name: b"Ether".to_vec(),
        symbol: b"ETH".to_vec(),
        decimals: 18,
    };
    fresh.pending.push(Pending {
        nonce: 5,
        sender: fresh.on_eth,
        recipient: fresh.on_solo,
        payload: mint.encode(),
    });
    ok(&fresh.deliver(0));
    let solo = fresh.on_solo;
    ok(&fresh.deposit(ALICE, solo, NATIVE, BOB, ETHER));
}

#[test]
#[allow(clippy::too_many_lines)]
fn transfers_over_the_rate_limit_wait_in_the_queue() {
    let mut w = World::new();
    let (on_eth, on_solo) = (w.on_eth, w.on_solo);
    w.eth.fund(ALICE, 100 * ETHER);
    let weth = wrapped_of(on_solo, NATIVE);
    // Wrapped ETH mints on Solo at 10 ETH at once, refilling 10 ETH per 1 000 s.
    reverted_with(
        &w.eth.call(
            STRANGER,
            on_solo,
            &set_mint_limit_calldata(&NATIVE, 10 * ETHER, 1_000),
        ),
        "NotOwner()",
    );
    for call in [
        set_mint_limit_calldata(&NATIVE, 1, 0),
        set_release_limit_calldata(&NATIVE, 1, 0),
    ] {
        reverted_with(&w.eth.call(OWNER, on_solo, &call), "BadWindow()");
    }
    ok(&w.eth.call(
        OWNER,
        on_solo,
        &set_mint_limit_calldata(&NATIVE, 10 * ETHER, 1_000),
    ));
    // 4 ETH mints at once; 25 more ETH exceed the limit by 19, and wait
    // until 1 900 s have refilled them.
    ok(&w.deposit(ALICE, on_eth, NATIVE, BOB, 4 * ETHER));
    ok(&w.deposit(ALICE, on_eth, NATIVE, CAROL, 25 * ETHER));
    w.deliver_all();
    let start = w.eth.timestamp();
    assert_eq!(w.balance_of(weth, BOB), 4 * ETHER);
    assert_eq!(w.balance_of(weth, CAROL), 0);
    assert_eq!(w.queued, vec![(on_solo, 0, start + 1_900)]);
    assert_eq!(
        w.gateway_view(on_solo, "mintsQueued(address)", NATIVE),
        25 * ETHER
    );
    w.check(on_eth, NATIVE, &[]);
    let queued = w.eth.view(
        RELAYER,
        on_solo,
        &abi::call("queued(uint256)", &[Value::uint(0)]),
    );
    assert_eq!(queued.output[12..32], NATIVE);
    assert_eq!(word_u64(&queued.output[32..64]), 1);
    assert_eq!(word_u64(&queued.output[64..96]), 0);
    assert_eq!(word_u64(&queued.output[96..128]), 0);
    assert_eq!(queued.output[7 * 32 + 12..8 * 32], CAROL);
    assert_eq!(
        u128::from_be_bytes(queued.output[8 * 32 + 16..9 * 32].try_into().unwrap()),
        25 * ETHER
    );
    // Not before its time, not twice, not an id never queued, not while paused.
    w.eth.advance(1_899);
    let ready_at = abi::call(
        "NotReady(uint64)",
        &[Value::uint(u128::from(start + 1_900))],
    );
    let early = w.execute(0);
    assert!(!early.success);
    assert_eq!(early.output, ready_at);
    w.eth.advance(1);
    ok(&w.eth.call(GUARDIAN, on_solo, &abi::call("pause()", &[])));
    reverted_with(&w.execute(0), "IsPaused()");
    ok(&w.eth.call(OWNER, on_solo, &abi::call("unpause()", &[])));
    let executed = w.execute(0);
    ok(&executed);
    let minted = keccak256(b"Minted(uint64,address,address,address,address,uint256)");
    assert!(executed.logs.iter().any(|l| l.data.topics()[0].0 == minted));
    assert_eq!(w.balance_of(weth, CAROL), 25 * ETHER);
    reverted_with(
        &w.eth.call(STRANGER, on_solo, &execute_queued_calldata(0)),
        "NothingQueued()",
    );
    reverted_with(
        &w.eth.call(STRANGER, on_solo, &execute_queued_calldata(7)),
        "NothingQueued()",
    );
    w.check(on_eth, NATIVE, &[]);
    // The limit is full now: 1 ETH waits 100 s. The mint cap counts what is
    // queued: with 29 minted and 1 queued, a cap of 31 refuses 2 more.
    ok(&w.deposit(ALICE, on_eth, NATIVE, BOB, ETHER));
    ok(&w.deposit(ALICE, on_eth, NATIVE, BOB, 2 * ETHER));
    ok(&w.deliver(0));
    assert_eq!(w.queued[0].2, w.eth.timestamp() + 100);
    ok(&w
        .eth
        .call(OWNER, on_solo, &set_mint_cap_calldata(&NATIVE, 31 * ETHER)));
    reverted_with_address(&w.deliver(0), "CapExceeded(address)", &NATIVE);
    ok(&w
        .eth
        .call(OWNER, on_solo, &set_mint_cap_calldata(&NATIVE, BIG)));
    // Lifting the limit lets the next mint through at once; the queued one
    // keeps its time. Setting it again starts from empty.
    ok(&w
        .eth
        .call(OWNER, on_solo, &set_mint_limit_calldata(&NATIVE, 0, 0)));
    ok(&w.deliver(0));
    assert_eq!(w.queued.len(), 1);
    assert_eq!(w.balance_of(weth, BOB), 6 * ETHER);
    w.execute_all();
    assert_eq!(w.balance_of(weth, BOB), 7 * ETHER);
    w.check(on_eth, NATIVE, &[]);

    // Releases of ETH on Ethereum at 5 ETH at once, refilling 5 ETH per
    // 500 s; a change of the limit counts what the old one used.
    ok(&w.eth.call(
        OWNER,
        on_eth,
        &set_release_limit_calldata(&NATIVE, 8 * ETHER, 100),
    ));
    ok(&w.deposit(BOB, on_solo, weth, DAVE, 3 * ETHER));
    w.deliver_all();
    assert_eq!(w.eth.balance(DAVE), 3 * ETHER);
    ok(&w.eth.call(
        OWNER,
        on_eth,
        &set_release_limit_calldata(&NATIVE, 5 * ETHER, 500),
    ));
    ok(&w.deposit(BOB, on_solo, weth, DAVE, 3 * ETHER));
    let receiver = w.eth.deploy(DEPLOYER, &init_code("TestReceiver"), &[]);
    let rejecting = |on: bool| abi::call("setRejecting(bool)", &[Value::uint(u128::from(on))]);
    ok(&w.eth.call(STRANGER, receiver, &rejecting(true)));
    ok(&w.deposit(CAROL, on_solo, weth, receiver, 2 * ETHER));
    w.deliver_all();
    // 3 used and 3 more: 1 over, 100 s; then 2 more for the receiver, 300 s.
    let now = w.eth.timestamp();
    assert_eq!(
        w.queued.iter().map(|q| q.2).collect::<Vec<_>>(),
        [now + 100, now + 300]
    );
    assert_eq!(w.eth.balance(DAVE), 3 * ETHER);
    assert_eq!(
        w.gateway_view(on_eth, "releasesQueued(address)", NATIVE),
        5 * ETHER
    );
    w.check(on_eth, NATIVE, &[receiver]);
    // A queued release needs the gas a release does; one to a recipient
    // that refuses is owed, as a delivered one would be.
    w.eth.advance(300);
    let data = execute_queued_calldata(w.queued[0].1);
    reverted_with(
        &w.eth.call_gas(STRANGER, on_eth, &data, 150_000),
        "InsufficientGas()",
    );
    w.execute_all();
    assert_eq!(w.eth.balance(DAVE), 6 * ETHER);
    assert_eq!(w.owed(on_eth, NATIVE, receiver), 2 * ETHER);
    assert_eq!(w.gateway_view(on_eth, "releasesQueued(address)", NATIVE), 0);
    w.check(on_eth, NATIVE, &[receiver]);
    // The limits as the gateway reports them.
    let limit = w
        .eth
        .view(
            RELAYER,
            on_eth,
            &address_view("releaseLimit(address)", &NATIVE),
        )
        .output;
    assert_eq!(
        u128::from_be_bytes(limit[16..32].try_into().unwrap()),
        5 * ETHER
    );
    assert_eq!(word_u64(&limit[32..64]), 500);
}

#[test]
#[allow(clippy::too_many_lines)]
fn one_queued_transfer_is_frozen_or_cancelled_alone() {
    let mut w = World::new();
    let (on_eth, on_solo) = (w.on_eth, w.on_solo);
    w.eth.fund(ALICE, 100 * ETHER);
    ok(&w.eth.call(
        OWNER,
        on_solo,
        &set_mint_limit_calldata(&NATIVE, ETHER, 1_000),
    ));
    ok(&w.eth.call(
        OWNER,
        on_eth,
        &set_release_limit_calldata(&NATIVE, ETHER, 1_000),
    ));
    // Two honest mints over the limit, and a forged one: the channel
    // delivers a MINT that no deposit on Ethereum locked.
    ok(&w.deposit(ALICE, on_eth, NATIVE, BOB, 2 * ETHER));
    ok(&w.deposit(ALICE, on_eth, NATIVE, CAROL, 3 * ETHER));
    w.deliver_all();
    let forged = Pending {
        nonce: 1_000,
        sender: on_eth,
        recipient: on_solo,
        payload: TokenMessage::Mint {
            origin: NATIVE,
            from: STRANGER,
            to: STRANGER,
            amount: 40 * ETHER,
            name: b"Ether".to_vec(),
            symbol: b"ETH".to_vec(),
            decimals: 18,
        }
        .encode(),
    };
    ok(&w.forge(&forged));
    let ids: Vec<u64> = w.queued.iter().map(|q| q.1).collect();
    assert_eq!(ids, [0, 1, 2]);
    assert_eq!(
        w.gateway_view(on_solo, "mintsQueued(address)", NATIVE),
        45 * ETHER
    );
    // The guardian freezes the forgery alone; nobody else may, and the owner
    // alone unfreezes or cancels. Ids that hold nothing are refused.
    let freeze = freeze_queued_calldata(2);
    reverted_with(&w.eth.call(STRANGER, on_solo, &freeze), "NotGuardian()");
    for call in [unfreeze_queued_calldata(2), cancel_queued_calldata(2)] {
        reverted_with(&w.eth.call(GUARDIAN, on_solo, &call), "NotOwner()");
    }
    for call in [
        freeze_queued_calldata(9),
        unfreeze_queued_calldata(9),
        cancel_queued_calldata(9),
    ] {
        reverted_with(&w.eth.call(OWNER, on_solo, &call), "NothingQueued()");
    }
    let frozen = w.eth.call(GUARDIAN, on_solo, &freeze);
    ok(&frozen);
    assert_eq!(frozen.gas, FREEZE_GAS);
    let topic = keccak256(b"QueueFrozen(uint256,address)");
    assert!(frozen.logs.iter().any(|l| l.data.topics()[0].0 == topic));
    // Time passes: the honest transfers execute, the frozen one does not.
    w.eth.advance(100_000);
    reverted_with(&w.execute(2), "Frozen()");
    ok(&w.execute(0));
    ok(&w.execute(0));
    let weth = wrapped_of(on_solo, NATIVE);
    assert_eq!(
        (w.balance_of(weth, BOB), w.balance_of(weth, CAROL)),
        (2 * ETHER, 3 * ETHER)
    );
    // Unfrozen, it could run again; frozen once more by the owner, the owner
    // cancels it, which drops the mint: no value moves anywhere, and the
    // invariant holds exactly as it did before the forgery.
    ok(&w.eth.call(OWNER, on_solo, &unfreeze_queued_calldata(2)));
    ok(&w.eth.call(OWNER, on_solo, &freeze));
    assert_eq!(w.queued.len(), 1);
    let cancelled = w.cancel(0);
    ok(&cancelled);
    assert_eq!(cancelled.gas, CANCEL_MINT_GAS);
    assert!(logged(
        &cancelled,
        "QueueCancelled(uint256,uint64,uint8,address,address,address,uint256)"
    ));
    assert_eq!(w.gateway_view(on_solo, "mintsQueued(address)", NATIVE), 0);
    assert_eq!(w.balance_of(weth, STRANGER), 0);
    w.check(on_eth, NATIVE, &[]);
    reverted_with(
        &w.eth.call(OWNER, on_solo, &cancel_queued_calldata(2)),
        "NothingQueued()",
    );
    reverted_with(
        &w.eth.call(STRANGER, on_solo, &execute_queued_calldata(2)),
        "NothingQueued()",
    );

    // A forged RELEASE on Ethereum takes what it asks out of `locked` and
    // queues it; cancelling it puts it back and gives the limit back what
    // it took, without pausing the gateway, which goes on releasing honest
    // transfers at once.
    let forged = Pending {
        nonce: 1_001,
        sender: on_solo,
        recipient: on_eth,
        payload: TokenMessage::Release {
            token: NATIVE,
            from: STRANGER,
            to: STRANGER,
            amount: 4 * ETHER,
        }
        .encode(),
    };
    let locked = w.gateway_view(on_eth, "locked(address)", NATIVE);
    ok(&w.forge(&forged));
    assert_eq!(
        w.gateway_view(on_eth, "locked(address)", NATIVE),
        locked - 4 * ETHER
    );
    let (_, id, _) = w.queued[0];
    ok(&w.eth.call(GUARDIAN, on_eth, &freeze_queued_calldata(id)));
    assert_eq!(w.cancel(0).gas, CANCEL_RELEASE_GAS);
    assert!(w.retired.is_empty());
    assert_eq!(w.gateway_view(on_eth, "locked(address)", NATIVE), locked);
    ok(&w.deposit(BOB, on_solo, weth, DAVE, ETHER / 2));
    w.deliver_all();
    assert!(w.queued.is_empty());
    assert_eq!(w.eth.balance(DAVE), ETHER / 2);
    assert_eq!(
        w.gateway_view(on_eth, "locked(address)", NATIVE),
        locked - ETHER / 2
    );
    assert_eq!(w.gateway_view(on_eth, "releasesQueued(address)", NATIVE), 0);
    assert_eq!(w.eth.balance(STRANGER), 0);
    w.check(on_eth, NATIVE, &[]);

    // An honest transfer cancelled stays where it was locked, counted as
    // retired: a cancelled release goes back into `locked` here, and a
    // cancelled mint leaves its origin locked on the other side.
    ok(&w.deposit(BOB, on_solo, weth, DAVE, ETHER));
    ok(&w.deposit(ALICE, on_eth, NATIVE, CAROL, 3 * ETHER));
    w.deliver_all();
    assert_eq!(w.queued.len(), 2);
    ok(&w.cancel(1));
    ok(&w.cancel(0));
    assert_eq!(w.retired.get(&(on_eth, NATIVE)), Some(&(4 * ETHER)));
    w.check(on_eth, NATIVE, &[]);

    // Refunded instead, an honest transfer goes back to its sender, because
    // its home gateway recorded sending it: a cancelled mint's ETH is
    // released to Alice on Ethereum, a cancelled release's burned ETH is
    // minted to Bob on Solo again. Releases now queue above 0.1 ETH.
    ok(&w.eth.call(
        OWNER,
        on_eth,
        &set_release_limit_calldata(&NATIVE, ETHER / 10, 1_000),
    ));
    let (alice, bob) = (w.eth.balance(ALICE), w.balance_of(weth, BOB));
    ok(&w.deposit(BOB, on_solo, weth, DAVE, ETHER / 2));
    ok(&w.deposit(ALICE, on_eth, NATIVE, CAROL, 3 * ETHER));
    let mint_nonce = w.pending[1].nonce;
    let identity = |kind: u8, from: [u8; 20], to: [u8; 20], amount: u128| {
        keccak256(&abi::encode(&[
            Value::uint(u128::from(kind)),
            Value::address(&NATIVE),
            Value::address(&from),
            Value::address(&to),
            Value::uint(amount),
        ]))
    };
    assert_eq!(
        w.sent(on_eth, mint_nonce),
        identity(1, ALICE, CAROL, 3 * ETHER)
    );
    let release_nonce = w.pending[0].nonce;
    assert_eq!(
        w.sent(on_solo, release_nonce),
        identity(2, BOB, DAVE, ETHER / 2)
    );
    assert_eq!(w.sent(on_eth, release_nonce), [0; 32]);
    w.deliver_all();
    assert_eq!(
        w.queued.iter().map(|q| q.0).collect::<Vec<_>>(),
        [on_eth, on_solo]
    );
    // Only the owner refunds, and only what is queued.
    let (_, mint_id, _) = w.queued[1];
    for who in [STRANGER, GUARDIAN] {
        reverted_with(
            &w.eth.call(who, on_solo, &refund_queued_calldata(mint_id)),
            "NotOwner()",
        );
    }
    reverted_with(
        &w.eth.call(OWNER, on_solo, &refund_queued_calldata(99)),
        "NothingQueued()",
    );
    let refunded = w.refund(1);
    ok(&refunded);
    assert_eq!(refunded.gas, REFUND_MINT_GAS);
    assert!(logged(&refunded, "RefundRequested(uint256,uint64,uint64)"));
    let back = w.pending[0].clone();
    assert_eq!(
        TokenMessage::decode(&back.payload),
        Some(TokenMessage::Refund {
            nonce: mint_nonce,
            kind: 1,
            token: NATIVE,
            from: ALICE,
            to: CAROL,
            amount: 3 * ETHER,
        })
    );
    assert_eq!((back.sender, back.recipient), (on_solo, on_eth));
    w.check(on_eth, NATIVE, &[]);
    let refunded = w.refund(0);
    ok(&refunded);
    assert_eq!(refunded.gas, REFUND_RELEASE_GAS);
    w.check(on_eth, NATIVE, &[]);
    let paid = w.deliver(0);
    ok(&paid);
    assert!(logged(&paid, "Refunded(uint64,uint64)"));
    w.deliver_all();
    w.check(on_eth, NATIVE, &[]);
    assert_eq!(w.sent(on_eth, mint_nonce), [0; 32]);
    assert_eq!(w.sent(on_solo, release_nonce), [0; 32]);
    // Alice's refund waits for the release limit; a transfer that a refund
    // queued is not refunded in turn.
    let i = w.queued.iter().position(|q| q.0 == on_eth).unwrap();
    let (_, id, _) = w.queued[i];
    let entry = w.queued_entry(on_eth, id);
    assert!(entry.refund);
    assert_eq!((entry.amount, entry.nonce), (3 * ETHER, back.nonce));
    reverted_with(
        &w.eth.call(OWNER, on_eth, &refund_queued_calldata(id)),
        "NotRefundable()",
    );
    w.execute_all();
    assert_eq!(w.eth.balance(ALICE), alice);
    assert_eq!(w.balance_of(weth, BOB), bob);
    assert_eq!(w.eth.balance(CAROL), 0);
    w.check(on_eth, NATIVE, &[]);
    // Paid once: the same refund delivered again, as no channel does, is
    // refused, and the message counts as delivered.
    let again = w.forge(&back);
    ok(&again);
    assert!(logged(&again, "RefundRefused(uint64,uint64)"));
    assert_eq!(w.eth.balance(ALICE), alice);

    // A refund of a forged transfer pays nothing, whatever it names: a mint
    // no deposit locked, a release no burn freed, and a mint that takes the
    // nonce of a message really sent but asks more than it did. The
    // undelivered honest message whose nonce the forgery took never arrives:
    // the channel delivers each nonce once.
    ok(&w.deposit(ALICE, on_eth, NATIVE, BOB, ETHER));
    let taken = w.strand(w.pending.len() - 1);
    let forgeries = [
        Pending {
            nonce: 1_002,
            sender: on_eth,
            recipient: on_solo,
            payload: TokenMessage::Mint {
                origin: NATIVE,
                from: STRANGER,
                to: STRANGER,
                amount: 40 * ETHER,
                name: b"Ether".to_vec(),
                symbol: b"ETH".to_vec(),
                decimals: 18,
            }
            .encode(),
        },
        Pending {
            nonce: 1_003,
            sender: on_solo,
            recipient: on_eth,
            payload: TokenMessage::Release {
                token: NATIVE,
                from: STRANGER,
                to: STRANGER,
                amount: 4 * ETHER,
            }
            .encode(),
        },
        Pending {
            nonce: taken.nonce,
            sender: on_eth,
            recipient: on_solo,
            payload: TokenMessage::Mint {
                origin: NATIVE,
                from: ALICE,
                to: BOB,
                amount: 30 * ETHER,
                name: b"Ether".to_vec(),
                symbol: b"ETH".to_vec(),
                decimals: 18,
            }
            .encode(),
        },
    ];
    let locked = w.gateway_view(on_eth, "locked(address)", NATIVE);
    let supply = w.supply(weth);
    for forged in &forgeries {
        ok(&w.forge(forged));
        let (gateway, id, _) = *w.queued.last().unwrap();
        ok(&w.eth.call(GUARDIAN, gateway, &freeze_queued_calldata(id)));
        w.check(on_eth, NATIVE, &[]);
        ok(&w.refund(w.queued.len() - 1));
        w.check(on_eth, NATIVE, &[]);
        let refused = w.deliver(0);
        ok(&refused);
        assert!(logged(&refused, "RefundRefused(uint64,uint64)"));
        assert!(!logged(&refused, "Refunded(uint64,uint64)"));
        w.check(on_eth, NATIVE, &[]);
    }
    assert!(w.queued.is_empty() && w.pending.is_empty());
    assert_eq!(w.gateway_view(on_eth, "locked(address)", NATIVE), locked);
    assert_eq!(w.supply(weth), supply);
    assert_eq!(w.eth.balance(STRANGER), 0);
    assert_eq!(w.eth.balance(ALICE), alice - ETHER);
    // But the refused refund told the home gateway that the nonce is spent
    // with nothing taking effect, so the honest message it recorded there
    // never arrives: anyone has it refunded to Alice, once (spec 21 §5.5c).
    // The forgeries of nonces no message took leave nothing to refund.
    assert_eq!(w.spent(on_eth, taken.nonce), VOID);
    assert_eq!(w.spent(on_eth, 1_002), VOID);
    assert_eq!(w.spent(on_solo, 1_003), VOID);
    assert_eq!(w.sent(on_eth, taken.nonce), identity(1, ALICE, BOB, ETHER));
    let paid = w.unstrand(0);
    ok(&paid);
    assert!(logged(&paid, "SpentRefunded(uint64)"));
    assert_eq!(w.sent(on_eth, taken.nonce), [0; 32]);
    w.check(on_eth, NATIVE, &[]);
    w.execute_all();
    assert_eq!(w.eth.balance(ALICE), alice);
    w.check(on_eth, NATIVE, &[]);
}

#[test]
#[allow(clippy::too_many_lines)]
fn messages_that_never_arrive_are_refunded_or_sent_again() {
    let mut w = World::new();
    let (on_eth, on_solo, tkn) = (w.on_eth, w.on_solo, w.tkn);
    for who in [ALICE, CAROL] {
        w.eth.fund(who, 100 * ETHER);
    }
    mint_and_approve(&mut w.eth, tkn, ALICE, 1_000, on_eth);
    ok(&w.eth.call(
        OWNER,
        on_solo,
        &set_mint_limit_calldata(&NATIVE, ETHER, 1_000),
    ));
    ok(&w.eth.call(
        OWNER,
        on_eth,
        &set_release_limit_calldata(&NATIVE, ETHER, 1_000),
    ));
    let weth = wrapped_of(on_solo, NATIVE);
    let wsolo = wrapped_of(on_eth, NATIVE);
    let forged_mint = |amount: u128| {
        TokenMessage::Mint {
            origin: NATIVE,
            from: STRANGER,
            to: STRANGER,
            amount,
            name: b"Ether".to_vec(),
            symbol: b"ETH".to_vec(),
            decimals: 18,
        }
        .encode()
    };
    let checks = |w: &mut World| {
        w.check(on_eth, NATIVE, &[]);
        w.check(on_solo, NATIVE, &[]);
        w.check(on_eth, tkn, &[]);
    };

    // A forgery takes the nonce of Alice's deposit while it is in flight,
    // over the mint limit so that it queues. Alice's message can never
    // arrive now, but nothing says so yet: her record is not refundable.
    let alice = w.eth.balance(ALICE);
    ok(&w.deposit(ALICE, on_eth, NATIVE, BOB, ETHER));
    let honest = w.strand(0);
    let forged = Pending {
        payload: forged_mint(40 * ETHER),
        ..honest.clone()
    };
    ok(&w.forge(&forged));
    checks(&mut w);
    reverted_with(&w.unstrand(0), "NotSpent()");
    let wrong = refund_spent_calldata(honest.nonce, 1, &NATIVE, &ALICE, &BOB, 2 * ETHER);
    reverted_with(&w.eth.call(ALICE, on_eth, &wrong), "NotRecorded()");
    // The owner on Solo refunds the forgery; its refund is refused at home,
    // which learns from it that the nonce was spent with no effect: Alice's
    // deposit is refunded to her by anyone, once, under the release limit.
    ok(&w.refund(0));
    let refused = w.deliver(0);
    ok(&refused);
    assert!(logged(&refused, "RefundRefused(uint64,uint64)"));
    assert!(logged(&refused, "NonceSpent(uint64,bytes32)"));
    assert_eq!(w.spent(on_eth, honest.nonce), VOID);
    checks(&mut w);
    let paid = w.unstrand(0);
    ok(&paid);
    assert!(logged(&paid, "SpentRefunded(uint64)"));
    assert!(logged(
        &paid,
        "Released(uint64,address,address,address,uint256)"
    ));
    assert_eq!(w.eth.balance(ALICE), alice);
    let again = w.eth.call(
        STRANGER,
        on_eth,
        &refund_spent_calldata(honest.nonce, 1, &NATIVE, &ALICE, &BOB, ETHER),
    );
    reverted_with(&again, "NotRecorded()");
    assert_eq!(w.balance_of(weth, STRANGER), 0);
    checks(&mut w);

    // From Solo: a forgery that pays out at once (a HELLO, which moves
    // nothing) takes the nonce of Carol's deposit. Anyone reports to Solo
    // what the inbox delivered with that nonce, and Carol is refunded there.
    let carol = w.eth.balance(CAROL);
    ok(&w.deposit(CAROL, on_solo, NATIVE, DAVE, ETHER));
    let honest = w.strand(0);
    let forged = Pending {
        payload: hello(true),
        ..honest.clone()
    };
    ok(&w.forge(&forged));
    // Only what the inbox delivered is reported, and only once.
    reverted_with(&w.report(honest.nonce, Some(&honest)), "NotDelivered()");
    reverted_with(&w.report(honest.nonce, None), "NotVetoed()");
    let reported = w.report(honest.nonce, Some(&forged));
    ok(&reported);
    assert!(logged(&reported, "Reported(uint64,bytes32,uint64)"));
    reverted_with(&w.report(honest.nonce, Some(&forged)), "AlreadyReported()");
    assert_eq!(
        TokenMessage::decode(&w.pending[0].payload),
        Some(TokenMessage::Spent {
            nonce: honest.nonce,
            effect: identity(&hello(true)),
        })
    );
    w.deliver_all();
    assert_eq!(w.spent(on_solo, honest.nonce), identity(&hello(true)));
    ok(&w.unstrand(0));
    assert_eq!(w.eth.balance(CAROL), carol);
    checks(&mut w);

    // A vetoed message is reported in the same way, with nothing delivered.
    ok(&w.deposit(CAROL, on_solo, NATIVE, DAVE, ETHER));
    let nonce = w.pending[0].nonce;
    reverted_with(&w.report(nonce, None), "NotVetoed()");
    w.veto(0);
    checks(&mut w);
    ok(&w.report(nonce, None));
    reverted_with(&w.report(nonce, None), "AlreadyReported()");
    w.deliver_all();
    assert_eq!(w.spent(on_solo, nonce), VOID);
    ok(&w.unstrand(0));
    assert_eq!(w.eth.balance(CAROL), carol);
    checks(&mut w);

    // An honest message reported as delivered is not refunded: the nonce
    // was spent by what its sender recorded.
    ok(&w.deposit(CAROL, on_solo, NATIVE, DAVE, ETHER));
    let delivered = w.pending[0].clone();
    w.deliver_all();
    ok(&w.report(delivered.nonce, Some(&delivered)));
    w.deliver_all();
    assert_eq!(
        w.spent(on_solo, delivered.nonce),
        identity(&delivered.payload)
    );
    w.stranded.push(delivered);
    reverted_with(&w.unstrand(0), "NotSpent()");
    w.stranded.clear();
    assert_eq!(w.balance_of(wsolo, DAVE), ETHER);
    checks(&mut w);
    // What a nonce was spent by is kept from the first report, unless it is
    // spent with no effect after all.
    for (effect, kept) in [([7; 32], [7; 32]), ([8; 32], [7; 32]), (VOID, VOID)] {
        let p = Pending {
            nonce: 5_000,
            sender: on_eth,
            recipient: on_solo,
            payload: TokenMessage::Spent {
                nonce: 50_000,
                effect,
            }
            .encode(),
        };
        ok(&w.forge(&p));
        assert_eq!(w.spent(on_solo, 50_000), kept);
    }

    // A refund is stranded in turn: the owner on Solo refunds an honest
    // queued deposit, and a forged release, queued on Ethereum, takes the
    // nonce of the refund. Refunding the forgery tells Solo the nonce was
    // spent, and anyone sends the refund again; a refund's record is the
    // hash of its payload, so it is not refunded but sent again, once.
    let alice = w.eth.balance(ALICE);
    ok(&w.deposit(ALICE, on_eth, NATIVE, BOB, 2 * ETHER));
    w.deliver_all();
    let i = w.queued.iter().position(|q| q.0 == on_solo).unwrap();
    ok(&w.refund(i));
    let refund = w.strand(0);
    assert_eq!(w.sent(on_solo, refund.nonce), keccak256(&refund.payload));
    let forged = Pending {
        nonce: refund.nonce,
        sender: on_solo,
        recipient: on_eth,
        payload: TokenMessage::Release {
            token: NATIVE,
            from: STRANGER,
            to: STRANGER,
            amount: 3 * ETHER / 2,
        }
        .encode(),
    };
    ok(&w.forge(&forged));
    checks(&mut w);
    let (_, id, _) = *w.queued.last().unwrap();
    ok(&w.eth.call(GUARDIAN, on_eth, &freeze_queued_calldata(id)));
    ok(&w.refund(w.queued.len() - 1));
    w.deliver_all();
    assert_eq!(w.spent(on_solo, refund.nonce), VOID);
    checks(&mut w);
    let resent = w.unstrand(0);
    ok(&resent);
    assert!(logged(&resent, "Resent(uint64,uint64)"));
    assert_eq!(w.sent(on_solo, refund.nonce), [0; 32]);
    let again = w.eth.call(
        STRANGER,
        on_solo,
        &resend_spent_calldata(refund.nonce, &refund.payload),
    );
    reverted_with(&again, "NotRecorded()");
    let paid = w.deliver(0);
    assert!(logged(&paid, "Refunded(uint64,uint64)"));
    w.execute_all();
    assert_eq!(w.eth.balance(ALICE), alice);
    assert_eq!(w.eth.balance(STRANGER), 0);
    checks(&mut w);
    // A release is refunded, never sent again.
    ok(&w.deposit(DAVE, on_eth, wsolo, CAROL, ETHER));
    let release = w.pending[0].clone();
    let release_again = resend_spent_calldata(release.nonce, &release.payload);
    reverted_with(
        &w.eth.call(STRANGER, on_eth, &release_again),
        "NotResendable()",
    );
    w.deliver_all();

    // A mint of a token the receiving gateway does not list goes back to be
    // refunded at once instead of waiting in its channel; a forged one's
    // refund is refused.
    ok(&w.eth.call(OWNER, on_solo, &set_mint_cap_calldata(&tkn, 0)));
    ok(&w.deposit(ALICE, on_eth, tkn, BOB, 600));
    assert_eq!(w.balance_of(tkn, ALICE), 400);
    let bounced = w.deliver(0);
    ok(&bounced);
    assert!(logged(&bounced, "Bounced(uint64,uint64)"));
    assert!(
        w.eth
            .view(
                RELAYER,
                wrapped_of(on_solo, tkn),
                &abi::call("totalSupply()", &[])
            )
            .output
            .is_empty()
    );
    checks(&mut w);
    let back = w.deliver(0);
    assert!(logged(&back, "Refunded(uint64,uint64)"));
    assert_eq!(w.balance_of(tkn, ALICE), 1_000);
    checks(&mut w);
    let forged = Pending {
        nonce: 6_000,
        sender: on_eth,
        recipient: on_solo,
        payload: TokenMessage::Mint {
            origin: tkn,
            from: STRANGER,
            to: STRANGER,
            amount: 600,
            name: b"Test Token".to_vec(),
            symbol: b"TKN".to_vec(),
            decimals: 6,
        }
        .encode(),
    };
    ok(&w.forge(&forged));
    let refused = w.deliver(0);
    assert!(logged(&refused, "RefundRefused(uint64,uint64)"));
    assert_eq!(w.balance_of(tkn, STRANGER), 0);
    checks(&mut w);
    assert!(w.pending.is_empty() && w.stranded.is_empty());
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
    // Limits on every mint and release: what exceeds them waits in the queue.
    for (gateway, token) in homes {
        let other = if gateway == on_eth { on_solo } else { on_eth };
        let limit = ETHER / 2;
        ok(&w.eth.call(
            OWNER,
            gateway,
            &set_release_limit_calldata(&token, limit, 300),
        ));
        ok(&w
            .eth
            .call(OWNER, other, &set_mint_limit_calldata(&token, limit, 300)));
    }
    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    let mut delivered = 0;
    let mut executed = 0;
    let mut cancelled = 0;
    let mut refused_frozen = 0;
    let mut refunded = 0;
    let mut refunds_paid = 0;
    let mut refunds_refused = 0;
    let mut forged_nonce = 1_000_000;
    let mut displaced = 0;
    let mut reports = 0;
    let mut made_whole = 0;
    // Nonces spent in `SoloInbox` that nobody reported to Solo yet: vetoed,
    // or delivered as a forgery.
    let mut reportable: Vec<(u64, Option<Pending>)> = Vec::new();
    let other = |gateway: [u8; 20]| if gateway == on_eth { on_solo } else { on_eth };
    // A forged transfer of `origin`, native to `home`, to gateway `to`: a mint
    // if `to` is away from home, else a release, and its sender.
    let forged_transfer = |home: [u8; 20], origin: [u8; 20], to: [u8; 20], amount: u128| {
        let message = if to == home {
            TokenMessage::Release {
                token: origin,
                from: STRANGER,
                to: STRANGER,
                amount,
            }
        } else {
            TokenMessage::Mint {
                origin,
                from: STRANGER,
                to: STRANGER,
                amount,
                name: b"Forged".to_vec(),
                symbol: b"F".to_vec(),
                decimals: 18,
            }
        };
        (other(to), message.encode())
    };
    for _ in 0..900 {
        // Deliveries and executions weigh more, so that most transfers
        // complete.
        let op = match rng.below(26) {
            22 | 23 => 5,
            24.. => 13,
            op => op,
        };
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
                let o = w.deliver(i);
                if o.success {
                    delivered += 1;
                }
                if logged(&o, "Refunded(uint64,uint64)") {
                    refunds_paid += 1;
                }
                if logged(&o, "RefundRefused(uint64,uint64)") {
                    refunds_refused += 1;
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
            11..=12 => w.eth.advance(rng.below(1_200)),
            13 if !w.queued.is_empty() => {
                let i = usize::try_from(rng.below(w.queued.len() as u64)).unwrap();
                let o = w.execute(i);
                if o.success {
                    executed += 1;
                } else if o.output == abi::selector("Frozen()") {
                    refused_frozen += 1;
                }
            }
            // The guardian freezes one queued transfer, the owner unfreezes
            // one, or, now and then, cancels one; the others run on.
            14 if !w.queued.is_empty() && rng.below(2) == 0 => {
                let (gateway, id, _) = rng.pick(&w.queued);
                ok(&w.eth.call(GUARDIAN, gateway, &freeze_queued_calldata(id)));
            }
            // The owner never unfreezes a forgery.
            15 if !w.queued.is_empty() => {
                let (gateway, id, _) = rng.pick(&w.queued);
                if !w.forged_entries.contains(&(gateway, id)) {
                    ok(&w.eth.call(OWNER, gateway, &unfreeze_queued_calldata(id)));
                }
            }
            // The owner cancels one, or refunds it to its sender, which a
            // transfer that a refund queued refuses.
            16 if !w.queued.is_empty() && rng.below(4) == 0 => {
                let i = usize::try_from(rng.below(w.queued.len() as u64)).unwrap();
                let (gateway, id, _) = w.queued[i];
                let refund = w.queued_entry(gateway, id).refund;
                if rng.below(3) == 0 {
                    ok(&w.cancel(i));
                    cancelled += 1;
                } else if refund {
                    reverted_with(&w.refund(i), "NotRefundable()");
                } else {
                    ok(&w.refund(i));
                    refunded += 1;
                }
            }
            // A channel delivers a forged mint or release, over its limit so
            // that it queues, and the guardian freezes it at once.
            17 => {
                let (home, origin) = rng.pick(&homes);
                let to = if rng.below(2) == 0 { other(home) } else { home };
                let (sender, payload) = forged_transfer(home, origin, to, ETHER / 2 + amount);
                forged_nonce += 1;
                let forged = Pending {
                    nonce: forged_nonce,
                    sender,
                    recipient: to,
                    payload,
                };
                // A mint of a token the gateway does not list goes back instead.
                let before = w.queued.len();
                if w.forge(&forged).success
                    && let Some(&(gateway, id, _)) = w.queued.get(before)
                {
                    assert!(gateway == to && w.forged_entries.contains(&(gateway, id)));
                    ok(&w.eth.call(GUARDIAN, gateway, &freeze_queued_calldata(id)));
                }
            }
            // A forgery takes the nonce of an honest message in flight, which
            // never arrives: a mint or release over its limit (or of a token
            // the receiving gateway does not list, which goes back at once),
            // or, from Solo, a HELLO that moves nothing.
            18..=19 if !w.pending.is_empty() => {
                let i = usize::try_from(rng.below(w.pending.len() as u64)).unwrap();
                let p = w.pending[i].clone();
                let payload = if op == 19 && p.recipient == on_eth {
                    hello(true)
                } else {
                    let (home, origin) = rng.pick(&homes);
                    let home = if rng.below(2) == 0 { home } else { other(home) };
                    let origin = if homes.contains(&(home, origin)) {
                        origin
                    } else {
                        NATIVE
                    };
                    forged_transfer(home, origin, p.recipient, ETHER / 2 + amount).1
                };
                let forged = Pending { payload, ..p };
                let before = w.queued.len();
                if w.forge(&forged).success {
                    w.strand(i);
                    displaced += 1;
                    if let Some(&(gateway, id, _)) = w.queued.get(before) {
                        ok(&w.eth.call(GUARDIAN, gateway, &freeze_queued_calldata(id)));
                    }
                    if forged.recipient == on_eth {
                        reportable.push((forged.nonce, Some(forged)));
                    }
                }
            }
            // `SoloInbox`'s guardian vetoes a message from Solo.
            20 if w.pending.iter().any(|p| p.recipient == on_eth) => {
                let i = w
                    .pending
                    .iter()
                    .position(|p| p.recipient == on_eth)
                    .unwrap();
                let p = w.veto(i);
                reportable.push((p.nonce, None));
            }
            // Anyone reports a nonce spent in `SoloInbox` to Solo, or has a
            // stranded message refunded or sent again, which works once the
            // nonce is known spent there by something else.
            21 if !reportable.is_empty() || !w.stranded.is_empty() => {
                if !reportable.is_empty() && rng.below(2) == 0 {
                    let i = usize::try_from(rng.below(reportable.len() as u64)).unwrap();
                    let (nonce, delivered) = reportable.remove(i);
                    ok(&w.report(nonce, delivered.as_ref()));
                    reports += 1;
                } else if !w.stranded.is_empty() {
                    let i = usize::try_from(rng.below(w.stranded.len() as u64)).unwrap();
                    if w.unstrand(i).success {
                        made_whole += 1;
                    }
                }
            }
            _ => {
                let (gateway, token) = rng.pick(&homes);
                let other = if gateway == on_eth { on_solo } else { on_eth };
                // A zero mint cap delists a token: its mints go back.
                let cap = match rng.below(8) {
                    0 => 0,
                    1 | 2 => amount * 3,
                    _ => BIG,
                };
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
    assert!(executed >= 5, "{executed}");
    assert!(cancelled >= 3, "{cancelled}");
    assert!(refused_frozen >= 1, "{refused_frozen}");
    assert!(refunded >= 5, "{refunded}");
    assert!(refunds_paid >= 2, "{refunds_paid}");
    assert!(refunds_refused >= 2, "{refunds_refused}");
    assert!(displaced >= 5, "{displaced}");
    assert!(reports >= 3, "{reports}");
    assert!(made_whole >= 3, "{made_whole}");
    // The owner refunds the forgeries still queued, and every other transfer
    // still queued runs once unfrozen.
    while let Some(i) = w
        .queued
        .iter()
        .position(|(gateway, id, _)| w.forged_entries.contains(&(*gateway, *id)))
    {
        ok(&w.refund(i));
    }
    assert!(w.forged_out.values().all(|v| *v == 0));
    for (gateway, id, _) in w.queued.clone() {
        ok(&w.eth.call(OWNER, gateway, &unfreeze_queued_calldata(id)));
    }
    // Unpause, lift the caps, deliver everything, bridge everything back and claim what is owed:
    // nothing is left owed or in flight, both equalities still hold, and the only value still
    // locked and minted is what the test receiver holds of wrapped tokens it does not bridge back.
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
    w.execute_all();
    // Every nonce spent in `SoloInbox` is reported, and every stranded message
    // is refunded or sent again, now that the forgeries' refunds told their
    // senders: none is left but those whose sender was never told, as when
    // the owner on Solo cancelled a forgery without a refund (and so a
    // report it took the nonce of).
    for (nonce, delivered) in std::mem::take(&mut reportable) {
        ok(&w.report(nonce, delivered.as_ref()));
    }
    w.deliver_all();
    for _ in 0..3 {
        let mut i = 0;
        while i < w.stranded.len() {
            let o = w.unstrand(i);
            if !o.success {
                assert_eq!(o.output, abi::selector("NotSpent()"));
                i += 1;
            }
        }
        w.deliver_all();
        w.execute_all();
    }
    for p in w.stranded.clone() {
        assert_eq!(w.spent(p.sender, p.nonce), [0; 32]);
    }
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
    w.execute_all();
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
    // What the test receiver holds of wrapped tokens it cannot bridge back, what owners
    // cancelled, and what stays stranded, is all that stays locked.
    for (home, origin) in homes {
        let away = if home == on_eth { on_solo } else { on_eth };
        let wrapped = wrapped_of(away, origin);
        let stuck = if w.supply(wrapped) > 0 {
            w.balance_of(wrapped, receiver)
        } else {
            0
        };
        let retired = w.retired.get(&(home, origin)).copied().unwrap_or(0);
        let stranded = w.stranded_amount(home, origin);
        assert_eq!(
            w.gateway_view(home, "locked(address)", origin),
            stuck + retired + stranded
        );
        assert_eq!(w.supply(wrapped), stuck);
    }
}
