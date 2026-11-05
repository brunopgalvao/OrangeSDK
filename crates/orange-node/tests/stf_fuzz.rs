//! Seeded streams of transactions through the reference kernel on a
//! one-validator chain with the fee market on (spec 23): transfers, calls
//! that store, revert, burn their gas or pay the block's beneficiary,
//! creations, nonce gaps and replays, gas limits below the intrinsic cost,
//! values above the balance, and fees below, at and above the base fee,
//! legacy and dynamic. After every block:
//!
//! - the supply is conserved: the balances of every account the stream
//!   touched, the beneficiary and the treasury included, plus every base fee
//!   burned, are what genesis allocated (spec 23 §4);
//! - every sender pays exactly `gas_used × effective_gas_price` plus the
//!   value it moved, and the beneficiary and the treasury or the burn get
//!   the two parts of it;
//! - nonces only go up, and each is the count of the sender's transactions
//!   that ran;
//! - receipts agree with their block: indices in order, cumulative gas,
//!   the header's gas used and transaction hashes.
//!
//! At the end the node restarts from its store on disk and has the same
//! head, state root and accounts. See `orange-fuzz` for the long mode.

use std::collections::{BTreeMap, BTreeSet};

use k256::ecdsa::SigningKey;
use orange_abi::Encode;
use orange_abi::chain::{
    Allocation, GenesisParams, Receipt, UpgradeParams, Validator, ValidatorSet,
};
use orange_abi::codec::Seq;
use orange_abi::fees::FeeParams;
use orange_abi::types::Genesis;
use orange_fuzz::Rng;
use orange_host::hash::keccak256;
use orange_node::{Node, NodeConfig, StoreConfig, validator_id};
use orange_rlp::{encode_bytes, encode_list, encode_uint};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 200;
const ETHER: u128 = 1_000_000_000_000_000_000;
const FLOOR: u64 = 1_000_000_000;

/// `JUMPDEST PUSH0 JUMP`: loops until its gas runs out.
const BURNER: [u8; 20] = [0x66; 20];
/// `PUSH1 0 DUP1 REVERT`.
const REVERTER: [u8; 20] = [0x67; 20];
/// `CALLDATASIZE PUSH1 0 SSTORE STOP`: stores its calldata's length.
const STORER: [u8; 20] = [0x68; 20];
/// Forwards the value it receives to `COINBASE`, the block's beneficiary.
const PAYER: [u8; 20] = [0x69; 20];

fn kernel_module() -> &'static [u8] {
    static MODULE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    MODULE.get_or_init(|| {
        orange_recompile::recompile(
            &orange_recompile::Input::load(KERNEL).unwrap(),
            &orange_recompile::Options::default(),
        )
        .unwrap()
    })
}

fn strip(b: &[u8]) -> &[u8] {
    let skip = b.iter().take_while(|x| **x == 0).count();
    &b[skip..]
}

struct Wallet {
    key: SigningKey,
    address: [u8; 20],
}

impl Wallet {
    fn new(seed: u8) -> Wallet {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let address = validator_id(&key)[12..].try_into().unwrap();
        Wallet { key, address }
    }

    /// A signed transaction: legacy at `price` when `tip` is `None`, else
    /// dynamic with `price` as the maximum fee; `to` `None` creates.
    #[allow(clippy::too_many_arguments)]
    fn sign(
        &self,
        nonce: u64,
        price: u128,
        tip: Option<u128>,
        gas: u64,
        to: Option<[u8; 20]>,
        value: u128,
        data: &[u8],
    ) -> Vec<u8> {
        let to: &[u8] = to.as_ref().map_or(&[], |a| &a[..]);
        let mut fields = Vec::new();
        let signature = |payload: &[u8]| {
            let (sig, rid) = self
                .key
                .sign_prehash_recoverable(&keccak256(payload))
                .unwrap();
            (
                strip(&sig.r().to_bytes()).to_vec(),
                strip(&sig.s().to_bytes()).to_vec(),
                u64::from(rid.to_byte()),
            )
        };
        if let Some(tip) = tip {
            encode_uint(u128::from(CHAIN_ID), &mut fields);
            encode_uint(u128::from(nonce), &mut fields);
            encode_uint(tip, &mut fields);
            encode_uint(price, &mut fields);
            encode_uint(u128::from(gas), &mut fields);
            encode_bytes(to, &mut fields);
            encode_uint(value, &mut fields);
            encode_bytes(data, &mut fields);
            encode_list(&[], &mut fields);
            let mut payload = vec![2u8];
            encode_list(&fields, &mut payload);
            let (r, s, parity) = signature(&payload);
            encode_uint(u128::from(parity), &mut fields);
            encode_bytes(&r, &mut fields);
            encode_bytes(&s, &mut fields);
            let mut out = vec![2u8];
            encode_list(&fields, &mut out);
            out
        } else {
            encode_uint(u128::from(nonce), &mut fields);
            encode_uint(price, &mut fields);
            encode_uint(u128::from(gas), &mut fields);
            encode_bytes(to, &mut fields);
            encode_uint(value, &mut fields);
            encode_bytes(data, &mut fields);
            let mut unsigned = fields.clone();
            encode_uint(u128::from(CHAIN_ID), &mut unsigned);
            encode_uint(0, &mut unsigned);
            encode_uint(0, &mut unsigned);
            let mut payload = Vec::new();
            encode_list(&unsigned, &mut payload);
            let (r, s, parity) = signature(&payload);
            encode_uint(u128::from(CHAIN_ID * 2 + 35 + parity), &mut fields);
            encode_bytes(&r, &mut fields);
            encode_bytes(&s, &mut fields);
            let mut out = Vec::new();
            encode_list(&fields, &mut out);
            out
        }
    }
}

fn contract(address: [u8; 20], code: Vec<u8>) -> Allocation {
    Allocation {
        address,
        nonce: 1,
        code,
        ..Allocation::default()
    }
}

fn genesis(validator: &SigningKey, wallets: &[Wallet], treasury: [u8; 20]) -> Genesis {
    let mut allocations: Vec<Allocation> = wallets
        .iter()
        .map(|w| Allocation {
            address: w.address,
            balance: 10 * ETHER,
            ..Allocation::default()
        })
        .collect();
    allocations.push(contract(BURNER, vec![0x5b, 0x5f, 0x56]));
    allocations.push(contract(REVERTER, vec![0x60, 0x00, 0x80, 0xfd]));
    allocations.push(contract(STORER, vec![0x36, 0x60, 0x00, 0x55, 0x00]));
    allocations.push(contract(
        PAYER,
        vec![
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x34, 0x41, 0x5a, 0xf1, 0x00,
        ],
    ));
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 16,
        allocations: Seq(allocations),
        upgrades: UpgradeParams::default(),
        fees: FeeParams {
            denominator: 100,
            elasticity: 2,
            min_base_fee: FLOOR,
            treasury,
        },
        ..GenesisParams::default()
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: ValidatorSet {
            validators: Seq(vec![Validator {
                id: validator_id(validator),
                weight: 1,
            }]),
        }
        .to_bytes(),
    }
}

/// The chain and everything the stream has done to it.
struct Run {
    node: Node,
    now_ms: u64,
    /// Every account whose balance can have changed.
    tracked: BTreeSet<[u8; 20]>,
    /// Their balances at genesis.
    initial: u128,
    /// Base fees burned so far.
    burned: u128,
    treasury: [u8; 20],
    /// The next nonce each wallet has not signed yet.
    signed: Vec<u64>,
    /// Transactions admitted and not yet seen in a block.
    pending: BTreeMap<[u8; 32], usize>,
    /// Transactions that ran, per wallet.
    ran: Vec<u64>,
    nonces: Vec<u64>,
}

impl Run {
    fn balances(&mut self) -> u128 {
        let tracked: Vec<[u8; 20]> = self.tracked.iter().copied().collect();
        tracked
            .iter()
            .map(|a| self.node.account(a).unwrap().balance)
            .sum()
    }

    /// One random transaction from a random wallet.
    fn transaction(&mut self, r: &mut Rng, wallets: &[Wallet]) -> (usize, Vec<u8>) {
        let w = r.index(wallets.len());
        let base = u128::from(self.node.fee_status().base_fee);
        let nonce = match r.below(10) {
            // A gap: the transaction waits in the queue, maybe for ever.
            0 => self.signed[w] + 1 + r.below(2),
            // A replay of a nonce already signed.
            1 if self.signed[w] > 0 => r.below(self.signed[w]),
            _ => self.signed[w],
        };
        let price = match r.below(6) {
            0 => base.saturating_sub(1 + base / 2),
            1 => base,
            _ => base + u128::from(r.below(3)) * u128::from(FLOOR),
        };
        let tip = r
            .chance(1, 2)
            .then(|| u128::from(r.below(3)) * u128::from(FLOOR) / 2);
        let fresh = {
            let mut a = [0xF0; 20];
            a[19] = u8::try_from(r.below(8)).unwrap();
            a
        };
        let (to, data, gas): (Option<[u8; 20]>, Vec<u8>, u64) = match r.below(8) {
            // Now and then a block over the gas target, so the base fee moves.
            0 if r.chance(1, 3) => (Some(BURNER), vec![], 16_000_000),
            0 => (Some(BURNER), vec![], 21_000 + r.below(60_000)),
            1 => (Some(REVERTER), vec![], 21_000 + r.below(60_000)),
            2 => {
                let len = r.index(5);
                (Some(STORER), r.bytes(len), 30_000 + r.below(60_000))
            }
            3 => (Some(PAYER), vec![], 50_000 + r.below(60_000)),
            // A creation whose init code stores 1 and stops.
            4 => (None, vec![0x60, 0x01, 0x60, 0x00, 0x55, 0x00], 100_000),
            5 => (
                Some(fresh),
                vec![],
                *r.pick(&[20_999, 21_000, 21_000, 30_000]),
            ),
            _ => (
                Some(wallets[r.index(wallets.len())].address),
                vec![],
                21_000,
            ),
        };
        if let Some(to) = to {
            self.tracked.insert(to);
        }
        let value = match r.below(5) {
            0 => 0,
            1 => 20 * ETHER,
            _ => u128::from(r.below(1_000)) * u128::from(FLOOR),
        };
        let raw = wallets[w].sign(nonce, price, tip, gas, to, value, &data);
        (w, raw)
    }

    fn block(&mut self, r: &mut Rng, wallets: &[Wallet]) {
        for _ in 0..r.below(6) {
            let (w, raw) = self.transaction(r, wallets);
            let nonce = orange_eth::decode(&raw).unwrap().nonce;
            if let Ok(hash) = self.node.submit(&raw) {
                self.pending.insert(hash, w);
                self.signed[w] = self.signed[w].max(nonce + 1);
            }
        }
        let before = self.balances();
        let height = self.node.block_number().unwrap();
        self.now_ms += SLOT_MS;
        self.node.tick(self.now_ms).unwrap();
        assert_eq!(self.node.block_number().unwrap(), height + 1);
        let header = self.node.block_by_number(height + 1).unwrap().unwrap();
        let receipts: Vec<([u8; 32], Receipt)> = header
            .tx_hashes
            .0
            .iter()
            .map(|h| (*h, self.node.receipt(h).unwrap().expect("a receipt")))
            .collect();
        let mut cumulative = 0;
        for (i, (hash, receipt)) in receipts.iter().enumerate() {
            assert_eq!(receipt.height, height + 1);
            assert_eq!(receipt.index as usize, i);
            cumulative += receipt.gas_used;
            assert_eq!(receipt.cumulative_gas_used, cumulative);
            assert!(receipt.status <= 1);
            assert!(receipt.effective_gas_price >= u128::from(header.base_fee));
            if self.treasury == [0; 20] {
                self.burned += u128::from(receipt.gas_used) * u128::from(header.base_fee);
            }
            if let Some(created) = receipt.contract {
                self.tracked.insert(created);
            }
            let w = self
                .pending
                .remove(hash)
                .expect("a transaction the stream sent");
            if receipt.gas_used > 0 {
                self.ran[w] += 1;
            }
        }
        assert_eq!(header.gas_used, cumulative);
        let after = self.balances();
        assert_eq!(
            after + self.burned,
            self.initial,
            "supply at block {} (it held {before} before)",
            height + 1
        );
        for (w, wallet) in wallets.iter().enumerate() {
            let nonce = self.node.account(&wallet.address).unwrap().nonce;
            assert!(nonce >= self.nonces[w], "the nonce of wallet {w} went down");
            assert_eq!(nonce, self.ran[w], "wallet {w}");
            self.nonces[w] = nonce;
        }
    }
}

fn stream(r: &mut Rng) {
    let validator = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let wallets: Vec<Wallet> = (1..=4).map(Wallet::new).collect();
    let treasury = if r.chance(1, 2) { [0; 20] } else { [0x7E; 20] };
    let genesis = genesis(&validator, &wallets, treasury);
    let dir = orange_scratch::Scratch::new("node-stf-fuzz", &format!("{:x}", r.u64()));
    let config = NodeConfig {
        now_ms: 10_000,
        key: Some(validator.clone()),
        store: StoreConfig::Disk(dir.to_path_buf()),
        ..NodeConfig::default()
    };
    let mut node = Node::open(kernel_module(), &genesis, config.clone()).unwrap();
    node.set_backend(orange_host::Backend::Native);
    node.start(None).unwrap();
    let mut tracked: BTreeSet<[u8; 20]> = wallets.iter().map(|w| w.address).collect();
    tracked.extend([BURNER, REVERTER, STORER, PAYER, [0; 20], treasury]);
    let mut run = Run {
        node,
        now_ms: 10_000,
        tracked,
        initial: 0,
        burned: 0,
        treasury,
        signed: vec![0; wallets.len()],
        pending: BTreeMap::new(),
        ran: vec![0; wallets.len()],
        nonces: vec![0; wallets.len()],
    };
    run.initial = run.balances();
    assert_eq!(run.initial, 40 * ETHER);
    for _ in 0..4 + r.below(5) {
        run.block(r, &wallets);
    }
    // Restarted from the store: the same head, root and accounts.
    let head = run.node.block_number().unwrap();
    let root = run.node.state_root();
    let tracked: Vec<[u8; 20]> = run.tracked.iter().copied().collect();
    let accounts: Vec<_> = tracked
        .iter()
        .map(|a| run.node.account(a).unwrap())
        .collect();
    let (persisted, resumed, now_ms) = (
        run.node.persisted(),
        run.node.persisted_driver_state.clone(),
        run.now_ms,
    );
    drop(run.node);
    let config = NodeConfig {
        persisted,
        now_ms,
        ..config
    };
    let mut again = Node::open(kernel_module(), &genesis, config).unwrap();
    again.start(resumed).unwrap();
    assert!(again.executed.is_empty());
    assert_eq!(again.block_number().unwrap(), head);
    assert_eq!(again.state_root(), root);
    for (a, account) in tracked.iter().zip(&accounts) {
        assert_eq!(&again.account(a).unwrap(), account);
    }
    // And it goes on producing blocks.
    again.tick(now_ms + SLOT_MS).unwrap();
    assert_eq!(again.block_number().unwrap(), head + 1);
}

#[test]
fn random_transaction_streams_keep_the_chain_invariants() {
    orange_fuzz::run("stf-streams", 2, stream);
}
