//! The fee market (spec 23) end to end: the base fee of every block pinned
//! against an EIP-1559 computation written out here, the floor and the
//! bounds of a block's change, admission and the pool under the base fee,
//! calls that run free and see it, the treasury and the routing of a
//! surcharge, governance changing the parameters by the key and by a
//! stake-track proposal, and the priority fees of an epoch paid out to four
//! validators and their delegators across epoch boundaries (spec 15 §10),
//! to the wei; and the market across a restart from the chain store and
//! a snapshot import (spec 22), a restarted validator's gate signal included.

use std::cell::Cell;

use k256::ecdsa::SigningKey;
use solo_abi::chain::{
    Allocation, BLOCK_GAS_LIMIT, BlockHeader, CallRequest, GenesisParams, Receipt, UpgradeParams,
    Validator, ValidatorSet, call_status, reason,
};
use solo_abi::codec::Seq;
use solo_abi::fees::{FEE_VAULT, FeeParams, FeeStatus, MAX_MIN_BASE_FEE, query as fee_query};
use solo_abi::governance::{self as gov, Call, GOVERNANCE_ADDRESS, GovernanceParams, mode};
use solo_abi::staking::{
    Delegation, DelegationEntry, GWEI, STAKING_ADDRESS, StakingAction, StakingParams,
    StakingStatus, event, query as staking_query,
};
use solo_abi::types::Genesis;
use solo_abi::{Decode, Encode};
use solo_host::hash::keccak256;
use solo_node::{Node, NodeConfig, Sim, StoreConfig, SubmitError, validator_id};
use solo_rlp::{encode_bytes, encode_list, encode_uint};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 200;
const START_MS: u64 = 10_000;
const ETHER: u128 = 1_000_000_000_000_000_000;
const FLOOR: u64 = 1_000_000_000;
/// The gas target under an elasticity of 2.
const TARGET: u64 = BLOCK_GAS_LIMIT / 2;
/// A contract that loops until it runs out of gas: `JUMPDEST PUSH0 JUMP`.
/// A transaction to it uses exactly its gas limit, so a block's gas used is
/// what the test chooses.
const BURNER: [u8; 20] = [0x66; 20];
const BURNER_CODE: [u8; 3] = [0x5b, 0x5f, 0x56];
/// The probe of `fixtures/evm/Contracts.sol`: `record()` logs what a block
/// looks like from inside the EVM.
const PROBE: [u8; 20] = [0x52; 20];
const PROBE_RUNTIME: &str = include_str!("fixtures/evm/Probe.runtime");

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

fn hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn word(n: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&n.to_be_bytes());
    w
}

fn address_word(address: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(address);
    w
}

fn strip(b: &[u8]) -> &[u8] {
    &b[b.iter().take_while(|x| **x == 0).count()..]
}

/// How a transaction pays.
#[derive(Clone, Copy)]
enum Fee {
    /// Legacy (EIP-155) at this gas price.
    Legacy(u128),
    /// EIP-1559 with this maximum fee and priority fee per gas.
    Dynamic(u128, u128),
}

struct Wallet {
    key: SigningKey,
    address: [u8; 20],
    nonce: Cell<u64>,
}

impl Wallet {
    fn new(seed: u8) -> Wallet {
        Wallet::from_key(SigningKey::from_slice(&[seed; 32]).unwrap())
    }

    fn from_key(key: SigningKey) -> Wallet {
        let address = validator_id(&key)[12..].try_into().unwrap();
        Wallet {
            key,
            address,
            nonce: Cell::new(0),
        }
    }

    /// A signed transaction with an explicit nonce.
    fn sign(
        &self,
        nonce: u64,
        fee: Fee,
        to: [u8; 20],
        value: u128,
        data: &[u8],
        gas: u64,
    ) -> Vec<u8> {
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
        match fee {
            Fee::Legacy(price) => {
                encode_uint(u128::from(nonce), &mut fields);
                encode_uint(price, &mut fields);
                encode_uint(u128::from(gas), &mut fields);
                encode_bytes(&to, &mut fields);
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
            Fee::Dynamic(max_fee, tip) => {
                encode_uint(u128::from(CHAIN_ID), &mut fields);
                encode_uint(u128::from(nonce), &mut fields);
                encode_uint(tip, &mut fields);
                encode_uint(max_fee, &mut fields);
                encode_uint(u128::from(gas), &mut fields);
                encode_bytes(&to, &mut fields);
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
            }
        }
    }

    /// A signed transaction with the wallet's next nonce.
    fn send(&self, fee: Fee, to: [u8; 20], value: u128, data: &[u8], gas: u64) -> Vec<u8> {
        let nonce = self.nonce.get();
        self.nonce.set(nonce + 1);
        self.sign(nonce, fee, to, value, data, gas)
    }

    /// A transaction to the burner at `price` using exactly `gas`.
    fn burn(&self, price: u128, gas: u64) -> Vec<u8> {
        self.send(Fee::Legacy(price), BURNER, 0, &[], gas)
    }

    /// Peeks at a transaction without using up the nonce.
    fn peek(&self, fee: Fee, to: [u8; 20], value: u128, data: &[u8], gas: u64) -> Vec<u8> {
        self.sign(self.nonce.get(), fee, to, value, data, gas)
    }
}

fn funded(address: [u8; 20], balance: u128) -> Allocation {
    Allocation {
        address,
        balance,
        ..Allocation::default()
    }
}

fn predeploy(address: [u8; 20], code: Vec<u8>) -> Allocation {
    Allocation {
        address,
        nonce: 1,
        code,
        ..Allocation::default()
    }
}

/// The market on: a denominator of 100, so a full block raises the fee by
/// exactly one percent, an elasticity of 2 and a one gwei floor.
fn market(treasury: [u8; 20]) -> FeeParams {
    FeeParams {
        denominator: 100,
        elasticity: 2,
        min_base_fee: FLOOR,
        treasury,
    }
}

/// A genesis of `validators` with `weights` (gwei of stake), the given
/// allocations and parameters.
struct Setup {
    allocations: Vec<Allocation>,
    fees: FeeParams,
    staking: StakingParams,
    governance: GovernanceParams,
    key: [u8; 20],
}

fn genesis(validators: &[SigningKey], weights: &[u64], setup: Setup) -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 16,
        allocations: Seq(setup.allocations),
        upgrades: UpgradeParams {
            governance: setup.key,
            min_delay: 1,
            epoch_blocks: 0,
        },
        staking: setup.staking,
        governance: setup.governance,
        fees: setup.fees,
        ..GenesisParams::default()
    };
    let set = ValidatorSet {
        validators: Seq(validators
            .iter()
            .zip(weights)
            .map(|(k, &weight)| Validator {
                id: validator_id(k),
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

/// EIP-1559's update with a floor, as the EIP states it (spec 23 §3):
/// the reference every header is checked against.
fn reference(params: &FeeParams, parent_fee: u64, parent_used: u64) -> u64 {
    let target = BLOCK_GAS_LIMIT / params.elasticity;
    let (fee, denominator) = (u128::from(parent_fee), u128::from(params.denominator));
    let next = match parent_used.cmp(&target) {
        std::cmp::Ordering::Equal => fee,
        std::cmp::Ordering::Greater => {
            let delta = fee * u128::from(parent_used - target) / u128::from(target) / denominator;
            fee + delta.max(1)
        }
        std::cmp::Ordering::Less => {
            fee - fee * u128::from(target - parent_used) / u128::from(target) / denominator
        }
    };
    u64::try_from(next).unwrap().max(params.min_base_fee)
}

/// A one-validator chain and its clock.
struct Chain {
    node: Node,
    now_ms: u64,
}

impl Chain {
    fn new(genesis: &Genesis, key: &SigningKey) -> Chain {
        let config = NodeConfig {
            now_ms: START_MS,
            key: Some(key.clone()),
            ..NodeConfig::default()
        };
        Chain::open(genesis, config, None)
    }

    /// The node opened with `config` and started with `resumed`, its
    /// driver's persisted state.
    fn open(genesis: &Genesis, config: NodeConfig, resumed: Option<Vec<u8>>) -> Chain {
        let now_ms = config.now_ms;
        let mut node = Node::open(kernel_module(), genesis, config).unwrap();
        // Blocks full of burning run on the native backend, which agrees
        // with the interpreter to the gas (spec 07 §4.1) and takes a fraction
        // of the time.
        node.set_backend(solo_host::Backend::Native);
        node.start(resumed).unwrap();
        Chain { node, now_ms }
    }

    /// Submits `txs`, produces the next block and returns their receipts.
    fn block(&mut self, txs: &[Vec<u8>]) -> Vec<Receipt> {
        let hashes: Vec<[u8; 32]> = txs
            .iter()
            .map(|raw| self.node.submit(raw).expect("admitted"))
            .collect();
        self.mine();
        hashes
            .iter()
            .map(|h| self.node.receipt(h).unwrap().expect("receipt"))
            .collect()
    }

    /// Produces the next block from what the pool holds.
    fn mine(&mut self) -> BlockHeader {
        let height = self.node.block_number().unwrap();
        self.now_ms += SLOT_MS;
        self.node.tick(self.now_ms).unwrap();
        assert_eq!(self.node.block_number().unwrap(), height + 1);
        self.header(height + 1)
    }

    fn header(&mut self, height: u64) -> BlockHeader {
        self.node.block_by_number(height).unwrap().unwrap()
    }

    fn balance(&mut self, address: [u8; 20]) -> u128 {
        self.node.account(&address).unwrap().balance
    }

    fn fees(&mut self) -> FeeStatus {
        let r = self.node.query(fee_query::FEES, &[]).unwrap();
        assert_eq!(r.status, 0);
        FeeStatus::from_bytes(&r.body).unwrap()
    }

    /// Checks every header from 1 to the head against the reference, and
    /// the node's view of the next base fee against the head.
    fn check_trajectory(&mut self, params: &FeeParams) {
        let head = self.node.block_number().unwrap();
        let mut parent = (params.min_base_fee, 0);
        for h in 1..=head {
            let header = self.header(h);
            assert_eq!(
                header.base_fee,
                reference(params, parent.0, parent.1),
                "block {h}"
            );
            assert_eq!(header.gas_limit, BLOCK_GAS_LIMIT);
            parent = (header.base_fee, header.gas_used);
        }
        let next = reference(params, parent.0, parent.1);
        assert_eq!(self.node.fee_status().base_fee, next);
        assert_eq!(self.fees().base_fee, next);
    }
}

/// The base fee the genesis header carries (spec 20 §3.1, 23 §3).
fn genesis_base_fee(node: &mut Node) -> u64 {
    node.block_by_number(0)
        .unwrap()
        .expect("the genesis block")
        .base_fee
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_base_fee_follows_eip_1559_above_the_floor() {
    let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let alice = Wallet::new(1);
    let params = market([0; 20]);
    let setup = Setup {
        allocations: vec![
            funded(alice.address, 1_000 * ETHER),
            predeploy(BURNER, BURNER_CODE.to_vec()),
        ],
        fees: params.clone(),
        staking: StakingParams::default(),
        governance: GovernanceParams::default(),
        key: [0; 20],
    };
    let genesis = genesis(std::slice::from_ref(&key), &[1], setup);
    let mut chain = Chain::new(&genesis, &key);
    let start = chain.balance(alice.address);
    let price = 2 * u128::from(FLOOR);
    // Before any block the next base fee is the floor, and so is block 1's.
    assert_eq!(chain.fees().base_fee, FLOOR);
    assert_eq!(genesis_base_fee(&mut chain.node), FLOOR);
    let empty = chain.mine();
    assert_eq!((empty.base_fee, empty.gas_used), (FLOOR, 0));
    // Two full blocks: each raises the next base fee by the largest step,
    // exactly a hundredth, compounding.
    let mut fees = 0u128;
    let mut burned = 0u128;
    let spent = |receipts: &[Receipt], header: &BlockHeader, fees: &mut u128, burned: &mut u128| {
        for r in receipts {
            assert_eq!((r.status, r.effective_gas_price), (0, price));
            *fees += u128::from(r.gas_used) * price;
            *burned += u128::from(r.gas_used) * u128::from(header.base_fee);
        }
    };
    let receipts = chain.block(&[alice.burn(price, TARGET), alice.burn(price, TARGET)]);
    let full = chain.header(2);
    assert_eq!(full.gas_used, BLOCK_GAS_LIMIT);
    assert!(
        receipts.iter().all(|r| r.gas_used == TARGET),
        "the burner uses its whole limit"
    );
    spent(&receipts, &full, &mut fees, &mut burned);
    assert_eq!(chain.fees().base_fee, FLOOR + FLOOR / 100);
    let receipts = chain.block(&[alice.burn(price, TARGET), alice.burn(price, TARGET)]);
    spent(&receipts, &chain.header(3), &mut fees, &mut burned);
    let second = FLOOR + FLOOR / 100;
    assert_eq!(chain.header(3).base_fee, second);
    assert_eq!(chain.fees().base_fee, second + second / 100);
    // A block at the target leaves the fee; one half way between target and
    // limit raises it by half the step; one at half the target lowers it by
    // half the step.
    let receipts = chain.block(&[alice.burn(price, TARGET)]);
    spent(&receipts, &chain.header(4), &mut fees, &mut burned);
    let at_target = chain.header(4).base_fee;
    assert_eq!(chain.fees().base_fee, at_target);
    let receipts = chain.block(&[alice.burn(price, TARGET), alice.burn(price, TARGET / 2)]);
    spent(&receipts, &chain.header(5), &mut fees, &mut burned);
    assert_eq!(chain.fees().base_fee, at_target + at_target / 200);
    let receipts = chain.block(&[alice.burn(price, TARGET / 2)]);
    let header = chain.header(6);
    spent(&receipts, &header, &mut fees, &mut burned);
    assert_eq!(
        chain.fees().base_fee,
        header.base_fee - header.base_fee / 200
    );
    // Empty blocks lower it by a hundredth each, never below the floor.
    let mut above = Vec::new();
    for _ in 0..8 {
        let header = chain.mine();
        above.push(header.base_fee > FLOOR);
    }
    assert!(
        above.starts_with(&[true, true]) && above.ends_with(&[false, false]),
        "{above:?}"
    );
    assert_eq!(chain.fees().base_fee, FLOOR);
    // Every header against the reference, from the genesis parent on.
    chain.check_trajectory(&params);
    // Every wei is accounted for: the sender paid gas times its price, the
    // zero-address beneficiary of a chain without staking got the tips, and
    // the base fee is gone from the supply.
    assert_eq!(chain.balance(alice.address), start - fees);
    assert_eq!(chain.balance([0; 20]), fees - burned);
    assert_eq!(chain.balance(FEE_VAULT), 0);
    assert_eq!(
        chain.balance(alice.address) + chain.balance([0; 20]) + burned,
        start
    );
    assert!(burned > 0);
}

#[test]
#[allow(clippy::too_many_lines)]
fn transactions_below_the_base_fee_are_refused_and_wait_in_the_pool() {
    let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let setup = Setup {
        allocations: vec![
            funded(alice.address, 1_000 * ETHER),
            funded(bob.address, 1_000 * ETHER),
            predeploy(BURNER, BURNER_CODE.to_vec()),
            predeploy(PROBE, hex(PROBE_RUNTIME)),
        ],
        fees: market([0; 20]),
        staking: StakingParams::default(),
        governance: GovernanceParams::default(),
        key: [0; 20],
    };
    let genesis = genesis(std::slice::from_ref(&key), &[1], setup);
    let mut chain = Chain::new(&genesis, &key);
    let floor = u128::from(FLOOR);
    let price = 2 * floor;
    // Admission: a gas price or a maximum fee below the base fee, in the
    // kernel's order after the tip check.
    for (raw, why) in [
        (
            bob.peek(Fee::Legacy(0), alice.address, 1, &[], 21_000),
            reason::FEE_TOO_LOW,
        ),
        (
            bob.peek(Fee::Legacy(floor - 1), alice.address, 1, &[], 21_000),
            reason::FEE_TOO_LOW,
        ),
        (
            bob.peek(Fee::Dynamic(floor - 1, 0), alice.address, 1, &[], 21_000),
            reason::FEE_TOO_LOW,
        ),
        (
            bob.peek(
                Fee::Dynamic(floor, floor + 1),
                alice.address,
                1,
                &[],
                21_000,
            ),
            reason::TIP_ABOVE_FEE_CAP,
        ),
        (
            bob.peek(Fee::Dynamic(0, 1), alice.address, 1, &[], 21_000),
            reason::TIP_ABOVE_FEE_CAP,
        ),
    ] {
        assert_eq!(chain.node.submit(&raw), Err(SubmitError::Rejected(why)));
    }
    // A transaction priced exactly at the base fee is admitted with no
    // priority; a full block then raises the base fee past it and it waits in
    // the pool, left out of every take, until the fee falls back.
    let exact = bob.send(Fee::Dynamic(floor, floor), alice.address, 1, &[], 21_000);
    let hash = chain.node.submit(&exact).unwrap();
    assert_eq!(chain.node.mempool().get(&hash).unwrap().priority, 0);
    let receipts = chain.block(&[alice.burn(price, TARGET), alice.burn(price, TARGET)]);
    assert_eq!(receipts.len(), 2);
    assert_eq!(chain.header(1).tx_hashes.0.len(), 2, "the block was full");
    assert_eq!(chain.node.fee_status().base_fee, FLOOR + FLOOR / 100);
    let header = chain.mine();
    assert!(header.tx_hashes.0.is_empty(), "priced below the base fee");
    assert!(chain.node.mempool().get(&hash).is_some());
    let mut included = None;
    for _ in 0..4 {
        let header = chain.mine();
        if header.tx_hashes.0 == vec![hash] {
            included = Some(header);
            break;
        }
    }
    let header = included.expect("included once the base fee fell");
    assert_eq!(header.base_fee, FLOOR);
    let receipt = chain.node.receipt(&hash).unwrap().unwrap();
    assert_eq!((receipt.status, receipt.effective_gas_price), (1, floor));
    assert!(chain.node.mempool().get(&hash).is_none());
    // A call runs free of the base fee, in the head block, and sees it.
    let record = keccak256(b"record()")[..4].to_vec();
    let call = CallRequest {
        from: alice.address,
        to: Some(PROBE),
        data: record.clone(),
        gas: 100_000,
        ..CallRequest::default()
    };
    let result = chain.node.call(&call).unwrap();
    assert_eq!(result.status, call_status::SUCCESS);
    let receipts = chain.block(&[
        alice.burn(price, 14_000_000),
        alice.burn(price, 14_000_000),
        alice.send(Fee::Legacy(price), PROBE, 0, &record, 100_000),
    ]);
    let seen = &receipts[2].logs.0[0];
    let header = chain.header(receipts[2].height);
    let fields: Vec<[u8; 32]> = seen
        .data
        .chunks(32)
        .map(|c| c.try_into().unwrap())
        .collect();
    assert_eq!(
        fields[4],
        address_word(&[0; 20]),
        "COINBASE without staking"
    );
    assert_eq!(fields[5], word(u128::from(header.base_fee)), "BASEFEE");
    assert_eq!(header.base_fee, FLOOR);
    assert_eq!(header.beneficiary, [0; 20]);
    // The probe's transaction did not fit a full block's worth of burning,
    // so its block is over the target: the next fee is up again.
    assert!(chain.node.fee_status().base_fee > FLOOR);
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_treasury_takes_the_base_fee_and_governance_changes_the_parameters() {
    let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let alice = Wallet::new(1);
    let treasury = [0x77; 20];
    let setup = Setup {
        allocations: vec![
            funded(alice.address, 1_000 * ETHER),
            predeploy(BURNER, BURNER_CODE.to_vec()),
        ],
        fees: market(treasury),
        staking: StakingParams::default(),
        governance: GovernanceParams::default(),
        key: alice.address,
    };
    let genesis = genesis(std::slice::from_ref(&key), &[1], setup);
    let mut chain = Chain::new(&genesis, &key);
    let floor = u128::from(FLOOR);
    let price = 2 * floor;
    let start = chain.balance(alice.address);
    // A burn at the floor, a million gas over the target: the treasury gets
    // the base fee of every gas used, the zero address the tip, exactly.
    let receipts = chain.block(&[alice.burn(price, TARGET + 1_000_000)]);
    let gas = u128::from(receipts[0].gas_used);
    assert_eq!(chain.balance(treasury), gas * floor);
    assert_eq!(chain.balance([0; 20]), gas * (price - floor));
    assert_eq!(chain.balance(alice.address), start - gas * price);
    // The key raises the floor to three gwei and names no treasury: the
    // surcharge of the governance call is routed like its other gas, and the
    // new parameters apply from the next block.
    let raised = FeeParams {
        min_base_fee: 3 * FLOOR,
        treasury: [0; 20],
        ..market(treasury)
    };
    let submit = Call::Submit {
        target: GOVERNANCE_ADDRESS,
        data: Call::SetFeeParams {
            params: raised.clone(),
        }
        .encode(),
    };
    let base_fee = chain.node.fee_status().base_fee;
    assert_eq!(
        u128::from(base_fee),
        floor + floor * 1_000_000 / u128::from(TARGET) / 100
    );
    let (treasury_before, zero_before, alice_before) = (
        chain.balance(treasury),
        chain.balance([0; 20]),
        chain.balance(alice.address),
    );
    let receipts = chain.block(&[alice.send(
        Fee::Legacy(price),
        GOVERNANCE_ADDRESS,
        0,
        &submit.encode(),
        200_000,
    )]);
    let r = &receipts[0];
    assert_eq!(r.status, 1);
    assert!(r.gas_used > gov::GOVERNANCE_GAS);
    assert_eq!(
        r.logs.0,
        vec![
            gov::enacted_log(
                &alice.address,
                &GOVERNANCE_ADDRESS,
                &Call::SetFeeParams {
                    params: raised.clone()
                }
                .encode()
            ),
            gov::fee_params_log(&raised),
        ]
    );
    let gas = u128::from(r.gas_used);
    assert_eq!(
        chain.balance(treasury),
        treasury_before + gas * u128::from(base_fee)
    );
    assert_eq!(
        chain.balance([0; 20]),
        zero_before + gas * (price - u128::from(base_fee))
    );
    assert_eq!(chain.balance(alice.address), alice_before - gas * price);
    let status = chain.fees();
    assert_eq!(status.params, raised);
    assert_eq!(
        status.base_fee,
        3 * FLOOR,
        "the floor binds from the next block"
    );
    assert_eq!(status.pool, 0);
    // Parameters that cannot work revert the submission and change nothing;
    // the market can be turned off too, and then every block is at its floor.
    for bad in [
        FeeParams {
            denominator: 50,
            ..raised.clone()
        },
        FeeParams {
            elasticity: 1,
            ..raised.clone()
        },
        FeeParams {
            denominator: 0,
            elasticity: 2,
            ..raised.clone()
        },
        // A treasury at the staking address would lock every base fee there.
        FeeParams {
            treasury: STAKING_ADDRESS,
            ..raised.clone()
        },
        // A floor above the bound, a wei over it.
        FeeParams {
            min_base_fee: MAX_MIN_BASE_FEE + 1,
            ..raised.clone()
        },
    ] {
        let submit = Call::Submit {
            target: GOVERNANCE_ADDRESS,
            data: Call::SetFeeParams { params: bad }.encode(),
        };
        let receipts = chain.block(&[alice.send(
            Fee::Legacy(4 * floor),
            GOVERNANCE_ADDRESS,
            0,
            &submit.encode(),
            200_000,
        )]);
        assert_eq!((receipts[0].status, receipts[0].logs.0.len()), (0, 0));
        assert_eq!(chain.fees().params, raised);
    }
    let off = FeeParams {
        min_base_fee: 5,
        ..FeeParams::default()
    };
    let submit = Call::Submit {
        target: GOVERNANCE_ADDRESS,
        data: Call::SetFeeParams {
            params: off.clone(),
        }
        .encode(),
    };
    let receipts = chain.block(&[alice.send(
        Fee::Legacy(4 * floor),
        GOVERNANCE_ADDRESS,
        0,
        &submit.encode(),
        200_000,
    )]);
    assert_eq!(receipts[0].status, 1);
    assert_eq!(chain.fees().base_fee, 5);
    let header = chain.mine();
    assert_eq!(header.base_fee, 5);
    // The treasury got nothing since it was unnamed.
    assert_eq!(
        chain.balance(treasury),
        treasury_before + gas * u128::from(base_fee)
    );
    // `setFeeParams` sent directly is no call anyone may make.
    let direct = alice.peek(
        Fee::Legacy(4 * floor),
        GOVERNANCE_ADDRESS,
        0,
        &Call::SetFeeParams { params: off }.encode(),
        200_000,
    );
    assert_eq!(
        chain.node.submit(&direct),
        Err(SubmitError::Rejected(reason::SYSTEM_ACTION))
    );
}

/// `kernel_init` traps on parameters that cannot work (spec 23 §2): a
/// treasury at the staking address, a floor above the bound, factors out
/// of range; the bound itself starts a chain.
#[test]
fn a_genesis_with_unworkable_fee_parameters_never_starts() {
    let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let setup = |fees: FeeParams| Setup {
        allocations: Vec::new(),
        fees,
        staking: StakingParams::default(),
        governance: GovernanceParams::default(),
        key: [0; 20],
    };
    let open = |fees: FeeParams| {
        let genesis = genesis(std::slice::from_ref(&key), &[1], setup(fees));
        Node::open(kernel_module(), &genesis, NodeConfig::default())
    };
    for bad in [
        market(STAKING_ADDRESS),
        FeeParams {
            treasury: STAKING_ADDRESS,
            ..FeeParams::default()
        },
        FeeParams {
            min_base_fee: MAX_MIN_BASE_FEE + 1,
            ..market([0; 20])
        },
        FeeParams {
            denominator: 99,
            ..market([0; 20])
        },
    ] {
        assert!(open(bad.clone()).is_err(), "{bad:?}");
    }
    let node = open(FeeParams {
        min_base_fee: MAX_MIN_BASE_FEE,
        ..market([7; 20])
    })
    .unwrap();
    assert_eq!(node.fee_status().base_fee, MAX_MIN_BASE_FEE);
}

// ---- The fee market on disk: restarts and snapshots (spec 22) ----

fn store_dir(name: &str) -> solo_scratch::Scratch {
    solo_scratch::Scratch::new("node-fees", name)
}

fn decoded<T: Decode>(r: &solo_abi::types::QueryResult) -> T {
    assert_eq!(r.status, 0);
    T::from_bytes(&r.body).unwrap()
}

/// What the fee market wrote lives in the chain store: a node restarted
/// over it, and a node that imports a snapshot of it, see the same
/// parameters, next base fee, reward pool and delegations, keep the
/// genesis block's base fee, and price the next block as the chain does.
#[test]
#[allow(clippy::too_many_lines)]
fn the_fee_market_survives_a_restart_and_travels_in_a_snapshot() {
    let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let validator = Wallet::from_key(key.clone());
    let (alice, d1) = (Wallet::new(1), Wallet::new(2));
    let params = market([0; 20]);
    let setup = Setup {
        allocations: vec![
            funded(alice.address, 1_000 * ETHER),
            funded(d1.address, 100 * ETHER),
            funded(validator.address, 100 * ETHER),
            predeploy(BURNER, BURNER_CODE.to_vec()),
        ],
        fees: params.clone(),
        staking: StakingParams {
            epoch_blocks: 4,
            unbonding_epochs: 1,
            ..StakingParams::default()
        },
        governance: GovernanceParams::default(),
        key: [0; 20],
    };
    let genesis = genesis(std::slice::from_ref(&key), &[1_000], setup);
    let dir = store_dir("restart");
    let config = NodeConfig {
        now_ms: START_MS,
        key: Some(key.clone()),
        store: StoreConfig::Disk(dir.to_path_buf()),
        ..NodeConfig::default()
    };
    let mut chain = Chain::open(&genesis, config.clone(), None);
    let price = 2 * u128::from(FLOOR);
    let delegate = d1.send(
        Fee::Legacy(price),
        STAKING_ADDRESS,
        500 * GWEI,
        &StakingAction::Delegate {
            validator: validator.address,
        }
        .encode(),
        200_000,
    );
    assert_eq!(chain.block(&[delegate])[0].status, 1);
    // Blocks over the target raise the base fee; their tips fill the pool.
    while chain.node.block_number().unwrap() < 11 {
        chain.block(&[alice.burn(price, TARGET + 1_000_000)]);
    }
    let fees = chain.node.fee_status().clone();
    assert!(fees.base_fee > FLOOR && fees.pool > 0, "{fees:?}");
    let delegated = delegations(&mut chain.node, d1.address);
    assert_eq!(delegated.len(), 1);
    assert_eq!(genesis_base_fee(&mut chain.node), FLOOR);
    let (persisted, resumed, now_ms) = (
        chain.node.persisted(),
        chain.node.persisted_driver_state.clone(),
        chain.now_ms,
    );
    drop(chain);
    // Restarted over its store, before and after the driver starts: the
    // same market, and the next block priced from the head.
    let config = NodeConfig {
        persisted,
        now_ms,
        ..config
    };
    let mut reopened = Node::open(kernel_module(), &genesis, config.clone()).unwrap();
    assert_eq!(reopened.fee_status(), &fees);
    assert_eq!(genesis_base_fee(&mut reopened), FLOOR);
    drop(reopened);
    let mut again = Chain::open(&genesis, config, resumed);
    assert!(again.node.executed.is_empty());
    assert_eq!(again.node.fee_status(), &fees);
    assert_eq!(again.fees(), fees);
    assert_eq!(delegations(&mut again.node, d1.address), delegated);
    again.block(&[alice.burn(price, TARGET + 1_000_000)]);
    again.check_trajectory(&params);
    // A snapshot of the latest epoch carries the market as it stood there:
    // the epoch's end has just paid the pool out to the validator and its
    // delegator, so the balances it carries hold the rewards.
    let snap_file = store_dir("market.snap");
    let snapshot = again.node.export_snapshot(None, &snap_file).unwrap();
    let height = snapshot.header.height;
    let expected: FeeStatus = decoded(
        &again
            .node
            .query_at(fee_query::FEES, &[], Some(height))
            .unwrap(),
    );
    let head = again.header(height);
    assert_eq!(
        expected.base_fee,
        reference(&params, head.base_fee, head.gas_used)
    );
    assert!(expected.base_fee > FLOOR, "{expected:?}");
    let expected_delegations: Seq<DelegationEntry> = decoded(
        &again
            .node
            .query_at(staking_query::DELEGATIONS, &d1.address, Some(height))
            .unwrap(),
    );
    let rewarded = again.node.account_at(&d1.address, Some(height)).unwrap();
    let before_payout = again
        .node
        .account_at(&d1.address, Some(height - 1))
        .unwrap();
    assert!(rewarded.balance > before_payout.balance);
    let expected_staking: StakingStatus = decoded(
        &again
            .node
            .query_at(staking_query::STAKING, &[], Some(height))
            .unwrap(),
    );
    let staked = again
        .node
        .account_at(&STAKING_ADDRESS, Some(height))
        .unwrap();
    let fresh_dir = store_dir("snapshot");
    let mut fresh = Node::open(
        kernel_module(),
        &genesis,
        NodeConfig {
            now_ms: again.now_ms,
            key: Some(key.clone()),
            store: StoreConfig::Disk(fresh_dir.to_path_buf()),
            ..NodeConfig::default()
        },
    )
    .unwrap();
    assert_eq!(fresh.fee_status().base_fee, FLOOR);
    fresh.import_snapshot(&snapshot).unwrap();
    // Before any block: the market the snapshot holds, not genesis's.
    assert_eq!(fresh.fee_status(), &expected);
    assert_eq!(fee_status(&mut fresh), expected);
    assert_eq!(genesis_base_fee(&mut fresh), FLOOR);
    assert_eq!(delegations(&mut fresh, d1.address), expected_delegations.0);
    assert_eq!(status(&mut fresh), expected_staking);
    assert_eq!(fresh.account(&STAKING_ADDRESS).unwrap(), staked);
    assert_eq!(fresh.account(&d1.address).unwrap(), rewarded);
    // Its next block carries that base fee.
    fresh.set_backend(solo_host::Backend::Native);
    fresh.start(None).unwrap();
    let mut now_ms = again.now_ms;
    for _ in 0..20 {
        if fresh.block_number().unwrap() > height {
            break;
        }
        now_ms += SLOT_MS;
        fresh.tick(now_ms).unwrap();
    }
    let next = fresh.block_by_number(height + 1).unwrap().unwrap();
    assert_eq!(next.base_fee, expected.base_fee);
}

/// A validator restarted over its store prices its gate signal at the
/// head's next base fee (spec 13 §8.2, spec 23 §3): the signal the restart
/// prepares is admitted at once and the first block carries it.
#[test]
fn a_restarted_validator_signals_at_the_base_fee() {
    let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let validator = Wallet::from_key(key.clone());
    let setup = Setup {
        allocations: vec![funded(validator.address, 100 * ETHER)],
        fees: market([0; 20]),
        staking: StakingParams::default(),
        governance: GovernanceParams::default(),
        key: [0; 20],
    };
    let mut genesis = genesis(std::slice::from_ref(&key), &[1], setup);
    let mut params = GenesisParams::from_bytes(&genesis.params).unwrap();
    params.upgrades.epoch_blocks = 3;
    genesis.params = params.to_bytes();
    let dir = store_dir("signal");
    let config = NodeConfig {
        now_ms: START_MS,
        key: Some(key.clone()),
        store: StoreConfig::Disk(dir.to_path_buf()),
        ..NodeConfig::default()
    };
    let signal_epoch = |node: &mut Node| {
        node.upgrade_status().unwrap().validators.0[0]
            .signal
            .as_ref()
            .map(|s| s.epoch)
    };
    let mut chain = Chain::open(&genesis, config.clone(), None);
    // Up to the last block of an epoch after the first signal: the next
    // block opens an epoch the signal does not cover.
    loop {
        chain.mine();
        let head = chain.node.block_number().unwrap();
        if head.is_multiple_of(3) && signal_epoch(&mut chain.node).is_some() {
            break;
        }
    }
    let covered = signal_epoch(&mut chain.node).unwrap();
    let (persisted, resumed, now_ms) = (
        chain.node.persisted(),
        chain.node.persisted_driver_state.clone(),
        chain.now_ms,
    );
    drop(chain);
    let mut again = Chain::open(
        &genesis,
        NodeConfig {
            persisted,
            now_ms,
            ..config
        },
        resumed,
    );
    assert!(again.node.fee_status().base_fee >= FLOOR);
    again.mine();
    assert!(signal_epoch(&mut again.node).unwrap() > covered);
}

/// A validator's gate signal carries headroom (spec 13 §8.2): priced at
/// the next base fee, it waits behind a block that fills up and raises
/// the base fee, and still lands in the block after, paying that block's
/// base fee and nothing over it. A signal priced at exactly the base fee
/// it was built at would be left out of every take from then on, and its
/// replacement refused as underpriced.
#[test]
fn a_signal_outlasts_a_rising_base_fee_and_pays_only_the_base_fee() {
    let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let validator = Wallet::from_key(key.clone());
    let alice = Wallet::new(1);
    let setup = Setup {
        allocations: vec![
            funded(validator.address, 100 * ETHER),
            funded(alice.address, 1_000 * ETHER),
            predeploy(BURNER, BURNER_CODE.to_vec()),
        ],
        fees: market([0; 20]),
        staking: StakingParams::default(),
        governance: GovernanceParams::default(),
        key: [0; 20],
    };
    let mut genesis = genesis(std::slice::from_ref(&key), &[1], setup);
    let mut params = GenesisParams::from_bytes(&genesis.params).unwrap();
    params.upgrades.epoch_blocks = 3;
    genesis.params = params.to_bytes();
    let mut chain = Chain::new(&genesis, &key);
    // Up to a block after which the node has a signal waiting in its pool.
    let pending = |node: &Node| {
        node.mempool()
            .iter()
            .find(|tx| tx.sender == validator.address)
            .map(|tx| (tx.hash, tx.fee_cap, tx.tip_cap))
    };
    let mut waiting = None;
    for _ in 0..12 {
        chain.mine();
        waiting = pending(&chain.node);
        if waiting.is_some() {
            break;
        }
    }
    let (hash, fee_cap, tip_cap) = waiting.expect("a signal waits");
    let priced_at = chain.node.fee_status().base_fee;
    assert_eq!((fee_cap, tip_cap), (2 * u128::from(priced_at), 0));
    // A block filled by two burns that leave no room for the signal's gas
    // limit: the base fee rises past what the signal was priced at.
    let price = 4 * u128::from(FLOOR);
    let full = chain.block(&[
        alice.burn(price, TARGET),
        alice.burn(price, TARGET - 50_000),
    ]);
    assert_eq!(full[0].gas_used + full[1].gas_used, 2 * TARGET - 50_000);
    assert!(chain.node.receipt(&hash).unwrap().is_none());
    let risen = chain.node.fee_status().base_fee;
    assert!(risen > priced_at, "{risen} > {priced_at}");
    let before = chain.balance(validator.address);
    let header = chain.mine();
    assert_eq!(header.base_fee, risen);
    let receipt = chain
        .node
        .receipt(&hash)
        .unwrap()
        .expect("the signal landed");
    assert_eq!(receipt.status, 1);
    assert_eq!(receipt.effective_gas_price, u128::from(risen));
    assert_eq!(
        chain.balance(validator.address),
        before - u128::from(receipt.gas_used) * u128::from(risen)
    );
}

// ---- Four validators, delegators and the reward pool ----

fn keys(n: u8) -> Vec<SigningKey> {
    (1..=n)
        .map(|i| SigningKey::from_slice(&[0x30 + i; 32]).unwrap())
        .collect()
}

fn at(now_ms: u64) -> NodeConfig {
    NodeConfig {
        now_ms,
        ..NodeConfig::default()
    }
}

fn status(node: &mut Node) -> StakingStatus {
    let r = node.query(staking_query::STAKING, &[]).unwrap();
    assert_eq!(r.status, 0);
    StakingStatus::from_bytes(&r.body).unwrap()
}

fn delegations(node: &mut Node, address: [u8; 20]) -> Vec<DelegationEntry> {
    let r = node.query(staking_query::DELEGATIONS, &address).unwrap();
    assert_eq!(r.status, 0);
    Seq::<DelegationEntry>::from_bytes(&r.body).unwrap().0
}

fn fee_status(node: &mut Node) -> FeeStatus {
    let r = node.query(fee_query::FEES, &[]).unwrap();
    assert_eq!(r.status, 0);
    FeeStatus::from_bytes(&r.body).unwrap()
}

fn balance(node: &mut Node, address: [u8; 20]) -> u128 {
    node.account(&address).unwrap().balance
}

/// Submits `raws` to node 0 and runs the network until every node has
/// executed them all; their receipts in order.
fn sim_include_all(sim: &mut Sim, raws: &[Vec<u8>]) -> Vec<Receipt> {
    let hashes: Vec<[u8; 32]> = raws
        .iter()
        .map(|raw| sim.submit(0, raw).expect("admitted"))
        .collect();
    let reached = sim
        .run_until(60 * SLOT_MS, |s| {
            s.nodes
                .iter_mut()
                .all(|n| hashes.iter().all(|hash| n.receipt(hash).unwrap().is_some()))
        })
        .unwrap();
    assert!(reached, "transactions not executed everywhere");
    hashes
        .iter()
        .map(|hash| sim.nodes[0].receipt(hash).unwrap().unwrap())
        .collect()
}

/// Submits `raw` to node 0 and runs the network until every node has
/// executed it.
fn sim_include(sim: &mut Sim, raw: &[u8]) -> Receipt {
    sim_include_all(sim, &[raw.to_vec()]).remove(0)
}

/// Runs the network until every node has executed block `height`.
fn sim_reach(sim: &mut Sim, height: u64) {
    let reached = sim
        .run_until(400 * SLOT_MS, |s| {
            s.nodes
                .iter_mut()
                .all(|n| n.block_number().unwrap() >= height)
        })
        .unwrap();
    assert!(reached, "height {height} not reached");
}

/// The priority fees the blocks `from..=to` collected: every receipt's gas
/// times what it paid over its block's base fee.
fn tips_of(node: &mut Node, from: u64, to: u64) -> u128 {
    let mut total = 0u128;
    for h in from..=to {
        let header = node.block_by_number(h).unwrap().unwrap();
        assert_eq!(header.beneficiary, FEE_VAULT);
        for hash in &header.tx_hashes.0 {
            let r = node.receipt(hash).unwrap().unwrap();
            total += u128::from(r.gas_used) * (r.effective_gas_price - u128::from(header.base_fee));
        }
    }
    total
}

/// The staking address holds the stakes, bonded and unbonding, of every
/// validator and delegation, and the pool: the invariant of spec 15 §3.4.
fn assert_staking_balance(node: &mut Node, delegators: &[[u8; 20]]) {
    let s = status(node);
    let mut held = s.pool;
    for e in &s.records.0 {
        held += e.record.stake + e.record.unbonding;
    }
    for d in delegators {
        for e in delegations(node, *d) {
            held += e.delegation.stake + e.delegation.unbonding;
        }
    }
    assert_eq!(balance(node, STAKING_ADDRESS), held);
    assert_eq!(
        balance(node, FEE_VAULT),
        0,
        "the vault is swept every block"
    );
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

/// The payout of `pool` to a set of `weights` with the given total stakes
/// and delegations behind each member, as spec 15 §10.2 states it: the
/// share of each validator, the part of each delegation, the validator's
/// rest, and the carry. Plain `u128` arithmetic, which the amounts here
/// never overflow.
fn payout(
    pool: u128,
    weights: &[u64],
    totals: &[u128],
    delegated: &[Vec<u128>],
) -> (Vec<u128>, Vec<Vec<u128>>, u128) {
    let total: u128 = weights.iter().map(|w| u128::from(*w)).sum();
    let mut validators = Vec::new();
    let mut parts = Vec::new();
    let mut paid = 0u128;
    for (i, w) in weights.iter().enumerate() {
        let share = pool * u128::from(*w) / total;
        let mut rest = share;
        let mut mine = Vec::new();
        for d in &delegated[i] {
            let part = (share * d).checked_div(totals[i]).unwrap_or(0);
            rest -= part;
            mine.push(part);
        }
        validators.push(rest);
        parts.push(mine);
        paid += share;
    }
    (validators, parts, pool - paid)
}

#[test]
#[allow(clippy::too_many_lines)]
fn priority_fees_are_paid_out_with_stake_to_validators_and_delegators() {
    let keys = keys(4);
    let weights = [5_000u64, 3_000, 1_000, 1_000];
    let alice = Wallet::new(1);
    let (d1, d2) = (Wallet::new(2), Wallet::new(3));
    let validators: Vec<Wallet> = keys.iter().cloned().map(Wallet::from_key).collect();
    let mut allocations = vec![
        funded(alice.address, 1_000 * ETHER),
        funded(d1.address, 100 * ETHER),
        funded(d2.address, 100 * ETHER),
        predeploy(BURNER, BURNER_CODE.to_vec()),
    ];
    allocations.extend(validators.iter().map(|v| funded(v.address, 100 * ETHER)));
    let setup = Setup {
        allocations,
        fees: market([0; 20]),
        staking: StakingParams {
            epoch_blocks: 20,
            unbonding_epochs: 1,
            ..StakingParams::default()
        },
        governance: GovernanceParams::default(),
        key: [0; 20],
    };
    let genesis = genesis(&keys, &weights, setup);
    let mut sim = Sim::new(kernel_module(), &genesis, &keys, 0, &at(START_MS), 20).unwrap();
    let floor = u128::from(FLOOR);
    let price = 2 * floor;
    let gwei = GWEI;
    let delegators = [d1.address, d2.address];
    let stakes: Vec<u128> = weights.iter().map(|w| u128::from(*w) * gwei).collect();
    let delegate = |w: &Wallet, to: [u8; 20], value: u128| {
        w.send(
            Fee::Legacy(price),
            STAKING_ADDRESS,
            value,
            &StakingAction::Delegate { validator: to }.encode(),
            200_000,
        )
    };
    // Delegations that cannot run: behind an account that is no validator,
    // behind oneself, with no value or a value that is not whole gwei; an
    // undelegation of more than is there.
    for raw in [
        delegate(&d1, alice.address, gwei),
        delegate(&validators[0], validators[0].address, gwei),
        delegate(&d1, validators[0].address, 0),
        delegate(&d1, validators[0].address, gwei + 1),
        d1.peek(
            Fee::Legacy(price),
            STAKING_ADDRESS,
            0,
            &StakingAction::Undelegate {
                validator: validators[0].address,
                amount: gwei,
            }
            .encode(),
            200_000,
        ),
    ] {
        assert_eq!(
            sim.submit(0, &raw),
            Err(SubmitError::Rejected(reason::STAKING_ACTION)),
        );
    }
    for w in [&d1, &validators[0]] {
        w.nonce.set(0);
    }
    // D1 puts 2 000 gwei behind validator 0, D2 1 000 behind validator 1.
    let receipts = sim_include_all(
        &mut sim,
        &[
            delegate(&d1, validators[0].address, 2_000 * gwei),
            delegate(&d2, validators[1].address, 1_000 * gwei),
        ],
    );
    let r = &receipts[0];
    assert_eq!(r.status, 1);
    assert_eq!(r.logs.0.len(), 1);
    assert_eq!(
        r.logs.0[0].topics.0,
        vec![
            event::DELEGATED,
            address_word(&d1.address),
            address_word(&validators[0].address)
        ]
    );
    assert_eq!(r.logs.0[0].data, word(2_000 * gwei));
    let d1_fees = u128::from(r.gas_used) * price;
    assert_eq!(receipts[1].status, 1);
    let mut d2_fees = u128::from(receipts[1].gas_used) * price;
    assert_eq!(
        delegations(&mut sim.nodes[1], d1.address),
        vec![DelegationEntry {
            validator: validator_id(&keys[0]),
            delegation: Delegation {
                stake: 2_000 * gwei,
                unbonding: 0,
                release_epoch: 0,
            },
        }]
    );
    let s = status(&mut sim.nodes[0]);
    assert_eq!(s.records.0[0].record.delegated, 2_000 * gwei);
    assert_eq!(s.records.0[1].record.delegated, 1_000 * gwei);
    assert_staking_balance(&mut sim.nodes[0], &delegators);
    // Priced transactions during epoch 0 fill the pool: every tip of every
    // block, and nothing else, is in it.
    sim_include_all(
        &mut sim,
        &[alice.burn(price, 4_000_000), alice.burn(price, 3_000_000)],
    );
    let head = sim.nodes[0].block_number().unwrap();
    assert!(head < 20, "still in epoch 0 at block {head}");
    let collected = tips_of(&mut sim.nodes[0], 1, head);
    assert!(collected > 0);
    assert_eq!(fee_status(&mut sim.nodes[0]).pool, collected);
    assert_eq!(status(&mut sim.nodes[0]).pool, collected);
    assert_staking_balance(&mut sim.nodes[0], &delegators);
    // At the end of epoch 0 the pool is paid to the genesis set by its
    // weights; within each validator's share the delegators take their
    // part of the total stake, the validator the rest, and the rounding
    // stays in the pool.
    let before: Vec<u128> = validators
        .iter()
        .map(|v| balance(&mut sim.nodes[0], v.address))
        .collect();
    sim_reach(&mut sim, 20);
    let pool = tips_of(&mut sim.nodes[0], 1, 20);
    let (paid, parts, carry) = payout(
        pool,
        &weights,
        &[
            stakes[0] + 2_000 * gwei,
            stakes[1] + 1_000 * gwei,
            stakes[2],
            stakes[3],
        ],
        &[vec![2_000 * gwei], vec![1_000 * gwei], vec![], vec![]],
    );
    assert!(paid.iter().all(|p| *p > 0));
    assert!(parts[0][0] > 0 && parts[1][0] > 0);
    for (i, v) in validators.iter().enumerate() {
        assert_eq!(
            balance(&mut sim.nodes[0], v.address),
            before[i] + paid[i],
            "validator {i}"
        );
    }
    assert_eq!(
        balance(&mut sim.nodes[0], d1.address),
        100 * ETHER - 2_000 * gwei - d1_fees + parts[0][0]
    );
    assert_eq!(
        balance(&mut sim.nodes[0], d2.address),
        100 * ETHER - 1_000 * gwei - d2_fees + parts[1][0]
    );
    assert_eq!(fee_status(&mut sim.nodes[1]).pool, carry);
    assert!(carry < 4);
    assert_eq!(
        paid.iter().sum::<u128>() + parts[0][0] + parts[1][0] + carry,
        pool
    );
    assert_staking_balance(&mut sim.nodes[0], &delegators);
    let parts_first = parts;
    // Epoch 1's set weighs the delegations: validator 0 at 7 000, 1 at 4 000.
    let set = status(&mut sim.nodes[0]).validators;
    let set_weights: Vec<u64> = set.validators.0.iter().map(|v| v.weight).collect();
    assert_eq!(set_weights, [7_000, 4_000, 1_000, 1_000]);
    // D2 undelegates everything in epoch 1: its stake earns nothing more,
    // the release comes two epochs later, and withdrawing early cannot run.
    let undelegate = StakingAction::Undelegate {
        validator: validators[1].address,
        amount: 1_000 * gwei,
    };
    let r = sim_include(
        &mut sim,
        &d2.send(
            Fee::Legacy(price),
            STAKING_ADDRESS,
            0,
            &undelegate.encode(),
            200_000,
        ),
    );
    d2_fees += u128::from(r.gas_used) * price;
    assert_eq!(r.status, 1);
    assert_eq!(
        r.logs.0[0].topics.0,
        vec![
            event::UNDELEGATED,
            address_word(&d2.address),
            address_word(&validators[1].address)
        ]
    );
    assert_eq!(r.logs.0[0].data, [word(1_000 * gwei), word(3)].concat());
    assert_eq!(status(&mut sim.nodes[0]).records.0[1].record.delegated, 0);
    let withdraw = d2.peek(
        Fee::Legacy(price),
        STAKING_ADDRESS,
        0,
        &StakingAction::Withdraw.encode(),
        200_000,
    );
    assert_eq!(
        sim.submit(0, &withdraw),
        Err(SubmitError::Rejected(reason::STAKING_ACTION))
    );
    sim_include_all(
        &mut sim,
        &[alice.burn(price, 6_000_000), alice.burn(price, 5_000_000)],
    );
    assert!(sim.nodes[0].block_number().unwrap() < 40);
    let before: Vec<u128> = validators
        .iter()
        .map(|v| balance(&mut sim.nodes[0], v.address))
        .collect();
    let (d1_before, d2_before) = (
        balance(&mut sim.nodes[0], d1.address),
        balance(&mut sim.nodes[0], d2.address),
    );
    sim_reach(&mut sim, 40);
    let pool = carry + tips_of(&mut sim.nodes[0], 21, 40);
    let (paid, parts, carry) = payout(
        pool,
        &set_weights,
        &[stakes[0] + 2_000 * gwei, stakes[1], stakes[2], stakes[3]],
        &[vec![2_000 * gwei], vec![0], vec![], vec![]],
    );
    for (i, v) in validators.iter().enumerate() {
        assert_eq!(
            balance(&mut sim.nodes[0], v.address),
            before[i] + paid[i],
            "validator {i}"
        );
    }
    assert_eq!(
        balance(&mut sim.nodes[0], d1.address),
        d1_before + parts[0][0]
    );
    assert_eq!(
        balance(&mut sim.nodes[0], d2.address),
        d2_before,
        "an undelegated stake earns nothing"
    );
    assert_eq!(parts[1][0], 0);
    assert_eq!(fee_status(&mut sim.nodes[2]).pool, carry);
    assert_staking_balance(&mut sim.nodes[0], &delegators);
    // Once released, in epoch 3, D2 withdraws: its stake comes back less
    // the fees it paid, and its delegation is gone with its places in the
    // lists; D1 may still add to its delegation.
    sim_reach(&mut sim, 61);
    let r = sim_include(&mut sim, &withdraw);
    d2.nonce.set(d2.nonce.get() + 1);
    d2_fees += u128::from(r.gas_used) * price;
    assert_eq!(r.status, 1);
    assert_eq!(
        r.logs.0[0].topics.0,
        vec![event::WITHDRAWN, address_word(&d2.address)]
    );
    assert_eq!(r.logs.0[0].data, word(1_000 * gwei));
    assert!(delegations(&mut sim.nodes[0], d2.address).is_empty());
    assert_eq!(
        balance(&mut sim.nodes[0], d2.address),
        100 * ETHER - d2_fees + parts_first[1][0],
        "D2 earned in epoch 0 alone"
    );
    let r = sim_include(&mut sim, &delegate(&d1, validators[0].address, gwei));
    assert_eq!(r.status, 1);
    assert_eq!(
        delegations(&mut sim.nodes[0], d1.address)[0]
            .delegation
            .stake,
        2_001 * gwei
    );
    assert_staking_balance(&mut sim.nodes[0], &delegators);
    assert_agreement(&mut sim);
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_stake_track_proposal_turns_the_market_on() {
    let keys = keys(4);
    let weights = [5u64, 3, 1, 1];
    let alice = Wallet::new(1);
    let guardian = Wallet::new(0x60);
    let validators: Vec<Wallet> = keys.iter().cloned().map(Wallet::from_key).collect();
    let mut allocations = vec![
        funded(alice.address, 1_000 * ETHER),
        predeploy(BURNER, BURNER_CODE.to_vec()),
    ];
    allocations.extend(validators.iter().map(|v| funded(v.address, 100 * ETHER)));
    let rules = GovernanceParams {
        mode: mode::STAKE,
        voting_blocks: 6,
        timelock_blocks: 1,
        quorum_bps: 5_000,
        deposit: ETHER,
    };
    let setup = Setup {
        allocations,
        fees: FeeParams::default(),
        staking: StakingParams::default(),
        governance: rules,
        key: guardian.address,
    };
    let genesis = genesis(&keys, &weights, setup);
    let mut sim = Sim::new(kernel_module(), &genesis, &keys, 0, &at(START_MS), 20).unwrap();
    // The market is off: a zero base fee, free transactions.
    assert_eq!(fee_status(&mut sim.nodes[0]).base_fee, 0);
    let r = sim_include(&mut sim, &alice.burn(0, 1_000_000));
    assert_eq!((r.status, r.effective_gas_price), (0, 0));
    // Validator 0 proposes the production defaults with Alice as treasury;
    // validators 0 and 1, 80% of the stake, vote yes.
    let params = FeeParams {
        treasury: alice.address,
        ..FeeParams::production()
    };
    let call = |c: &Call| c.encode();
    let submit = Call::Submit {
        target: GOVERNANCE_ADDRESS,
        data: call(&Call::SetFeeParams {
            params: params.clone(),
        }),
    };
    let r = sim_include(
        &mut sim,
        &validators[0].send(
            Fee::Legacy(0),
            GOVERNANCE_ADDRESS,
            0,
            &call(&submit),
            300_000,
        ),
    );
    assert_eq!(r.status, 1);
    let submitted = r.height;
    let vote = Call::Vote {
        id: 1,
        support: true,
    };
    let votes: Vec<Vec<u8>> = validators[..2]
        .iter()
        .map(|v| v.send(Fee::Legacy(0), GOVERNANCE_ADDRESS, 0, &call(&vote), 200_000))
        .collect();
    let receipts = sim_include_all(&mut sim, &votes);
    assert!(
        receipts
            .iter()
            .all(|r| r.status == 1 && r.height <= submitted + 6)
    );
    // Passed at the end of voting, executable after the timelock: anyone
    // executes it, and the parameters apply from the next block.
    sim_reach(&mut sim, submitted + 6 + 1 + 1);
    let execute = Call::Execute { id: 1 };
    let r = sim_include(
        &mut sim,
        &alice.send(
            Fee::Legacy(0),
            GOVERNANCE_ADDRESS,
            0,
            &call(&execute),
            200_000,
        ),
    );
    assert_eq!(r.status, 1);
    assert_eq!(
        r.logs.0,
        vec![gov::executed_log(1), gov::fee_params_log(&params)]
    );
    let status = fee_status(&mut sim.nodes[3]);
    assert_eq!(status.params, params);
    assert_eq!(status.base_fee, FLOOR);
    // From then on a free transaction is refused and a priced one pays the
    // treasury its base fee.
    assert_eq!(
        sim.submit(0, &alice.peek(Fee::Legacy(0), BURNER, 0, &[], 100_000)),
        Err(SubmitError::Rejected(reason::FEE_TOO_LOW))
    );
    let before = balance(&mut sim.nodes[0], alice.address);
    let r = sim_include(&mut sim, &alice.burn(2 * u128::from(FLOOR), 1_000_000));
    assert_eq!(
        (r.status, r.effective_gas_price),
        (0, 2 * u128::from(FLOOR))
    );
    // Alice is both the payer and the treasury: she is out the tip alone.
    assert_eq!(
        balance(&mut sim.nodes[0], alice.address),
        before - u128::from(r.gas_used) * u128::from(FLOOR)
    );
    let header = sim.nodes[0].block_by_number(r.height).unwrap().unwrap();
    assert_eq!(header.base_fee, FLOOR);
    assert_eq!(header.beneficiary, [0; 20], "no staking, no vault");
    assert_agreement(&mut sim);
}
