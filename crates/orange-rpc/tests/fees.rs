//! The fee methods under a running market (spec 23 §7): `eth_gasPrice` and
//! `eth_maxPriorityFeePerGas` against geth's oracle written out here over
//! the same receipts, `eth_feeHistory`'s base fees against alloy's EIP-1559
//! computation and its rewards against a percentile walk of the same
//! receipts, the refusals of underpriced transactions in geth's words, and
//! the block views.

mod common;

use alloy_eips::eip1559::{BaseFeeParams, calc_next_block_base_fee};
use common::{CHAIN_ID, ETHER, Fields, SLOT_MS, Wallet, err, kernel_module, node_key, ok};
use orange_abi::Encode;
use orange_abi::chain::{Allocation, BLOCK_GAS_LIMIT, GenesisParams, Receipt};
use orange_abi::codec::Seq;
use orange_abi::fees::FeeParams;
use orange_abi::types::Genesis;
use orange_rpc::Rpc;
use orange_rpc::fees::{
    ORACLE_BLOCKS, ORACLE_IGNORE_TIP, ORACLE_MAX_TIP, ORACLE_PERCENTILE, ORACLE_SAMPLE,
};
use orange_rpc::methods::{data, parse_quantity, quantity};
use serde_json::{Value, json};

const GWEI: u128 = 1_000_000_000;
const FLOOR: u64 = 1_000_000_000;
/// A contract that loops until out of gas, so a transaction to it uses
/// exactly its gas limit.
const BURNER: [u8; 20] = [0x66; 20];

fn params() -> FeeParams {
    FeeParams {
        denominator: 100,
        elasticity: 2,
        min_base_fee: FLOOR,
        treasury: [0; 20],
    }
}

/// A single-validator chain with the market on, every wallet funded and the
/// burner deployed.
fn rpc(wallets: &[&Wallet]) -> Rpc {
    let mut allocations: Vec<Allocation> = wallets
        .iter()
        .map(|w| Allocation {
            address: w.address,
            balance: 1_000 * ETHER,
            ..Allocation::default()
        })
        .collect();
    allocations.push(Allocation {
        address: BURNER,
        nonce: 1,
        code: vec![0x5b, 0x5f, 0x56],
        ..Allocation::default()
    });
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs: 16,
        allocations: Seq(allocations),
        fees: params(),
        ..GenesisParams::default()
    };
    let genesis = Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: orange_node::Sim::validator_set(&[node_key()]).to_bytes(),
    };
    let config = orange_node::NodeConfig {
        now_ms: 1_000,
        key: Some(node_key()),
        ..orange_node::NodeConfig::default()
    };
    let mut node = orange_node::Node::open(&kernel_module(), &genesis, config).unwrap();
    node.start(None).unwrap();
    Rpc::new(node)
}

/// Produces the next block.
fn mine(rpc: &mut Rpc) {
    let height = rpc.node_mut().block_number().unwrap();
    rpc.node_mut().tick(1_000 + (height + 1) * SLOT_MS).unwrap();
}

fn number(v: &Value) -> u128 {
    u128::from(parse_quantity(v.as_str().unwrap()).unwrap())
}

/// A burn of `gas` from `wallet` at legacy `price`, or with a dynamic fee.
fn burn(wallet: &Wallet, nonce: u64, gas: u64, fee: (u128, Option<u128>)) -> Vec<u8> {
    let fields = Fields {
        nonce,
        to: Some(BURNER),
        value: 0,
        gas_limit: gas,
        data: &[],
    };
    match fee {
        (price, None) => wallet.legacy_on(&fields, price, CHAIN_ID),
        (max_fee, Some(tip)) => wallet.dynamic(&fields, max_fee, tip, &[]),
    }
}

/// The headers and receipts of blocks 1 to the head, read through the node.
fn blocks(rpc: &mut Rpc) -> Vec<(orange_abi::chain::BlockHeader, Vec<Receipt>)> {
    let head = rpc.node_mut().block_number().unwrap();
    (1..=head)
        .map(|h| {
            let header = rpc.node_mut().block_by_number(h).unwrap().unwrap();
            let receipts = header
                .tx_hashes
                .0
                .iter()
                .map(|hash| rpc.node_mut().receipt(hash).unwrap().unwrap())
                .collect();
            (header, receipts)
        })
        .collect()
}

/// geth's `SuggestTipCap`, written from its description: the cheapest
/// `ORACLE_SAMPLE` tips of each of the last `ORACLE_BLOCKS` blocks (more
/// while blocks are empty, up to twice as many), the last price for an empty
/// block, the `ORACLE_PERCENTILE`th percentile, capped.
fn reference_tip(blocks: &[(orange_abi::chain::BlockHeader, Vec<Receipt>)], default: u128) -> u128 {
    let mut results = Vec::new();
    let mut looked = 0u64;
    let mut want = ORACLE_BLOCKS.min(blocks.len() as u64);
    let mut height = blocks.len() as u64;
    while looked < want && height > 0 {
        let (header, receipts) = &blocks[usize::try_from(height).unwrap() - 1];
        let mut tips: Vec<u128> = receipts
            .iter()
            .filter(|r| r.from != header.beneficiary)
            .map(|r| r.effective_gas_price - u128::from(header.base_fee))
            .filter(|t| *t >= ORACLE_IGNORE_TIP)
            .collect();
        tips.sort_unstable();
        tips.truncate(ORACLE_SAMPLE);
        if tips.is_empty() {
            tips.push(default);
        }
        if tips.len() == 1 && want < 2 * ORACLE_BLOCKS && height > 1 {
            want += 1;
        }
        results.extend(tips);
        looked += 1;
        height -= 1;
    }
    results.sort_unstable();
    let price = results
        .get((results.len().saturating_sub(1)) * ORACLE_PERCENTILE / 100)
        .copied()
        .unwrap_or(default);
    price.min(ORACLE_MAX_TIP)
}

/// geth's reward percentiles: the tip paid by the transaction at each
/// share of the block's gas, the receipts sorted by tip.
fn reference_rewards(
    header: &orange_abi::chain::BlockHeader,
    receipts: &[Receipt],
    percentiles: &[u64],
) -> Vec<u128> {
    let mut sorted: Vec<(u128, u64)> = receipts
        .iter()
        .map(|r| {
            (
                r.effective_gas_price - u128::from(header.base_fee),
                r.gas_used,
            )
        })
        .collect();
    sorted.sort_by_key(|(tip, _)| *tip);
    percentiles
        .iter()
        .map(|p| {
            let threshold = header.gas_used * p / 100;
            let mut sum = 0;
            for (tip, gas) in &sorted {
                sum += gas;
                if sum >= threshold {
                    return *tip;
                }
            }
            sorted.last().map_or(0, |(tip, _)| *tip)
        })
        .collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn gas_price_and_fee_history_follow_geth() {
    let alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut rpc = rpc(&[&alice, &bob]);
    let floor = u128::from(FLOOR);
    // Before any block: the floor plus the default tip, and the genesis block
    // reports the floor.
    assert_eq!(
        ok(&mut rpc, "eth_maxPriorityFeePerGas", json!([])),
        quantity(GWEI)
    );
    assert_eq!(
        ok(&mut rpc, "eth_gasPrice", json!([])),
        quantity(floor + GWEI)
    );
    let genesis = ok(&mut rpc, "eth_getBlockByNumber", json!(["0x0", false]));
    assert_eq!(genesis["baseFeePerGas"], quantity(floor));
    assert_eq!(genesis["miner"], data(&[0; 20]));
    // Blocks with tips of 2, 3 and 5 gwei at several sizes, a full one among
    // them, then empty ones.
    let mut nonce = 0;
    let send = |rpc: &mut Rpc, raws: Vec<Vec<u8>>| {
        for raw in &raws {
            ok(rpc, "eth_sendRawTransaction", json!([data(raw)]));
        }
        mine(rpc);
    };
    let legacy = |n: u64, gas: u64, price: u128| burn(&alice, n, gas, (price, None));
    let dynamic = |n: u64, gas: u64, cap: u128, tip: u128| burn(&bob, n, gas, (cap, Some(tip)));
    send(
        &mut rpc,
        vec![
            legacy(nonce, 15_000_000, floor + 2 * GWEI),
            dynamic(0, 15_000_000, 10 * GWEI, 3 * GWEI),
        ],
    );
    nonce += 1;
    send(
        &mut rpc,
        vec![
            legacy(nonce, 4_000_000, floor + 5 * GWEI),
            dynamic(1, 2_000_000, 2 * GWEI + floor, 2 * GWEI),
        ],
    );
    nonce += 1;
    send(&mut rpc, vec![dynamic(2, 1_000_000, 10 * GWEI, 1)]);
    for _ in 0..3 {
        mine(&mut rpc);
    }
    send(&mut rpc, vec![legacy(nonce, 100_000, floor + 7 * GWEI)]);
    let all = blocks(&mut rpc);
    assert_eq!(all.len(), 7);
    assert_eq!(all[0].0.gas_used, BLOCK_GAS_LIMIT);
    // Every header's base fee is alloy's EIP-1559 computation from its
    // parent, floored; the genesis parent is at the floor and empty.
    let alloy = BaseFeeParams::new(100, 2);
    let mut parent = (FLOOR, 0u64);
    for (header, _) in &all {
        let expected =
            calc_next_block_base_fee(parent.1, BLOCK_GAS_LIMIT, parent.0, alloy).max(FLOOR);
        assert_eq!(header.base_fee, expected, "block {}", header.height);
        parent = (header.base_fee, header.gas_used);
    }
    assert!(all[1].0.base_fee > FLOOR && all[6].0.base_fee == FLOOR);
    // The suggested tip is the oracle's, the gas price the head's base fee
    // plus it.
    let tip = number(&ok(&mut rpc, "eth_maxPriorityFeePerGas", json!([])));
    assert_eq!(tip, reference_tip(&all, GWEI));
    assert!(
        tip > GWEI && tip < 3 * GWEI,
        "{tip}: the 60th percentile of the tips paid"
    );
    let head_base = u128::from(all[6].0.base_fee);
    assert_eq!(
        number(&ok(&mut rpc, "eth_gasPrice", json!([]))),
        head_base + tip
    );
    // Asked again at the same head, the oracle answers from memory; a new
    // default starts it over, and at a new head it looks again.
    assert_eq!(
        number(&ok(&mut rpc, "eth_maxPriorityFeePerGas", json!([]))),
        tip
    );
    rpc.gas_price = 5;
    assert_eq!(
        number(&ok(&mut rpc, "eth_maxPriorityFeePerGas", json!([]))),
        reference_tip(&all, 5)
    );
    rpc.gas_price = GWEI;
    mine(&mut rpc);
    let all = blocks(&mut rpc);
    assert_eq!(
        number(&ok(&mut rpc, "eth_maxPriorityFeePerGas", json!([]))),
        reference_tip(&all, GWEI)
    );
    // Fee history: the base fee of every block and of the next, the gas
    // ratios, and the rewards at the percentiles of each block's gas.
    let percentiles = [0u64, 25, 50, 75, 100];
    let history = ok(
        &mut rpc,
        "eth_feeHistory",
        json!(["0x8", "latest", percentiles]),
    );
    assert_eq!(history["oldestBlock"], quantity(1));
    let base_fees: Vec<u128> = history["baseFeePerGas"]
        .as_array()
        .unwrap()
        .iter()
        .map(number)
        .collect();
    let mut expected: Vec<u128> = all.iter().map(|(h, _)| u128::from(h.base_fee)).collect();
    expected.push(u128::from(rpc.node().fee_status().base_fee));
    assert_eq!(base_fees, expected);
    let (last, _) = all.last().unwrap();
    assert_eq!(
        *expected.last().unwrap(),
        u128::from(
            calc_next_block_base_fee(last.gas_used, BLOCK_GAS_LIMIT, last.base_fee, alloy)
                .max(FLOOR)
        )
    );
    let rewards = history["reward"].as_array().unwrap();
    assert_eq!(rewards.len(), all.len());
    for (i, (header, receipts)) in all.iter().enumerate() {
        let got: Vec<u128> = rewards[i].as_array().unwrap().iter().map(number).collect();
        assert_eq!(
            got,
            reference_rewards(header, receipts, &percentiles),
            "block {}",
            header.height
        );
    }
    // The full first block: two transactions of half the gas each, tipping
    // 2 and 3 gwei, so the lower tip covers the percentiles up to 50.
    assert_eq!(
        rewards[0]
            .as_array()
            .unwrap()
            .iter()
            .map(number)
            .collect::<Vec<_>>(),
        vec![2 * GWEI, 2 * GWEI, 2 * GWEI, 3 * GWEI, 3 * GWEI]
    );
    // A window that ends below the head takes the next block's base fee from
    // its header.
    let older = ok(&mut rpc, "eth_feeHistory", json!(["0x2", "0x3", []]));
    assert_eq!(
        older["baseFeePerGas"],
        json!([
            quantity(expected[1]),
            quantity(expected[2]),
            quantity(expected[3])
        ])
    );
    // Block views carry each header's base fee and beneficiary.
    let block = ok(&mut rpc, "eth_getBlockByNumber", json!(["0x2", false]));
    assert_eq!(block["baseFeePerGas"], quantity(expected[1]));
    assert_eq!(block["miner"], data(&[0; 20]));
}

#[test]
fn underpriced_transactions_are_refused_in_geths_words() {
    let alice = Wallet::new(1);
    let mut rpc = rpc(&[&alice]);
    let floor = u128::from(FLOOR);
    let a = data(&alice.address);
    let cases = [
        (
            burn(&alice, 0, 100_000, (floor - 1, None)),
            format!(
                "max fee per gas less than block base fee: address {a}, maxFeePerGas: {}, baseFee: {floor}",
                floor - 1
            ),
        ),
        (
            burn(&alice, 0, 100_000, (0, Some(0))),
            format!(
                "max fee per gas less than block base fee: address {a}, maxFeePerGas: 0, baseFee: {floor}"
            ),
        ),
        (
            burn(&alice, 0, 100_000, (floor, Some(floor + 1))),
            format!(
                "max priority fee per gas higher than max fee per gas: address {a}, maxPriorityFeePerGas: {}, maxFeePerGas: {floor}",
                floor + 1
            ),
        ),
    ];
    for (raw, text) in cases {
        assert_eq!(
            err(&mut rpc, "eth_sendRawTransaction", json!([data(&raw)])),
            (-32000, text)
        );
    }
    // At the base fee it goes through, and the receipt says what it paid.
    let hash = ok(
        &mut rpc,
        "eth_sendRawTransaction",
        json!([data(&burn(&alice, 0, 100_000, (floor, Some(floor))))]),
    );
    mine(&mut rpc);
    let receipt = ok(&mut rpc, "eth_getTransactionReceipt", json!([hash]));
    assert_eq!(receipt["effectiveGasPrice"], quantity(floor));
    assert_eq!(receipt["status"], "0x0", "the burner runs out of gas");
}

#[test]
fn the_oracle_caps_its_suggestion_and_how_far_it_looks() {
    let alice = Wallet::new(1);
    let mut rpc = rpc(&[&alice]);
    let floor = u128::from(FLOOR);
    // One block of tips far above the cap: the suggestion is the cap.
    for nonce in 0..3 {
        let raw = burn(&alice, nonce, 100_000, (floor + 600 * GWEI, None));
        ok(&mut rpc, "eth_sendRawTransaction", json!([data(&raw)]));
    }
    mine(&mut rpc);
    assert_eq!(
        number(&ok(&mut rpc, "eth_maxPriorityFeePerGas", json!([]))),
        ORACLE_MAX_TIP
    );
    // Twice the oracle's blocks of empty ones after it: it looks that far
    // and no further, so the priced block drops out of its sample and the
    // suggestion is the last one it made.
    for _ in 0..2 * ORACLE_BLOCKS {
        mine(&mut rpc);
    }
    let all = blocks(&mut rpc);
    assert_eq!(all.len() as u64, 2 * ORACLE_BLOCKS + 1);
    let tip = number(&ok(&mut rpc, "eth_maxPriorityFeePerGas", json!([])));
    assert_eq!(tip, ORACLE_MAX_TIP);
    assert_eq!(tip, reference_tip(&all, ORACLE_MAX_TIP));
    assert_eq!(
        ok(&mut rpc, "eth_gasPrice", json!([])),
        quantity(floor + ORACLE_MAX_TIP)
    );
}
