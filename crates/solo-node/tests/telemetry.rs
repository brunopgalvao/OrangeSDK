//! What a node records about itself (spec 11): chain progress and kernel
//! calls from the driver loop, faults, the scrape-time views behind
//! `/metrics` and `/status`, and the TCP transport's peers and traffic.

// Every value compared here is a small count or height, exact in an f64.
#![allow(clippy::float_cmp)]

use std::time::{Duration, Instant};

use k256::ecdsa::SigningKey;
use solo_abi::Encode;
use solo_abi::chain::GenesisParams;
use solo_abi::codec::Seq;
use solo_abi::types::{Effect, Genesis, exports};
use solo_metrics::node::{
    BLOCK_GAS, BLOCK_TRANSACTIONS, BLOCKS_EXECUTED, BLOCKS_FINALIZED, EMITTED_COUNTER, ENTRYPOINTS,
    FAULT_STATUSES, FINALIZED, HEAD, KERNEL_CALL_SECONDS, KERNEL_FAULTS, KERNEL_GAS, P2P_BYTES,
    P2P_FRAMES,
};
use solo_metrics::{Desc, VERSION, parse};
use solo_node::{Node, NodeConfig, Sim, Transport};

const KERNEL: &[u8] = include_bytes!("fixtures/kernel.elf");
const CHAIN_ID: u64 = 1337;
const SLOT_MS: u64 = 100;

fn kernel_module() -> Vec<u8> {
    solo_recompile::recompile(
        &solo_recompile::Input::load(KERNEL).unwrap(),
        &solo_recompile::Options::default(),
    )
    .unwrap()
}

fn key() -> SigningKey {
    SigningKey::from_slice(&[0x42; 32]).unwrap()
}

/// A chain with one validator, [`key`], and no accounts.
fn genesis() -> Genesis {
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: GenesisParams {
            slot_ms: SLOT_MS,
            max_txs: 8,
            allocations: Seq(vec![]),
            ..GenesisParams::default()
        }
        .to_bytes(),
        validators: Sim::validator_set(&[key()]).to_bytes(),
    }
}

fn open(key: Option<SigningKey>, now_ms: u64) -> Node {
    let config = NodeConfig {
        now_ms,
        key,
        ..NodeConfig::default()
    };
    let mut node = Node::open(&kernel_module(), &genesis(), config).unwrap();
    node.start(None).unwrap();
    node
}

fn value(node: &Node, desc: &Desc, labels: &[&str]) -> f64 {
    node.telemetry()
        .registry()
        .value(desc, labels)
        .unwrap_or_else(|| panic!("{} {labels:?} not recorded", desc.name))
}

#[test]
fn the_driver_loop_records_progress_and_kernel_calls() {
    let mut node = open(Some(key()), 1_000);
    assert_eq!(value(&node, &HEAD, &[]), 0.0);
    let calls = |node: &Node, entrypoint: &str| {
        node.telemetry()
            .registry()
            .histogram(&KERNEL_CALL_SECONDS, &[entrypoint])
            .map_or(0, |(count, _)| count)
    };
    assert_eq!(calls(&node, exports::INIT), 1);
    assert_eq!(calls(&node, exports::DRIVER_STEP), 1);
    // Two slots: two blocks executed and finalized, each emitting the driver's `blocks` metric.
    node.tick(1_000 + SLOT_MS).unwrap();
    node.tick(1_000 + 2 * SLOT_MS).unwrap();
    assert_eq!(node.executed.len(), 2);
    assert_eq!(value(&node, &HEAD, &[]), 2.0);
    assert_eq!(value(&node, &FINALIZED, &[]), 2.0);
    assert_eq!(value(&node, &BLOCKS_EXECUTED, &[]), 2.0);
    assert_eq!(value(&node, &BLOCKS_FINALIZED, &[]), 2.0);
    assert_eq!(value(&node, &BLOCK_TRANSACTIONS, &[]), 0.0);
    assert_eq!(value(&node, &BLOCK_GAS, &[]), 0.0);
    assert_eq!(value(&node, &EMITTED_COUNTER, &["driver", "blocks"]), 2.0);
    assert_eq!(calls(&node, exports::EXECUTE_BLOCK), 2);
    assert_eq!(calls(&node, exports::FINALIZE_BLOCK), 2);
    assert!(value(&node, &KERNEL_GAS, &[exports::DRIVER_STEP]) > 0.0);
    // Every fault series exists from the start, at zero (spec 11 section 3).
    for entrypoint in ENTRYPOINTS {
        for status in FAULT_STATUSES {
            assert_eq!(value(&node, &KERNEL_FAULTS, &[entrypoint, status]), 0.0);
        }
    }
    // An injected metric is recorded like an emitted one.
    node.apply_effect(Effect::Metric {
        name: b"injected".to_vec(),
        value: 4,
    })
    .unwrap();
    assert_eq!(value(&node, &EMITTED_COUNTER, &["driver", "injected"]), 4.0);
    let text = node.metrics_text();
    let samples = parse(&text).unwrap();
    let sample = |name: &str| {
        samples
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("{name} missing from\n{text}"))
            .value
    };
    assert_eq!(sample("ethereum_blockchain_height"), 2.0);
    assert_eq!(sample("ethereum_best_known_block_number"), 2.0);
    assert_eq!(sample("solo_chain_id"), 1337.0);
    assert_eq!(sample("solo_mempool_transactions"), 0.0);
    assert_eq!(sample("solo_driver_timers"), 2.0);
    assert!(sample("solo_chain_head_age_seconds") >= 0.0);
    assert!(text.contains(&format!("solo_build_info{{version=\"{VERSION}\"}} 1\n")));
    assert!(text.contains("# TYPE ethereum_peer_count gauge\n"));
    assert!(!samples.iter().any(|s| s.name == "ethereum_peer_count"));
    // The chain id is asked of the kernel once; later scrapes reuse it.
    let queries = calls(&node, exports::QUERY);
    assert!(queries >= 1);
    let status = node.status().unwrap();
    node.metrics_text();
    assert_eq!(calls(&node, exports::QUERY), queries);
    assert_eq!(status.chain_id, CHAIN_ID);
    assert_eq!((status.head, status.finalized), (2, 2));
    assert_eq!((status.p2p, status.peers, status.mempool), (false, 0, 0));
    assert_eq!(status.validator, Some(solo_node::validator_id(&key())));
    assert_eq!(status.version, VERSION);
    assert!(status.uptime_seconds >= status.head_age_seconds);
    node.telemetry_mut().block_finalized(9);
    assert_eq!(node.telemetry().finalized(), 9);
}

#[test]
fn fault_series_cover_every_entrypoint_of_spec_06() {
    let mut names = vec![
        exports::INIT,
        exports::DRIVER_STEP,
        exports::DRIVER_STATE,
        exports::MIGRATE,
        exports::VALIDATE_TX,
        exports::BUILD_BLOCK,
        exports::EXECUTE_BLOCK,
        exports::FINALIZE_BLOCK,
        exports::QUERY,
    ];
    assert_eq!(names, ENTRYPOINTS);
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), ENTRYPOINTS.len());
}

#[test]
fn kernel_faults_are_counted_and_status_fails_loudly() {
    let mut node = open(None, 1_000);
    node.kernel_gas = 1;
    assert!(node.tick(1_000 + 10 * SLOT_MS).is_err());
    assert_eq!(
        value(&node, &KERNEL_FAULTS, &[exports::DRIVER_STEP, "out_of_gas"]),
        1.0
    );
    assert!(node.status().is_err());
    // Metrics still render, without a chain id the kernel could not give.
    // Until the kernel answers, each request asks it again, and each of
    // those calls is counted: here the status and the metrics request.
    let text = node.metrics_text();
    assert!(
        text.contains(
            "solo_kernel_faults_total{entrypoint=\"kernel_query\",status=\"out_of_gas\"} 2\n"
        ),
        "{text}"
    );
    assert!(!text.contains("\nsolo_chain_id "), "{text}");
}

#[test]
fn the_transport_records_peers_and_traffic() {
    let start = Instant::now();
    let epoch = 1_000_000;
    let mut nodes = [open(Some(key()), epoch), open(None, epoch)];
    let validator = Transport::bind(
        "127.0.0.1:0",
        solo_node::validator_id(&key()),
        CHAIN_ID,
        vec![],
    )
    .unwrap();
    let dial = vec![validator.local_addr().unwrap()];
    let observer = Transport::bind("127.0.0.1:0", [0xEE; 32], CHAIN_ID, dial).unwrap();
    let mut transports = [validator, observer];
    // Wait until the observer has followed the validator to height 3 over the wire.
    let deadline = Instant::now() + Duration::from_mins(2);
    let followed = |nodes: &[Node; 2]| nodes[1].finalized.len() >= 3;
    while !followed(&nodes) && Instant::now() < deadline {
        let now = epoch + u64::try_from(start.elapsed().as_millis()).unwrap();
        for (node, transport) in nodes.iter_mut().zip(transports.iter_mut()) {
            node.tick(now).unwrap();
            transport.poll(node, now).unwrap();
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(followed(&nodes), "observer at {:?}", nodes[1].finalized);
    for node in &mut nodes {
        let status = node.status().unwrap();
        assert_eq!((status.p2p, status.peers), (true, 1));
        assert_eq!(value(node, &P2P_FRAMES, &["in", "hello"]), 1.0);
        assert_eq!(value(node, &P2P_FRAMES, &["out", "hello"]), 1.0);
        assert!(value(node, &P2P_BYTES, &["in"]) > 0.0);
        assert!(value(node, &P2P_BYTES, &["out"]) > 0.0);
        assert!(node.metrics_text().contains("\nethereum_peer_count 1\n"));
    }
    // The validator broadcasts consensus messages; the observer only listens.
    assert!(value(&nodes[0], &P2P_FRAMES, &["out", "message"]) > 0.0);
    assert!(value(&nodes[1], &P2P_FRAMES, &["in", "message"]) > 0.0);
}
