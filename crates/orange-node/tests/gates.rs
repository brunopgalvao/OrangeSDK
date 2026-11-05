//! Host feature gates (spec 13 §7–§8): the gated host function resolves only
//! while its gate is active and verifies signatures as specified; a
//! validator's host signals its gates every epoch, the chain locks a gate in
//! after two qualifying epochs and activates it one epoch later; an upgrade
//! that needs the gate becomes loadable; a host without the feature is told.

mod support;

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use k256::ecdsa::SigningKey;
use orange_abi::types::Genesis;
use orange_host::hash::keccak256;
use orange_host::{Executor, Flags, ModuleCache};
use orange_node::ChainState;
use orange_node::upgrade::{
    BLS12381_FAST_AGGREGATE_VERIFY, GATED, PRECOMPILE_HANDLE, SECP256K1_VERIFY,
    SIGNAL_FEE_HEADROOM, SUPPORTED, gated, precompile, signal_tx,
};
use orange_node::{GatedExtension, Node, NodeConfig, NodeExtension, NodeServices, validator_id};
use orange_upgrade::{Action, gate};
use orange_vm::builder::ModuleBuilder;
use orange_vm::host::Capability;
use orange_vm::isa::{Instruction, Reg, StoreWidth};
use orange_vm::status::{HostStatus, Termination};
use support::{
    genesis, governance, governed, include, keys, run_until, stage_actions, tiny_kernel, v1,
};

const BUF: i64 = 0xFFFC_0000;

fn li(rd: Reg, imm: i64) -> Instruction {
    Instruction::Li { rd, imm }
}

/// A module importing `output_write` and `name`: it calls `name` with `args`
/// in `a0`.. and outputs the `a0` it returns, 8 bytes.
fn caller(name: &str, args: &[i64], rodata: &[u8]) -> Vec<u8> {
    let mut b = ModuleBuilder::new().rodata(rodata);
    b.import("output_write");
    b.import(name);
    let regs = [Reg::A0, Reg::A1, Reg::A2];
    let mut code: Vec<Instruction> = args.iter().zip(regs).map(|(v, r)| li(r, *v)).collect();
    code.extend([
        Instruction::Ecall { import: 1 },
        li(Reg::A7, BUF),
        Instruction::Store {
            width: StoreWidth::D,
            rs1: Reg::A7,
            rs2: Reg::A0,
            off: 0,
        },
        li(Reg::A0, BUF),
        li(Reg::A1, 8),
        Instruction::Ecall { import: 0 },
        Instruction::Halt,
    ]);
    b.block(&code);
    b.export("main", 0).build()
}

fn executor(active: u64) -> (Executor<ChainState>, Rc<Cell<u64>>) {
    let services = Rc::new(RefCell::new(NodeServices {
        now_ms: 77,
        ..NodeServices::default()
    }));
    let gates = Rc::new(Cell::new(active));
    let mut exec = Executor::new(ModuleCache::default(), ChainState::default());
    exec.set_extension(Box::new(GatedExtension::new(
        NodeExtension::new(services),
        Rc::clone(&gates),
    )));
    (exec, gates)
}

fn run(
    exec: &mut Executor<ChainState>,
    module: &[u8],
    capability: Capability,
) -> (Termination, u64) {
    let hash = exec.load(module, capability).expect("imports resolve");
    let r = exec.call(&hash, [0; 32], b"", 1_000_000, capability, Flags::default());
    let a0 = r
        .output
        .get(..8)
        .map_or(u64::MAX, |b| u64::from_le_bytes(b.try_into().unwrap()));
    (r.status, a0)
}

/// `n - s` for the secp256k1 group order `n`: the high-`s` twin of a signature.
fn negate(s: &[u8]) -> Vec<u8> {
    let n: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    let mut out = vec![0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(n[i]) - i16::from(s[i]) - borrow;
        borrow = i16::from(d < 0);
        if d < 0 {
            d += 256;
        }
        out[i] = u8::try_from(d).unwrap();
    }
    out
}

#[test]
fn the_gated_function_resolves_only_while_its_gate_is_active() {
    assert_eq!(GATED.len(), 15);
    for f in GATED {
        assert_eq!(SUPPORTED >> f.gate & 1, 1, "{f:?}");
    }
    assert_eq!(SUPPORTED, 0b111);
    // Gate 2 guards the thirteen precompile functions, in their order (spec 05 §4.8).
    for (i, f) in GATED[2..].iter().enumerate() {
        let (name, _) = orange_host::precompiles::FUNCTIONS[i];
        let handle = PRECOMPILE_HANDLE + u32::try_from(i).unwrap();
        assert_eq!(
            (f.name, f.gate, f.handle, f.sandboxed),
            (name, 2, handle, true)
        );
        assert_eq!(gated(name, Capability::Sandboxed, 0b011), None);
        assert_eq!(gated(name, Capability::Sandboxed, 0b100), Some(handle));
    }
    assert_eq!(PRECOMPILE_HANDLE, 202);
    assert_eq!(precompile(12), GATED[14]);
    assert_eq!(
        (GATED[0].name, GATED[0].handle, SECP256K1_VERIFY),
        ("secp256k1_verify", 200, 200)
    );
    assert_eq!(
        (GATED[1].name, GATED[1].gate, GATED[1].handle),
        (
            "bls12381_fast_aggregate_verify",
            1,
            BLS12381_FAST_AGGREGATE_VERIFY
        )
    );
    assert_eq!(
        gated("bls12381_fast_aggregate_verify", Capability::Sandboxed, 1),
        None
    );
    assert_eq!(
        gated("bls12381_fast_aggregate_verify", Capability::Sandboxed, 2),
        Some(201)
    );
    assert_eq!(
        gated("secp256k1_verify", Capability::Sandboxed, 1),
        Some(200)
    );
    assert_eq!(gated("secp256k1_verify", Capability::Privileged, 0), None);
    assert_eq!(gated("time_now", Capability::Privileged, u64::MAX), None);
    let module = caller("secp256k1_verify", &[], &[0; 4]);
    let (mut exec, gates) = executor(0);
    assert!(exec.load(&module, Capability::Privileged).is_err());
    assert!(exec.load(&module, Capability::Sandboxed).is_err());
    gates.set(1 << gate::SECP256K1_VERIFY);
    assert!(exec.load(&module, Capability::Sandboxed).is_ok());
    // The node's own functions still resolve through the wrapper, privileged only.
    let time = caller("time_now", &[], &[0; 4]);
    assert!(exec.load(&time, Capability::Sandboxed).is_err());
    assert_eq!(
        run(&mut exec, &time, Capability::Privileged),
        (Termination::Halt, 77)
    );
}

#[test]
fn the_node_serves_bls12381_fast_aggregate_verify_behind_gate_1() {
    use orange_bls::curve::{G1Affine, G2Affine, G2Projective, Scalar};
    let secret = Scalar::from(77u64);
    let key = G1Affine::from(G1Affine::generator() * secret).to_compressed();
    let msg = [0x33u8; 32];
    let h = G2Projective::from(orange_bls::hash::to_g2(&msg, orange_bls::eth::DST));
    let sig = G2Affine::from(h * secret).to_compressed();
    let base = 0x1_0000;
    let module = |sig: &[u8]| {
        let rodata = [&key[..], &msg, sig].concat();
        let mut b = ModuleBuilder::new().rodata(&rodata);
        b.import("output_write");
        b.import("bls12381_fast_aggregate_verify");
        b.block(&[
            li(Reg::A0, base),
            li(Reg::A1, 1),
            li(Reg::A2, base + 48),
            li(Reg::A3, 32),
            li(Reg::A4, base + 80),
            Instruction::Ecall { import: 1 },
            li(Reg::A7, BUF),
            Instruction::Store {
                width: StoreWidth::D,
                rs1: Reg::A7,
                rs2: Reg::A0,
                off: 0,
            },
            li(Reg::A0, BUF),
            li(Reg::A1, 8),
            Instruction::Ecall { import: 0 },
            Instruction::Halt,
        ]);
        b.export("main", 0).build()
    };
    let (mut exec, gates) = executor(1);
    assert!(exec.load(&module(&sig), Capability::Sandboxed).is_err());
    gates.set(0b10);
    assert_eq!(
        run(&mut exec, &module(&sig), Capability::Sandboxed),
        (Termination::Halt, 0)
    );
    assert_eq!(
        run(&mut exec, &module(&[0xFF; 96]), Capability::Sandboxed),
        (Termination::Halt, 1)
    );
}

#[test]
fn the_node_serves_the_precompile_functions_behind_gate_2() {
    // bn254 G1 generator doubled, then a point off the curve.
    let mut g1 = [0u8; 64];
    g1[31] = 1;
    g1[63] = 2;
    let mut off = g1;
    off[63] = 3;
    let base = 0x1_0000;
    let module = |p: &[u8; 64]| {
        let rodata = [&g1[..], p].concat();
        let mut b = ModuleBuilder::new().rodata(&rodata);
        b.import("output_write");
        b.import("evm_bn254_add");
        b.block(&[
            li(Reg::A0, base),
            li(Reg::A1, BUF + 8),
            Instruction::Ecall { import: 1 },
            li(Reg::A7, BUF),
            Instruction::Store {
                width: StoreWidth::D,
                rs1: Reg::A7,
                rs2: Reg::A0,
                off: 0,
            },
            li(Reg::A0, BUF),
            li(Reg::A1, 8),
            Instruction::Ecall { import: 0 },
            Instruction::Halt,
        ]);
        b.export("main", 0).build()
    };
    let (mut exec, gates) = executor(2);
    assert!(exec.load(&module(&g1), Capability::Sandboxed).is_err());
    gates.set(0b100);
    assert_eq!(
        run(&mut exec, &module(&g1), Capability::Sandboxed),
        (Termination::Halt, 0)
    );
    assert_eq!(
        run(&mut exec, &module(&off), Capability::Sandboxed),
        (Termination::Halt, 1)
    );
}

#[test]
fn secp256k1_verify_checks_low_s_signatures_against_a_public_key() {
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let digest = keccak256(b"message");
    let (sig, _) = key.sign_prehash_recoverable(&digest).unwrap();
    let sig = sig.to_bytes().to_vec();
    let pubkey = key.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec();
    let (mut exec, _) = executor(1);
    let base = 0x1_0000;
    let check = |exec: &mut Executor<ChainState>, msg: &[u8], sig: &[u8], pubkey: &[u8]| {
        let rodata = [msg, sig, pubkey].concat();
        run(
            exec,
            &caller("secp256k1_verify", &[base, base + 32, base + 96], &rodata),
            Capability::Sandboxed,
        )
    };
    assert_eq!(
        check(&mut exec, &digest, &sig, &pubkey),
        (Termination::Halt, 0)
    );
    assert_eq!(
        check(&mut exec, &keccak256(b"other"), &sig, &pubkey),
        (Termination::Halt, 1)
    );
    let high = [&sig[..32], &negate(&sig[32..])].concat();
    assert_eq!(
        check(&mut exec, &digest, &high, &pubkey),
        (Termination::Halt, 1)
    );
    assert_eq!(
        check(&mut exec, &digest, &[0xFF; 64], &pubkey),
        (Termination::Halt, 1)
    );
    assert_eq!(
        check(&mut exec, &digest, &sig, &[0; 64]),
        (Termination::Halt, 1)
    );
    // A range outside the instance's memory ends it.
    let (status, _) = run(
        &mut exec,
        &caller("secp256k1_verify", &[0x50, base, base], &[0; 4]),
        Capability::Sandboxed,
    );
    assert_eq!(
        status,
        Termination::HostError(HostStatus::MemoryFault.code())
    );
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

fn signal_features(node: &mut Node) -> Option<u64> {
    node.upgrade_status().unwrap().validators.0[0]
        .signal
        .as_ref()
        .map(|s| s.features)
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_validator_signals_and_its_gate_activates_an_epoch_after_locking_in() {
    let mut node = start(&genesis(&keys(1), governed(1, 3), 8));
    assert!(!node.resolves("secp256k1_verify", Capability::Privileged));
    assert_eq!(
        (node.upgrades().features, node.upgrades().active()),
        (SUPPORTED, 0)
    );
    // The host signals after the first block; the next block carries it.
    run_until(&mut node, 10, &mut |n| signal_features(n).is_some());
    let status = node.upgrade_status().unwrap();
    let validator = &status.validators.0[0];
    assert_eq!(
        (validator.id, validator.weight),
        (orange_node::validator_id(&keys(1)[0]), 1)
    );
    assert_eq!(validator.signal.as_ref().unwrap().features, SUPPORTED);
    // Two epochs in a row with all stake behind it lock the gate in.
    run_until(&mut node, 30, &mut |n| {
        n.upgrade_status().unwrap().gates.locked_in() != 0
    });
    let locked_at = node.block_number().unwrap();
    assert_eq!(locked_at % 3, 0);
    let record = node
        .upgrade_status()
        .unwrap()
        .gates
        .record(gate::SECP256K1_VERIFY)
        .cloned()
        .unwrap();
    assert_eq!(
        (record.streak, record.activation_height),
        (2, locked_at + 3 + 1)
    );
    // A full epoch of notice, then active from the first block of the epoch after.
    assert!(!node.resolves("secp256k1_verify", Capability::Privileged));
    run_until(&mut node, 10, &mut |n| {
        n.block_number().unwrap() + 2 >= record.activation_height
    });
    assert_eq!(node.upgrades().active(), 0);
    run_until(&mut node, 10, &mut |n| {
        n.block_number().unwrap() + 1 >= record.activation_height
    });
    assert_eq!(node.upgrades().active(), SUPPORTED);
    assert!(node.resolves("secp256k1_verify", Capability::Privileged));
    assert!(node.resolves("bls12381_fast_aggregate_verify", Capability::Sandboxed));
    assert!(node.resolves("secp256k1_verify", Capability::Sandboxed));
    assert_eq!(node.upgrades().missing_gates(), 0);
    assert!(
        node.metrics_text()
            .contains("\norange_upgrade_missing_gates 0\n")
    );
    assert_eq!(node.status().unwrap().missing_gates, 0);
    // A kernel that imports the gated function can now be prepared for an upgrade.
    let tiny = tiny_kernel(&2u32.to_le_bytes(), false, Some("secp256k1_verify"));
    let code_hash = keccak256(&tiny);
    let gov = governance();
    assert_eq!(
        include(&mut node, &gov.action(0, &stage_actions(&tiny)[0])).status,
        1
    );
    let h = node.block_number().unwrap() + 20;
    let propose = Action::Propose {
        code_hash,
        activation_height: h,
        required_gates: 1,
    };
    assert_eq!(include(&mut node, &gov.action(1, &propose)).status, 1);
    assert_eq!(
        (node.upgrades().prepared, node.upgrades().alert.clone()),
        (Some(code_hash), None)
    );
    assert_eq!(
        include(&mut node, &gov.action(2, &Action::Cancel { code_hash })).status,
        1
    );
    assert_eq!(node.upgrades().prepared, None);
    // A host without the feature serves nothing, signals what it has, and is told what it lacks.
    node.set_host_features(0);
    run_until(&mut node, 10, &mut |n| signal_features(n) == Some(0));
    assert_eq!(node.upgrades().active(), 0);
    assert!(!node.resolves("secp256k1_verify", Capability::Privileged));
    assert_eq!(node.upgrades().missing_gates(), SUPPORTED);
    // The operator hears of it through /metrics and /status (spec 13 §7.2).
    let text = node.metrics_text();
    assert!(
        text.contains("\norange_upgrade_missing_gates 3\n"),
        "{text}"
    );
    assert!(text.contains("\norange_upgrade_blocked 0\n"), "{text}");
    assert_eq!(node.status().unwrap().missing_gates, SUPPORTED);
    // Locked in stays locked in.
    let gates = node.upgrade_status().unwrap().gates;
    assert_eq!(gates.record(gate::SECP256K1_VERIFY), Some(&record));
}

#[test]
fn a_signal_is_a_dynamic_fee_transaction_to_the_upgrade_address() {
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let raw = signal_tx(&key, 1337, 4, 0b101, 7);
    let again = signal_tx(&key, 1337, 4, 0b101, 7);
    assert_eq!(
        raw, again,
        "deterministic signatures make resubmission idempotent"
    );
    assert_ne!(raw, signal_tx(&key, 1337, 5, 0b101, 7));
    assert_ne!(raw, signal_tx(&key, 1337, 4, 0b101, 8));
    let data = Action::Signal { features: 0b101 }.encode();
    // A fee cap of twice the base fee it was priced at and no tip: the
    // sender pays the base fee of the block that includes it (spec 13 §8.2).
    let tx = orange_eth::decode(&raw).unwrap();
    assert_eq!(tx.tx_type, 2);
    assert_eq!(tx.chain_id, Some(1337));
    assert_eq!(tx.nonce, 4);
    assert_eq!(tx.gas_price, 14);
    assert_eq!(tx.priority_fee, Some(0));
    assert_eq!(tx.gas_limit, orange_upgrade::SIGNAL_GAS);
    assert_eq!(tx.to, Some(orange_upgrade::UPGRADE_ADDRESS));
    assert_eq!((tx.value, tx.input), (0, data));
    assert_eq!(SIGNAL_FEE_HEADROOM, 2);
    let pool = orange_node::PoolTx::parse(&raw).unwrap();
    assert_eq!(
        pool.sender,
        <[u8; 20]>::try_from(&validator_id(&key)[12..]).unwrap()
    );
    // At the largest base fee its fee cap still fits 128 bits.
    let top = orange_eth::decode(&signal_tx(&key, 1337, 4, 0b101, u64::MAX)).unwrap();
    assert_eq!(top.gas_price, u128::from(u64::MAX) * 2);
}
