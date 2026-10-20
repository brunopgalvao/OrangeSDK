//! Shared by the upgrade and feature-gate tests: the two kernel versions,
//! wallets that sign legacy transactions, genesis with upgrade parameters,
//! stage transactions, and tiny hand-assembled kernels.

#![allow(dead_code)]

use std::sync::OnceLock;

use k256::ecdsa::SigningKey;
use solo_abi::Encode;
use solo_abi::chain::{Allocation, GenesisParams, Receipt, UpgradeParams};
use solo_abi::codec::Seq;
use solo_abi::types::Genesis;
use solo_host::hash::keccak256;
use solo_node::{Node, Sim};
use solo_rlp::{encode_bytes, encode_list, encode_uint};
use solo_upgrade::{Action, CHUNK_SIZE, UPGRADE_ADDRESS};
use solo_vm::builder::ModuleBuilder;
use solo_vm::isa::{Instruction, Reg};

pub const CHAIN_ID: u64 = 1337;
pub const SLOT_MS: u64 = 400;
pub const ETHER: u128 = 1_000_000_000_000_000_000;
/// Gas limit of a stage transaction: above the calldata floor of a full chunk.
pub const STAGE_GAS: u64 = 3_000_000;

const KERNEL_V1: &[u8] = include_bytes!("../fixtures/kernel.elf");
const KERNEL_V2: &[u8] = include_bytes!("../fixtures/kernel_v2.elf");

fn recompile(elf: &[u8]) -> Vec<u8> {
    solo_recompile::recompile(
        &solo_recompile::Input::load(elf).unwrap(),
        &solo_recompile::Options::default(),
    )
    .unwrap()
}

/// The reference kernel, version 1.
pub fn v1() -> &'static [u8] {
    static MODULE: OnceLock<Vec<u8>> = OnceLock::new();
    MODULE.get_or_init(|| recompile(KERNEL_V1))
}

/// The reference kernel built with `upgrade-test`: version 2.
pub fn v2() -> &'static [u8] {
    static MODULE: OnceLock<Vec<u8>> = OnceLock::new();
    MODULE.get_or_init(|| recompile(KERNEL_V2))
}

pub struct Wallet {
    pub key: SigningKey,
    pub address: [u8; 20],
}

impl Wallet {
    pub fn new(seed: u8) -> Wallet {
        Wallet::from_key(SigningKey::from_slice(&[seed; 32]).unwrap())
    }

    pub fn from_key(key: SigningKey) -> Wallet {
        let point = key.verifying_key().to_encoded_point(false);
        let digest = keccak256(&point.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&digest[12..]);
        Wallet { key, address }
    }

    /// A legacy EIP-155 transaction with gas price zero.
    pub fn tx(&self, nonce: u64, to: [u8; 20], value: u128, gas: u64, data: &[u8]) -> Vec<u8> {
        let fields = |out: &mut Vec<u8>| {
            encode_uint(u128::from(nonce), out);
            encode_uint(0, out);
            encode_uint(u128::from(gas), out);
            encode_bytes(&to, out);
            encode_uint(value, out);
            encode_bytes(data, out);
        };
        let mut unsigned = Vec::new();
        fields(&mut unsigned);
        encode_uint(u128::from(CHAIN_ID), &mut unsigned);
        encode_uint(0, &mut unsigned);
        encode_uint(0, &mut unsigned);
        let mut list = Vec::new();
        encode_list(&unsigned, &mut list);
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(&keccak256(&list))
            .unwrap();
        let mut signed = Vec::new();
        fields(&mut signed);
        encode_uint(
            u128::from(CHAIN_ID * 2 + 35 + u64::from(rid.to_byte())),
            &mut signed,
        );
        let strip = |b: &[u8]| b[b.iter().take_while(|x| **x == 0).count()..].to_vec();
        encode_bytes(&strip(&sig.r().to_bytes()), &mut signed);
        encode_bytes(&strip(&sig.s().to_bytes()), &mut signed);
        let mut out = Vec::new();
        encode_list(&signed, &mut out);
        out
    }

    /// A pre-EIP-155 legacy transaction (no chain id, `v` = 27 or 28) with gas price zero.
    pub fn unprotected_tx(&self, nonce: u64, to: [u8; 20], gas: u64, data: &[u8]) -> Vec<u8> {
        let fields = |out: &mut Vec<u8>| {
            encode_uint(u128::from(nonce), out);
            encode_uint(0, out);
            encode_uint(u128::from(gas), out);
            encode_bytes(&to, out);
            encode_uint(0, out);
            encode_bytes(data, out);
        };
        let mut unsigned = Vec::new();
        fields(&mut unsigned);
        let mut list = Vec::new();
        encode_list(&unsigned, &mut list);
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(&keccak256(&list))
            .unwrap();
        let mut signed = Vec::new();
        fields(&mut signed);
        encode_uint(u128::from(27 + rid.to_byte()), &mut signed);
        let strip = |b: &[u8]| b[b.iter().take_while(|x| **x == 0).count()..].to_vec();
        encode_bytes(&strip(&sig.r().to_bytes()), &mut signed);
        encode_bytes(&strip(&sig.s().to_bytes()), &mut signed);
        let mut out = Vec::new();
        encode_list(&signed, &mut out);
        out
    }

    /// A transaction carrying `action` to the upgrade address.
    pub fn action(&self, nonce: u64, action: &Action) -> Vec<u8> {
        self.tx(nonce, UPGRADE_ADDRESS, 0, STAGE_GAS, &action.encode())
    }
}

/// The governance account of the test chains.
pub fn governance() -> Wallet {
    Wallet::new(0x60)
}

/// A funded user account.
pub fn alice() -> Wallet {
    Wallet::new(1)
}

/// Validator keys.
pub fn keys(n: u8) -> Vec<SigningKey> {
    (1..=n)
        .map(|i| SigningKey::from_slice(&[0x10 + i; 32]).unwrap())
        .collect()
}

/// A chain of `validators` with Alice funded and the given upgrade parameters.
pub fn genesis(validators: &[SigningKey], upgrades: UpgradeParams, max_txs: u32) -> Genesis {
    let params = GenesisParams {
        slot_ms: SLOT_MS,
        max_txs,
        allocations: Seq(vec![Allocation {
            address: alice().address,
            balance: 100 * ETHER,
            ..Allocation::default()
        }]),
        upgrades,
        ..GenesisParams::default()
    };
    Genesis {
        chain_id: CHAIN_ID,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: Sim::validator_set(validators).to_bytes(),
    }
}

/// Upgrade parameters with the test governance account.
pub fn governed(min_delay: u64, epoch_blocks: u64) -> UpgradeParams {
    UpgradeParams {
        governance: governance().address,
        min_delay,
        epoch_blocks,
    }
}

/// The stage actions that upload `code`.
pub fn stage_actions(code: &[u8]) -> Vec<Action> {
    let code_hash = keccak256(code);
    code.chunks(CHUNK_SIZE)
        .enumerate()
        .map(|(i, chunk)| Action::Stage {
            code_hash,
            index: u32::try_from(i).unwrap(),
            chunk: chunk.to_vec(),
        })
        .collect()
}

/// A hand-assembled module whose `kernel_version` outputs `version` and whose
/// `kernel_migrate` traps or halts; `import` adds an import it never calls.
pub fn tiny_kernel(version: &[u8], migrate_traps: bool, import: Option<&str>) -> Vec<u8> {
    let mut b = ModuleBuilder::new().rodata(version);
    b.import("output_write");
    if let Some(name) = import {
        b.import(name);
    }
    let base = i64::from(b.layout.ro_base);
    b.block(&[
        Instruction::Li {
            rd: Reg::A0,
            imm: base,
        },
        Instruction::Li {
            rd: Reg::A1,
            imm: i64::try_from(version.len()).unwrap(),
        },
        Instruction::Ecall { import: 0 },
        Instruction::Halt,
    ]);
    b.block(&[if migrate_traps {
        Instruction::Trap
    } else {
        Instruction::Halt
    }]);
    b.export("kernel_version", 0)
        .export("kernel_migrate", 1)
        .build()
}

/// Ticks a single node one slot at a time until `done` holds, at most `max` slots.
pub fn run_until(node: &mut Node, max: u32, done: &mut dyn FnMut(&mut Node) -> bool) {
    for _ in 0..max {
        if done(node) {
            return;
        }
        let t = node.now_ms() + SLOT_MS;
        node.tick(t).unwrap();
    }
    assert!(done(node), "not reached within {max} slots");
}

/// Submits `raw` to a single node and runs it until the transaction has a receipt.
pub fn include(node: &mut Node, raw: &[u8]) -> Receipt {
    let hash = node.submit(raw).expect("admitted");
    run_until(node, 10, &mut |n| n.receipt(&hash).unwrap().is_some());
    node.receipt(&hash).unwrap().unwrap()
}
