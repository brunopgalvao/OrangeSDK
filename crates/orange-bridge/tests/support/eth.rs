//! An Ethereum stand-in for the bridge tests: revm at Osaka (so the EIP-2537
//! precompiles exist) over an in-memory database, and the compiled contracts
//! of `contracts/build`, checked against their sources.

#![allow(dead_code)]

use std::collections::BTreeMap;

use revm::context::result::{ExecutionResult, Output};
use revm::context::{BlockEnv, Context, TxEnv};
use revm::database::{CacheDB, EmptyDB};
use revm::handler::{MainnetContext, MainnetEvm};
use revm::primitives::hardfork::SpecId;
use revm::primitives::{Address, Bytes, TxKind, U256};
use revm::{ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext};
use sha2::{Digest, Sha256};

/// The chain id of the stand-in.
pub const ETH_CHAIN_ID: u64 = 1;

const CONTRACTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts");

/// A compiled contract's init code, from `contracts/build`.
pub fn init_code(name: &str) -> Vec<u8> {
    let hex = std::fs::read_to_string(format!("{CONTRACTS}/build/{name}.bin")).unwrap();
    decode_hex(hex.trim())
}

/// A compiled contract's runtime code, from `contracts/build`.
pub fn runtime_code(name: &str) -> Vec<u8> {
    let hex = std::fs::read_to_string(format!("{CONTRACTS}/build/{name}.bin-runtime")).unwrap();
    decode_hex(hex.trim())
}

pub fn decode_hex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Every source under `contracts/` with the sha256 `contracts/build/SOURCES`
/// records for it; panics if a source is missing from SOURCES or the reverse.
pub fn source_hashes() -> Vec<(String, String, String)> {
    let recorded: BTreeMap<String, String> =
        std::fs::read_to_string(format!("{CONTRACTS}/build/SOURCES"))
            .unwrap()
            .lines()
            .map(|l| {
                let (hash, path) = l.split_once("  ").unwrap();
                (path.to_string(), hash.to_string())
            })
            .collect();
    let mut sources = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(CONTRACTS)];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path.file_name().unwrap() != "build" {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|e| e == "sol") {
                let rel = path
                    .strip_prefix(CONTRACTS)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                let actual = format!("{:x}", Sha256::digest(std::fs::read(&path).unwrap()));
                sources.push((rel, actual));
            }
        }
    }
    sources.sort();
    let listed: Vec<&String> = recorded.keys().collect();
    let found: Vec<&String> = sources.iter().map(|(p, _)| p).collect();
    assert_eq!(
        listed, found,
        "contracts/build/SOURCES lists other sources than contracts/ holds; run tools/build-contracts.sh"
    );
    sources
        .into_iter()
        .map(|(p, actual)| (p.clone(), actual, recorded[&p].clone()))
        .collect()
}

/// What a transaction did.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub success: bool,
    pub output: Vec<u8>,
    /// Gas the transaction used, intrinsic and calldata included.
    pub gas: u64,
    pub logs: Vec<revm::primitives::Log>,
}

/// The stand-in chain.
pub struct Eth {
    evm: MainnetEvm<MainnetContext<CacheDB<EmptyDB>>>,
    nonces: BTreeMap<Address, u64>,
}

impl Default for Eth {
    fn default() -> Self {
        Self::new()
    }
}

impl Eth {
    pub fn new() -> Eth {
        let mut block = BlockEnv {
            number: U256::from(1),
            timestamp: U256::from(1_000_000),
            gas_limit: 60_000_000,
            basefee: 0,
            ..BlockEnv::default()
        };
        block.set_blob_excess_gas_and_price(
            0,
            revm::primitives::eip4844::BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE,
        );
        let evm = Context::mainnet()
            .modify_cfg_chained(|cfg| {
                cfg.set_spec_and_mainnet_gas_params(SpecId::OSAKA);
                cfg.chain_id = ETH_CHAIN_ID;
            })
            .with_block(block)
            .with_db(CacheDB::new(EmptyDB::default()))
            .build_mainnet();
        Eth {
            evm,
            nonces: BTreeMap::new(),
        }
    }

    /// The block timestamp in seconds.
    pub fn timestamp(&self) -> u64 {
        self.evm.ctx.block.timestamp.to::<u64>()
    }

    /// Moves the clock forward by `seconds`.
    pub fn advance(&mut self, seconds: u64) {
        self.evm.ctx.block.timestamp += U256::from(seconds);
        self.evm.ctx.block.number += U256::from(1);
    }

    fn tx(&mut self, from: [u8; 20], kind: TxKind, data: Vec<u8>) -> TxEnv {
        let caller = Address::from(from);
        let nonce = self.nonces.entry(caller).or_insert(0);
        let tx = TxEnv {
            caller,
            kind,
            data: Bytes::from(data),
            gas_limit: 16_000_000,
            gas_price: 0,
            nonce: *nonce,
            chain_id: Some(ETH_CHAIN_ID),
            ..TxEnv::default()
        };
        *nonce += 1;
        tx
    }

    fn outcome(result: ExecutionResult) -> (Outcome, Option<Address>) {
        match result {
            ExecutionResult::Success {
                gas, logs, output, ..
            } => {
                let (bytes, created) = match output {
                    Output::Call(b) => (b, None),
                    Output::Create(b, a) => (b, a),
                };
                (
                    Outcome {
                        success: true,
                        output: bytes.to_vec(),
                        gas: gas.tx_gas_used(),
                        logs,
                    },
                    created,
                )
            }
            ExecutionResult::Revert { gas, output, logs } => (
                Outcome {
                    success: false,
                    output: output.to_vec(),
                    gas: gas.tx_gas_used(),
                    logs,
                },
                None,
            ),
            ExecutionResult::Halt { gas, logs, .. } => (
                Outcome {
                    success: false,
                    output: Vec::new(),
                    gas: gas.tx_gas_used(),
                    logs,
                },
                None,
            ),
        }
    }

    /// Deploys `init ‖ args` from `from` and returns the new contract's address.
    pub fn deploy(&mut self, from: [u8; 20], init: &[u8], args: &[u8]) -> [u8; 20] {
        let (outcome, created) = self.try_deploy(from, init, args);
        assert!(outcome.success, "deployment failed: {outcome:?}");
        created.unwrap()
    }

    /// Deploys `init ‖ args`, reporting what happened.
    pub fn try_deploy(
        &mut self,
        from: [u8; 20],
        init: &[u8],
        args: &[u8],
    ) -> (Outcome, Option<[u8; 20]>) {
        let mut data = init.to_vec();
        data.extend_from_slice(args);
        let tx = self.tx(from, TxKind::Create, data);
        let (outcome, created) = Self::outcome(self.evm.transact_commit(tx).unwrap());
        (outcome, created.map(|a| a.0.0))
    }

    /// Sends a transaction from `from` to `to` with `data`, committing its effects.
    pub fn call(&mut self, from: [u8; 20], to: [u8; 20], data: &[u8]) -> Outcome {
        let tx = self.tx(from, TxKind::Call(Address::from(to)), data.to_vec());
        Self::outcome(self.evm.transact_commit(tx).unwrap()).0
    }

    /// Sends a transaction from `from` to `to` carrying `value` wei with `data`, committing its
    /// effects.
    pub fn call_value(
        &mut self,
        from: [u8; 20],
        to: [u8; 20],
        value: u128,
        data: &[u8],
    ) -> Outcome {
        let mut tx = self.tx(from, TxKind::Call(Address::from(to)), data.to_vec());
        tx.value = U256::from(value);
        Self::outcome(self.evm.transact_commit(tx).unwrap()).0
    }

    /// Sends a transaction from `from` to `to` with `data` and a gas limit of `gas`.
    pub fn call_gas(&mut self, from: [u8; 20], to: [u8; 20], data: &[u8], gas: u64) -> Outcome {
        let mut tx = self.tx(from, TxKind::Call(Address::from(to)), data.to_vec());
        tx.gas_limit = gas;
        Self::outcome(self.evm.transact_commit(tx).unwrap()).0
    }

    /// Sets the balance of `account` to `wei`.
    pub fn fund(&mut self, account: [u8; 20], wei: u128) {
        let db = &mut self.evm.ctx.journaled_state.database;
        let address = Address::from(account);
        let mut info = db
            .cache
            .accounts
            .get(&address)
            .map(|a| a.info.clone())
            .unwrap_or_default();
        info.balance = U256::from(wei);
        db.insert_account_info(address, info);
    }

    /// The balance of `account` in wei.
    pub fn balance(&self, account: [u8; 20]) -> u128 {
        self.evm
            .ctx
            .journaled_state
            .database
            .cache
            .accounts
            .get(&Address::from(account))
            .map_or(0, |a| a.info.balance.to::<u128>())
    }

    /// The state as Ethereum commits to it, with the proofs `eth_getProof` returns.
    pub fn state(&self) -> orange_ethlc::testing::EthState {
        let mut out = orange_ethlc::testing::EthState::default();
        for (address, a) in &self.evm.ctx.journaled_state.database.cache.accounts {
            let storage = a
                .storage
                .iter()
                .filter(|(_, v)| !v.is_zero())
                .map(|(k, v)| (k.to_be_bytes::<32>(), v.to_be_bytes::<32>()))
                .collect();
            let account = orange_ethlc::testing::Account {
                nonce: a.info.nonce,
                balance: a.info.balance.to::<u128>(),
                code_hash: a.info.code_hash.0,
                storage,
            };
            if account.nonce != 0
                || account.balance != 0
                || account.code_hash != revm::primitives::KECCAK_EMPTY.0
            {
                out.accounts.insert(address.0.0, account);
            }
        }
        out
    }

    /// Runs a call from `from` to `to` without keeping its effects.
    pub fn view(&mut self, from: [u8; 20], to: [u8; 20], data: &[u8]) -> Outcome {
        let caller = Address::from(from);
        let nonce = *self.nonces.get(&caller).unwrap_or(&0);
        let tx = TxEnv {
            caller,
            kind: TxKind::Call(Address::from(to)),
            data: Bytes::from(data.to_vec()),
            gas_limit: 16_000_000,
            gas_price: 0,
            nonce,
            chain_id: Some(ETH_CHAIN_ID),
            ..TxEnv::default()
        };
        Self::outcome(self.evm.transact(tx).unwrap().result).0
    }
}

/// The 4-byte selector of a Solidity error or function.
pub fn selector(signature: &str) -> Vec<u8> {
    orange_bridge::abi::selector(signature).to_vec()
}

/// A 32-byte word holding `v`.
pub fn word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// The last 8 bytes of a word as an integer.
pub fn word_u64(w: &[u8]) -> u64 {
    u64::from_be_bytes(w[24..32].try_into().unwrap())
}
