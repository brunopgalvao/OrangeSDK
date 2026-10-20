//! The EVM: revm over the kernel's state, with the host's native crypto.

use alloc::vec::Vec;
use core::convert::Infallible;

use revm::bytecode::Bytecode;
use revm::context::result::{ExecutionResult, Output};
use revm::context::transaction::{AccessList, AccessListItem};
use revm::context::{BlockEnv, Context, TxEnv};
use revm::precompile::{Crypto, PrecompileHalt};
use revm::primitives::hardfork::SpecId;
use revm::primitives::{Address as RAddress, B256, Bytes, KECCAK_EMPTY, TxKind, U256};
use revm::state::{Account as RAccount, AccountInfo};
use revm::{Database, ExecuteEvm, MainBuilder, MainContext};
use solo_abi::chain::{Account, BLOCK_GAS_LIMIT, Log, call_status};
use solo_abi::codec::Seq;
use solo_abi::types::{Address, Hash};
use solo_guest::host;

use crate::state;

/// Base fee per gas. Constant in this kernel version; fees go to the zero address.
pub const BASE_FEE: u64 = 0;

/// Kernel state seen through revm's `Database`.
pub struct StateDb;

impl Database for StateDb {
    type Error = Infallible;

    fn basic(&mut self, address: RAddress) -> Result<Option<AccountInfo>, Infallible> {
        let Some(account) = state::get::<Account>(&state::account_key(&address.0.0)) else {
            return Ok(None);
        };
        let code_hash = if account.code_hash == [0; 32] { KECCAK_EMPTY } else { B256::from(account.code_hash) };
        Ok(Some(AccountInfo { balance: U256::from(account.balance), nonce: account.nonce, code_hash, code: None, ..AccountInfo::default() }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Infallible> {
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::default());
        }
        Ok(state::get_raw(&state::code_key(&code_hash.0)).map_or_else(Bytecode::default, |code| Bytecode::new_raw(code.into())))
    }

    fn storage(&mut self, address: RAddress, index: U256) -> Result<U256, Infallible> {
        Ok(state::get_raw(&state::slot_key(&address.0.0, &index.to_be_bytes::<32>())).map_or(U256::ZERO, |v| U256::from_be_slice(&v)))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Infallible> {
        Ok(state::block_by_number(number).map_or(B256::ZERO, |h| B256::from(state::keccak256(&solo_abi::Encode::to_bytes(&h)))))
    }
}

fn u128_of(v: U256) -> u128 {
    u128::try_from(v).unwrap_or(u128::MAX)
}

/// Writes revm's changes to the kernel state, as revm's own `CacheDB` would,
/// plus the EIP-161 rule that `CacheDB` leaves to its user: a touched account
/// left empty (no code, nonce or balance) is removed.
fn commit(changes: impl IntoIterator<Item = (RAddress, RAccount)>) {
    for (address, account) in changes {
        if !account.is_touched() {
            continue;
        }
        let a = address.0.0;
        if account.is_selfdestructed() {
            // Post-Cancun, only an account created in the same transaction self-destructs,
            // so every slot it has is among the ones this transaction touched.
            for key in account.storage.keys() {
                state::delete(&state::slot_key(&a, &key.to_be_bytes::<32>()));
            }
            state::delete(&state::account_key(&a));
            continue;
        }
        let info = &account.info;
        if info.is_empty() {
            // Only an account that never had code, nonce or storage can be empty after a
            // transaction (a zero-value call, a zero fee to the beneficiary), so there is
            // nothing else to remove.
            state::delete(&state::account_key(&a));
            continue;
        }
        let code_hash = if info.code_hash == KECCAK_EMPTY { [0; 32] } else { info.code_hash.0 };
        if let Some(code) = &info.code
            && code_hash != [0; 32]
            && account.is_created()
        {
            state::set_raw(&state::code_key(&code_hash), code.original_byte_slice());
        }
        state::set_account(&a, &Account { balance: u128_of(info.balance), nonce: info.nonce, code_hash });
        for (key, slot) in account.changed_storage_slots() {
            let k = state::slot_key(&a, &key.to_be_bytes::<32>());
            if slot.present_value.is_zero() {
                state::delete(&k);
            } else {
                state::set_raw(&k, &slot.present_value.to_be_bytes::<32>());
            }
        }
    }
}

/// Block fields the EVM sees.
#[derive(Debug, Clone, Copy)]
pub struct BlockFields {
    /// Height.
    pub number: u64,
    /// Timestamp in seconds.
    pub timestamp: u64,
}

/// A message to execute.
pub struct Message {
    /// Transaction type.
    pub tx_type: u8,
    /// Caller.
    pub caller: Address,
    /// Callee, or `None` to create.
    pub to: Option<Address>,
    /// Value.
    pub value: u128,
    /// Calldata or initcode.
    pub data: Vec<u8>,
    /// Gas limit.
    pub gas_limit: u64,
    /// Gas price, or max fee per gas.
    pub gas_price: u128,
    /// Max priority fee per gas, for dynamic-fee transactions.
    pub priority_fee: Option<u128>,
    /// Nonce; `None` skips the nonce check (calls).
    pub nonce: Option<u64>,
    /// Access list.
    pub access_list: Vec<solo_eth::AccessItem>,
}

/// What a message did.
pub struct Outcome {
    /// `call_status::*`.
    pub status: u8,
    /// Gas used.
    pub gas_used: u64,
    /// Return or revert data.
    pub output: Vec<u8>,
    /// Logs.
    pub logs: Vec<Log>,
    /// Created contract.
    pub contract: Option<Address>,
}

/// Executes `message` at `block`; commits the state changes only if `commit_state`.
pub fn run(message: Message, block: BlockFields, commit_state: bool) -> Outcome {
    install_host_crypto();
    let chain_id = state::chain_id();
    let skip_nonce = message.nonce.is_none();
    let tx = TxEnv {
        tx_type: message.tx_type,
        caller: RAddress::from(message.caller),
        gas_limit: message.gas_limit,
        gas_price: message.gas_price,
        kind: message.to.map_or(TxKind::Create, |to| TxKind::Call(RAddress::from(to))),
        value: U256::from(message.value),
        data: Bytes::from(message.data),
        nonce: message.nonce.unwrap_or(0),
        chain_id: Some(chain_id),
        access_list: AccessList(
            message
                .access_list
                .into_iter()
                .map(|i| AccessListItem { address: RAddress::from(i.address), storage_keys: i.keys.into_iter().map(B256::from).collect() })
                .collect(),
        ),
        gas_priority_fee: message.priority_fee,
        ..TxEnv::default()
    };
    let block_env = BlockEnv {
        number: U256::from(block.number),
        timestamp: U256::from(block.timestamp),
        gas_limit: BLOCK_GAS_LIMIT,
        basefee: BASE_FEE,
        prevrandao: Some(B256::ZERO),
        ..BlockEnv::default()
    };
    let mut evm = Context::mainnet()
        .modify_cfg_chained(|cfg| {
            cfg.set_spec_and_mainnet_gas_params(SpecId::OSAKA);
            cfg.chain_id = chain_id;
            // A call query is a simulation: like geth's eth_call it skips the nonce
            // and lets a contract be the caller (EIP-3607 applies to transactions).
            cfg.disable_nonce_check = skip_nonce;
            cfg.disable_eip3607 = skip_nonce;
        })
        .with_block(block_env)
        .with_db(StateDb)
        .build_mainnet();
    let Ok(result) = evm.transact(tx) else {
        return Outcome { status: call_status::INVALID, gas_used: 0, output: Vec::new(), logs: Vec::new(), contract: None };
    };
    let (status, gas_used, output, logs, contract) = match result.result {
        ExecutionResult::Success { gas, logs, output, .. } => {
            let (bytes, contract) = match output {
                Output::Call(b) => (b, None),
                Output::Create(b, address) => (b, address.map(|a| a.0.0)),
            };
            (call_status::SUCCESS, gas.tx_gas_used(), bytes.to_vec(), logs, contract)
        }
        ExecutionResult::Revert { gas, logs, output } => (call_status::REVERT, gas.tx_gas_used(), output.to_vec(), logs, None),
        ExecutionResult::Halt { gas, logs, .. } => (call_status::HALT, gas.tx_gas_used(), Vec::new(), logs, None),
    };
    if commit_state {
        commit(result.state);
    }
    let logs = logs
        .into_iter()
        .map(|l| Log { address: l.address.0.0, topics: Seq(l.data.topics().iter().map(|t| t.0).collect()), data: l.data.data.to_vec() })
        .collect();
    Outcome { status, gas_used, output, logs, contract }
}

/// The order of the secp256k1 group.
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// The host's native implementations of the precompiles it accelerates.
#[derive(Debug)]
struct HostCrypto;

impl Crypto for HostCrypto {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        // SAFETY: valid pointers into our own buffers.
        unsafe { host::__solo_import_hash_sha256(input.as_ptr(), input.len() as u32, out.as_mut_ptr()) };
        out
    }

    fn secp256k1_ecrecover(&self, sig: &[u8; 64], recid: u8, msg: &[u8; 32]) -> Result<[u8; 32], PrecompileHalt> {
        let mut full = [0u8; 65];
        full[..64].copy_from_slice(sig);
        full[64] = recid;
        // The host recovers low-s signatures only, the form EIP-2 requires of
        // transactions. The precompile accepts either: (r, s) and (r, n - s) with the
        // other parity name the same key, so a high s is mirrored, as revm itself does.
        let n = U256::from_be_bytes(SECP256K1_ORDER);
        let s = U256::from_be_slice(&sig[32..]);
        if s > n >> 1 && s < n {
            full[32..64].copy_from_slice(&(n - s).to_be_bytes::<32>());
            full[64] ^= 1;
        }
        let address = crate::tx::recover_address(msg, &full).ok_or(PrecompileHalt::Secp256k1RecoverFailed)?;
        let mut out = [0u8; 32];
        out[12..].copy_from_slice(&address);
        Ok(out)
    }

    fn secp256r1_verify_signature(&self, msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> bool {
        // SAFETY: valid pointers into our own buffers of the sizes the host function reads.
        unsafe { host::__solo_import_p256_verify(msg.as_ptr(), sig.as_ptr(), pk.as_ptr()) == 0 }
    }
}

fn install_host_crypto() {
    // Repeated installs are refused by revm and harmless.
    let _ = revm::precompile::install_crypto(HostCrypto);
}

/// Contract code at `address`.
pub fn code(address: &Address) -> Vec<u8> {
    let account: Account = state::get(&state::account_key(address)).unwrap_or_default();
    if account.code_hash == [0; 32] {
        return Vec::new();
    }
    state::get_raw(&state::code_key(&account.code_hash)).unwrap_or_default()
}

/// Storage slot of `address`.
pub fn storage(address: &Address, slot: &Hash) -> Hash {
    state::get_raw(&state::slot_key(address, slot)).and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok()).unwrap_or([0; 32])
}
