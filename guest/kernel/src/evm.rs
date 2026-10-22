//! The EVM: revm over the kernel's state, with the host's native crypto.

use alloc::vec::Vec;
use core::convert::Infallible;

use revm::bytecode::Bytecode;
use revm::context::result::{ExecutionResult, Output};
use revm::context::either::Either;
use revm::context::transaction::{AccessList, AccessListItem, Authorization as RAuthorization, RecoveredAuthority, RecoveredAuthorization};
use revm::context::{BlockEnv, Context, TxEnv};
use revm::handler::{EthPrecompiles, MainnetContext, PrecompileProvider};
use revm::interpreter::InterpreterResult;
use revm::precompile::bls12_381::{G1Point, G1PointScalar, G2Point, G2PointScalar};
use revm::precompile::{Crypto, PrecompileHalt};
use revm::primitives::hardfork::SpecId;
use revm::primitives::eip4844::BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE;
use revm::primitives::{Address as RAddress, B256, Bytes, KECCAK_EMPTY, TxKind, U256};
use revm::state::{Account as RAccount, AccountInfo};
use revm::{Database, ExecuteEvm, MainBuilder, MainContext};
use solo_abi::chain::{Account, BLOCK_GAS_LIMIT, Log, call_status};
use solo_abi::codec::Seq;
use solo_abi::types::{Address, Hash};
use solo_guest::host;

use crate::state;

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
        Ok(state::get_raw(&state::code_key(&code_hash.0)).map_or_else(Bytecode::default, bytecode))
    }

    fn storage(&mut self, address: RAddress, index: U256) -> Result<U256, Infallible> {
        Ok(state::get_raw(&state::slot_key(&address.0.0, &index.to_be_bytes::<32>())).map_or(U256::ZERO, |v| U256::from_be_slice(&v)))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Infallible> {
        Ok(state::block_hash(number).map_or(B256::ZERO, B256::from))
    }
}

/// Stored code as revm runs it. A delegation designator delegates; anything
/// else is legacy code, including genesis code that starts with 0xEF01 but is
/// no designator, which geth runs the same way (0xEF is an invalid opcode).
/// revm's `Bytecode::new_raw` would panic on such code and trap the kernel.
fn bytecode(code: Vec<u8>) -> Bytecode {
    let code = Bytes::from(code);
    Bytecode::new_raw_checked(code.clone()).unwrap_or_else(|_| Bytecode::new_legacy(code))
}

/// Whether `code` is an EIP-7702 delegation designator, `0xef0100 ‖ address`:
/// the only code an account may have and still send transactions (EIP-3607).
pub fn is_delegation(code: &[u8]) -> bool {
    code.len() == 23 && code.starts_with(&[0xEF, 0x01, 0x00])
}

fn u128_of(v: U256) -> u128 {
    u128::try_from(v).unwrap_or(u128::MAX)
}

/// Writes revm's changes to the kernel state, plus the EIP-161 rule that
/// revm's `CacheDB` leaves to its user: a touched account left empty (no code,
/// nonce or balance) is removed.
///
/// Unlike `CacheDB`, this never clears an account's old slots, because no
/// account it creates, destroys or removes has any. Every account with storage
/// has code or a non-zero nonce: genesis refuses storage on any other account
/// (`state::init`), only code writes storage, and creation sets the nonce to 1.
/// revm creates only where there is neither code nor nonce, so it never creates
/// over old slots, which is also why leaving out EIP-7610 is safe.
///
/// An account whose storage the precompile provider commits itself (a
/// native contract, spec 16 §5, or the outbox, spec 17 §2.3) gets only its
/// balance, nonce and code hash written here, and is deleted when it has none
/// of them.
fn commit<P: Precompiles>(changes: impl IntoIterator<Item = (RAddress, RAccount)>, precompiles: &P) {
    for (address, account) in changes {
        if !account.is_touched() {
            continue;
        }
        let a = address.0.0;
        if precompiles.commit_storage(&a, &account) {
            let info = &account.info;
            if info.is_empty() {
                // A provider-kept account with no code, nonce or balance (the
                // empty outbox) is left out of state; its slots are its provider's.
                state::delete(&state::account_key(&a));
            } else {
                let code_hash = if info.code_hash == KECCAK_EMPTY { [0; 32] } else { info.code_hash.0 };
                state::set_account(&a, &Account { balance: u128_of(info.balance), nonce: info.nonce, code_hash });
            }
            continue;
        }
        if account.is_selfdestructed() {
            // Post-Cancun, only an account created in the same transaction self-destructs;
            // it had no slots before, so every slot it has is one this transaction touched.
            for key in account.storage.keys() {
                state::delete(&state::slot_key(&a, &key.to_be_bytes::<32>()));
            }
            state::delete(&state::account_key(&a));
            continue;
        }
        let info = &account.info;
        if info.is_empty() {
            // An account with neither code nor nonce has no storage (see above), so the
            // account key is all there is to remove: after a zero-value call, or a zero
            // fee paid to the beneficiary.
            state::delete(&state::account_key(&a));
            continue;
        }
        let code_hash = if info.code_hash == KECCAK_EMPTY { [0; 32] } else { info.code_hash.0 };
        // Code enters state by a creation, or as the delegation designator an
        // EIP-7702 authorization writes, which revm sets without creating.
        if let Some(code) = &info.code
            && code_hash != [0; 32]
            && (account.is_created() || is_delegation(code.original_byte_slice()))
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
    /// Base fee per gas (spec 23 §3).
    pub base_fee: u64,
    /// Fee recipient (`COINBASE`): the fee vault or the zero address (spec 23 §4).
    pub beneficiary: Address,
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
    /// Authorizations of a set-code transaction, each with the authority its
    /// signature names (`tx::authority`); empty for every other type.
    pub authorization_list: Vec<(solo_eth::Authorization, Option<Address>)>,
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

/// The block environment a message runs in, as the EVM sees it.
#[derive(Debug, Clone, Copy)]
pub struct Env {
    /// Chain id.
    pub chain_id: u64,
    /// Height.
    pub number: u64,
    /// Timestamp in seconds.
    pub timestamp: u64,
    /// Block gas limit.
    pub gas_limit: u64,
    /// Base fee per gas.
    pub basefee: u64,
    /// Fee recipient (`COINBASE`).
    pub beneficiary: Address,
    /// `PREVRANDAO`.
    pub prevrandao: Hash,
    /// Difficulty, big-endian.
    pub difficulty: Hash,
    /// Excess blob gas, from which `BLOBBASEFEE` follows.
    pub excess_blob_gas: u64,
}

impl Env {
    /// What the reference kernel's blocks look like to the EVM: the fixed
    /// block gas limit, the block's base fee and beneficiary (spec 23), the
    /// zero `PREVRANDAO` and difficulty, and no excess blob gas.
    pub fn kernel(block: BlockFields) -> Env {
        Env {
            chain_id: state::chain_id(),
            number: block.number,
            timestamp: block.timestamp,
            gas_limit: BLOCK_GAS_LIMIT,
            basefee: block.base_fee,
            beneficiary: block.beneficiary,
            prevrandao: [0; 32],
            difficulty: [0; 32],
            excess_blob_gas: 0,
        }
    }
}

/// The precompiles a message runs with. Ethereum's are [`EthPrecompiles`];
/// a kernel adds its own beside them through this trait, so this file
/// builds without them (the reference kernel's native contracts are in
/// `native.rs`).
pub trait Precompiles: PrecompileProvider<MainnetContext<StateDb>, Output = InterpreterResult> + Sized {
    /// The provider for one message at `block`; `query` for a call query.
    fn for_message(block: BlockFields, query: bool) -> Self;

    /// Commits the storage changes of `account` at `address` if the
    /// provider keeps that account's storage itself; whether it did.
    fn commit_storage(&self, address: &Address, account: &RAccount) -> bool;
}

impl Precompiles for EthPrecompiles {
    fn for_message(_: BlockFields, _: bool) -> Self {
        EthPrecompiles::new(SpecId::OSAKA)
    }

    fn commit_storage(&self, _: &Address, _: &RAccount) -> bool {
        false
    }
}

/// Executes `message` in `env` with the precompiles `P`; commits the state
/// changes only if `commit_state`. The conformance harness (spec 07 §4.2)
/// runs Ethereum's state tests through this function with their own
/// environments.
pub fn run_in<P: Precompiles>(message: Message, env: &Env, commit_state: bool) -> Outcome {
    install_host_crypto();
    let chain_id = env.chain_id;
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
        authorization_list: message.authorization_list.into_iter().map(recovered).collect(),
        ..TxEnv::default()
    };
    let mut block_env = BlockEnv {
        number: U256::from(env.number),
        beneficiary: RAddress::from(env.beneficiary),
        timestamp: U256::from(env.timestamp),
        gas_limit: env.gas_limit,
        basefee: env.basefee,
        difficulty: U256::from_be_bytes(env.difficulty),
        prevrandao: Some(B256::from(env.prevrandao)),
        ..BlockEnv::default()
    };
    block_env.set_blob_excess_gas_and_price(env.excess_blob_gas, BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE);
    let mut evm = Context::mainnet()
        .modify_cfg_chained(|cfg| {
            cfg.set_spec_and_mainnet_gas_params(SpecId::OSAKA);
            cfg.chain_id = chain_id;
            // A call query is a simulation: like geth's eth_call it skips the nonce,
            // lets a contract be the caller (EIP-3607 applies to transactions) and
            // runs at a gas price of zero under any base fee, which `BASEFEE` still
            // reports (spec 23 §3).
            cfg.disable_nonce_check = skip_nonce;
            cfg.disable_eip3607 = skip_nonce;
            cfg.disable_base_fee = skip_nonce;
        })
        .with_block(block_env)
        .with_db(StateDb)
        .build_mainnet()
        .with_precompiles(P::for_message(
            BlockFields { number: env.number, timestamp: env.timestamp, base_fee: env.basefee, beneficiary: env.beneficiary },
            !commit_state,
        ));
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
        commit(result.state, &evm.precompiles);
    }
    let logs = logs
        .into_iter()
        .map(|l| Log { address: l.address.0.0, topics: Seq(l.data.topics().iter().map(|t| t.0).collect()), data: l.data.data.to_vec() })
        .collect();
    Outcome { status, gas_used, output, logs, contract }
}

/// An authorization as revm applies it: recovered by the kernel through the
/// host, so revm needs no signature code of its own (spec 20 §2.2).
fn recovered((auth, authority): (solo_eth::Authorization, Option<Address>)) -> Either<revm::context::transaction::SignedAuthorization, RecoveredAuthorization> {
    let inner = RAuthorization { chain_id: U256::from_be_bytes(auth.chain_id), address: RAddress::from(auth.address), nonce: auth.nonce };
    let authority = authority.map_or(RecoveredAuthority::Invalid, |a| RecoveredAuthority::Valid(RAddress::from(a)));
    Either::Right(RecoveredAuthorization::new_unchecked(inner, authority))
}

/// The order of the secp256k1 group.
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// The host's native implementations of the precompiles it accelerates:
/// SHA-256, ECRECOVER and P-256 from genesis, the others of spec 19 once
/// gate 2 is active. `KECCAK256` reaches the host through `alloy-primitives`'
/// `native-keccak` hook (`precompiles::native_keccak256`).
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

    // The rest run on the host once gate 2 is active (spec 19, `precompiles.rs`).

    fn modexp(&self, base: &[u8], exp: &[u8], modulus: &[u8]) -> Result<Vec<u8>, PrecompileHalt> {
        crate::precompiles::modexp(base, exp, modulus)
    }

    fn bn254_g1_add(&self, p1: &[u8], p2: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        crate::precompiles::bn254_add(p1, p2)
    }

    fn bn254_g1_mul(&self, point: &[u8], scalar: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        crate::precompiles::bn254_mul(point, scalar)
    }

    fn bn254_pairing_check(&self, pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileHalt> {
        crate::precompiles::bn254_pairing(pairs)
    }

    fn blake2_compress(&self, rounds: u32, h: &mut [u64; 8], m: &[u64; 16], t: &[u64; 2], f: bool) {
        crate::precompiles::blake2f(rounds, h, m, t, f);
    }

    fn verify_kzg_proof(&self, z: &[u8; 32], y: &[u8; 32], commitment: &[u8; 48], proof: &[u8; 48]) -> Result<(), PrecompileHalt> {
        crate::precompiles::kzg(z, y, commitment, proof)
    }

    fn bls12_381_g1_add(&self, a: G1Point, b: G1Point) -> Result<[u8; 96], PrecompileHalt> {
        crate::precompiles::g1_add(a, b)
    }

    fn bls12_381_g1_msm(&self, pairs: &mut dyn Iterator<Item = Result<G1PointScalar, PrecompileHalt>>) -> Result<[u8; 96], PrecompileHalt> {
        crate::precompiles::g1_msm(pairs)
    }

    fn bls12_381_g2_add(&self, a: G2Point, b: G2Point) -> Result<[u8; 192], PrecompileHalt> {
        crate::precompiles::g2_add(a, b)
    }

    fn bls12_381_g2_msm(&self, pairs: &mut dyn Iterator<Item = Result<G2PointScalar, PrecompileHalt>>) -> Result<[u8; 192], PrecompileHalt> {
        crate::precompiles::g2_msm(pairs)
    }

    fn bls12_381_pairing_check(&self, pairs: &[(G1Point, G2Point)]) -> Result<bool, PrecompileHalt> {
        crate::precompiles::pairing(pairs)
    }

    fn bls12_381_fp_to_g1(&self, fp: &[u8; 48]) -> Result<[u8; 96], PrecompileHalt> {
        crate::precompiles::map_fp(fp)
    }

    fn bls12_381_fp2_to_g2(&self, fp2: ([u8; 48], [u8; 48])) -> Result<[u8; 192], PrecompileHalt> {
        crate::precompiles::map_fp2(fp2)
    }
}

fn install_host_crypto() {
    // Repeated installs are refused by revm and harmless.
    let _ = revm::precompile::install_crypto(HostCrypto);
}

/// Contract code at `address`.
pub fn code(address: &Address) -> Vec<u8> {
    code_of(&state::account(address))
}

/// The code of `account`.
pub fn code_of(account: &Account) -> Vec<u8> {
    if account.code_hash == [0; 32] {
        return Vec::new();
    }
    state::get_raw(&state::code_key(&account.code_hash)).unwrap_or_default()
}

/// Storage slot of `address`.
pub fn storage(address: &Address, slot: &Hash) -> Hash {
    state::get_raw(&state::slot_key(address, slot)).and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok()).unwrap_or([0; 32])
}
