//! Kernel modules (spec 16): installs at genesis and by governance, the
//! registry, block hooks, `module_query`, and invoking a module through the
//! host.

use alloc::vec;
use alloc::vec::Vec;

use solo_abi::chain::{Log, call_status, reason};
use solo_abi::codec::Seq;
use solo_abi::modules::{self, Install, ModuleCall, ModuleOutput, ModuleQuery, ModuleRecord, Write, capability, keys, status};
use solo_abi::types::{Address, Genesis, Hash, QueryResult};
use solo_abi::{Decode, Encode};
use solo_guest::host;

use crate::evm::{self, BlockFields, Message, Outcome};
use crate::state;
use crate::tx::Signed;

/// What an invoke of a module produced.
pub struct Invoked {
    /// The module's output, if it halted with a well-formed one.
    pub output: Option<ModuleOutput>,
    /// VM gas the module used.
    pub gas_used: u64,
}

/// `invoke` flag bits (spec 05 §4.4).
const PRIVILEGED: u64 = 1;
const STATIC: u64 = 2;

/// The VM gas this kernel instance has left.
pub fn gas_remaining() -> u64 {
    // SAFETY: no arguments.
    unsafe { host::__solo_import_gas_remaining() }
}

/// Invokes the module `code_hash` static under `namespace`, with the
/// `Privileged` set if `privileged`. The output counts only if the module
/// halted and its output decodes with a known status and a valid write set.
pub fn invoke(code_hash: &Hash, namespace: &Hash, input: &[u8], gas_limit: u64, privileged: bool) -> Invoked {
    let flags = STATIC | if privileged { PRIVILEGED } else { 0 };
    // SAFETY: valid pointers into our own buffers of the stated sizes.
    let result = unsafe { host::__solo_import_invoke(code_hash.as_ptr(), namespace.as_ptr(), input.as_ptr(), input.len() as u32, gas_limit, flags) };
    if result.a0 != 0 {
        return Invoked { output: None, gas_used: result.a1 };
    }
    // SAFETY: no arguments, then a buffer of the reported length.
    let bytes = unsafe {
        let len = host::__solo_import_invoke_output_len() as usize;
        let mut buf = vec![0u8; len];
        host::__solo_import_invoke_output_read(buf.as_mut_ptr(), 0, len as u32);
        buf
    };
    let output = ModuleOutput::from_bytes(&bytes).ok().filter(|o| (o.status == status::RETURN || o.status == status::REVERT) && modules::writes_valid(&o.writes.0));
    Invoked { output, gas_used: result.a1 }
}

/// The stored key a write of the module with `ns` names: its namespace in
/// front for a sandboxed module, the key as is for a privileged one.
fn stored_key(ns: Option<&Hash>, key: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(32 + key.len());
    if let Some(ns) = ns {
        k.extend_from_slice(ns);
    }
    k.extend_from_slice(key);
    k
}

/// Applies a write set in order.
pub fn apply(ns: Option<&Hash>, writes: &[Write]) {
    for w in writes {
        let key = stored_key(ns, &w.key);
        match &w.value {
            Some(v) => state::set_raw(&key, v),
            None => state::delete(&key),
        }
    }
}

/// The addresses of installed modules, ascending.
fn installed() -> Vec<Address> {
    state::get::<Seq<Address>>(keys::MODULES).map(|s| s.0).unwrap_or_default()
}

/// The record of the module at `address`.
pub fn record(address: &Address) -> Option<ModuleRecord> {
    state::get(&keys::module(address))
}

/// Runs a kernel-invoked entry (`init` or a hook) of an installed module and
/// applies its writes; whether it returned.
fn run_entry(address: &Address, record: &ModuleRecord, call: &ModuleCall) -> bool {
    let privileged = record.capabilities & capability::PRIVILEGED != 0;
    let ns = modules::namespace(address);
    let invoked = invoke(&record.code_hash, &ns, &call.to_bytes(), modules::HOOK_GAS, privileged);
    match invoked.output {
        Some(out) if out.status == status::RETURN => {
            apply((!privileged).then_some(&ns), &out.writes.0);
            true
        }
        _ => false,
    }
}

/// Addresses in the system range `0x0000…0000` to `0x0000…FFFF` hold the
/// precompiles and the system addresses; no module goes there.
fn system_address(address: &Address) -> bool {
    address[..18].iter().all(|b| *b == 0)
}

/// Installs the module `code_hash`, whose code is already at `code/` ‖ hash,
/// at `address`: runs its `init`, and only if that returns records it and
/// gives the account the designator as its code. Whether it was installed.
fn install(address: &Address, code_hash: &Hash, capabilities: u64, init: &[u8], height: u64) -> bool {
    let record = ModuleRecord { code_hash: *code_hash, capabilities, installed_at: height };
    if !run_entry(address, &record, &ModuleCall::Init { arg: init.to_vec() }) {
        return false;
    }
    let designator = modules::designator(code_hash);
    let designator_hash = state::keccak256(&designator);
    state::set_raw(&state::code_key(&designator_hash), &designator);
    let mut account = state::account(address);
    account.code_hash = designator_hash;
    state::set_account(address, &account);
    state::set(&keys::module(address), &record);
    let mut list = installed();
    if let Err(at) = list.binary_search(address) {
        list.insert(at, *address);
    }
    state::set(keys::MODULES, &Seq(list));
    true
}

/// Installs the genesis modules (spec 16 §4.1), after the allocations: each
/// module's bytes arrived as the code of the allocation at its address.
/// Traps on anything that would leave the chain without the module.
pub fn init(genesis: &Genesis) {
    for m in &genesis.modules.0 {
        let account = state::account(&m.address);
        let size = state::get_raw(&state::code_key(&m.code_hash)).map_or(0, |c| c.len());
        if m.capabilities & !capability::KNOWN != 0 || system_address(&m.address) || account.code_hash != m.code_hash || size == 0 || size > modules::MAX_MODULE_SIZE {
            solo_guest::trap();
        }
        if !install(&m.address, &m.code_hash, m.capabilities, &m.init, 0) {
            solo_guest::trap();
        }
    }
}

fn hooks(call: &ModuleCall) {
    for address in installed() {
        if let Some(record) = record(&address)
            && record.capabilities & capability::HOOKS != 0
        {
            // A hook that fails changes nothing; the block goes on.
            run_entry(&address, &record, call);
        }
    }
}

/// The `begin_block` hooks, before the block's first transaction.
pub fn begin_block(height: u64, timestamp_ms: u64) {
    hooks(&ModuleCall::BeginBlock { height, timestamp_ms });
}

/// The `end_block` hooks, after the block's last transaction.
pub fn end_block(height: u64, timestamp_ms: u64) {
    hooks(&ModuleCall::EndBlock { height, timestamp_ms });
}

/// The install a transaction to the module address carries, if it can run:
/// signed for this chain, no value, an `install` the governance account sent.
fn install_of(s: &Signed) -> Option<Install> {
    if s.tx.chain_id != Some(state::chain_id()) || s.tx.value != 0 {
        return None;
    }
    let governance = state::params().upgrades.governance;
    let install = Install::decode(&s.tx.input)?;
    (governance != [0; 20] && s.from == governance).then_some(install)
}

/// Admission: a transaction to the module address must be able to run.
pub fn admit(s: &Signed) -> Result<(), u32> {
    if s.tx.to == Some(modules::MODULE_ADDRESS) && install_of(s).is_none() { Err(reason::SYSTEM_ACTION) } else { Ok(()) }
}

/// Executes a transaction to the module address: a plain call through the
/// EVM for gas, fees and nonce, then the install, which reverts the
/// transaction if its checks fail (spec 16 §4.2).
pub fn run(s: &Signed, height: u64, message: Message, block: BlockFields) -> Outcome {
    let Some(install) = install_of(s) else {
        return Outcome { status: call_status::INVALID, gas_used: 0, output: Vec::new(), logs: Vec::new(), contract: None };
    };
    let mut outcome = evm::run(message, block, true);
    if outcome.status == call_status::SUCCESS {
        match governance_install(&install, height) {
            Some(log) => outcome.logs.push(log),
            None => outcome.status = call_status::REVERT,
        }
    }
    outcome
}

/// The staged code of `code_hash` (spec 13 §3): chunks from 0 up to the
/// first missing one, concatenated.
fn staged(code_hash: &Hash) -> Vec<u8> {
    let mut code = Vec::new();
    let mut index = 0;
    while let Some(chunk) = state::get_raw(&solo_upgrade::keys::chunk(code_hash, index)) {
        code.extend_from_slice(&chunk);
        index += 1;
    }
    code
}

fn governance_install(action: &Install, height: u64) -> Option<Log> {
    let target = &action.target;
    let account = state::account(target);
    if action.capabilities & !capability::HOOKS != 0 || system_address(target) || account.code_hash != [0; 32] || account.nonce != 0 || record(target).is_some() {
        return None;
    }
    let key = state::code_key(&action.code_hash);
    let present = state::get_raw(&key).is_some();
    if !present {
        let code = staged(&action.code_hash);
        if code.is_empty() || code.len() > modules::MAX_MODULE_SIZE || state::keccak256(&code) != action.code_hash {
            return None;
        }
        state::set_raw(&key, &code);
    }
    if !install(target, &action.code_hash, action.capabilities, &action.init, height) {
        if !present {
            state::delete(&key);
        }
        return None;
    }
    let mut caps = [0u8; 32];
    caps[24..].copy_from_slice(&action.capabilities.to_be_bytes());
    Some(Log { address: modules::MODULE_ADDRESS, topics: Seq(vec![modules::INSTALLED_TOPIC, modules::namespace(target), action.code_hash]), data: caps.to_vec() })
}

/// The module queries; `None` for any other method.
pub fn query(method: &str, params: &[u8]) -> Option<QueryResult> {
    let result = |status: u32, body: Vec<u8>| Some(QueryResult { status, body });
    match method {
        modules::query::MODULE => match Address::from_bytes(params) {
            Ok(address) => record(&address).map_or_else(|| result(1, Vec::new()), |r| result(0, r.to_bytes())),
            Err(_) => result(2, Vec::new()),
        },
        modules::query::MODULE_QUERY => {
            let Ok(q) = ModuleQuery::from_bytes(params) else { return result(2, Vec::new()) };
            let Some(code_hash) = modules::designated(&evm::code(&q.address)) else { return result(1, Vec::new()) };
            let call = ModuleCall::Query { data: q.data };
            let invoked = invoke(&code_hash, &modules::namespace(&q.address), &call.to_bytes(), gas_remaining() / 2, false);
            match invoked.output {
                Some(out) if out.status == status::RETURN => result(0, out.data),
                Some(out) => result(4, out.data),
                None => result(5, Vec::new()),
            }
        }
        _ => None,
    }
}
