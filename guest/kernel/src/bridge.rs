//! The Ethereum-to-Orange bridge (spec 18): at genesis, the light-client and
//! message-verifier modules behind their addresses, the checked checkpoint,
//! and the inbox contract at the inbox address; afterwards, the admission
//! checks of transactions to the three, and the governed calls governance
//! makes to the two modules on the chain's behalf (spec 13 §9.5).
//! Everything else is the modules' (spec 16 native contracts) and the inbox
//! contract's.

use alloc::vec::Vec;

use orange_abi::bridge_in::{INBOX_ADDRESS, LIGHT_CLIENT_ADDRESS, VERIFIER_ADDRESS};
use orange_abi::chain::{Account, GenesisParams};
use orange_abi::codec::Seq;
use orange_abi::modules::{self, CallContext, ModuleCall, status};
use orange_abi::types::{Address, Genesis, Hash};
use orange_abi::{Decode, Encode};
use orange_ethlc::client::{self, Storage};
use orange_ethlc::{Crypto, verifier};
use orange_guest::host;

use crate::evm::BlockFields;
use crate::state;
use crate::tx::Signed;

/// The inbox's runtime code, compiled by `tools/build-contracts.sh`.
const INBOX_CODE: &str = include_str!("../../../contracts/build/EthereumInbox.bin-runtime");

/// A native contract's namespace in kernel state (spec 16 §2.3).
struct Namespace(orange_abi::types::Address);

impl Namespace {
    fn key(&self, key: &[u8]) -> Vec<u8> {
        [modules::namespace(&self.0).as_slice(), key].concat()
    }
}

impl Storage for Namespace {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        state::get_raw(&self.key(key))
    }

    fn set(&mut self, key: &[u8], value: Option<&[u8]>) {
        match value {
            Some(v) => state::set_raw(&self.key(key), v),
            None => state::delete(&self.key(key)),
        }
    }
}

/// Hashing through the host. The kernel never checks a signature: that is
/// the module's, through a gated host function the kernel does not import.
struct HostCrypto;

impl Crypto for HostCrypto {
    fn sha256(&self, data: &[u8]) -> Hash {
        let mut out = [0u8; 32];
        // SAFETY: valid pointers into our own buffers.
        unsafe {
            host::__orange_import_hash_sha256(data.as_ptr(), data.len() as u32, out.as_mut_ptr())
        };
        out
    }

    fn keccak256(&self, data: &[u8]) -> Hash {
        state::keccak256(data)
    }

    fn fast_aggregate_verify(&self, _: &[u8], _: &Hash, _: &[u8; 96]) -> bool {
        false
    }
}

fn unhex(s: &str) -> Vec<u8> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => orange_guest::trap(),
    };
    s.trim()
        .as_bytes()
        .chunks(2)
        .map(|p| digit(p[0]) << 4 | digit(p[1]))
        .collect()
}

/// Gives `address` `code`, stored by its `keccak256`, and nonce 1.
fn place(address: &orange_abi::types::Address, code: &[u8]) {
    let code_hash = state::keccak256(code);
    state::set_raw(&state::code_key(&code_hash), code);
    state::set_account(
        address,
        &Account {
            balance: 0,
            nonce: 1,
            code_hash,
        },
    );
}

/// Genesis (spec 18 §4.1). With a light-client module in the parameters,
/// the light-client and verifier addresses become native contracts running
/// their modules and the inbox address gets the inbox contract; the
/// checkpoint is checked and written to the light client's namespace, the
/// verifier's configuration to its own. Traps when any of the three
/// addresses is allocated, a module is empty or longer than a storage
/// value, or the configuration or checkpoint cannot work.
pub fn init(genesis: &Genesis) {
    let params =
        GenesisParams::from_bytes(&genesis.params).unwrap_or_else(|_| orange_guest::trap());
    let bridge = params.bridge_in;
    if bridge.light_client.is_empty() {
        return;
    }
    let ours = [LIGHT_CLIENT_ADDRESS, VERIFIER_ADDRESS, INBOX_ADDRESS];
    let allocated = params
        .allocations
        .0
        .iter()
        .any(|a| ours.contains(&a.address));
    let sizes_ok = [&bridge.light_client, &bridge.verifier]
        .iter()
        .all(|m| !m.is_empty() && m.len() <= modules::MAX_MODULE_SIZE);
    if allocated || !sizes_ok {
        orange_guest::trap();
    }
    for (address, module) in [
        (LIGHT_CLIENT_ADDRESS, &bridge.light_client),
        (VERIFIER_ADDRESS, &bridge.verifier),
    ] {
        let code_hash = state::keccak256(module);
        state::set_raw(&state::code_key(&code_hash), module);
        place(&address, &modules::designator(&code_hash));
    }
    place(&INBOX_ADDRESS, &unhex(INBOX_CODE));
    // The modules take their governance from the governance track in force
    // (spec 13 §9.5): the key, or the governance address.
    let governance = crate::governance::authority();
    if client::genesis(
        &HostCrypto,
        &mut Namespace(LIGHT_CLIENT_ADDRESS),
        &bridge,
        governance,
    )
    .is_err()
    {
        orange_guest::trap();
    }
    verifier::genesis(
        &mut Namespace(VERIFIER_ADDRESS),
        &bridge,
        genesis.chain_id,
        governance,
    );
}

/// Whether `address` is a governed native contract of the bridge: one of
/// its two addresses, holding a module designator (the bridge is on).
pub fn governed(address: &Address) -> bool {
    (*address == LIGHT_CLIENT_ADDRESS || *address == VERIFIER_ADDRESS)
        && modules::designated(&crate::evm::code(address)).is_some()
}

/// Names `governance` as the account both modules take governed calls
/// from, when the chain switches governance tracks (spec 13 §9.6). Nothing
/// happens on a chain without the bridge.
pub fn set_governance(governance: &Address) {
    let mut light = Namespace(LIGHT_CLIENT_ADDRESS);
    if let Some(cfg) = light
        .get(client::keys::CONFIG)
        .and_then(|b| client::Config::from_bytes(&b).ok())
    {
        light.set(
            client::keys::CONFIG,
            Some(
                &client::Config {
                    governance: *governance,
                    ..cfg
                }
                .to_bytes(),
            ),
        );
    }
    let mut messages = Namespace(VERIFIER_ADDRESS);
    if let Some(cfg) = messages
        .get(verifier::keys::CONFIG)
        .and_then(|b| verifier::Config::from_bytes(&b).ok())
    {
        messages.set(
            verifier::keys::CONFIG,
            Some(
                &verifier::Config {
                    governance: *governance,
                    ..cfg
                }
                .to_bytes(),
            ),
        );
    }
}

/// A governed call to the module at `target` (spec 18 §5.1–§5.2) made by
/// governance in `block` (spec 13 §9.5): the module runs sandboxed with
/// `gas` VM gas, as the governance account, with no value, and its writes
/// are applied if it returns. `None`, with nothing changed, if the address
/// is not a governed native contract, the module fails or reverts.
pub fn govern(target: &Address, data: &[u8], block: BlockFields, gas: u64) -> Option<()> {
    if !governed(target) {
        return None;
    }
    let code_hash = modules::designated(&crate::evm::code(target))?;
    let namespace = modules::namespace(target);
    let call = ModuleCall::Call {
        context: CallContext {
            address: *target,
            caller: crate::governance::authority(),
            value: 0,
            height: block.number,
            timestamp: block.timestamp,
            is_static: false,
        },
        data: data.to_vec(),
        pending: Seq(Vec::new()),
    };
    let invoked = crate::modules::invoke(&code_hash, &namespace, &call.to_bytes(), gas, false);
    match invoked.output {
        Some(out) if out.status == status::RETURN => {
            crate::modules::apply(Some(&namespace), &out.writes.0);
            Some(())
        }
        _ => None,
    }
}

/// Admission (spec 18 §7): a transaction to the light-client or inbox
/// address must pass the module's cheap checks.
pub fn admit(s: &Signed) -> Result<(), u32> {
    match s.tx.to {
        Some(to) => client::admit(
            &Namespace(LIGHT_CLIENT_ADDRESS),
            &Namespace(VERIFIER_ADDRESS),
            &to,
            s.tx.value,
            &s.tx.input,
        ),
        None => Ok(()),
    }
}
