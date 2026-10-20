//! The Ethereum-to-Solo bridge (spec 18): at genesis, the light-client and
//! message-verifier modules behind their addresses, the checked checkpoint,
//! and the inbox contract at the inbox address; afterwards, the admission
//! checks of transactions to the three. Everything else is the modules'
//! (spec 16 native contracts) and the inbox contract's.

use alloc::vec::Vec;

use solo_abi::Decode;
use solo_abi::bridge_in::{INBOX_ADDRESS, LIGHT_CLIENT_ADDRESS, VERIFIER_ADDRESS};
use solo_abi::chain::{Account, GenesisParams};
use solo_abi::modules;
use solo_abi::types::{Genesis, Hash};
use solo_ethlc::client::{self, Storage};
use solo_ethlc::{Crypto, verifier};
use solo_guest::host;

use crate::state;
use crate::tx::Signed;

/// The inbox's runtime code, compiled by `tools/build-contracts.sh`.
const INBOX_CODE: &str = include_str!("../../../contracts/fixtures/SoloInbox.runtime");

/// A native contract's namespace in kernel state (spec 16 §2.3).
struct Namespace(solo_abi::types::Address);

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
        unsafe { host::__solo_import_hash_sha256(data.as_ptr(), data.len() as u32, out.as_mut_ptr()) };
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
        _ => solo_guest::trap(),
    };
    s.trim().as_bytes().chunks(2).map(|p| digit(p[0]) << 4 | digit(p[1])).collect()
}

/// Gives `address` `code`, stored by its `keccak256`, and nonce 1.
fn place(address: &solo_abi::types::Address, code: &[u8]) {
    let code_hash = state::keccak256(code);
    state::set_raw(&state::code_key(&code_hash), code);
    state::set_account(address, &Account { balance: 0, nonce: 1, code_hash });
}

/// Genesis (spec 18 §4.1). With a light-client module in the parameters,
/// the light-client and verifier addresses become native contracts running
/// their modules and the inbox address gets the inbox contract; the
/// checkpoint is checked and written to the light client's namespace, the
/// verifier's configuration to its own. Traps when any of the three
/// addresses is allocated, a module is empty or longer than a storage
/// value, or the configuration or checkpoint cannot work.
pub fn init(genesis: &Genesis) {
    let params = GenesisParams::from_bytes(&genesis.params).unwrap_or_else(|_| solo_guest::trap());
    let bridge = params.bridge_in;
    if bridge.light_client.is_empty() {
        return;
    }
    let ours = [LIGHT_CLIENT_ADDRESS, VERIFIER_ADDRESS, INBOX_ADDRESS];
    let allocated = params.allocations.0.iter().any(|a| ours.contains(&a.address));
    let sizes_ok = [&bridge.light_client, &bridge.verifier].iter().all(|m| !m.is_empty() && m.len() <= modules::MAX_MODULE_SIZE);
    if allocated || !sizes_ok {
        solo_guest::trap();
    }
    for (address, module) in [(LIGHT_CLIENT_ADDRESS, &bridge.light_client), (VERIFIER_ADDRESS, &bridge.verifier)] {
        let code_hash = state::keccak256(module);
        state::set_raw(&state::code_key(&code_hash), module);
        place(&address, &modules::designator(&code_hash));
    }
    place(&INBOX_ADDRESS, &unhex(INBOX_CODE));
    let governance = params.upgrades.governance;
    if client::genesis(&HostCrypto, &mut Namespace(LIGHT_CLIENT_ADDRESS), &bridge, governance).is_err() {
        solo_guest::trap();
    }
    verifier::genesis(&mut Namespace(VERIFIER_ADDRESS), &bridge, genesis.chain_id, governance);
}

/// Admission (spec 18 §7): a transaction to the light-client or inbox
/// address must pass the module's cheap checks.
pub fn admit(s: &Signed) -> Result<(), u32> {
    match s.tx.to {
        Some(to) => client::admit(&Namespace(LIGHT_CLIENT_ADDRESS), &Namespace(VERIFIER_ADDRESS), &to, s.tx.value, &s.tx.input),
        None => Ok(()),
    }
}
