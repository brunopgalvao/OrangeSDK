//! `eth-message-verifier`: the message-verifier module (spec 18). The
//! kernel makes the verifier address `0x…454D` a native contract running it
//! (spec 16 §5); its interface is `contracts/IMessageVerifier.sol` and its
//! logic `solo_ethlc::verifier`. It needs no gated host function.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use solo_ethlc::client::{Context, Storage};
use solo_ethlc::{Crypto, Hash, verifier};
use solo_guest::host;
use solo_module::Store;
use solo_module::solo_abi::modules::ModuleCall;

/// Hashing through the host; this module checks no signature.
struct HostCrypto;

impl Crypto for HostCrypto {
    fn sha256(&self, data: &[u8]) -> Hash {
        let mut out = [0u8; 32];
        // SAFETY: valid pointers into our own buffers.
        unsafe { host::__solo_import_hash_sha256(data.as_ptr(), data.len() as u32, out.as_mut_ptr()) };
        out
    }

    fn keccak256(&self, data: &[u8]) -> Hash {
        solo_module::keccak256(data)
    }

    fn fast_aggregate_verify(&self, _: &[u8], _: &Hash, _: &[u8; 96]) -> bool {
        false
    }
}

/// The module's namespace, through the write-set store.
struct Namespace<'a>(&'a mut Store);

impl Storage for Namespace<'_> {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get(key)
    }

    fn set(&mut self, key: &[u8], value: Option<&[u8]>) {
        match value {
            Some(v) => self.0.set(key, v),
            None => self.0.delete(key),
        }
    }
}

fn handle(call: &ModuleCall, store: &mut Store) -> Result<Vec<u8>, Vec<u8>> {
    match call {
        ModuleCall::Call { context, data, .. } => {
            let ctx = Context { caller: context.caller, timestamp: context.timestamp };
            verifier::call(&HostCrypto, &mut Namespace(store), &ctx, data)
        }
        ModuleCall::Query { data } => verifier::query(&Namespace(store), data),
        // Never installed as a kernel module: no init, no hooks.
        _ => Err(Vec::new()),
    }
}

solo_module::module!(handle);
