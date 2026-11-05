//! `eth-light-client`: the Ethereum light-client module (spec 18). The
//! kernel makes the light-client address `0x…454C` a native contract
//! running it (spec 16 §5); its interface is
//! `contracts/IEthereumLightClient.sol` and its logic `orange_ethlc::client`.
//! It checks sync-committee signatures with `bls12381_fast_aggregate_verify`,
//! a host function behind feature gate 1, so it loads, and the light client
//! works, only once that gate is active (spec 13 §8).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use orange_ethlc::client::{self, Context, Storage};
use orange_ethlc::{Crypto, Hash};
use orange_guest::host;
use orange_module::Store;
use orange_module::orange_abi::modules::ModuleCall;

/// Hashing and the signature check through the host.
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
        orange_module::keccak256(data)
    }

    fn fast_aggregate_verify(&self, keys: &[u8], msg: &Hash, signature: &[u8; 96]) -> bool {
        let count = (keys.len() / 48) as u32;
        // SAFETY: valid pointers into our own buffers of the sizes the host function reads.
        unsafe {
            host::__orange_import_bls12381_fast_aggregate_verify(
                keys.as_ptr(),
                count,
                msg.as_ptr(),
                32,
                signature.as_ptr(),
            ) == 0
        }
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
            let ctx = Context {
                caller: context.caller,
                timestamp: context.timestamp,
            };
            client::call(&HostCrypto, &mut Namespace(store), &ctx, data)
        }
        ModuleCall::Query { data } => client::query(&Namespace(store), data),
        // Never installed as a kernel module: no init, no hooks.
        _ => Err(Vec::new()),
    }
}

orange_module::module!(handle);
