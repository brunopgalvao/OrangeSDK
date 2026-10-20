//! Runtime for kernel modules and native contracts (spec 16).
//!
//! A module exports `main`. The kernel invokes it with a `ModuleCall` as the
//! input blob and reads a `ModuleOutput` back from the output blob. The kernel
//! always invokes a module static: storage writes do not go to the host but
//! into the output's write set, which the kernel applies, so that a native
//! contract's writes follow the EVM's revert rules. [`Store`] hides that:
//! reads see the module's own writes first, then the writes earlier calls of
//! the same transaction left pending, then the host's storage.
//!
//! ```ignore
//! fn handle(call: &ModuleCall, store: &mut Store) -> Result<Vec<u8>, Vec<u8>> { ... }
//! solo_module::module!(handle);
//! ```

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub use solo_abi;
use solo_abi::codec::Seq;
use solo_abi::modules::{ModuleCall, ModuleOutput, Write, status};
use solo_abi::{Decode, Encode};
use solo_guest::host;

/// A module's view of its storage namespace for one call.
#[derive(Debug, Default)]
pub struct Store {
    pending: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl Store {
    /// A store over the writes an earlier call left pending, oldest first.
    #[must_use]
    pub fn new(pending: &[Write]) -> Store {
        let mut store = Store::default();
        for w in pending {
            store.pending.insert(w.key.clone(), w.value.clone());
        }
        store
    }

    /// The value of `key`, or `None` if it is absent.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(v) = self.writes.get(key).or_else(|| self.pending.get(key)) {
            return v.clone();
        }
        host_get(key)
    }

    /// Sets `key` to `value`.
    pub fn set(&mut self, key: &[u8], value: &[u8]) {
        self.writes.insert(key.to_vec(), Some(value.to_vec()));
    }

    /// Deletes `key`.
    pub fn delete(&mut self, key: &[u8]) {
        self.writes.insert(key.to_vec(), None);
    }

    /// A `u64` stored little-endian under `key`, 0 if absent or malformed.
    #[must_use]
    pub fn get_u64(&self, key: &[u8]) -> u64 {
        self.get(key).and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok()).map_or(0, u64::from_le_bytes)
    }

    /// Stores `value` little-endian under `key`.
    pub fn set_u64(&mut self, key: &[u8], value: u64) {
        self.set(key, &value.to_le_bytes());
    }

    /// The write set, in key order.
    #[must_use]
    pub fn into_writes(self) -> Vec<Write> {
        self.writes.into_iter().map(|(key, value)| Write { key, value }).collect()
    }
}

fn host_get(key: &[u8]) -> Option<Vec<u8>> {
    let mut buf = alloc::vec![0u8; 256];
    // SAFETY: valid pointers into our own buffers.
    let len = unsafe { host::__solo_import_storage_get(key.as_ptr(), key.len() as u32, buf.as_mut_ptr(), buf.len() as u32) };
    if len == u64::from(u32::MAX) {
        return None;
    }
    let len = len as usize;
    if len > buf.len() {
        buf = alloc::vec![0u8; len];
        // SAFETY: as above, with a buffer large enough for the whole value.
        unsafe { host::__solo_import_storage_get(key.as_ptr(), key.len() as u32, buf.as_mut_ptr(), buf.len() as u32) };
    }
    buf.truncate(len);
    Some(buf)
}

/// `keccak256` through the host.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: valid pointers into our own buffers.
    unsafe { host::__solo_import_hash_keccak256(data.as_ptr(), data.len() as u32, out.as_mut_ptr()) };
    out
}

/// Runs `handler` on the input blob and writes its output blob: `Ok` returns
/// data and applies the store's writes, `Err` reverts with data and drops
/// them. An input that is no `ModuleCall` traps.
pub fn run(handler: fn(&ModuleCall, &mut Store) -> Result<Vec<u8>, Vec<u8>>) -> Vec<u8> {
    let input = solo_guest::input_vec();
    let Ok(call) = ModuleCall::from_bytes(&input) else { solo_guest::trap() };
    let mut store = match &call {
        ModuleCall::Call { pending, .. } => Store::new(&pending.0),
        _ => Store::default(),
    };
    let output = match handler(&call, &mut store) {
        Ok(data) => ModuleOutput { status: status::RETURN, data, writes: Seq(store.into_writes()) },
        Err(data) => ModuleOutput { status: status::REVERT, data, writes: Seq(Vec::new()) },
    };
    output.to_bytes()
}

/// Defines the module's `main` export over a handler
/// `fn(&ModuleCall, &mut Store) -> Result<Vec<u8>, Vec<u8>>`.
#[macro_export]
macro_rules! module {
    ($handler:path) => {
        solo_guest::solo_export!(main, |_input: &[u8]| -> alloc::vec::Vec<u8> { $crate::run($handler) });
    };
}

/// Solidity ABI helpers for native contracts.
pub mod abi {
    use alloc::vec::Vec;

    /// The 4-byte selector of `data`, if it has one.
    #[must_use]
    pub fn selector(data: &[u8]) -> Option<[u8; 4]> {
        data.get(..4)?.try_into().ok()
    }

    /// Argument word `index` after the selector.
    #[must_use]
    pub fn arg(data: &[u8], index: usize) -> Option<[u8; 32]> {
        data.get(4 + 32 * index..4 + 32 * (index + 1))?.try_into().ok()
    }

    /// A word as a `u64`, if its high 24 bytes are zero.
    #[must_use]
    pub fn as_u64(word: &[u8; 32]) -> Option<u64> {
        word[..24].iter().all(|b| *b == 0).then(|| u64::from_be_bytes(word[24..].try_into().expect("8 bytes")))
    }

    /// A word holding `value`.
    #[must_use]
    pub fn word(value: u128) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&value.to_be_bytes());
        w
    }

    /// A word holding an address.
    #[must_use]
    pub fn address(a: &[u8; 20]) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(a);
        w
    }

    /// The `bytes` argument whose offset word is argument `index`.
    #[must_use]
    pub fn bytes_arg(data: &[u8], index: usize) -> Option<Vec<u8>> {
        let body = data.get(4..)?;
        let offset = usize::try_from(as_u64(&arg(data, index)?)?).ok()?;
        let len_word: [u8; 32] = body.get(offset..offset.checked_add(32)?)?.try_into().ok()?;
        let len = usize::try_from(as_u64(&len_word)?).ok()?;
        let start = offset + 32;
        Some(body.get(start..start.checked_add(len)?)?.to_vec())
    }

    /// Encodes a custom error or call: a selector followed by words.
    #[must_use]
    pub fn encode(selector: [u8; 4], words: &[[u8; 32]]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 32 * words.len());
        out.extend_from_slice(&selector);
        for w in words {
            out.extend_from_slice(w);
        }
        out
    }
}
