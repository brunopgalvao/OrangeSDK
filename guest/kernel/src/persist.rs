//! Node-local persistence and the node's key (spec 05 §4.3, §4.6). Nothing
//! here is chain state: votes, proposals and the driver's own bookkeeping
//! differ between nodes and must never touch the state commitment.

use alloc::vec::Vec;

use solo_abi::chain::Signature;
use solo_abi::types::Hash;
use solo_abi::{Decode, Encode};
use solo_guest::host;

/// Reads a raw persisted value.
pub fn get_raw(key: &[u8]) -> Option<Vec<u8>> {
    let mut buf = alloc::vec![0u8; 4096];
    // SAFETY: valid pointers into our own buffers.
    let len = unsafe {
        host::__solo_import_persist_get(
            key.as_ptr(),
            key.len() as u32,
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    };
    if len == u64::from(u32::MAX) {
        return None;
    }
    let len = len as usize;
    if len > buf.len() {
        buf = alloc::vec![0u8; len];
        // SAFETY: as above, with a buffer large enough for the whole value.
        unsafe {
            host::__solo_import_persist_get(
                key.as_ptr(),
                key.len() as u32,
                buf.as_mut_ptr(),
                buf.len() as u32,
            )
        };
    }
    buf.truncate(len);
    Some(buf)
}

/// Writes a raw persisted value.
pub fn set_raw(key: &[u8], value: &[u8]) {
    // SAFETY: valid pointers into our own buffers.
    unsafe {
        host::__solo_import_persist_set(
            key.as_ptr(),
            key.len() as u32,
            value.as_ptr(),
            value.len() as u32,
        )
    };
}

/// Reads a decoded persisted value, trapping on a corrupt encoding.
pub fn get<T: Decode>(key: &[u8]) -> Option<T> {
    get_raw(key).map(|b| T::from_bytes(&b).unwrap_or_else(|_| solo_guest::trap()))
}

/// Writes an encoded persisted value.
pub fn set<T: Encode>(key: &[u8], value: &T) {
    set_raw(key, &value.to_bytes());
}

/// Signs a 32-byte message with the node's consensus key, if it has one.
pub fn sign(key_role: u64, msg: &Hash) -> Option<Signature> {
    let mut out = [0u8; 65];
    // SAFETY: valid pointers into our own buffers of the stated sizes.
    let n = unsafe { host::__solo_import_sign(key_role, msg.as_ptr(), 32, out.as_mut_ptr(), 65) };
    (n == 65).then_some(Signature(out))
}

/// The host's clock in milliseconds.
pub fn time_now() -> u64 {
    // SAFETY: no pointers.
    unsafe { host::__solo_import_time_now() }
}
