//! Storage access and the state layout (`solo_abi::chain::keys`).

use alloc::vec::Vec;

use solo_abi::chain::{Account, BlockHeader, GenesisParams, Receipt, keys};
use solo_abi::types::{Address, Genesis, Hash};
use solo_abi::{Decode, Encode};
use solo_guest::host;

/// Reads a raw value.
pub fn get_raw(key: &[u8]) -> Option<Vec<u8>> {
    let mut buf = alloc::vec![0u8; 4096];
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

/// Writes a raw value.
pub fn set_raw(key: &[u8], value: &[u8]) {
    // SAFETY: valid pointers into our own buffers.
    unsafe { host::__solo_import_storage_set(key.as_ptr(), key.len() as u32, value.as_ptr(), value.len() as u32) };
}

/// Deletes a value.
pub fn delete(key: &[u8]) {
    // SAFETY: a valid pointer into our own buffer.
    unsafe { host::__solo_import_storage_delete(key.as_ptr(), key.len() as u32) };
}

/// Reads a decoded value, trapping on a corrupt encoding.
pub fn get<T: Decode>(key: &[u8]) -> Option<T> {
    get_raw(key).map(|b| T::from_bytes(&b).unwrap_or_else(|_| solo_guest::trap()))
}

/// Writes an encoded value.
pub fn set<T: Encode>(key: &[u8], value: &T) {
    set_raw(key, &value.to_bytes());
}

fn concat(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(prefix.len() + suffix.len());
    k.extend_from_slice(prefix);
    k.extend_from_slice(suffix);
    k
}

/// Key of an account.
pub fn account_key(address: &Address) -> Vec<u8> {
    concat(keys::ACCOUNT, address)
}

/// Key of a block header by height.
pub fn block_key(height: u64) -> Vec<u8> {
    concat(keys::BLOCK, &height.to_be_bytes())
}

/// The account at `address`, empty if absent.
pub fn account(address: &Address) -> Account {
    get(&account_key(address)).unwrap_or_default()
}

/// Stores an account.
pub fn set_account(address: &Address, account: &Account) {
    set(&account_key(address), account);
}

/// Chain id.
pub fn chain_id() -> u64 {
    get(keys::CHAIN_ID).unwrap_or(0)
}

/// Last executed height, or `None` before the first block.
pub fn height() -> Option<u64> {
    get(keys::HEIGHT)
}

/// Hash of the last executed block, zero before the first.
pub fn last_hash() -> Hash {
    get(keys::LAST_HASH).unwrap_or([0; 32])
}

/// Stores a block and its index entries.
pub fn put_block(header: &BlockHeader, hash: &Hash) {
    set(&block_key(header.height), header);
    set(&concat(keys::BLOCK_HASH, hash), &header.height);
    set(keys::HEIGHT, &header.height);
    set(keys::LAST_HASH, hash);
}

/// Block header by height.
pub fn block_by_number(height: u64) -> Option<BlockHeader> {
    get(&block_key(height))
}

/// Block header by hash.
pub fn block_by_hash(hash: &Hash) -> Option<BlockHeader> {
    let height: u64 = get(&concat(keys::BLOCK_HASH, hash))?;
    block_by_number(height)
}

/// Stores a receipt and the raw transaction.
pub fn put_receipt(tx_hash: &Hash, receipt: &Receipt, raw: &[u8]) {
    set(&concat(keys::RECEIPT, tx_hash), receipt);
    set_raw(&concat(keys::TX_RAW, tx_hash), raw);
}

/// Receipt by transaction hash.
pub fn receipt(tx_hash: &Hash) -> Option<Receipt> {
    get(&concat(keys::RECEIPT, tx_hash))
}

/// Raw transaction by hash.
pub fn transaction(tx_hash: &Hash) -> Option<Vec<u8>> {
    get_raw(&concat(keys::TX_RAW, tx_hash))
}

/// Genesis parameters as stored.
pub fn params() -> GenesisParams {
    get(b"meta/params").unwrap_or_default()
}

/// Key of contract code by its hash.
pub fn code_key(code_hash: &Hash) -> Vec<u8> {
    concat(keys::CODE, code_hash)
}

/// Key of a storage slot.
pub fn slot_key(address: &Address, slot: &Hash) -> Vec<u8> {
    let mut k = Vec::with_capacity(keys::SLOT.len() + 20 + 32);
    k.extend_from_slice(keys::SLOT);
    k.extend_from_slice(address);
    k.extend_from_slice(slot);
    k
}

/// Applies genesis: chain id, parameters, and the allocated accounts with
/// their code and storage. The stored parameters leave the allocations out:
/// the driver reads them on every step and the accounts already hold them.
///
/// Traps on an account with storage but neither code nor nonce. revm leaves
/// out EIP-7610, so a CREATE could land on such an account and its slots would
/// show through the new contract; refusing it here keeps every account with
/// storage out of a creation's reach (see `evm::commit`).
pub fn init(genesis: &Genesis) {
    set(keys::CHAIN_ID, &genesis.chain_id);
    let mut params = GenesisParams::from_bytes(&genesis.params).unwrap_or_else(|_| solo_guest::trap());
    let allocations = core::mem::take(&mut params.allocations.0);
    set(b"meta/params", &params);
    set_raw(b"meta/validators", &genesis.validators);
    for allocation in &allocations {
        let has_storage = allocation.storage.0.iter().any(|slot| slot.value != [0; 32]);
        if has_storage && allocation.code.is_empty() && allocation.nonce == 0 {
            solo_guest::trap();
        }
        let code_hash = if allocation.code.is_empty() {
            [0; 32]
        } else {
            let hash = keccak256(&allocation.code);
            set_raw(&code_key(&hash), &allocation.code);
            hash
        };
        set_account(&allocation.address, &Account { balance: allocation.balance, nonce: allocation.nonce, code_hash });
        for slot in &allocation.storage.0 {
            if slot.value != [0; 32] {
                set_raw(&slot_key(&allocation.address, &slot.key), &slot.value);
            }
        }
    }
    set(keys::FINALIZED, &0u64);
}

/// `keccak256` through the host.
pub fn keccak256(data: &[u8]) -> Hash {
    let mut out = [0u8; 32];
    // SAFETY: valid pointers into our own buffers.
    unsafe { host::__solo_import_hash_keccak256(data.as_ptr(), data.len() as u32, out.as_mut_ptr()) };
    out
}

/// The state commitment through the host (privileged `storage_commit`).
pub fn commit() -> Hash {
    let mut out = [0u8; 32];
    // SAFETY: a 32-byte destination.
    unsafe { host::__solo_import_storage_commit(out.as_mut_ptr()) };
    out
}
