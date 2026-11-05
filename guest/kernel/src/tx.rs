//! Transactions: decoding through `orange-eth` and sender recovery through the host.

use alloc::vec::Vec;

use orange_abi::chain::reason;
use orange_abi::types::{Address, Hash};
use orange_eth::Tx;
use orange_guest::host;

use crate::state::keccak256;

/// A decoded transaction with its sender and hash.
#[derive(Debug, Clone)]
pub struct Signed {
    /// The transaction.
    pub tx: Tx,
    /// Recovered sender.
    pub from: Address,
    /// The authority each authorization of a set-code transaction names, in
    /// order; `None` for one whose signature names none, which the EVM
    /// skips (EIP-7702). Empty for every other type.
    pub authorities: Vec<Option<Address>>,
}

/// The authority that signed an authorization, through the host's
/// `secp256k1_recover` (spec 20 §2.2).
pub fn authority(auth: &orange_eth::Authorization) -> Option<Address> {
    recover_address(&keccak256(&auth.signing_payload()), &auth.signature()?)
}

/// The uncompressed public key (64 bytes) that signed `msg`, via the host.
pub fn recover_pubkey(msg: &Hash, sig: &[u8; 65]) -> Option<[u8; 64]> {
    let mut pubkey = [0u8; 64];
    // SAFETY: valid pointers into our own buffers of the stated sizes.
    let status = unsafe {
        host::__orange_import_secp256k1_recover(msg.as_ptr(), sig.as_ptr(), pubkey.as_mut_ptr())
    };
    (status == 0).then_some(pubkey)
}

/// The address that signed `msg`.
pub fn recover_address(msg: &Hash, sig: &[u8; 65]) -> Option<Address> {
    let pubkey = recover_pubkey(msg, sig)?;
    let digest = keccak256(&pubkey);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[12..]);
    Some(address)
}

/// Decodes a raw transaction, checks its chain id and recovers its sender.
/// Pre-EIP-155 legacy transactions are accepted, as Ethereum does.
pub fn decode_signed(raw: &[u8], chain_id: u64) -> Result<Signed, u32> {
    let tx = orange_eth::decode(raw).map_err(|e| match e {
        orange_eth::Error::Malformed => reason::MALFORMED,
        orange_eth::Error::Unsupported => reason::UNSUPPORTED,
        orange_eth::Error::BadSignature => reason::BAD_SIGNATURE,
    })?;
    if tx.chain_id.is_some_and(|id| id != chain_id) {
        return Err(reason::WRONG_CHAIN);
    }
    let from = recover_address(&keccak256(&tx.signing_payload), &tx.signature())
        .ok_or(reason::BAD_SIGNATURE)?;
    let authorities = tx.authorization_list.iter().map(authority).collect();
    Ok(Signed {
        tx,
        from,
        authorities,
    })
}
