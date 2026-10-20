//! Ethereum legacy transactions (RLP, EIP-155).

use alloc::vec::Vec;

use solo_abi::chain::{TRANSFER_GAS, reason};
use solo_abi::types::{Address, Hash};
use solo_guest::host;
use solo_rlp::{Item, decode, encode_bytes, encode_list, encode_uint};

use crate::state::keccak256;

/// A decoded, sender-recovered transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub hash: Hash,
    pub from: Address,
    pub to: Address,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub value: u128,
}

impl Transfer {
    /// The most the sender can be charged: value plus gas limit times price.
    pub fn max_cost(&self) -> Option<u128> {
        self.value.checked_add(u128::from(self.gas_limit).checked_mul(self.gas_price)?)
    }

    /// What execution charges: value plus the intrinsic gas times price.
    pub fn cost(&self) -> Option<u128> {
        self.value.checked_add(u128::from(TRANSFER_GAS).checked_mul(self.gas_price)?)
    }
}

fn sighash(fields: &[Item<'_>], chain_id: Option<u64>) -> Hash {
    let mut payload = Vec::new();
    for f in &fields[..6] {
        encode_bytes(f.bytes().unwrap_or(&[]), &mut payload);
    }
    if let Some(id) = chain_id {
        encode_uint(u128::from(id), &mut payload);
        encode_uint(0, &mut payload);
        encode_uint(0, &mut payload);
    }
    let mut out = Vec::new();
    encode_list(&payload, &mut out);
    keccak256(&out)
}

/// The uncompressed public key (64 bytes) that signed `msg`, via the host.
pub fn recover_pubkey(msg: &Hash, sig: &[u8; 65]) -> Option<[u8; 64]> {
    let mut pubkey = [0u8; 64];
    // SAFETY: valid pointers into our own buffers of the stated sizes.
    let status = unsafe { host::__solo_import_secp256k1_recover(msg.as_ptr(), sig.as_ptr(), pubkey.as_mut_ptr()) };
    (status == 0).then_some(pubkey)
}

fn recover(msg: &Hash, r: &[u8; 32], s: &[u8; 32], recid: u8) -> Option<Address> {
    let mut sig = [0u8; 65];
    sig[..32].copy_from_slice(r);
    sig[32..64].copy_from_slice(s);
    sig[64] = recid;
    let pubkey = recover_pubkey(msg, &sig)?;
    let digest = keccak256(&pubkey);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[12..]);
    Some(address)
}

/// Decodes a raw legacy transaction and recovers its sender. The chain id
/// must match `expected_chain_id` for EIP-155 transactions; pre-155
/// transactions (v = 27 or 28) are accepted as Ethereum does.
pub fn decode_transfer(raw: &[u8], expected_chain_id: u64) -> Result<Transfer, u32> {
    let item = decode(raw).map_err(|_| reason::MALFORMED)?;
    let fields = item.list().map_err(|_| reason::MALFORMED)?;
    if fields.len() != 9 {
        return Err(reason::MALFORMED);
    }
    let nonce = fields[0].u64().map_err(|_| reason::MALFORMED)?;
    let gas_price = fields[1].u128().map_err(|_| reason::MALFORMED)?;
    let gas_limit = fields[2].u64().map_err(|_| reason::MALFORMED)?;
    let to_bytes = fields[3].bytes().map_err(|_| reason::MALFORMED)?;
    let value = fields[4].u128().map_err(|_| reason::MALFORMED)?;
    let data = fields[5].bytes().map_err(|_| reason::MALFORMED)?;
    let v = fields[6].u64().map_err(|_| reason::MALFORMED)?;
    let r = fields[7].array::<32>().map_err(|_| reason::MALFORMED)?;
    let s = fields[8].array::<32>().map_err(|_| reason::MALFORMED)?;
    if to_bytes.len() != 20 || !data.is_empty() {
        return Err(reason::UNSUPPORTED);
    }
    if gas_limit < TRANSFER_GAS {
        return Err(reason::GAS_TOO_LOW);
    }
    let (chain_id, recid) = match v {
        27 | 28 => (None, (v - 27) as u8),
        _ if v >= 35 => {
            let id = (v - 35) / 2;
            if id != expected_chain_id {
                return Err(reason::WRONG_CHAIN);
            }
            (Some(id), ((v - 35) % 2) as u8)
        }
        _ => return Err(reason::BAD_SIGNATURE),
    };
    let msg = sighash(fields, chain_id);
    let from = recover(&msg, &r, &s, recid).ok_or(reason::BAD_SIGNATURE)?;
    let mut to = [0u8; 20];
    to.copy_from_slice(to_bytes);
    Ok(Transfer { hash: keccak256(raw), from, to, nonce, gas_price, gas_limit, value })
}
