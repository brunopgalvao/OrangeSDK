//! Messages from Ethereum (spec 18 §6): what `contracts/EthereumOutbox.sol`
//! stores for each message, where, and the proof that it did.

use alloc::vec::Vec;

use orange_abi::types::Address;
use orange_rlp::decode;

use crate::abi::{address_word, word};
use crate::mpt::{self, BadProof};
use crate::{Crypto, Hash};

/// The storage slot of the outbox's `messages` mapping.
pub const MESSAGES_SLOT: u64 = 0;

/// A message an `EthereumOutbox` sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Its nonce in the outbox, from 0.
    pub nonce: u64,
    /// The account that called `send` on Ethereum.
    pub sender: Address,
    /// The contract on the OrangeSDK chain it is for.
    pub recipient: Address,
    /// The gas the recipient gets to handle it, which the sender chose.
    pub gas_limit: u64,
    /// The payload.
    pub payload: Vec<u8>,
}

impl Message {
    /// `keccak256(abi.encode(orangeChainId, nonce, sender, recipient, gasLimit, payload))`,
    /// the value the outbox stores.
    #[must_use]
    pub fn hash(&self, c: &dyn Crypto, chain_id: u64) -> Hash {
        let mut data = Vec::new();
        for w in [
            word(chain_id),
            word(self.nonce),
            address_word(&self.sender),
            address_word(&self.recipient),
            word(self.gas_limit),
            word(6 * 32),
            word(self.payload.len() as u64),
        ] {
            data.extend_from_slice(&w);
        }
        data.extend_from_slice(&self.payload);
        data.resize(7 * 32 + self.payload.len().div_ceil(32) * 32, 0);
        c.keccak256(&data)
    }

    /// The outbox call that sends it: `send(recipient, gasLimit, payload)`,
    /// made on Ethereum by `sender`.
    #[must_use]
    pub fn send_call(&self) -> Vec<u8> {
        let mut out = crate::abi::encode(
            crate::abi::SEND,
            &[
                address_word(&self.recipient),
                word(self.gas_limit),
                word(3 * 32),
                word(self.payload.len() as u64),
            ],
        );
        out.extend_from_slice(&self.payload);
        out.resize(4 + 4 * 32 + self.payload.len().div_ceil(32) * 32, 0);
        out
    }
}

/// The storage slot of `messages[nonce]`: `keccak256(nonce ‖ MESSAGES_SLOT)`, both as words.
#[must_use]
pub fn slot(c: &dyn Crypto, nonce: u64) -> Hash {
    c.keccak256(&[word(nonce), word(MESSAGES_SLOT)].concat())
}

/// The storage root of `account` in the state under `state_root`, from its
/// proof (an account is `rlp([nonce, balance, storageRoot, codeHash])`).
///
/// # Errors
/// [`BadProof`], also when the account does not exist.
pub fn storage_root(
    c: &dyn Crypto,
    state_root: &Hash,
    account: &Address,
    proof: &[Vec<u8>],
) -> Result<Hash, BadProof> {
    let raw = mpt::verify(c, state_root, &c.keccak256(account), proof)?.ok_or(BadProof)?;
    let item = decode(&raw).map_err(|_| BadProof)?;
    match item.list() {
        Ok([_, _, root, _]) => root.array::<32>().map_err(|_| BadProof),
        _ => Err(BadProof),
    }
}

/// Whether the proofs show `message` stored by the outbox at `outbox` in
/// the state under `state_root`, for the OrangeSDK chain `chain_id`: its
/// hash (spec 18 §6.1) when they do.
///
/// # Errors
/// [`BadProof`] when they do not.
pub fn verify(
    c: &dyn Crypto,
    state_root: &Hash,
    outbox: &Address,
    chain_id: u64,
    message: &Message,
    account_proof: &[Vec<u8>],
    storage_proof: &[Vec<u8>],
) -> Result<Hash, BadProof> {
    let root = storage_root(c, state_root, outbox, account_proof)?;
    let raw = mpt::verify(
        c,
        &root,
        &c.keccak256(&slot(c, message.nonce)),
        storage_proof,
    )?
    .ok_or(BadProof)?;
    let stored = decode(&raw).and_then(|v| v.u256()).ok().ok_or(BadProof)?;
    let hash = message.hash(c, chain_id);
    if stored == hash {
        Ok(hash)
    } else {
        Err(BadProof)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::mpt::Trie;
    use crate::testing::Native;

    #[test]
    fn an_account_must_be_a_four_item_list() {
        let c = Native;
        for value in [
            vec![0xC3, 1, 2, 3],
            vec![0x83, 1, 2, 3],
            vec![0xC4, 0x80, 0x80, 0x81, 0x00],
        ] {
            let mut t = Trie::new();
            t.insert(&c.keccak256(&[7; 20]), &value);
            let proof = t.prove(&c, &c.keccak256(&[7; 20]));
            assert_eq!(
                storage_root(&c, &t.root(&c), &[7; 20], &proof),
                Err(BadProof)
            );
            // An account the state does not hold.
            let absent = t.prove(&c, &c.keccak256(&[8; 20]));
            assert_eq!(
                storage_root(&c, &t.root(&c), &[8; 20], &absent),
                Err(BadProof)
            );
        }
    }
}
