//! The Ethereum block header and receipt encodings (spec 20 §3): the header
//! the reference kernel derives from its block record, whose `keccak256` is
//! the block hash, and the receipt encoding its receipts root commits to.

use alloc::vec::Vec;

use orange_abi::chain::{BlockHeader, Log, Receipt};
use orange_rlp::{encode_bytes, encode_list, encode_uint};

use crate::mpt::EMPTY_ROOT;

/// `keccak256(rlp([]))`: the ommers hash of every post-merge header.
pub const EMPTY_OMMERS_HASH: [u8; 32] = [
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc, 0xd4, 0x1a,
    0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13, 0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
];

/// `sha256("")`: the EIP-7685 requests hash of a block without requests.
pub const EMPTY_REQUESTS_HASH: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// An Ethereum block header of the Prague and Osaka forks: the fifteen
/// original fields, the base fee (EIP-1559), the withdrawals root
/// (EIP-4895), blob gas (EIP-4844), the parent beacon root (EIP-4788) and
/// the requests hash (EIP-7685), in that order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Hash of the parent block.
    pub parent_hash: [u8; 32],
    /// Ommers hash.
    pub ommers_hash: [u8; 32],
    /// Fee recipient.
    pub beneficiary: [u8; 20],
    /// State root.
    pub state_root: [u8; 32],
    /// Root of the transactions trie.
    pub transactions_root: [u8; 32],
    /// Root of the receipts trie.
    pub receipts_root: [u8; 32],
    /// Bloom of every log of the block.
    pub logs_bloom: [u8; 256],
    /// Difficulty, zero since the merge.
    pub difficulty: u128,
    /// Block number.
    pub number: u64,
    /// Gas limit.
    pub gas_limit: u64,
    /// Gas used.
    pub gas_used: u64,
    /// Timestamp in seconds.
    pub timestamp: u64,
    /// Extra data.
    pub extra_data: Vec<u8>,
    /// Mix hash (`PREVRANDAO` since the merge).
    pub mix_hash: [u8; 32],
    /// Nonce, zero since the merge.
    pub nonce: [u8; 8],
    /// Base fee per gas.
    pub base_fee_per_gas: u64,
    /// Root of the withdrawals trie.
    pub withdrawals_root: [u8; 32],
    /// Blob gas used.
    pub blob_gas_used: u64,
    /// Excess blob gas.
    pub excess_blob_gas: u64,
    /// Parent beacon block root.
    pub parent_beacon_block_root: [u8; 32],
    /// Requests hash.
    pub requests_hash: [u8; 32],
}

impl Header {
    /// The header of an OrangeSDK block (spec 20 §3.1): the record's fields where it
    /// has them, the constants of a chain with no ommers, withdrawals, blobs,
    /// beacon chain or requests elsewhere, and the timestamp in seconds.
    #[must_use]
    pub fn of(block: &BlockHeader) -> Header {
        Header {
            parent_hash: block.parent_hash,
            ommers_hash: EMPTY_OMMERS_HASH,
            beneficiary: block.beneficiary,
            state_root: block.state_root,
            transactions_root: block.transactions_root,
            receipts_root: block.receipts_root,
            logs_bloom: block.logs_bloom.as_slice().try_into().unwrap_or([0; 256]),
            difficulty: 0,
            number: block.height,
            gas_limit: block.gas_limit,
            gas_used: block.gas_used,
            timestamp: block.timestamp_ms / 1000,
            extra_data: Vec::new(),
            mix_hash: [0; 32],
            nonce: [0; 8],
            base_fee_per_gas: block.base_fee,
            withdrawals_root: EMPTY_ROOT,
            blob_gas_used: 0,
            excess_blob_gas: 0,
            parent_beacon_block_root: [0; 32],
            requests_hash: EMPTY_REQUESTS_HASH,
        }
    }

    /// The header's RLP encoding.
    #[must_use]
    pub fn rlp(&self) -> Vec<u8> {
        let mut body = Vec::new();
        encode_bytes(&self.parent_hash, &mut body);
        encode_bytes(&self.ommers_hash, &mut body);
        encode_bytes(&self.beneficiary, &mut body);
        encode_bytes(&self.state_root, &mut body);
        encode_bytes(&self.transactions_root, &mut body);
        encode_bytes(&self.receipts_root, &mut body);
        encode_bytes(&self.logs_bloom, &mut body);
        encode_uint(self.difficulty, &mut body);
        for n in [self.number, self.gas_limit, self.gas_used, self.timestamp] {
            encode_uint(u128::from(n), &mut body);
        }
        encode_bytes(&self.extra_data, &mut body);
        encode_bytes(&self.mix_hash, &mut body);
        encode_bytes(&self.nonce, &mut body);
        encode_uint(u128::from(self.base_fee_per_gas), &mut body);
        encode_bytes(&self.withdrawals_root, &mut body);
        encode_uint(u128::from(self.blob_gas_used), &mut body);
        encode_uint(u128::from(self.excess_blob_gas), &mut body);
        encode_bytes(&self.parent_beacon_block_root, &mut body);
        encode_bytes(&self.requests_hash, &mut body);
        let mut out = Vec::new();
        encode_list(&body, &mut out);
        out
    }

    /// The block hash: `keccak256` of [`Header::rlp`].
    #[must_use]
    pub fn hash(&self, keccak: fn(&[u8]) -> [u8; 32]) -> [u8; 32] {
        keccak(&self.rlp())
    }
}

/// The hash of an OrangeSDK block: that of its Ethereum header (spec 20 §3.1).
#[must_use]
pub fn block_hash(block: &BlockHeader, keccak: fn(&[u8]) -> [u8; 32]) -> [u8; 32] {
    Header::of(block).hash(keccak)
}

/// Appends a log's RLP encoding, `[address, [topics], data]`.
pub fn encode_log(log: &Log, out: &mut Vec<u8>) {
    let mut fields = Vec::new();
    encode_bytes(&log.address, &mut fields);
    let mut topics = Vec::new();
    for topic in &log.topics.0 {
        encode_bytes(topic, &mut topics);
    }
    encode_list(&topics, &mut fields);
    encode_bytes(&log.data, &mut fields);
    encode_list(&fields, out);
}

/// The logs bloom of a receipt's logs.
#[must_use]
pub fn receipt_bloom(receipt: &Receipt, keccak: fn(&[u8]) -> [u8; 32]) -> [u8; 256] {
    let entries: Vec<(&[u8; 20], &[[u8; 32]])> = receipt
        .logs
        .0
        .iter()
        .map(|log| (&log.address, log.topics.0.as_slice()))
        .collect();
    crate::logs_bloom(&entries, keccak)
}

/// A receipt as Ethereum's receipts trie holds it (EIP-2718): for a typed
/// transaction its type byte, then `rlp([status, cumulative gas used,
/// bloom, logs])`; `bloom` is [`receipt_bloom`]'s.
#[must_use]
pub fn receipt_envelope(receipt: &Receipt, bloom: &[u8; 256]) -> Vec<u8> {
    let mut body = Vec::new();
    encode_uint(u128::from(receipt.status), &mut body);
    encode_uint(u128::from(receipt.cumulative_gas_used), &mut body);
    encode_bytes(bloom, &mut body);
    let mut logs = Vec::new();
    for log in &receipt.logs.0 {
        encode_log(log, &mut logs);
    }
    encode_list(&logs, &mut body);
    let mut out = Vec::new();
    if receipt.tx_type != 0 {
        out.push(receipt.tx_type);
    }
    encode_list(&body, &mut out);
    out
}

/// ORs `bloom` into `into`.
pub fn accrue(into: &mut [u8; 256], bloom: &[u8; 256]) {
    for (a, b) in into.iter_mut().zip(bloom) {
        *a |= b;
    }
}
