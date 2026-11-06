//! The Solidity ABI of the light client and the inbox
//! (`contracts/IEthereumLightClient.sol`, `contracts/EthereumInbox.sol`):
//! selectors, error data, and the canonical encodings this crate reads.

use alloc::vec::Vec;

use orange_abi::types::Address;

use crate::Hash;
use crate::inbox::Message;

/// `submitUpdate(bytes)`.
pub const SUBMIT_UPDATE: [u8; 4] = [0xd1, 0x76, 0x7a, 0x4a];
/// `submitFinalityUpdate(bytes)`.
pub const SUBMIT_FINALITY_UPDATE: [u8; 4] = [0x7c, 0xe7, 0x59, 0x0d];
/// `setCheckpoint(bytes)`.
pub const SET_CHECKPOINT: [u8; 4] = [0xfa, 0x8d, 0x85, 0x8d];
/// `setDelay(uint64)`.
pub const SET_DELAY: [u8; 4] = [0xc1, 0x07, 0x33, 0x02];
/// `finalized()`.
pub const FINALIZED: [u8; 4] = [0xb3, 0xf0, 0x5b, 0x97];
/// `executionRoot(uint64)`.
pub const EXECUTION_ROOT: [u8; 4] = [0xe4, 0x77, 0x9d, 0xaa];
/// `delay()`.
pub const DELAY: [u8; 4] = [0x6a, 0x42, 0xb8, 0xf8];

/// The verifier's `consume(bytes32,uint64,address,address,uint64,bytes,bytes[],bytes[])`.
pub const CONSUME: [u8; 4] = [0x56, 0x60, 0x4c, 0x65];
/// `pause()`.
pub const PAUSE: [u8; 4] = [0x84, 0x56, 0xcb, 0x59];
/// `unpause()`.
pub const UNPAUSE: [u8; 4] = [0x3f, 0x4b, 0xa8, 0x3a];
/// `setRateLimit(uint64,uint64)`.
pub const SET_RATE_LIMIT: [u8; 4] = [0xe1, 0xe5, 0xcc, 0xa4];
/// `delivered(uint64)`.
pub const DELIVERED: [u8; 4] = [0x2f, 0x2b, 0x02, 0x89];
/// `paused()`.
pub const PAUSED: [u8; 4] = [0x5c, 0x97, 0x5a, 0xbb];
/// `rateLimit()`.
pub const RATE_LIMIT: [u8; 4] = [0x61, 0xe0, 0x8e, 0x72];
/// `setRecipientLimit(address,uint64)`.
pub const SET_RECIPIENT_LIMIT: [u8; 4] = [0xb4, 0x3b, 0x5e, 0xbc];
/// `recipientLimit(address)`.
pub const RECIPIENT_LIMIT: [u8; 4] = [0x86, 0xfa, 0x88, 0x6d];

/// The inbox's `deliver(uint64,uint64,address,address,uint64,bytes,bytes[],bytes[])`.
pub const DELIVER: [u8; 4] = [0x9a, 0x28, 0x8f, 0x33];

/// The outbox's `send(address,uint64,bytes)`, on Ethereum.
pub const SEND: [u8; 4] = [0xdd, 0x62, 0x4a, 0x88];

/// Error `UpdateRejected(uint8)`.
pub const UPDATE_REJECTED: [u8; 4] = [0xd0, 0x0c, 0xa2, 0x93];
/// Error `NotGovernance()`.
pub const NOT_GOVERNANCE: [u8; 4] = [0xb5, 0x6f, 0x93, 0x2c];
/// Error `NotInbox()`.
pub const NOT_INBOX: [u8; 4] = [0x72, 0x10, 0x9f, 0x77];
/// Error `Paused()`.
pub const PAUSED_ERROR: [u8; 4] = [0x9e, 0x87, 0xfa, 0xc8];
/// Error `AlreadyDelivered(uint64)`.
pub const ALREADY_DELIVERED: [u8; 4] = [0xf1, 0x23, 0x7c, 0xa2];
/// Error `RateLimited()`.
pub const RATE_LIMITED: [u8; 4] = [0x3f, 0x7b, 0x7a, 0x68];
/// Error `BadProof()`.
pub const BAD_PROOF: [u8; 4] = [0x7c, 0xa5, 0x5c, 0x77];
/// The inbox's error `UnknownBlock(uint64)`.
pub const UNKNOWN_BLOCK: [u8; 4] = [0xc5, 0xcf, 0xeb, 0x84];
/// The inbox's error `TooEarly(uint64)`.
pub const TOO_EARLY: [u8; 4] = [0xd6, 0x06, 0xd8, 0x3f];
/// The inbox's error `DeliveryFailed(bytes)`.
pub const DELIVERY_FAILED: [u8; 4] = [0xa5, 0xb6, 0x73, 0x5f];
/// The inbox's error `InsufficientGas(uint64)`.
pub const INSUFFICIENT_GAS: [u8; 4] = [0xc0, 0xa1, 0x81, 0x3d];

/// A `uint256` word holding `v`.
#[must_use]
pub fn word(v: u64) -> Hash {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// An `address` word.
#[must_use]
pub fn address_word(a: &Address) -> Hash {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(a);
    out
}

/// `selector ‖ words`: error data or a call.
#[must_use]
pub fn encode(selector: [u8; 4], words: &[Hash]) -> Vec<u8> {
    let mut out = selector.to_vec();
    for w in words {
        out.extend_from_slice(w);
    }
    out
}

/// The tail encoding of `bytes`: its length word and its data padded to whole words.
fn bytes_tail(b: &[u8]) -> Vec<u8> {
    let mut out = word(b.len() as u64).to_vec();
    out.extend_from_slice(b);
    out.resize(32 + b.len().div_ceil(32) * 32, 0);
    out
}

/// The tail encoding of `bytes[]`.
fn bytes_array_tail(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = word(items.len() as u64).to_vec();
    let tails: Vec<Vec<u8>> = items.iter().map(|i| bytes_tail(i)).collect();
    let mut offset = 32 * items.len();
    for t in &tails {
        out.extend_from_slice(&word(offset as u64));
        offset += t.len();
    }
    for t in &tails {
        out.extend_from_slice(t);
    }
    out
}

/// `selector ‖ abi.encode(bytes)`.
#[must_use]
pub fn encode_bytes_call(selector: [u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = encode(selector, &[word(32)]);
    out.extend_from_slice(&bytes_tail(data));
    out
}

/// The `bytes` argument of a canonical `selector ‖ abi.encode(bytes)`.
#[must_use]
pub fn decode_bytes_call(data: &[u8]) -> Option<Vec<u8>> {
    let args = data.get(4..)?;
    let len = usize::try_from(read_u64(args.get(32..64)?)?).ok()?;
    let out = args.get(64..64usize.checked_add(len)?)?.to_vec();
    (encode_bytes_call([0; 4], &out)[4..] == *args).then_some(out)
}

fn read_u64(w: &[u8]) -> Option<u64> {
    w[..24]
        .iter()
        .all(|b| *b == 0)
        .then(|| u64::from_be_bytes(w[24..32].try_into().expect("8 bytes")))
}

/// The `address` argument word at `index` after the selector, if its high
/// bytes are zero.
#[must_use]
pub fn address_arg(data: &[u8], index: usize) -> Option<Address> {
    read_address(data.get(4 + 32 * index..36 + 32 * index)?)
}

fn read_address(w: &[u8]) -> Option<Address> {
    w[..12]
        .iter()
        .all(|b| *b == 0)
        .then(|| w[12..32].try_into().expect("20 bytes"))
}

/// A delivery: what the inbox's `deliver` and the verifier's `consume` carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// The first argument: for `deliver` the execution block number as a
    /// word, for `consume` the state root the proofs are against.
    pub anchor: Hash,
    /// The message.
    pub message: Message,
    /// The outbox account's proof, root node first.
    pub account_proof: Vec<Vec<u8>>,
    /// The message slot's proof in the outbox's storage, root node first.
    pub storage_proof: Vec<Vec<u8>>,
}

impl Delivery {
    /// `selector ‖ abi.encode(blockNumber, nonce, sender, recipient, gasLimit, payload, accountProof, storageProof)`.
    #[must_use]
    pub fn encode(&self, selector: [u8; 4]) -> Vec<u8> {
        let m = &self.message;
        let payload = bytes_tail(&m.payload);
        let account = bytes_array_tail(&self.account_proof);
        let storage = bytes_array_tail(&self.storage_proof);
        let head = 8 * 32;
        let words = [
            self.anchor,
            word(m.nonce),
            address_word(&m.sender),
            address_word(&m.recipient),
            word(m.gas_limit),
            word(head as u64),
            word((head + payload.len()) as u64),
            word((head + payload.len() + account.len()) as u64),
        ];
        let mut out = encode(selector, &words);
        out.extend_from_slice(&payload);
        out.extend_from_slice(&account);
        out.extend_from_slice(&storage);
        out
    }

    /// Decodes calldata with any selector, accepting only the canonical
    /// encoding, the one [`Delivery::encode`] and Solidity produce: zero
    /// high bytes in every integer and address word, each offset pointing
    /// where the previous part ends, zero padding, and nothing after the
    /// last part (spec 18 §5).
    ///
    /// Parts are read in order and each must start where the one before
    /// ended, so no two overlap and the decoded value is never larger than
    /// `data`: offsets that alias one large element are refused before
    /// anything is copied for them.
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Delivery> {
        let args = data.get(4..)?;
        let head = 8 * 32;
        offset_is(args, 5, head)?;
        let (payload, end) = bytes_at(args, head)?;
        offset_is(args, 6, end)?;
        let (account_proof, end) = array_at(args, end)?;
        offset_is(args, 7, end)?;
        let (storage_proof, end) = array_at(args, end)?;
        (end == args.len()).then_some(())?;
        Some(Delivery {
            anchor: args[..32].try_into().ok()?,
            message: Message {
                nonce: read_u64(&args[32..64])?,
                sender: read_address(&args[64..96])?,
                recipient: read_address(&args[96..128])?,
                gas_limit: read_u64(&args[128..160])?,
                payload,
            },
            account_proof,
            storage_proof,
        })
    }
}

/// The `uint64` word at byte `at` of `args`, as a length or an offset.
fn usize_at(args: &[u8], at: usize) -> Option<usize> {
    usize::try_from(read_u64(args.get(at..at.checked_add(32)?)?)?).ok()
}

/// Whether head word `index` is the offset `expected`.
fn offset_is(args: &[u8], index: usize, expected: usize) -> Option<()> {
    (usize_at(args, 32 * index)? == expected).then_some(())
}

/// The canonical `bytes` whose tail starts at `at`, and where its padded tail ends.
fn bytes_at(args: &[u8], at: usize) -> Option<(Vec<u8>, usize)> {
    let len = usize_at(args, at)?;
    let start = at + 32;
    let end = start.checked_add(len.checked_next_multiple_of(32)?)?;
    let padded = args.get(start..end)?;
    padded[len..]
        .iter()
        .all(|b| *b == 0)
        .then(|| (padded[..len].to_vec(), end))
}

/// The canonical `bytes[]` whose tail starts at `at`, and where it ends:
/// element `i`'s offset must be where element `i - 1` ended (the first,
/// just past the offsets).
fn array_at(args: &[u8], at: usize) -> Option<(Vec<Vec<u8>>, usize)> {
    let count = usize_at(args, at)?;
    let base = at + 32;
    // The offsets must be in the data, which bounds `count` before the loop.
    let mut end = base.checked_add(count.checked_mul(32)?)?;
    args.get(base..end)?;
    let mut items = Vec::new();
    for i in 0..count {
        if usize_at(args, base + 32 * i)? != end - base {
            return None;
        }
        let (item, next) = bytes_at(args, end)?;
        items.push(item);
        end = next;
    }
    Some((items, end))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn bytes_calls_round_trip_canonically() {
        for data in [vec![], vec![1], vec![2; 32], vec![3; 33]] {
            let call = encode_bytes_call(SUBMIT_UPDATE, &data);
            assert_eq!(call.len(), 4 + 64 + data.len().div_ceil(32) * 32);
            assert_eq!(decode_bytes_call(&call), Some(data));
        }
        let mut dirty = encode_bytes_call(SUBMIT_UPDATE, &[1]);
        *dirty.last_mut().unwrap() = 1;
        assert_eq!(decode_bytes_call(&dirty), None);
        let mut far = encode_bytes_call(SUBMIT_UPDATE, &[1]);
        far[4 + 63] = 0xFF;
        assert_eq!(decode_bytes_call(&far), None);
        let mut huge = encode_bytes_call(SUBMIT_UPDATE, &[1]);
        huge[4 + 32..4 + 64].fill(0xFF);
        assert_eq!(decode_bytes_call(&huge), None);
        assert_eq!(decode_bytes_call(&[1, 2]), None);
        assert_eq!(decode_bytes_call(&[0; 40]), None);
    }

    fn sample() -> Delivery {
        Delivery {
            anchor: word(7),
            message: Message {
                nonce: 3,
                sender: [1; 20],
                recipient: [2; 20],
                gas_limit: 50_000,
                payload: vec![9; 40],
            },
            account_proof: vec![vec![5; 33], vec![6]],
            storage_proof: vec![],
        }
    }

    #[test]
    fn deliveries_round_trip_and_only_canonically() {
        let d = sample();
        let call = d.encode(DELIVER);
        assert_eq!(&call[..4], &DELIVER);
        assert_eq!(Delivery::decode(&call), Some(d.clone()));
        // Every word changed in turn: either still canonical (a value word) or refused.
        for i in 0..(call.len() - 4) / 32 {
            for bit in [0x80, 0x01] {
                let mut changed = call.clone();
                changed[4 + 32 * i + if bit == 1 { 31 } else { 0 }] ^= bit;
                let decoded = Delivery::decode(&changed);
                assert!(
                    decoded.is_none() || decoded.as_ref() != Some(&d),
                    "word {i}"
                );
            }
        }
        // Trailing bytes, which Solidity's decoder reads past, are not canonical.
        let mut trailing = call.clone();
        trailing.extend_from_slice(&[0; 32]);
        assert_eq!(Delivery::decode(&trailing), None);
        assert_eq!(Delivery::decode(&call[..100]), None);
        assert_eq!(Delivery::decode(&call[..call.len() - 1]), None);
        assert_eq!(Delivery::decode(&[]), None);
        // Counts and offsets that point outside the data.
        let account_at = 4 + 8 * 32 + 32 + 64;
        let mut many = call.clone();
        many[account_at + 31] = 0xFF;
        assert_eq!(Delivery::decode(&many), None);
        let mut huge = call.clone();
        huge[account_at..account_at + 32].copy_from_slice(&word(u64::MAX));
        assert_eq!(Delivery::decode(&huge), None);
        let mut off = call.clone();
        off[4 + 6 * 32..4 + 7 * 32].copy_from_slice(&[0xFF; 32]);
        assert_eq!(Delivery::decode(&off), None);
        let mut elem = call.clone();
        elem[account_at + 32..account_at + 64].copy_from_slice(&word(u64::MAX));
        assert_eq!(Delivery::decode(&elem), None);
        // A length whose padded end overflows.
        let mut long = call.clone();
        long[4 + 8 * 32..4 + 9 * 32].copy_from_slice(&word(u64::MAX));
        assert_eq!(Delivery::decode(&long), None);
        // Non-zero padding after the payload.
        let mut dirty = call.clone();
        dirty[4 + 9 * 32 + 40] = 1;
        assert_eq!(Delivery::decode(&dirty), None);
        assert_eq!(word(1)[31], 1);
        assert_eq!(address_word(&[7; 20])[12..], [7; 20]);
    }

    /// Offsets that make every element of a proof the same large element:
    /// Solidity's decoder would read it once per offset; this one refuses
    /// the call before copying anything, so the work stays linear in the
    /// calldata (spec 18 §7).
    #[test]
    fn aliased_offsets_are_refused() {
        let big = vec![0x11; 4096];
        let d = Delivery {
            account_proof: vec![big.clone()],
            storage_proof: vec![],
            ..sample()
        };
        let call = d.encode(DELIVER);
        assert_eq!(Delivery::decode(&call), Some(d.clone()));
        // Rewrite the account proof as `n` offsets all pointing at one element.
        let account_at = 4 + 8 * 32 + 32 + 64;
        let n = 64usize;
        let mut aliased = call[..account_at].to_vec();
        aliased.extend_from_slice(&word(n as u64));
        for _ in 0..n {
            aliased.extend_from_slice(&word(32 * n as u64));
        }
        aliased.extend_from_slice(&bytes_tail(&big));
        let storage_at = aliased.len() - 4;
        aliased.extend_from_slice(&word(0));
        aliased[4 + 7 * 32..4 + 8 * 32].copy_from_slice(&word(storage_at as u64));
        assert_eq!(Delivery::decode(&aliased), None);
        // Element offsets that skip ahead or go back are refused the same way.
        let two = Delivery {
            account_proof: vec![vec![1], vec![2]],
            ..sample()
        }
        .encode(DELIVER);
        for second in [0u64, 32, 96, 160] {
            let mut moved = two.clone();
            moved[account_at + 64..account_at + 96].copy_from_slice(&word(second));
            assert_eq!(Delivery::decode(&moved), None, "{second}");
        }
    }
}
