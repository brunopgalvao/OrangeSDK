//! The OrangeSDK-to-Ethereum half of the bridge (spec 17): the outbox system
//! address, the call it accepts, the message it records and where in chain
//! state it records it, the proposal anchor a light client reads, and the
//! finality-proof query a relayer makes.

use alloc::vec::Vec;

use crate::codec::{Decode, DecodeError, Decoder, Encode, Encoder};
use crate::types::{Address, Hash};

/// The outbox address, `0x0000000000000000000000000000000000004f42` (ASCII
/// `OB`). Any account or contract calls `send` on it (spec 17 §2).
pub const OUTBOX_ADDRESS: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x4F, 0x42,
];

/// Version byte that opens every message encoding.
pub const MESSAGE_VERSION: u8 = 1;

/// Largest payload a message carries, in bytes.
pub const MAX_PAYLOAD: usize = 4_096;

/// EVM gas of a `send`, before its payload words.
pub const SEND_GAS: u64 = 50_000;

/// EVM gas per started 32 bytes of a `send`'s payload.
pub const SEND_WORD_GAS: u64 = 300;

/// The EVM gas a `send` with a payload of `len` bytes costs (spec 17 §2.4).
#[must_use]
pub fn send_gas(len: usize) -> u64 {
    SEND_GAS + SEND_WORD_GAS * len.div_ceil(32) as u64
}

/// `send(uint64,address,bytes)`.
pub const SEND_SELECTOR: [u8; 4] = [0x67, 0x91, 0x4f, 0x6e];

/// `keccak256("MessageSent(uint64,address,uint64,address,uint256,bytes32,bytes)")`.
pub const MESSAGE_SENT: Hash = [
    0x8f, 0xab, 0xcd, 0xa9, 0xa3, 0xd5, 0x5f, 0xe5, 0xb0, 0x4a, 0xf5, 0x09, 0x47, 0x3a, 0x7e, 0x85,
    0xe1, 0x8d, 0x39, 0xae, 0x5e, 0x91, 0xb7, 0x39, 0xa4, 0x8a, 0x64, 0x7c, 0xa2, 0x6f, 0x10, 0x17,
];

/// The outbox's EVM storage slot holding the last nonce it assigned.
pub const NONCE_SLOT: Hash = [0; 32];

/// The outbox's EVM storage slot holding the hash of message `nonce`: the
/// nonce as a big-endian 256-bit word.
#[must_use]
pub fn message_slot(nonce: u64) -> Hash {
    word(nonce)
}

/// The chain-state key of message `nonce`: `slot/ ‖ outbox ‖ slot`, the key
/// of that EVM storage slot (spec 17 §3).
#[must_use]
pub fn message_key(nonce: u64) -> Vec<u8> {
    [
        crate::chain::keys::SLOT,
        &OUTBOX_ADDRESS[..],
        &message_slot(nonce)[..],
    ]
    .concat()
}

/// Byte offsets of the anchor in an encoded proposal (spec 08 §4): the
/// fields before it are fixed-size, so a contract reads it in place.
pub mod anchor {
    /// Offset of the proposal's height, little-endian `u64`.
    pub const HEIGHT: usize = 8;
    /// Offset of the anchor height, little-endian `u64`.
    pub const ANCHOR_HEIGHT: usize = 56;
    /// Offset of the anchor's 32-byte state root.
    pub const ANCHOR_ROOT: usize = 64;
    /// The shortest encoded proposal.
    pub const MIN_LENGTH: usize = 96;
}

/// Query methods of the bridge.
pub mod query {
    /// `u64` height → `FinalityProof` of the threshold certificate the node
    /// stored for that height; status 1 if it has none, 2 for bad params.
    pub const FINALITY_PROOF: &str = "finality_proof";
}

fn word(value: u64) -> Hash {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&value.to_be_bytes());
    w
}

fn address_word(address: &Address) -> Hash {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(address);
    w
}

fn value_word(value: u128) -> Hash {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&value.to_be_bytes());
    w
}

/// The value of an ABI word whose first 24 bytes are zero.
fn uint64(w: &[u8]) -> Option<u64> {
    let (high, low) = w.split_at(24);
    high.iter()
        .all(|b| *b == 0)
        .then(|| u64::from_be_bytes(low.try_into().unwrap_or_default()))
}

/// Appends `bytes` and zero padding to a multiple of 32 bytes.
fn padded(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes);
    out.resize(
        out.len() + bytes.len().next_multiple_of(32) - bytes.len(),
        0,
    );
}

/// A call of `send(destChainId, recipient, payload)` on the outbox.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SendCall {
    /// The chain the message is for.
    pub dest_chain_id: u64,
    /// The account on that chain that receives it.
    pub recipient: Address,
    /// What it carries.
    pub payload: Vec<u8>,
}

impl SendCall {
    /// The canonical calldata of this call.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 32 * 4 + self.payload.len().next_multiple_of(32));
        out.extend_from_slice(&SEND_SELECTOR);
        out.extend_from_slice(&word(self.dest_chain_id));
        out.extend_from_slice(&address_word(&self.recipient));
        out.extend_from_slice(&word(96));
        out.extend_from_slice(&word(self.payload.len() as u64));
        padded(&mut out, &self.payload);
        out
    }

    /// The call `data` encodes, if it is the canonical Solidity encoding of
    /// a `send` whose payload is at most [`MAX_PAYLOAD`] bytes (spec 17 §2.1).
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<SendCall> {
        let body = data.strip_prefix(&SEND_SELECTOR[..])?;
        if body.len() < 128 {
            return None;
        }
        let w = |i: usize| &body[32 * i..32 * i + 32];
        let dest_chain_id = uint64(w(0))?;
        let recipient_word = w(1);
        if recipient_word[..12].iter().any(|b| *b != 0) || uint64(w(2))? != 96 {
            return None;
        }
        let len = usize::try_from(uint64(w(3))?)
            .ok()
            .filter(|n| *n <= MAX_PAYLOAD)?;
        let rest = &body[128..];
        let canonical =
            rest.len() == len.next_multiple_of(32) && rest[len..].iter().all(|b| *b == 0);
        canonical.then(|| SendCall {
            dest_chain_id,
            recipient: recipient_word[12..].try_into().unwrap_or_default(),
            payload: rest[..len].to_vec(),
        })
    }

    /// Whether the outbox of chain `chain_id` accepts this call: another,
    /// non-zero destination chain and a non-zero recipient (spec 17 §2.2).
    #[must_use]
    pub fn acceptable(&self, chain_id: u64) -> bool {
        self.dest_chain_id != 0 && self.dest_chain_id != chain_id && self.recipient != [0; 20]
    }
}

/// A message the outbox recorded (spec 17 §3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    /// The OrangeSDK chain that sent it.
    pub source_chain_id: u64,
    /// Its nonce, from 1, in the order the outbox recorded messages.
    pub nonce: u64,
    /// The account that called `send`.
    pub sender: Address,
    /// The chain it is for.
    pub dest_chain_id: u64,
    /// The account on that chain that receives it.
    pub recipient: Address,
    /// The wei the `send` call carried, which the outbox keeps.
    pub value: u128,
    /// What it carries.
    pub payload: Vec<u8>,
}

impl Message {
    /// The message encoding, whose `keccak256` is the message hash:
    /// `version ‖ source_chain_id ‖ nonce ‖ sender ‖ dest_chain_id ‖
    /// recipient ‖ value ‖ payload`, integers big-endian, `value` 32 bytes,
    /// as Solidity's `abi.encodePacked` lays the same fields out.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(97 + self.payload.len());
        out.push(MESSAGE_VERSION);
        out.extend_from_slice(&self.source_chain_id.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.dest_chain_id.to_be_bytes());
        out.extend_from_slice(&self.recipient);
        out.extend_from_slice(&value_word(self.value));
        out.extend_from_slice(&self.payload);
        out
    }

    /// The topics of the `MessageSent` log of this message.
    #[must_use]
    pub fn topics(&self) -> [Hash; 4] {
        [
            MESSAGE_SENT,
            word(self.nonce),
            address_word(&self.sender),
            word(self.dest_chain_id),
        ]
    }

    /// The data of the `MessageSent` log of this message with hash `hash`:
    /// the ABI encoding of `(recipient, value, hash, payload)`.
    #[must_use]
    pub fn log_data(&self, hash: &Hash) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 5 + self.payload.len().next_multiple_of(32));
        out.extend_from_slice(&address_word(&self.recipient));
        out.extend_from_slice(&value_word(self.value));
        out.extend_from_slice(hash);
        out.extend_from_slice(&word(128));
        out.extend_from_slice(&word(self.payload.len() as u64));
        padded(&mut out, &self.payload);
        out
    }

    /// The message a `MessageSent` log of chain `source_chain_id` names,
    /// with the hash the log states; `None` if the log is not one.
    #[must_use]
    pub fn from_log(source_chain_id: u64, topics: &[Hash], data: &[u8]) -> Option<(Message, Hash)> {
        let [topic, nonce, sender, dest] = topics else {
            return None;
        };
        if *topic != MESSAGE_SENT
            || sender[..12].iter().any(|b| *b != 0)
            || data.len() < 160
            || data[..12].iter().any(|b| *b != 0)
            || data[32..48].iter().any(|b| *b != 0)
        {
            return None;
        }
        let len = usize::try_from(uint64(&data[128..160])?)
            .ok()
            .filter(|n| *n <= MAX_PAYLOAD)?;
        if uint64(&data[96..128])? != 128 || data.len() != 160 + len.next_multiple_of(32) {
            return None;
        }
        let message = Message {
            source_chain_id,
            nonce: uint64(nonce)?,
            sender: sender[12..].try_into().unwrap_or_default(),
            dest_chain_id: uint64(dest)?,
            recipient: data[12..32].try_into().unwrap_or_default(),
            value: u128::from_be_bytes(data[48..64].try_into().unwrap_or_default()),
            payload: data[160..160 + len].to_vec(),
        };
        Some((message, data[64..96].try_into().unwrap_or_default()))
    }
}

/// `query::FINALITY_PROOF`'s result: a threshold certificate and the
/// proposal it certifies, as a relayer submits them to the light client.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FinalityProof {
    /// The 89-byte certificate (spec 12 §7).
    pub certificate: Vec<u8>,
    /// The encoded proposal whose hash the certificate names (spec 08 §4).
    pub proposal: Vec<u8>,
}

impl Encode for FinalityProof {
    fn encode(&self, e: &mut Encoder) {
        self.certificate.encode(e);
        self.proposal.encode(e);
    }
}

impl Decode for FinalityProof {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(FinalityProof {
            certificate: d.get()?,
            proposal: d.get()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn constants() {
        assert_eq!(OUTBOX_ADDRESS[18..], [0x4F, 0x42]);
        assert_eq!(send_gas(0), 50_000);
        assert_eq!(send_gas(1), 50_300);
        assert_eq!(send_gas(33), 50_600);
        assert_eq!(send_gas(MAX_PAYLOAD), 88_400);
        assert_eq!(message_slot(5)[31], 5);
        let key = message_key(258);
        assert_eq!(key.len(), 57);
        assert!(key.starts_with(b"slot/"));
        assert_eq!(&key[5..25], &OUTBOX_ADDRESS);
        assert_eq!(&key[55..], &[1, 2]);
        assert_eq!(query::FINALITY_PROOF, "finality_proof");
        assert_eq!(crate::chain::reason::OUTBOX_MESSAGE, 14);
        assert_eq!(
            (
                anchor::HEIGHT,
                anchor::ANCHOR_HEIGHT,
                anchor::ANCHOR_ROOT,
                anchor::MIN_LENGTH
            ),
            (8, 56, 64, 96)
        );
    }

    #[test]
    fn send_calls_round_trip_and_reject_non_canonical_calldata() {
        let call = SendCall {
            dest_chain_id: 1,
            recipient: [7; 20],
            payload: vec![1, 2, 3],
        };
        let data = call.encode();
        assert_eq!(data.len(), 4 + 32 * 5);
        assert_eq!(SendCall::decode(&data), Some(call.clone()));
        let empty = SendCall {
            payload: vec![],
            ..call.clone()
        };
        assert_eq!(SendCall::decode(&empty.encode()), Some(empty));
        let at = |i: usize, b: u8| {
            let mut d = data.clone();
            d[i] = b;
            d
        };
        assert_eq!(SendCall::decode(&data[..100]), None);
        assert_eq!(SendCall::decode(&at(0, 0)), None);
        assert_eq!(SendCall::decode(&at(4, 1)), None);
        assert_eq!(SendCall::decode(&at(36, 1)), None);
        assert_eq!(SendCall::decode(&at(68 + 31, 64)), None);
        assert_eq!(SendCall::decode(&at(68, 1)), None);
        assert_eq!(SendCall::decode(&at(100, 1)), None);
        assert_eq!(SendCall::decode(&at(4 + 128 + 5, 1)), None);
        let mut long = data.clone();
        long.extend_from_slice(&[0; 32]);
        assert_eq!(SendCall::decode(&long), None);
        let big = SendCall {
            payload: vec![0; MAX_PAYLOAD + 1],
            ..call.clone()
        };
        assert_eq!(SendCall::decode(&big.encode()), None);
        let max = SendCall {
            payload: vec![9; MAX_PAYLOAD],
            ..call.clone()
        };
        assert_eq!(SendCall::decode(&max.encode()), Some(max));
        assert!(call.acceptable(5));
        assert!(!call.acceptable(1));
        assert!(
            !SendCall {
                dest_chain_id: 0,
                ..call.clone()
            }
            .acceptable(5)
        );
        assert!(
            !SendCall {
                recipient: [0; 20],
                ..call
            }
            .acceptable(5)
        );
    }

    #[test]
    fn messages_encode_packed_and_round_trip_through_their_log() {
        let m = Message {
            source_chain_id: 1337,
            nonce: 3,
            sender: [1; 20],
            dest_chain_id: 1,
            recipient: [2; 20],
            value: 5,
            payload: vec![0xAA; 33],
        };
        let e = m.encode();
        assert_eq!(e.len(), 97 + 33);
        assert_eq!(e[0], 1);
        assert_eq!(&e[1..9], &1337u64.to_be_bytes());
        assert_eq!(&e[9..17], &3u64.to_be_bytes());
        assert_eq!(&e[17..37], &[1; 20]);
        assert_eq!(&e[37..45], &1u64.to_be_bytes());
        assert_eq!(&e[45..65], &[2; 20]);
        assert_eq!(e[96], 5);
        let hash = [9; 32];
        let topics = m.topics();
        let data = m.log_data(&hash);
        assert_eq!(
            Message::from_log(1337, &topics, &data),
            Some((m.clone(), hash))
        );
        let bad = |topics: &[Hash], data: &[u8]| Message::from_log(1337, topics, data).is_none();
        assert!(bad(&topics[..3], &data));
        let mut t = topics;
        t[0] = [0; 32];
        assert!(bad(&t, &data));
        let mut t = topics;
        t[2][0] = 1;
        assert!(bad(&t, &data));
        let mut t = topics;
        t[1][0] = 1;
        assert!(bad(&t, &data));
        let mut t = topics;
        t[3][0] = 1;
        assert!(bad(&t, &data));
        assert!(bad(&topics, &data[..159]));
        let at = |i: usize| {
            let mut d = data.clone();
            d[i] = 1;
            d
        };
        assert!(bad(&topics, &at(0)));
        assert!(bad(&topics, &at(32)));
        assert!(bad(&topics, &at(127)));
        assert!(bad(&topics, &at(128)));
        assert!(bad(&topics, &data[..data.len() - 32]));
        let mut huge = data.clone();
        huge[128..160].copy_from_slice(&word(MAX_PAYLOAD as u64 + 1));
        assert!(bad(&topics, &huge));
    }

    #[test]
    fn finality_proofs_round_trip() {
        let p = FinalityProof {
            certificate: vec![1; 89],
            proposal: vec![2; 100],
        };
        assert_eq!(FinalityProof::from_bytes(&p.to_bytes()).unwrap(), p);
    }
}
