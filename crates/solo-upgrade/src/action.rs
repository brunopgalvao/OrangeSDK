//! Upgrade actions: what a transaction to [`UPGRADE_ADDRESS`] carries as
//! calldata, encoded exactly as the Solidity ABI encodes calls to
//!
//! ```solidity
//! interface ISoloUpgrades {
//!     function stage(bytes32 codeHash, uint32 index, bytes calldata chunk) external;
//!     function propose(bytes32 codeHash, uint64 activationHeight, uint64 requiredGates) external;
//!     function cancel(bytes32 codeHash) external;
//!     function signal(uint64 features) external;
//!     event UpgradeProposed(bytes32 indexed codeHash, uint64 activationHeight, uint64 requiredGates);
//!     event UpgradeCancelled(bytes32 indexed codeHash);
//! }
//! ```
//!
//! so `cast send`, wallets and every Ethereum library can produce them
//! (spec 13 §2). Decoding is strict: only the canonical encoding of a call
//! within the limits below is an action.

use alloc::vec;
use alloc::vec::Vec;

use solo_abi::chain::Log;
use solo_abi::codec::Seq;
use solo_abi::types::Hash;

use crate::{CHUNK_SIZE, MAX_CHUNKS, UPGRADE_ADDRESS};

/// Function selectors: the first four bytes of `keccak256` of each signature.
pub mod selector {
    /// `stage(bytes32,uint32,bytes)`.
    pub const STAGE: [u8; 4] = [0x64, 0x63, 0x9a, 0x2e];
    /// `propose(bytes32,uint64,uint64)`.
    pub const PROPOSE: [u8; 4] = [0x15, 0x29, 0xd2, 0x82];
    /// `cancel(bytes32)`.
    pub const CANCEL: [u8; 4] = [0xc4, 0xd2, 0x52, 0xf5];
    /// `signal(uint64)`.
    pub const SIGNAL: [u8; 4] = [0xf5, 0x2e, 0xc6, 0x58];
}

/// Event topics: `keccak256` of each event signature.
pub mod event {
    use solo_abi::types::Hash;

    /// `UpgradeProposed(bytes32,uint64,uint64)`.
    pub const PROPOSED: Hash = [
        0x75, 0xdb, 0xee, 0xe3, 0x69, 0x13, 0xcb, 0x7f, 0xf6, 0xf4, 0x21, 0x49, 0xba, 0xdf, 0x5a,
        0x16, 0x93, 0x25, 0x4f, 0x42, 0x75, 0xc4, 0x8f, 0x63, 0x57, 0xf2, 0x36, 0x7c, 0x19, 0xf4,
        0x09, 0x81,
    ];
    /// `UpgradeCancelled(bytes32)`.
    pub const CANCELLED: Hash = [
        0x35, 0x81, 0xf2, 0x52, 0x6e, 0x53, 0xa2, 0x76, 0xef, 0xfa, 0x51, 0x16, 0xf0, 0x57, 0x95,
        0x62, 0xb2, 0x39, 0x47, 0xcb, 0xd7, 0x5f, 0xba, 0xbd, 0xeb, 0x60, 0x49, 0xaa, 0x7f, 0x5c,
        0x50, 0xe6,
    ];
}

/// One action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Stores chunk `index` of the code whose hash is `code_hash`.
    Stage {
        /// `keccak256` of the whole module.
        code_hash: Hash,
        /// Chunk index, below [`MAX_CHUNKS`].
        index: u32,
        /// One to [`CHUNK_SIZE`] bytes.
        chunk: Vec<u8>,
    },
    /// Schedules the staged code as the next kernel.
    Propose {
        /// `keccak256` of the staged module.
        code_hash: Hash,
        /// The last block the current kernel executes.
        activation_height: u64,
        /// Feature gates the new kernel needs, a bit per gate.
        required_gates: u64,
    },
    /// Withdraws the pending upgrade of `code_hash`.
    Cancel {
        /// The pending upgrade's code hash.
        code_hash: Hash,
    },
    /// A validator's host announces the feature gates it supports.
    Signal {
        /// A bit per supported gate.
        features: u64,
    },
}

/// A 32-byte big-endian ABI word holding `value`.
#[must_use]
pub fn word(value: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&value.to_be_bytes());
    w
}

/// The value of an ABI word of an unsigned type `bytes` wide, if every
/// higher byte is zero, as a canonical encoding requires.
fn uint(w: &[u8], bytes: usize) -> Option<u64> {
    let (high, low) = w.split_at(32 - bytes);
    let mut be = [0u8; 8];
    be[8 - bytes..].copy_from_slice(low);
    high.iter()
        .all(|b| *b == 0)
        .then_some(u64::from_be_bytes(be))
}

fn hash(w: &[u8]) -> Hash {
    w.try_into().expect("a word is 32 bytes")
}

impl Action {
    /// The calldata of this action.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Action::Stage {
                code_hash,
                index,
                chunk,
            } => {
                out.extend_from_slice(&selector::STAGE);
                out.extend_from_slice(code_hash);
                out.extend_from_slice(&word(u64::from(*index)));
                out.extend_from_slice(&word(96));
                out.extend_from_slice(&word(chunk.len() as u64));
                out.extend_from_slice(chunk);
                out.resize(
                    out.len() + chunk.len().next_multiple_of(32) - chunk.len(),
                    0,
                );
            }
            Action::Propose {
                code_hash,
                activation_height,
                required_gates,
            } => {
                out.extend_from_slice(&selector::PROPOSE);
                out.extend_from_slice(code_hash);
                out.extend_from_slice(&word(*activation_height));
                out.extend_from_slice(&word(*required_gates));
            }
            Action::Cancel { code_hash } => {
                out.extend_from_slice(&selector::CANCEL);
                out.extend_from_slice(code_hash);
            }
            Action::Signal { features } => {
                out.extend_from_slice(&selector::SIGNAL);
                out.extend_from_slice(&word(*features));
            }
        }
        out
    }

    /// The action `data` encodes, or `None` if it is not the canonical
    /// encoding of one within the limits.
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Action> {
        let (sel, body) = data.split_at_checked(4)?;
        let words = body.len() / 32;
        let w = |i: usize| &body[32 * i..32 * i + 32];
        match <[u8; 4]>::try_from(sel).ok()? {
            selector::STAGE if words >= 4 => {
                let index = u32::try_from(uint(w(1), 4)?)
                    .ok()
                    .filter(|i| *i < MAX_CHUNKS)?;
                let len = usize::try_from(uint(w(3), 4)?)
                    .ok()
                    .filter(|n| (1..=CHUNK_SIZE).contains(n))?;
                let (chunk, padding) = body[128..].split_at_checked(len)?;
                let canonical = uint(w(2), 8) == Some(96)
                    && padding.len() == len.next_multiple_of(32) - len
                    && padding.iter().all(|b| *b == 0);
                canonical.then(|| Action::Stage {
                    code_hash: hash(w(0)),
                    index,
                    chunk: chunk.to_vec(),
                })
            }
            selector::PROPOSE if body.len() == 96 => Some(Action::Propose {
                code_hash: hash(w(0)),
                activation_height: uint(w(1), 8)?,
                required_gates: uint(w(2), 8)?,
            }),
            selector::CANCEL if body.len() == 32 => Some(Action::Cancel {
                code_hash: hash(w(0)),
            }),
            selector::SIGNAL if body.len() == 32 => Some(Action::Signal {
                features: uint(w(0), 8)?,
            }),
            _ => None,
        }
    }

    /// Whether the governance key authorizes this action; otherwise it is a
    /// validator's signal.
    #[must_use]
    pub fn is_governance(&self) -> bool {
        !matches!(self, Action::Signal { .. })
    }
}

/// The log `propose` emits.
#[must_use]
pub fn proposed_log(code_hash: &Hash, activation_height: u64, required_gates: u64) -> Log {
    let mut data = word(activation_height).to_vec();
    data.extend_from_slice(&word(required_gates));
    Log {
        address: UPGRADE_ADDRESS,
        topics: Seq(vec![event::PROPOSED, *code_hash]),
        data,
    }
}

/// The log `cancel` emits.
#[must_use]
pub fn cancelled_log(code_hash: &Hash) -> Log {
    Log {
        address: UPGRADE_ADDRESS,
        topics: Seq(vec![event::CANCELLED, *code_hash]),
        data: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use tiny_keccak::{Hasher, Keccak};

    use super::*;

    fn keccak(data: &[u8]) -> Hash {
        let mut k = Keccak::v256();
        k.update(data);
        let mut out = [0u8; 32];
        k.finalize(&mut out);
        out
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn selectors_and_topics_are_the_signature_hashes() {
        for (sel, sig) in [
            (selector::STAGE, "stage(bytes32,uint32,bytes)"),
            (selector::PROPOSE, "propose(bytes32,uint64,uint64)"),
            (selector::CANCEL, "cancel(bytes32)"),
            (selector::SIGNAL, "signal(uint64)"),
        ] {
            assert_eq!(sel, keccak(sig.as_bytes())[..4], "{sig}");
        }
        assert_eq!(
            event::PROPOSED,
            keccak(b"UpgradeProposed(bytes32,uint64,uint64)")
        );
        assert_eq!(event::CANCELLED, keccak(b"UpgradeCancelled(bytes32)"));
    }

    /// The calldata `cast calldata` produces for the same calls.
    #[test]
    fn encodings_match_the_solidity_abi() {
        let h = [0x11; 32];
        let stage = Action::Stage {
            code_hash: h,
            index: 7,
            chunk: vec![0xab, 0xcd, 0xef],
        };
        let expected = hex(concat!(
            "64639a2e",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "0000000000000000000000000000000000000000000000000000000000000007",
            "0000000000000000000000000000000000000000000000000000000000000060",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "abcdef0000000000000000000000000000000000000000000000000000000000",
        ));
        assert_eq!(stage.encode(), expected);
        let propose = Action::Propose {
            code_hash: h,
            activation_height: 1200,
            required_gates: 1,
        };
        let expected = hex(concat!(
            "1529d282",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "00000000000000000000000000000000000000000000000000000000000004b0",
            "0000000000000000000000000000000000000000000000000000000000000001",
        ));
        assert_eq!(propose.encode(), expected);
        let cancel = Action::Cancel { code_hash: h };
        assert_eq!(
            cancel.encode(),
            hex("c4d252f51111111111111111111111111111111111111111111111111111111111111111")
        );
        let signal = Action::Signal { features: 1 };
        assert_eq!(
            signal.encode(),
            hex("f52ec6580000000000000000000000000000000000000000000000000000000000000001")
        );
        for action in [&stage, &propose, &cancel, &signal] {
            assert_eq!(Action::decode(&action.encode()).as_ref(), Some(action));
        }
        assert!(stage.is_governance() && propose.is_governance() && cancel.is_governance());
        assert!(!signal.is_governance());
        // A chunk of a whole number of words carries no padding.
        let full = Action::Stage {
            code_hash: h,
            index: MAX_CHUNKS - 1,
            chunk: vec![1; CHUNK_SIZE],
        };
        assert_eq!(full.encode().len(), 4 + 128 + CHUNK_SIZE);
        assert_eq!(Action::decode(&full.encode()), Some(full));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn only_canonical_encodings_within_limits_decode() {
        let h = [0x22; 32];
        let stage = Action::Stage {
            code_hash: h,
            index: 1,
            chunk: vec![5; 40],
        }
        .encode();
        let mut bad = vec![
            Vec::new(),
            vec![0x64, 0x63, 0x9a],
            vec![0xde, 0xad, 0xbe, 0xef],
            stage[..4 + 96].to_vec(),
            // A missing padding byte.
            stage[..stage.len() - 1].to_vec(),
        ];
        let mut longer = stage.clone();
        longer.extend_from_slice(&[0; 32]);
        bad.push(longer);
        let mut dirty = stage.clone();
        *dirty.last_mut().unwrap() = 1;
        bad.push(dirty);
        // An index with a high byte set, at the limit; an offset other than 96;
        // a length of zero, above the limit, with a high byte set, past the data.
        let patch = |word: usize, value: &[u8; 32]| {
            let mut v = stage.clone();
            v[4 + 32 * word..4 + 32 * word + 32].copy_from_slice(value);
            v
        };
        let mut high = [0u8; 32];
        high[0] = 1;
        bad.push(patch(1, &high));
        bad.push(patch(1, &word(u64::from(MAX_CHUNKS))));
        bad.push(patch(2, &word(64)));
        bad.push(patch(2, &high));
        bad.push(patch(3, &word(0)));
        bad.push(patch(3, &word(CHUNK_SIZE as u64 + 1)));
        bad.push(patch(3, &high));
        bad.push(patch(3, &word(1_000)));
        let mut index_too_wide = word(0);
        index_too_wide[27] = 1;
        bad.push(patch(1, &index_too_wide));
        // Fixed-size calls of the wrong length or with out-of-range values.
        let propose = Action::Propose {
            code_hash: h,
            activation_height: 9,
            required_gates: 0,
        }
        .encode();
        bad.push(propose[..propose.len() - 1].to_vec());
        let mut wide = propose.clone();
        wide[4 + 32] = 1;
        bad.push(wide);
        let mut wide = propose.clone();
        wide[4 + 64] = 1;
        bad.push(wide);
        let cancel = Action::Cancel { code_hash: h }.encode();
        let mut long = cancel.clone();
        long.push(0);
        bad.push(long);
        let signal = Action::Signal { features: 3 }.encode();
        bad.push(signal[..20].to_vec());
        let mut wide = signal.clone();
        wide[4] = 1;
        bad.push(wide);
        for (i, data) in bad.iter().enumerate() {
            assert_eq!(Action::decode(data), None, "case {i}");
        }
        assert!(Action::decode(&stage).is_some());
    }

    #[test]
    fn logs() {
        let log = proposed_log(&[3; 32], 500, 1);
        assert_eq!(log.address, UPGRADE_ADDRESS);
        assert_eq!(log.topics.0, vec![event::PROPOSED, [3; 32]]);
        assert_eq!(log.data.len(), 64);
        assert_eq!(&log.data[..32], &word(500));
        assert_eq!(&log.data[32..], &word(1));
        let log = cancelled_log(&[4; 32]);
        assert_eq!(log.topics.0, vec![event::CANCELLED, [4; 32]]);
        assert!(log.data.is_empty());
        assert_eq!(uint(&word(u64::MAX), 8), Some(u64::MAX));
        assert_eq!(uint(&word(u64::from(u32::MAX) + 1), 4), None);
    }

    proptest! {
        #[test]
        fn stage_roundtrips(chunk in proptest::collection::vec(any::<u8>(), 1..300), index in 0..MAX_CHUNKS, h in any::<[u8; 32]>()) {
            let action = Action::Stage { code_hash: h, index, chunk };
            let data = action.encode();
            prop_assert_eq!(data.len() % 32, 4);
            prop_assert_eq!(Action::decode(&data), Some(action));
        }

        #[test]
        fn fixed_calls_roundtrip(a in any::<u64>(), b in any::<u64>(), h in any::<[u8; 32]>()) {
            for action in [Action::Propose { code_hash: h, activation_height: a, required_gates: b }, Action::Cancel { code_hash: h }, Action::Signal { features: a }] {
                prop_assert_eq!(Action::decode(&action.encode()), Some(action));
            }
        }
    }
}
