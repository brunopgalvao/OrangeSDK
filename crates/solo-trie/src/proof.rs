//! Proofs: their byte encoding and their verification against a root.

use alloc::vec::Vec;
use core::fmt;

use crate::{EMPTY, Hash, HashFn, MAX_DEPTH, bit, branch_hash, leaf_hash};

/// Terminal tag of a proof that ends at an empty subtree (spec 10 §5.1).
pub const TERMINAL_EMPTY: u8 = 0x00;

/// Terminal tag of a proof that ends at a leaf (spec 10 §5.1).
pub const TERMINAL_LEAF: u8 = 0x01;

/// Where a proof's walk down the key's path ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    /// An empty subtree: the key is absent.
    Empty,
    /// The subtree's single leaf. The key is present with `value_hash` when
    /// `path` is the key's path, and absent otherwise.
    Leaf {
        /// The leaf's path, `keccak256` of its key.
        path: Hash,
        /// `keccak256` of the leaf's value.
        value_hash: Hash,
    },
}

/// A proof for one key (spec 10 §5): the sibling hashes along the key's
/// path from the root down, and the subtree the path ends in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// `siblings[i]` is the hash of the child at depth `i + 1` on the other
    /// side of path bit `i`.
    pub siblings: Vec<Hash>,
    /// The subtree at depth `siblings.len()` on the key's path.
    pub terminal: Terminal,
}

/// Why a proof was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// The bytes are not a proof encoding: wrong length or unknown terminal tag.
    Malformed,
    /// More than [`MAX_DEPTH`] siblings.
    TooDeep,
    /// The terminal leaf's path leaves the key's path above the terminal, so
    /// the leaf cannot be where the proof puts it.
    WrongLeaf,
    /// The proof does not hash to the root.
    RootMismatch,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ProofError::Malformed => "malformed proof encoding",
            ProofError::TooDeep => "proof deeper than 256",
            ProofError::WrongLeaf => "terminal leaf off the key's path",
            ProofError::RootMismatch => "proof does not lead to the root",
        })
    }
}

impl core::error::Error for ProofError {}

impl Proof {
    /// Length of [`Proof::encode`]'s output.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let terminal = match self.terminal {
            Terminal::Empty => 1,
            Terminal::Leaf { .. } => 65,
        };
        2 + 32 * self.siblings.len() + terminal
    }

    /// The encoding of spec 10 §5.1: sibling count (u16, little-endian), the
    /// siblings top-down, the terminal tag, and for a leaf its path and value
    /// hash.
    ///
    /// # Panics
    /// If the proof has more than 65 535 siblings; a trie never produces more
    /// than [`MAX_DEPTH`].
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        let count = u16::try_from(self.siblings.len()).expect("at most MAX_DEPTH siblings");
        out.extend_from_slice(&count.to_le_bytes());
        for sibling in &self.siblings {
            out.extend_from_slice(sibling);
        }
        match &self.terminal {
            Terminal::Empty => out.push(TERMINAL_EMPTY),
            Terminal::Leaf { path, value_hash } => {
                out.push(TERMINAL_LEAF);
                out.extend_from_slice(path);
                out.extend_from_slice(value_hash);
            }
        }
        out
    }

    /// Decodes [`Proof::encode`]'s output, rejecting anything else.
    ///
    /// # Errors
    /// [`ProofError::TooDeep`] for a count above [`MAX_DEPTH`],
    /// [`ProofError::Malformed`] for a wrong length or terminal tag.
    pub fn decode(bytes: &[u8]) -> Result<Proof, ProofError> {
        let (count, rest) = bytes
            .split_first_chunk::<2>()
            .ok_or(ProofError::Malformed)?;
        let count = usize::from(u16::from_le_bytes(*count));
        if count > MAX_DEPTH {
            return Err(ProofError::TooDeep);
        }
        let (siblings, rest) = rest
            .split_at_checked(32 * count)
            .ok_or(ProofError::Malformed)?;
        let terminal = match rest {
            [TERMINAL_EMPTY] => Terminal::Empty,
            [TERMINAL_LEAF, body @ ..] => match body.as_chunks::<32>() {
                (&[path, value_hash], []) => Terminal::Leaf { path, value_hash },
                _ => return Err(ProofError::Malformed),
            },
            _ => return Err(ProofError::Malformed),
        };
        Ok(Proof {
            siblings: siblings.as_chunks::<32>().0.to_vec(),
            terminal,
        })
    }

    /// Verifies the proof for `key` against `root` (spec 10 §5.3). Returns
    /// the key's value hash if the proof shows it present, `None` if it
    /// shows it absent.
    ///
    /// # Errors
    /// Why the proof does not establish either for this key and root.
    pub fn verify(
        &self,
        hash: HashFn,
        root: &Hash,
        key: &[u8],
    ) -> Result<Option<Hash>, ProofError> {
        self.verify_hashed(hash, root, &hash(key))
    }

    /// [`Proof::verify`] for a key already hashed to its path.
    ///
    /// # Errors
    /// As [`Proof::verify`].
    pub fn verify_hashed(
        &self,
        hash: HashFn,
        root: &Hash,
        path: &Hash,
    ) -> Result<Option<Hash>, ProofError> {
        let depth = self.siblings.len();
        if depth > MAX_DEPTH {
            return Err(ProofError::TooDeep);
        }
        let (mut node, found) = match &self.terminal {
            Terminal::Empty => (EMPTY, None),
            Terminal::Leaf {
                path: leaf_path,
                value_hash,
            } => {
                if (0..depth).any(|i| bit(leaf_path, i) != bit(path, i)) {
                    return Err(ProofError::WrongLeaf);
                }
                let found = (leaf_path == path).then_some(*value_hash);
                (leaf_hash(hash, leaf_path, value_hash), found)
            }
        };
        for (i, sibling) in self.siblings.iter().enumerate().rev() {
            node = if bit(path, i) {
                branch_hash(hash, sibling, &node)
            } else {
                branch_hash(hash, &node, sibling)
            };
        }
        if node == *root {
            Ok(found)
        } else {
            Err(ProofError::RootMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Trie, keccak256};
    use alloc::string::ToString;
    use alloc::vec;

    #[test]
    fn errors_display() {
        for (e, text) in [
            (ProofError::Malformed, "malformed"),
            (ProofError::TooDeep, "256"),
            (ProofError::WrongLeaf, "off the key's path"),
            (ProofError::RootMismatch, "root"),
        ] {
            assert!(e.to_string().contains(text), "{e:?}");
            let _: &dyn core::error::Error = &e;
        }
    }

    #[test]
    fn decode_rejects_every_malformation() {
        let mut t = Trie::new();
        t.insert(b"a", b"1");
        t.insert(b"b", b"2");
        let leaf = t.prove(b"a").encode();
        let empty = Proof {
            siblings: vec![[7; 32]],
            terminal: Terminal::Empty,
        }
        .encode();
        assert_eq!(Proof::decode(&leaf).unwrap(), t.prove(b"a"));
        assert_eq!(Proof::decode(&empty).unwrap().siblings, vec![[7; 32]]);
        // Too short for the count, the siblings, or the terminal.
        assert_eq!(Proof::decode(&[1]), Err(ProofError::Malformed));
        assert_eq!(Proof::decode(&empty[..20]), Err(ProofError::Malformed));
        assert_eq!(Proof::decode(&empty[..34]), Err(ProofError::Malformed));
        assert_eq!(
            Proof::decode(&leaf[..leaf.len() - 1]),
            Err(ProofError::Malformed)
        );
        // Trailing bytes, an unknown tag, a count above 256.
        let mut long = empty.clone();
        long.push(0);
        assert_eq!(Proof::decode(&long), Err(ProofError::Malformed));
        let mut tag = empty.clone();
        tag[34] = 2;
        assert_eq!(Proof::decode(&tag), Err(ProofError::Malformed));
        assert_eq!(Proof::decode(&[1, 1, 0]), Err(ProofError::TooDeep));
        assert_eq!(leaf.len(), t.prove(b"a").encoded_len());
        assert_eq!(empty.len(), 35);
    }

    #[test]
    fn verify_rejects_impossible_shapes() {
        let mut t = Trie::new();
        t.insert(b"a", b"1");
        let root = t.root();
        let too_deep = Proof {
            siblings: vec![EMPTY; MAX_DEPTH + 1],
            terminal: Terminal::Empty,
        };
        assert_eq!(
            too_deep.verify(keccak256, &root, b"a"),
            Err(ProofError::TooDeep)
        );
        // A leaf whose path leaves the key's path above the terminal.
        let path = keccak256(b"a");
        let mut off = path;
        off[0] ^= 0x80;
        let wrong = Proof {
            siblings: vec![EMPTY],
            terminal: Terminal::Leaf {
                path: off,
                value_hash: keccak256(b"1"),
            },
        };
        assert_eq!(
            wrong.verify(keccak256, &root, b"a"),
            Err(ProofError::WrongLeaf)
        );
        assert_eq!(
            t.prove(b"a").verify(keccak256, &root, b"a"),
            Ok(Some(keccak256(b"1")))
        );
        assert_eq!(
            t.prove(b"a").verify(keccak256, &EMPTY, b"a"),
            Err(ProofError::RootMismatch)
        );
    }
}
