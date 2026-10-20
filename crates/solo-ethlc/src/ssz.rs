//! SSZ merkleization (consensus-specs `ssz/simple-serialize.md`) over
//! SHA-256, and the Merkle branches the light client checks.

use alloc::vec::Vec;

use crate::{Crypto, Hash};

/// The zero chunk.
pub const ZERO: Hash = [0; 32];

/// The chunk of a `uint64`: little-endian, zero-padded.
#[must_use]
pub fn uint64(v: u64) -> Hash {
    let mut out = ZERO;
    out[..8].copy_from_slice(&v.to_le_bytes());
    out
}

/// `hash(a ‖ b)`.
#[must_use]
pub fn pair(c: &dyn Crypto, a: &Hash, b: &Hash) -> Hash {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    c.sha256(&buf)
}

/// `merkleize(chunks, limit)`: the root of the binary tree whose leaves are
/// `chunks` padded with zero chunks to `limit` rounded up to a power of
/// two. `chunks` must not exceed that width; callers pass fixed shapes.
///
/// # Panics
/// If `chunks` is longer than the width, a caller's bug.
#[must_use]
pub fn merkleize(c: &dyn Crypto, chunks: &[Hash], limit: usize) -> Hash {
    let width = limit.max(1).next_power_of_two();
    assert!(chunks.len() <= width, "more chunks than the limit");
    let mut layer: Vec<Hash> = chunks.to_vec();
    let mut zero = ZERO;
    let mut size = width;
    while size > 1 {
        if layer.is_empty() {
            layer.push(zero);
        }
        if layer.len() % 2 == 1 {
            layer.push(zero);
        }
        layer = layer
            .chunks_exact(2)
            .map(|p| pair(c, &p[0], &p[1]))
            .collect();
        zero = pair(c, &zero, &zero);
        size /= 2;
    }
    layer.first().copied().unwrap_or(zero)
}

/// `mix_in_length(root, length)`.
#[must_use]
pub fn mix_in_length(c: &dyn Crypto, root: &Hash, length: u64) -> Hash {
    pair(c, root, &uint64(length))
}

/// The chunks of a byte string: 32 bytes each, the last zero-padded.
#[must_use]
pub fn chunks(bytes: &[u8]) -> Vec<Hash> {
    bytes
        .chunks(32)
        .map(|chunk| {
            let mut out = ZERO;
            out[..chunk.len()].copy_from_slice(chunk);
            out
        })
        .collect()
}

/// The root of a `ByteVector[N]` with `N = bytes.len()`.
#[must_use]
pub fn byte_vector(c: &dyn Crypto, bytes: &[u8]) -> Hash {
    let chunks = chunks(bytes);
    merkleize(c, &chunks, chunks.len())
}

/// The root of a `ByteList[limit]` holding `bytes`.
#[must_use]
pub fn byte_list(c: &dyn Crypto, bytes: &[u8], limit: usize) -> Hash {
    let root = merkleize(c, &chunks(bytes), limit.div_ceil(32));
    mix_in_length(c, &root, bytes.len() as u64)
}

/// `is_valid_merkle_branch` for generalized index `gindex`: whether `leaf`
/// at that position under `root` is proven by `branch`, which must hold
/// exactly `floor(log2(gindex))` hashes, deepest first.
#[must_use]
pub fn verify_branch(
    c: &dyn Crypto,
    leaf: &Hash,
    branch: &[Hash],
    gindex: u64,
    root: &Hash,
) -> bool {
    let depth = (u64::BITS - 1 - gindex.max(1).leading_zeros()) as usize;
    if branch.len() != depth {
        return false;
    }
    let mut value = *leaf;
    for (i, sibling) in branch.iter().enumerate() {
        value = if gindex >> i & 1 == 1 {
            pair(c, sibling, &value)
        } else {
            pair(c, &value, sibling)
        };
    }
    value == *root
}

/// The branch proving the leaf at `index` of the tree over `leaves` (a
/// power of two of them), deepest first; for tests and tooling that build
/// SSZ trees.
#[must_use]
pub fn branch(c: &dyn Crypto, leaves: &[Hash], index: usize) -> Vec<Hash> {
    let mut layer = leaves.to_vec();
    let mut index = index;
    let mut out = Vec::new();
    while layer.len() > 1 {
        out.push(layer[index ^ 1]);
        layer = layer
            .chunks_exact(2)
            .map(|p| pair(c, &p[0], &p[1]))
            .collect();
        index /= 2;
    }
    out
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::testing::Native;

    #[test]
    fn merkleization_pads_with_zero_subtrees() {
        let c = Native;
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(merkleize(&c, &[], 0), ZERO);
        assert_eq!(merkleize(&c, &[a], 1), a);
        assert_eq!(merkleize(&c, &[a, b], 2), pair(&c, &a, &b));
        let z1 = pair(&c, &ZERO, &ZERO);
        assert_eq!(merkleize(&c, &[a], 4), pair(&c, &pair(&c, &a, &ZERO), &z1));
        assert_eq!(merkleize(&c, &[], 4), pair(&c, &z1, &z1));
        assert_eq!(
            merkleize(&c, &[a, b, a], 3),
            pair(&c, &pair(&c, &a, &b), &pair(&c, &a, &ZERO))
        );
        assert_eq!(uint64(0x0102), {
            let mut x = ZERO;
            x[0] = 2;
            x[1] = 1;
            x
        });
        assert_eq!(
            chunks(&[7; 33]),
            vec![[7; 32], {
                let mut x = ZERO;
                x[0] = 7;
                x
            }]
        );
        assert_eq!(byte_vector(&c, &[9; 20]), chunks(&[9; 20])[0]);
        let empty = byte_list(&c, &[], 32);
        assert_eq!(empty, mix_in_length(&c, &ZERO, 0));
        assert_eq!(
            byte_list(&c, &[5; 3], 32),
            mix_in_length(&c, &chunks(&[5; 3])[0], 3)
        );
    }

    #[test]
    #[should_panic(expected = "more chunks than the limit")]
    fn more_chunks_than_the_limit_is_a_bug() {
        let _ = merkleize(&Native, &[ZERO, ZERO, ZERO], 2);
    }

    #[test]
    fn branches_round_trip_and_reject_tampering() {
        let c = Native;
        let leaves: Vec<Hash> = (0u8..8).map(|i| [i; 32]).collect();
        let root = merkleize(&c, &leaves, 8);
        for i in 0..8 {
            let proof = branch(&c, &leaves, i);
            assert!(verify_branch(&c, &leaves[i], &proof, 8 + i as u64, &root));
            assert!(!verify_branch(
                &c,
                &leaves[i],
                &proof,
                8 + ((i as u64 + 1) % 8),
                &root
            ));
            assert!(!verify_branch(
                &c,
                &leaves[i],
                &proof[..2],
                8 + i as u64,
                &root
            ));
        }
        assert!(verify_branch(&c, &root, &[], 1, &root));
        assert!(!verify_branch(&c, &root, &[], 0, &leaves[0]));
    }
}
