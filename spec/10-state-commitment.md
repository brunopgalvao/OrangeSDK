# 10 — State commitment (version 0)

## 1. Overview

The state commitment is the 32-byte root that `storage_commit` returns (05 §4.2) and that the reference kernel places in every block header as `state_root`. It is the root of a binary Merkle trie over the committed entries of the store: a sparse Merkle tree over 256-bit paths, `path = keccak256(key)`, in which an empty subtree hashes to zero and a subtree holding a single entry is that entry's leaf. `storage_proof` (05 §4.2) returns a proof for one key that verifies against the root alone, showing either the key's value or that the key is absent.

The construction has three properties this document relies on:

- The root is a function of the set of committed entries and nothing else: not the order of writes, not how they were grouped into calls, overlays or blocks.
- Changing one entry changes only the nodes on one path, so a host that keeps the trie can recompute the root in O(depth) hashes per changed key, where depth is about `log2(n)` for `n` entries and never more than 256.
- A proof is the sibling hashes along one path; verifying it needs only the key, the claimed value and the root.

## 2. Committed entries

Instances name keys of 1–64 bytes and values of 0–65 536 bytes (05 §4.2). A privileged instance's key is stored as it is named; a sandboxed instance's is stored behind the instance's 32-byte namespace (05 §4.2), so the keys of the store are 1–96 bytes. The trie sees the full stored key. The *committed entries* at a point of execution are every `(key, value)` visible to the calling instance there, meaning the base store with every open overlay layer applied (05 §4.2, §4.4), except entries whose key begins with the six bytes `local/` (`6c 6f 63 61 6c 2f`). Keys under `local/` are node-local bookkeeping (05 §4.3); they never affect the root and a proof for one shows it absent.

A key stored with an empty value is present: its leaf commits to the hash of the empty string, and a proof shows it present with that value.

## 3. Hash, paths and bits

- `H` is Keccak-256 with the original Keccak padding, as Ethereum uses it, not FIPS 202 SHA3-256. `H("")` is `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`.
- The *path* of a key `k` is `H(k)`, 256 bits. Every key, whatever its length, maps to a path of the same length, so keys need no length prefix or terminator and no path is a prefix of another. Two distinct keys share a path only through a Keccak collision.
- `bit(p, i)` for `0 ≤ i < 256` is bit `7 − (i mod 8)` of byte `⌊i / 8⌋` of `p`: the first bit of a path is the most significant bit of its first byte. A `0` bit selects the left child, a `1` bit the right.
- The *value hash* of a value `v` is `H(v)`.

## 4. Nodes and the root

For a set `S` of entries whose paths all share their first `d` bits, the subtree hash `T(S, d)` is:

| `S` | `T(S, d)` |
|---|---|
| empty | `EMPTY`, 32 zero bytes |
| one entry `(k, v)` | `leaf(H(k), H(v))` |
| two or more entries | `branch(T(S₀, d + 1), T(S₁, d + 1))`, where `S₀` holds the entries with `bit(H(k), d) = 0` and `S₁` the others |

```
leaf(path, value_hash) = H(0x00 || path || value_hash)      65-byte preimage
branch(left, right)    = H(0x01 || left || right)            65-byte preimage
```

The state commitment is `T(C, 0)` for the committed entries `C`. An empty store commits to `EMPTY`; a store with one entry commits to that entry's leaf.

Consequences of the definition:

- **Domain separation.** Leaf and branch preimages differ in their first byte and both are 65 bytes, so no leaf hash is a branch hash without a Keccak collision. `EMPTY` is not a hash of anything without a Keccak preimage of zero.
- **Canonical shape.** A subtree with one entry is that entry's leaf, placed as high as possible: a leaf's depth is one more than the longest prefix its path shares with any other committed path (0 when it is the only entry). A branch may have one empty child, when every entry below it shares bit `d`; it never has an empty child beside a leaf, and never two empty children.
- **Order independence.** `T` depends only on the set `C`. Any sequence of writes and deletions that ends with the same committed entries gives the same root, so two nodes that executed the same blocks commit to the same roots however their writes were batched.
- **Depth.** With `n` keys of independent random paths the expected depth of a leaf is about `log2(n)` plus a small constant. A leaf whose path shares `s` bits with another committed path sits at depth `s + 1`, under a chain of branches whose other side is mostly empty. Keys that share long prefixes take work to find, and how much depends on who picks them: a key sharing `s` bits with one given key costs about `2^s` hash evaluations, with any of `n` committed keys about `2^s / n`, and two new keys sharing `s` bits with each other, both picked by one party, about `2^(s/2)` by a birthday search. The last is the cheap case and the one to plan for. A contract can grind two of its own storage slots: `W` evaluations buy a pair sharing about `2·log2(W)` bits, so two leaves at that depth with about `2·log2(W) − log2(n)` more branches above them than random keys would have. For example, `2^40` evaluations, minutes on one GPU, put a pair at depth 81 where random keys among `n = 2^27` sit near 28. Each update of such a key rehashes its whole path, and each extra branch is a node the host keeps. The depth a pair buys grows only with the logarithm of the work spent on it, and depth never exceeds 256. So whatever the work, a committed key costs at most 256 branches, an update of it at most 257 node hashes besides its path and value hashes, and a proof of it at most 8 259 bytes (§5.1). Hosts provision for that worst case, and a kernel's state-growth pricing (05 §4.2) should not assume the random-key depth for keys a sender chooses.

## 5. Proofs

### 5.1 Structure and encoding

A proof for key `k` consists of `d` sibling hashes `siblings[0..d]` and a *terminal*, either `Empty` or `Leaf { path, value_hash }`. Its encoding is:

| Field | Bytes | Content |
|---|---|---|
| count | 2 | `d`, unsigned little-endian, `0 ≤ d ≤ 256` |
| siblings | `32 · d` | `siblings[0]` first |
| tag | 1 | `0x00` for `Empty`, `0x01` for `Leaf` |
| leaf path | 32 | `Leaf` only |
| leaf value hash | 32 | `Leaf` only |

An encoded proof is `3 + 32d` bytes with an `Empty` terminal and `67 + 32d` bytes with a `Leaf` terminal. A decoder MUST reject input shorter than 2 bytes, a count above 256, a total length other than the one the count and tag imply, and any other tag.

### 5.2 Generation

Start at the root of the trie of the committed entries, at depth 0, with no siblings. While the current node is a branch at depth `i`, append the hash of its child on the other side of `bit(H(k), i)` to `siblings`, and move to the child on the side of `bit(H(k), i)`. At the first node that is not a branch, stop: an empty subtree gives the terminal `Empty`, a leaf gives `Leaf` with that leaf's path and value hash. The leaf need not be `k`'s: a different leaf at that position proves `k` absent.

### 5.3 Verification

Input: a root `r`, a key `k`, a proof. Output: *present* with a value hash, *absent*, or *reject*.

1. Let `d` be the number of siblings. If `d > 256`, reject.
2. Let `p = H(k)`.
3. If the terminal is `Empty`, let `h = EMPTY` and the outcome be absent. If it is `Leaf { q, w }`: if `bit(q, i) ≠ bit(p, i)` for some `i < d`, reject; otherwise let `h = leaf(q, w)`, and the outcome be present with value hash `w` if `q = p`, absent if not.
4. For `i` from `d − 1` down to 0: `h = branch(h, siblings[i])` if `bit(p, i) = 0`, else `h = branch(siblings[i], h)`.
5. If `h ≠ r`, reject. Otherwise return the outcome.

A verifier holding `(k, v)` accepts it as committed when the outcome is present with value hash `H(v)`, and accepts `k` as uncommitted when the outcome is absent.

Why this is sound: by collision resistance, each `h` computed in step 4 equals the hash of the node at the same position of the trie that produced `r`, so the terminal is the node at depth `d` on `p`'s path. Domain separation keeps a leaf or `EMPTY` from standing in for a branch or the reverse. An empty subtree on `p`'s path holds no entry with `p`'s prefix, and a subtree that is a single leaf holds no entry but that leaf; either way an outcome of absent is correct. The verifier does not check that the proof's shape is canonical; it does not need to.

## 6. Maintaining the trie (informative)

Only the root and proofs are observable; how a host computes them is its own choice. The reference host keeps the trie of its base store with every node's hash cached, and updates it on every write that reaches the base store. An insert walks down the key's path and either fills an empty subtree, replaces a leaf with the same path, or splits a leaf with another path into a branch where the two paths first differ, with one single-child branch per shared bit above it. A deletion walks down, removes the leaf, and replaces any branch left with one leaf and an empty side by that leaf, which then rises past every branch it would otherwise sit alone under. Both rehash only the nodes they pass. Each overlay layer builds the trie of everything visible through it, a copy-on-write clone of the trie beneath with its own writes applied, the first time `storage_commit` or `storage_proof` needs it; it then keeps that trie and applies to it only the keys written since. So the hashing behind a root or a proof is O(depth) per key written since the previous one, however often either is called, and a discarded layer leaves the trie beneath it as it was. A layer merged into the base store hands its trie over instead of having its writes hashed again. The chain store of spec 22 persists the nodes themselves, content-addressed and reference-counted per kept root, and opens a trie from its root alone, reading a node when a path first passes through it; the roots are the same by §4.

## 7. Worked example

Three entries, keys and values one ASCII byte each: `a → 1`, `b → 2`, `c → 3`.

| Key | Path `H(key)` | Value hash `H(value)` | Leaf |
|---|---|---|---|
| `a` | `3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb` | `c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6` | `c3fd1ef33b82b45747a4dfeaa6bd2bb314df989be8ade3eb7e4738c78db82912` |
| `b` | `b5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510` | `ad7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5` | `5bc843c9d95183b878cfd5794d53c4c9d6e908fe1a6b20dccfd74dc0aa081e40` |
| `c` | `0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2` | `2a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4de` | `315a952a5f964923400b9628a78f149ee38cfa30fdafa297eca98eee688ddace` |

The paths begin `0011…` (`a`, byte `0x3a`), `1011…` (`b`, `0xb5`) and `0000…` (`c`, `0x0b`). Bit 0 puts `b` alone on the right. `a` and `c` share bit 1 (both 0), so the depth-1 branch on the left has an empty right child; they differ at bit 2, where `c` goes left and `a` right.

```
root = branch(n0, leaf_b)       = c263b0367df71e753bca510361673e7ea418ef6cbd2c8e10d5754d509aa23605
n0   = branch(n00, EMPTY)       = 1fe8b3b11661b5428f424fa077bc6943bb2b377c312de263d913ffc159db8069
n00  = branch(leaf_c, leaf_a)   = b600ff7b28e7cb984a9a124e17ac49a2a76d6474e0a7ff4a1ebcd147fe7d9ce8
```

Inserting the three in any order gives this root. The trie holding only `a → 1` has root `leaf_a`; the empty trie has root `EMPTY`.

Proof of `a` (present): three siblings, `leaf_b` at depth 0, `EMPTY` at depth 1, `leaf_c` at depth 2, and `a`'s leaf. 163 bytes:

```
0300
5bc843c9d95183b878cfd5794d53c4c9d6e908fe1a6b20dccfd74dc0aa081e40
0000000000000000000000000000000000000000000000000000000000000000
315a952a5f964923400b9628a78f149ee38cfa30fdafa297eca98eee688ddace
01
3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb
c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6
```

Proof of `d` (absent). `H(d) = f1918e8562236eb17adc8502332f4c9c82bc14e19bfc0aa10ab674ff75b3d2f3` begins with a 1 bit, so the walk ends at the leaf of `b`, whose path differs from `H(d)`. 99 bytes:

```
0100
1fe8b3b11661b5428f424fa077bc6943bb2b377c312de263d913ffc159db8069
01
b5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510
ad7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5
```

Proof of `k1` (absent). `H(k1) = 50826078203fe70dc5c60aa54c46fd03a1ff4023845c4acb1064f791419880c1` begins `01`, so the walk goes left at the root and right at `n0`, into the empty subtree. 67 bytes:

```
0200
5bc843c9d95183b878cfd5794d53c4c9d6e908fe1a6b20dccfd74dc0aa081e40
b600ff7b28e7cb984a9a124e17ac49a2a76d6474e0a7ff4a1ebcd147fe7d9ce8
00
```

`crates/solo-trie/tests/example.rs` asserts every value in this section.

## 8. Not in version 0

Proofs of several keys sharing siblings, compression of empty siblings in proofs, and historical roots for `storage_proof` (a proof from inside an instance is always against the state as it stands when it is called). The reference node keeps the tries of its recent blocks' roots, on disk when it has a data directory (spec 22), and serves this format through `eth_getProof` (spec 20 §4), in place of Ethereum's Merkle-Patricia proofs over a different trie.
