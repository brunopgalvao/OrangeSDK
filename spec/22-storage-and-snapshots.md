# 22 — Storage and snapshots (version 0)

## 1. Overview

A node keeps its chain state across restarts. This document specifies what the reference host writes to disk under its data directory, when, and with what atomicity (§2–§4); what a restarted node does with it (§5); the snapshot record the kernel writes at every epoch boundary (§6); the snapshot file a node exports from that record, how a new node verifies one before it serves anything, and how it joins the chain from it (§7); what bounds the disk and what telemetry reports about it (§8). Codex ADR 0037 records the decisions.

Two stores sit side by side in the data directory. The *driver store* (spec 08 §7, codex ADR 0036: `driver.state` and `persist.log`) holds what the driver persists through `persist_*` and `PersistState`: node-local, synced before anything the node signs leaves it. The *chain store* (`chain.redb`, this document) holds the chain state the kernel reads and writes through the storage functions of spec 05 §4.2, the trie behind every header root the node still serves, the history window of spec 20 §5 and the block log of §5. The in-memory state of `solo dev` without `--data-dir` and of the simulator keeps the same contents in memory; everything observable (roots, proofs, queries at a height) is the same from either.

## 2. Contents

The chain store holds, for one chain:

| What | Keyed by | Content |
|---|---|---|
| the flat state | the stored key (10 §2) | its value, keys under `local/` included |
| trie nodes | node hash | the 65-byte preimage of spec 10 §4 and a reference count: how many live parents and roots name the node |
| history | `(key, version)` | what the key held before the span of `version` first wrote it: absent, or the value |
| writes | `(version, key)` | the keys each version's span wrote, to prune by |
| versions | version | the header root the version's trie is kept for (none when the kernel asked for no root in that block, and none for a version loaded from a snapshot), the number of keys its span wrote, and the number of committed entries it holds |
| metadata | name | the latest and oldest versions kept, the root of the current trie, the code hash of the kernel that wrote last, the genesis root, the format |

A *version* is a sealed block height: the genesis state is version 0, and each executed block seals its height. The *span* of version `v` is everything written since version `v − 1` was sealed: the block's execution, the finalization and kernel-switch writes before it, and nothing after it. History and tries keep the semantics of spec 20 §5.1: reading as version `v` yields the committed entries as they were when `v` was sealed, and the trie of `v` is the one behind the root of block `v`'s header, which the kernel asked for before its bookkeeping writes (06 §5).

Receipts, transactions and block headers are chain state (`receipt/`, `txraw/`, `block/`, `bnum/`, `bhash/`, spec 20 §3) and live in the flat state like every other key; the store adds nothing for them.

## 3. Trie nodes

### 3.1 Content addressing

Nodes are stored under their hash, so a node shared by many versions is stored once, and a trie is opened from its root alone: the host reads a node when a path first passes through it (an update or a proof), never the whole trie. A node opened over its store therefore starts in constant time whatever the size of the state, and the memory it uses grows with the paths it touches.

### 3.2 Reference counts

A node's count is the number of nodes among the kept tries that name it as a child, plus the roots that name it: one for each version whose header root it is, and one for the root of the current state. Sealing a version writes the nodes its span created, each counting one reference for every child it names, and one reference for the version's root and one for the current root, giving back the previous current root's reference. The nodes a span created all lie on the paths of the keys the span wrote, so the host writes them by walking those paths from the root and stopping at the first node whose row exists and was not written on that walk: its subtree is on disk and counted.

Pruning a version (§8) gives its root's reference back; a node whose count reaches zero is deleted and gives back the references it held. A node two versions share by hash keeps the count both gave it, so a write that restores an older value restores an older node without confusing the counts.

## 4. Atomicity

One transaction seals a version: the span's writes to the flat state, its history rows and write rows, the trie nodes it created with their counts, the version row and the metadata, committed together and synced to disk before the host goes on. A crash before the commit leaves the store exactly as the version before left it; a crash after it leaves the version whole. Nothing is ever torn.

Between seals the host buffers the kernel's writes in memory and reads through them, so a kernel call sees what the calls before it wrote whether or not a version has been sealed since. Two more transactions write the buffer without sealing: after `kernel_stf_finalize_block` (the finalized height, under `local/`) and after `kernel_migrate` (the switch record of spec 13 §5, with the code hash of the new kernel as the kernel that writes from then on). A crash between a block's seal and its finalization write loses the finalized height only, which §5 recovers.

The write of a block that fails (the disk refuses, or a test injects the failure) halts the node: every later step reports the failure, nothing the failing step queued for peers is sent (its driver state never reached the driver store, so a restarted node could otherwise sign differently in a view it had signed in), the block is not on disk, and the driver's tables already say it was finalized, so the node restarts over the store, where §5 takes it up again. The reference implementation's engine is `redb` (codex ADR 0037): one file, copy-on-write B-trees, a commit that is durable when it returns.

## 5. Restarts

A node opened over a store that a previous run sealed runs no `kernel_init` and executes nothing again. It reads the metadata, opens the current trie from its root, and takes the store's latest version as its executed height and as a finalized height (the reference host executes finalized blocks only, 08 §5). It loads the kernel named on the command line; when the store names another kernel as the last writer, that kernel is an upgrade the chain enacted, whose code chain state holds (13 §6), and the node compiles and runs that one instead, with the gates active for the next block (13 §8.6); a store last written by a kernel that is neither is refused. It then does what it does after every executed block (13 §7.1): reads the upgrade status, prepares a pending upgrade, and switches at the activation height if the store's head is that height.

The driver resumes from the driver store as before (08 §7). Its tables can lag the chain store: the chain store commits a block inside the step that executes it, the driver store syncs after the step. To close the gap without a peer, the reference driver keeps a *block log* in chain state, under `local/log/` (node-local, outside the commitment, 10 §2): for each height it finalizes, in the same step that asks for the block's execution and therefore in the block's transaction, the proposal (`local/log/prop/` + height), its finalize vote certificate (`local/log/cert/` + height) and its threshold certificate when it has one (`local/log/bcert/` + height), dropping the entries 64 heights behind. On `Started`, when chain state is ahead of the finalized height the driver remembers, the driver takes the heights between from the log into its tables (08 §7), makes the last one its tip when its tip is behind it, enters the view after that certificate's when its view is not past it (views only increase, 08 §3), and sets its finalized height to the chain state's. When chain state is behind, it replays its own finalized blocks as 08 §7 says, which with this store happens at most for the block whose write a crash cut short.

A node started over a store therefore resumes in constant time: the time to open the file and read a few rows, not a function of the chain's length, the versions it keeps or the state's size. The history window's bound in key writes (20 §5.1) is read from the version rows when a block is sealed, never held in memory per version. `solo node` and `solo dev` open the chain store under `--data-dir`; without it the state stays in memory. `solo_node_open_seconds` reports the time (§8).

## 6. The snapshot record

The reference kernel writes a *snapshot record* for every completed epoch. The epoch length is the staking epoch (15 §4) when staking is on; else the feature-gate epoch (13 §8) when upgrades are governed; else `SNAPSHOT_INTERVAL` = 1 024 blocks. In the first block of epoch `e + 1` (height `end(e) + 1`), before anything else of the block, the kernel asks for the state commitment (`storage_commit`): the root of the whole state as block `end(e)` left it, its bookkeeping included, which is exactly the state the host sealed as version `end(e)`. It stores

```
struct SnapshotRecord { height: u64, state_root: [32] }    // height = end(e)
```

under `snap/` + `e` (big-endian u64) and `e` under `meta/snapshot`. Both are committed keys: the record is in the root of block `end(e) + 1` and of every later block, so a certificate for any later proposal vouches for it through the proposal's anchor (17 §4) and a spec 10 proof of the key. The query `snapshot` takes an epoch (`u64`) or nothing, for the latest, and returns the record; status 1 when there is none yet.

A snapshot is *identified* by its record: the chain, the epoch, the height and the root. Two nodes export the same snapshot of an epoch whatever they did since.

## 7. Snapshot files

### 7.1 Export

`solo snapshot export --data-dir <dir> --out <file> [--epoch <n>]`, over a stopped node's directory, writes the snapshot of an epoch (the latest recorded by default). The file holds:

- a header: the chain id, the epoch, the record's height and root, the entry count; the encoded proposal `P` that vouches for the record, its certificate (a version-2 threshold certificate when the node stored one for `P`, 08 §6a, else `P`'s finalize vote certificate, 08 §6) and the spec 10 proof of `snap/` + epoch against `P.anchor_root`; and the proposal of block `height`, its finalize vote certificate and its threshold certificate when there is one, for the importing node's driver;
- the committed entries of version `height`, in key order, keys under `local/` left out, each as `key length ‖ key ‖ value length ‖ value` with `u32` little-endian lengths.

The file starts with `SOLOSNAP`, the format (`u32`, 1) and the header's length (`u32`) before the header. `P` is the latest finalized proposal in the node's tables whose `anchor_height` is above the record's height, whose view is at or above the head certificate's (§7.2, check 6) and whose anchor root the store still keeps the trie of (the record is written in block `height + 1`, so a proposal anchoring `height + 1` or later covers it); without one, or when the window no longer reaches `height`, the export fails and says so. It also fails, naming the cause, when the entries do not hash to the record's root: a kernel switch right after block `height` (13 §5) writes its switch record after the version is sealed and before the next block takes the record's root, so that epoch has no snapshot in version 0 and another epoch's serves.

### 7.2 Verification

`solo snapshot verify --snapshot <file> --genesis <genesis.json> [--trust-key <0x 96 bytes>]`, and every import, checks in order:

1. the chain id is the genesis file's;
2. `P` decodes and `P.anchor_height > height`;
3. the certificate is `P`'s and verifies under the trust: a threshold certificate (12 §7) must name `P`'s height and hash and verify, over the chain id and its key id, under the group key `--trust-key` names; a vote certificate must be a finalize certificate for `P`'s hash whose votes index the genesis validator set, with distinct indices, weighing a quorum (08 §1) and each recovering to its validator (08 §6), which is accepted only without `--trust-key` and only for a chain without staking: the genesis set is the chain's set for good only there, and on a chain with staking validators that have since left the set could sign a history of their own, so a verifier of such a chain refuses to go on without `--trust-key`;
4. the proof is a spec 10 proof of `snap/` + epoch against `P.anchor_root` whose outcome is *present* with the value hash of the encoded record `{ height, state_root }`;
5. the entries number what the header says, are committed keys in strictly ascending order, and their trie (10 §4) hashes to `state_root`;
6. the head proposal decodes and is block `height`'s, and the head certificate is a finalize certificate whose view is not above `P`'s; it names the head or a descendant that finalized it, such as a suffix proposal (08 §3a), whose ancestors are not in the file; under the genesis set its votes must also verify as in check 3. These two seed the importing driver (its tip, entry certificate and view) and the trust does not vouch for them; bounding the view by `P`'s, which it does vouch for, keeps a forged head from moving a node past the views the chain has had. A forged head proposal can at worst keep the node from linking its first sync response to its finalized head, which its operator sees as a node that does not sync; it never changes the state the node serves.

Anything else is refused with the first failing check named. The trusted group key is the verifier's own assumption: the key of the chain's current key set, as the light client on Ethereum holds it (17 §5) or a node the operator trusts reports it. A chain whose key has rotated past the one the operator trusts needs a newer snapshot or a newer key.

### 7.3 Import and joining

`solo snapshot import --snapshot <file> --data-dir <dir> --kernel <kernel> --genesis <genesis.json> [--trust-key …]` verifies the file and loads it into a data directory that holds no chain yet, and `solo node --data-dir <dir> --snapshot <file> [--trust-key …]` does the same before starting when the directory holds no chain (a directory that holds one keeps it and says the snapshot was ignored). Loading runs `kernel_init` first, so the genesis root is known for block 0 (20 §3.1), then replaces the state with the entries, builds and stores their trie, seals version `height` as the oldest and latest version with no header root (proofs begin with the next block), writes the finalized height and the block log entry of `height` under `local/`, and takes up the kernel the state's latest enacted upgrade names (13 §6), the genesis kernel when there is none. Queries answer at `height` and above; `eth_getProof` from `height + 1` on.

Started with no driver data, the driver finds chain state ahead of a finalized height of 0, takes block `height` from the log (§5), enters the view after its certificate's or, with staking, the first view of the next epoch (08 §3a), looks itself up in that epoch's set, and syncs forward from its peers from `height + 1` (08 §7a), finalizing and executing as any node does. A validator reinstalled this way is back in consensus once it has synced to the head; it has nothing of its old driver tables, so a key that had voted in the current view before the reinstall would vote again: operators reinstall a key only from a directory whose driver store they keep, or after a view has passed.

## 8. Bounds and telemetry

The window of spec 20 §5.1 bounds the store: after each seal the host prunes the versions below the oldest the window keeps, deleting their history rows and giving their roots back (§3.2), so the file holds the current state, the nodes the kept roots reach and the history of the window; with `--archive` nothing is pruned. The file does not shrink when rows are deleted: the engine reuses freed pages, and when a file opens with more freed bytes than live ones plus 8 MiB the host compacts it, giving the space back.

Telemetry (11 §4) reports `solo_store_size_bytes`, the file's size; `solo_store_write_bytes_total`, the bytes of keys, values and nodes written since the node opened, whose increase per block is the store's write amplification; `solo_store_versions`, the versions kept; `solo_store_nodes`, the trie nodes held; and `solo_node_open_seconds`, the time from opening the store to the node being ready. Measured on 2026-10-22 on the reference host (`crates/solo-node/tests/store.rs` prints the open time; codex ADR 0037 the write figures): a one-validator chain of transfers writes about 4 KB per block to the store beside the block's own bytes (the trie paths of some ten changed keys at a depth of about six), and a node of a few hundred blocks reopens in under 100 ms, the same whatever its height.

## 9. Not in version 0

Pruning of the driver store's tables; a snapshot of an epoch whose last block a kernel switch followed (§7.1); streaming imports that do not hold the entries in memory; a snapshot of the state behind a block's header root (a snapshot is the sealed state, so proofs at its own height are not served); snapshots fetched from peers over the transport, and the vote certificate of the head block verified against the set in the snapshot's own state; eviction of loaded trie nodes from memory.
