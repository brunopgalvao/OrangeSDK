# 20 — Ethereum surface

## 1. Overview

Codex ADR 0003 makes Solo a Type 2 Ethereum chain: standard EVM bytecode at exact gas, every transaction type a wallet sends, the full RPC, and Solo's own state tree, consensus and block format underneath. This document specifies where the reference kernel and host meet Ethereum tooling beyond the EVM itself (codex ADR 0033):

- the transaction types the kernel accepts, including EIP-7702 set-code transactions, and the one it refuses, EIP-4844 blob transactions (§2);
- the block header: every block, the genesis block included, has an Ethereum header whose `keccak256` of the RLP is the block hash, with Merkle-Patricia transactions and receipts roots and a logs bloom, while the state root stays Solo's binary trie (§3); the genesis block's hash and the chain id identify the chain (§3.4);
- `eth_getProof`, which answers with spec 10 proofs in EIP-1186's response shape (§4);
- historical state: the state methods answer at any block within a retention window, or at every block on an archive node (§5).

It extends codex ADR 0020, which specified the RPC with state at the head only and Solo's own block commitments; §3 and §5 replace its points 2 and 5. What this document does not change: proposals, anchors and threshold certificates (spec 08, 12, 17) keep their formats, since none of them carries the block hash or the receipts root; the state commitment is spec 10's.

## 2. Transactions

### 2.1 Types

| Type | Transaction | Accepted |
|---|---|---|
| legacy (RLP list), pre-EIP-155 and EIP-155 | legacy | yes |
| `0x01` | EIP-2930 access list | yes |
| `0x02` | EIP-1559 dynamic fee | yes |
| `0x03` | EIP-4844 blob | no: reason 7, `UNSUPPORTED` |
| `0x04` | EIP-7702 set code | yes |
| any other byte below `0x80` | — | no: reason 7 |

A blob transaction pays for data that a data-availability layer keeps for a while; a solochain has none, so the kernel refuses the type before execution (`solo-eth` decodes it as unsupported). Every header therefore records zero blob gas used and zero excess blob gas (§3.1), and `BLOBBASEFEE` is the minimum, 1.

### 2.2 Set-code transactions

A set-code transaction is `0x04 ‖ rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, value, data, access_list, authorization_list, y_parity, r, s])`, and its signature covers `keccak256(0x04 ‖ rlp([...the first ten fields]))`. Each authorization is `[chain_id, address, nonce, y_parity, r, s]`. Decoding refuses with reason 1 (`MALFORMED`) a destination that is not 20 bytes (a set-code transaction cannot create), an empty authorization list, and an authorization whose `chain_id` exceeds 32 bytes, whose address is not 20 bytes, whose `nonce` exceeds 64 bits, whose `y_parity` exceeds 8 bits or whose `r` or `s` exceeds 32 bytes, as EIP-7702 makes such a transaction invalid. Every other check of the transaction's own fields and signature is as for a dynamic-fee transaction.

Intrinsic gas is that of a dynamic-fee transaction plus 25 000 (`PER_EMPTY_ACCOUNT_COST`) per authorization. The EIP-7623 floor is unchanged.

**Authorities.** The authority of an authorization is the address that signed `keccak256(0x05 ‖ rlp([chain_id, address, nonce]))`. The kernel recovers it through the host's `secp256k1_recover` (05 §4.3), exactly as it recovers senders, and hands revm the recovered authorization, so the kernel carries no signature code of its own. An authorization names no authority when its `y_parity` is neither 0 nor 1, its `r` or `s` is zero, its `s` is above half the group order (EIP-7702 requires low `s`, which is also the only form the host function recovers, codex ADR 0021) or recovery fails. revm (43, Osaka) then applies each authorization in order, as EIP-7702 specifies: one is skipped when it names no authority, its chain id is neither 0 nor the chain's, its nonce is `2^64 − 1` or not the authority's nonce, or the authority's code is neither empty nor a delegation designator; otherwise the authority's nonce is incremented, 12 500 gas (`PER_EMPTY_ACCOUNT_COST − PER_AUTH_BASE_COST`) is refunded when the authority's account existed, and its code becomes `0xEF0100 ‖ address`, or empty for the zero address. A skipped authorization never makes the transaction invalid.

The kernel stores a designator as it stores any code, under its `keccak256` at `code/` with the account's code hash naming it (`evm::commit` writes code that a creation produced or that is a designator), and a call to a delegated account runs the delegate's code in the account's context, as on Ethereum.

**Native contracts.** A designator of spec 16 (`0xEF02 ‖ code hash`) and a delegation do not mix. An authorization writes only `0xEF0100 ‖ address`, so it cannot create a native contract. An account holding a native-contract designator is skipped as an authority (its code is neither empty nor a delegation) and cannot send. A call to an account that delegates to a native contract fails without running the module (16 §5.3).

**Senders.** The admission check of reason 11 (`SENDER_NOT_EOA`, EIP-3607) refuses a sender whose code is neither empty nor a delegation designator: a delegated account keeps sending, its nonce, balance and fees as before.
### 2.3 Calls and estimates

A call object (`eth_call`, `eth_estimateGas`) may carry `authorizationList`, a list of `{chainId, address, nonce, yParity, r, s}` (geth's names; `v` is accepted for `yParity`), every field required. It reaches the kernel as `CallRequest.authorization_list` (`SignedAuthorization` records), and a call with a non-empty list runs as a set-code transaction: authorities recovered as in §2.2, the list's intrinsic gas charged and its authorizations applied. A wallet that estimates a set-code transaction with its list therefore gets the gas the transaction needs.

### 2.4 The pool

The reference host's pool (spec 14) applies geth's two rules for delegation:

- **In-flight limit.** A sender whose account holds code (only a delegation can, §2.2) or that an authorization of a pool transaction names may have one transaction in the pool. A newcomer with another nonce is refused with `in-flight transaction limit reached for delegated accounts`; a replacement of the one it has is allowed. A delegated account's code can spend its balance from other accounts' transactions, so its later transactions could stop being payable at any block.
- **Reserved authorities.** A set-code transaction whose authorizations name an authority holding more than one transaction in the pool is refused with `authority already reserved`.

The authorities come from the pool's own recovery of each authorization's signature; one that names no authority is ignored. After a block, a sender whose code changed keeps its transactions (14 §5).

geth's builder runs each transaction and drops one that fails; the reference driver proposes the pool's take without running anything (06 §5.1), so the take adds a third rule. **Authorities ahead.** Once a set-code transaction is in a take's order, carried in `skip` or taken, the senders its authorizations name contribute nothing more to that answer (14 §3): the authorization can move such a sender's nonce when it runs, after which the sender's pending transaction could not. The transaction stays in the pool; after the block it is dropped if its nonce was used and taken again otherwise. A sender whose transaction comes before the set-code transaction is taken as usual, and the authorization then finds its nonce moved and is skipped. What a delegated account's code does during other senders' transactions stays unforeseen (06 §5.1).

### 2.5 RPC views

A set-code transaction's view has `type` `0x4`, the dynamic-fee fields, `accessList` and `authorizationList`: `{chainId, address, nonce, yParity, r, s}` per authorization, quantities as geth writes them. Its receipt has `type` `0x4`; nothing else in it differs from a dynamic-fee transaction's receipt.

## 3. The block header

### 3.1 Ethereum header and block hash

The kernel stores, for each block, the record `solo_abi::chain::BlockHeader`:

| Field | Content |
|---|---|
| `height` | block number |
| `parent_hash` | the previous block's hash: the genesis block's for block 1, zero for the genesis block (§3.4) |
| `timestamp_ms` | the proposal's timestamp, milliseconds |
| `state_root` | the state commitment (spec 10) the block returned (06 §5) |
| `receipts_root` | §3.2 |
| `tx_hashes` | the hashes of the transactions the block records, in order (codex ADR 0022) |
| `gas_used` | gas used by them |
| `transactions_root` | §3.2 |
| `logs_bloom` | the bloom of every log of the block, 256 bytes |
| `gas_limit` | the block gas limit, 30 000 000 |
| `base_fee` | the block's base fee per gas (23 §3) |
| `beneficiary` | the fee recipient: the fee vault `0x…4645` on a chain with staking, the zero address without (23 §4) |

The block's **Ethereum header** is the Prague/Osaka header with these values, in RLP order (`solo_eth::header::Header::of`):

| Header field | Value |
|---|---|
| `parentHash` | `parent_hash` |
| `ommersHash` | `keccak256(rlp([]))` = `1dcc4de8…d49347` |
| `beneficiary` | `beneficiary` |
| `stateRoot` | `state_root`: Solo's binary-trie root, not a Merkle-Patricia root (§3.3) |
| `transactionsRoot` | `transactions_root` |
| `receiptsRoot` | `receipts_root` |
| `logsBloom` | `logs_bloom` |
| `difficulty` | 0 |
| `number` | `height` |
| `gasLimit` | `gas_limit` |
| `gasUsed` | `gas_used` |
| `timestamp` | `⌊timestamp_ms / 1000⌋` |
| `extraData` | empty |
| `mixHash` | zero: the kernel's `PREVRANDAO` |
| `nonce` | 8 zero bytes |
| `baseFeePerGas` | `base_fee` |
| `withdrawalsRoot` | the empty-trie root `56e81f17…b421` (no withdrawals) |
| `blobGasUsed` | 0 |
| `excessBlobGas` | 0 |
| `parentBeaconBlockRoot` | zero (no beacon chain) |
| `requestsHash` | `sha256("")` = `e3b0c442…b855` (no EIP-7685 requests) |

The **block hash** is `keccak256` of the header's RLP. The kernel computes it after storing the block's receipts, stores it beside the record (the `bnum/` and `bhash/` indexes) and as the next block's `parent_hash`; `BLOCKHASH` returns it (19 §4); the host reports it in `BlockExecuted` (06 §4.1) and the RPC serves it as `hash`. The RPC's block view is exactly the header's fields with that hash, plus `size` (the length of `rlp([header, transactions, [], []])`, a typed transaction as the string of its bytes), `totalDifficulty` 0, empty `uncles` and `withdrawals`, and the transactions. So `keccak256(rlp(header))`, rebuilt from the view by any Ethereum library, is the view's `hash`, and the parent link holds from the genesis block on (§3.4).

### 3.2 Transactions and receipts roots

Both are roots of Ethereum's hexary Merkle-Patricia trie (Yellow Paper, appendices C and D; `solo_eth::mpt::ordered_root`) holding item `i` of a list under the key `rlp(i)`:

- the **transactions root** over the raw transactions the block records, in order, each exactly as received (for a typed transaction its type byte and payload, for a legacy one its RLP list): the bytes whose `keccak256` is the transaction's hash;
- the **receipts root** over their receipts, each in its EIP-2718 encoding: the type byte for a typed transaction, then `rlp([status, cumulative_gas_used, logs_bloom, logs])`, a log being `[address, [topics], data]` and `logs_bloom` the receipt's own.

The block's `logs_bloom` is the OR of its receipts' blooms. A transaction the block records that could not run (codex ADR 0022: bytes that do not decode, or a transaction that should not have been included) has status 0, the cumulative gas of the transactions before it, no logs, and type 0. An empty block has the empty-trie root for both.

`ExecuteSummary.receipts_root` (06 §5) is the receipts root, and `ExecuteSummary.logs_bloom` the block's bloom.

### 3.3 State root

`stateRoot` is Solo's state commitment (spec 10), a binary Merkle trie over the store's entries. It is not, and cannot be checked as, an Ethereum state root: a tool that verifies Ethereum state proofs against it fails, and Solo's state proofs follow spec 10 (§4). What an Ethereum state root would commit to (accounts, storage) is in Solo's store under the keys of §4.1, alongside the kernel's other state.

### 3.4 The genesis block

`kernel_init` (06 §2) ends by storing block 0, after everything else it writes (`stf::genesis` in the reference kernel). Its record is

| Field | Value |
|---|---|
| `height` | 0 |
| `parent_hash` | zero |
| `timestamp_ms` | 0 |
| `state_root` | the commitment `storage_commit` returns at that point: of everything `kernel_init` wrote |
| `receipts_root`, `transactions_root` | the empty-trie root `56e81f17…b421` |
| `tx_hashes`, `gas_used` | none, 0 |
| `logs_bloom` | 256 zero bytes |
| `gas_limit` | the block gas limit, 30 000 000 |
| `base_fee` | the floor the genesis parameters set, `min_base_fee` (23 §2): the parent at the floor that used nothing from which 23 §3 derives block 1's base fee |
| `beneficiary` | the zero address: no fee is paid at genesis |

and its Ethereum header and hash follow from it exactly as for every block (§3.1): the hash is `keccak256(rlp(header))`, with parent hash zero, so a header chain verifies from block 0. The kernel stores it as it stores every block, under `block/`, `bnum/` and `bhash/` (so `BLOCKHASH(0)` returns it, 19 §4), and its hash as `meta/last_hash`, which becomes block 1's `parent_hash`; `meta/height` stays unset until block 1 executes, so everything that reads the executed height reads none before the first block, as before. The header is a function of the genesis (`Genesis` of 06 §5: the chain id, the parameters, the validators and the allocations) and of the genesis kernel's `kernel_init`, so every node of the chain computes the same one.

The host keeps the trie behind the genesis header's root as version 0 of its state (22 §3), the trie `storage_commit` returned, not the state after the header was stored, exactly as it keeps the trie behind each block's root (§4.3); the genesis root the node and its store report is that root, and `eth_getProof` at block 0 verifies against block 0's `stateRoot`. The RPC serves block 0 from the stored record like any other block: `eth_getBlockByNumber(0)` (and `earliest`), `eth_getBlockByHash` with its hash, `eth_getBlockReceipts` and `eth_getLogs` with its hash (none), and its hash as a state method's block parameter (§5.2). The zero hash names no block.

**Chain identity.** A chain is identified by its chain id together with its genesis hash. Through the state root the genesis hash commits to the chain id (`meta/chain_id`), the stored genesis parameters (`meta/params`: fees, governance, staking, upgrades), the genesis validator set (`meta/validators`), every allocated account with its code and storage, the genesis modules and the bridge's configuration: every chain parameter genesis fixes. Two chains that share a chain id but differ in any of these have different genesis hashes and are different chains; a snapshot of one does not import into the other (22 §7.3). The genesis hash does not commit to the genesis kernel's code hash: two kernels whose `kernel_init` writes the same state give the same genesis block, and a node is held to the kernel that wrote its store by the store itself (22 §5).

**Chains that predate the genesis block.** A chain's genesis block is whatever its genesis kernel's `kernel_init` stored; nothing stores it later. A reference kernel built before 2026-10-23 stored none: on a chain whose genesis kernel is such a kernel, block 1's parent hash is zero, `BLOCKHASH(0)` answers zero and the RPC answers `null` for block 0 and for its hash. A kernel upgrade cannot give such a chain a genesis block, since every block hash from block 1 on commits to a parent hash of zero; a later kernel runs on it unchanged, reading `meta/last_hash` as before, and the chain keeps its identity as its chain id and the hash of its block 1. Data directories and devnets made with an earlier kernel fixture are made again (`solo devnet init`), as after any rebuild of the genesis kernel: a node refuses a store written by a kernel that is neither the one it is given nor an upgrade in that store's chain state (22 §5).

## 4. `eth_getProof`

### 4.1 Request and response

`eth_getProof(address, storageKeys, block)` takes an address, a list of at most 1 024 storage keys (`MAX_PROOF_KEYS`; hex words of at most 32 bytes) and a block parameter as the state methods take one (§5). A longer list is refused with `-32602`, `too many storage keys: <n>, the limit is 1024`. Each key costs a kernel query and a proof on the thread that drives consensus, so the node's background work runs before each, as between the entries of a batch; the head can move meanwhile, and every value and proof in the response is of the block the request named. It returns:

| Field | Content |
|---|---|
| `address` | the address |
| `balance`, `nonce` | the account's, at that block |
| `codeHash` | `keccak256` of the account's code; `keccak256("")` for an account without code |
| `storageHash` | the block's state root (Solo has no per-account storage trie) |
| `stateRoot` | the block's state root, the header's `stateRoot` |
| `proofFormat` | `solo-binary-trie-v0`: the proofs are spec 10's |
| `accountKey` | the account's state key, `acct/ ‖ address` (`61 63 63 74 2f` then 20 bytes) |
| `accountValue` | the entry's value: the account record, `balance` (16 bytes, little-endian) ‖ `nonce` (8 bytes, little-endian) ‖ `code_hash` (32 bytes, zero for no code), 56 bytes (06 §2); `0x` when the account is not in state |
| `accountProof` | the proof of `accountKey` (§4.2) |
| `storageProof` | per requested key, in order: `{key, value, proof}` with the key as requested, the slot's value as a quantity (0 when unset), and the proof of the slot's state key `slot/ ‖ address ‖ key` (the key left-padded to 32 bytes); a set slot's entry value is its 32 big-endian bytes, an unset slot has no entry |

### 4.2 Proofs

A proof is a list of hex strings: the `d` sibling hashes of spec 10 §5.1 from the root down, then the terminal, `0x00` for an empty subtree or `0x01 ‖ path ‖ value_hash` (65 bytes) for a leaf. It is the spec 10 §5.1 encoding with the count dropped and the parts listed separately, so the count is the list's length less one.

To verify an account: take `stateRoot` from the block's header, `k = accountKey`, and run spec 10 §5.3. The account is present with the response's fields when the outcome is *present* with value hash `keccak256(accountValue)` and `accountValue` decodes to `balance`, `nonce` and `codeHash` (a zero code hash being `keccak256("")`); it is absent, with zero balance and nonce and no code, when the outcome is *absent*. A slot holds `value` when the outcome for its state key is *present* with value hash `keccak256` of `value` as 32 big-endian bytes, and is unset (value 0) when it is *absent*. `crates/solo-rpc/tests/ethereum.rs` checks the responses with a verifier written from spec 10, independent of `solo-trie`.

### 4.3 Heights

A proof is against the trie behind the root of the block's header, which the node keeps for every height within its state history (§5) and for the genesis state. The values are read from the state right after that block, which holds the same accounts and slots: the kernel writes only its block bookkeeping after it asks for the root (06 §5). A height the node does not keep is refused with the error of §5.3.

## 5. Historical state

### 5.1 Retention

The reference node keeps the state of its latest `state_history` executed blocks, 1 024 by default (`STATE_HISTORY`; `solo node --state-history <blocks>`), or of every block from genesis on an archive node (`--archive`, `ARCHIVE`). It keeps, per executed block, the value every committed key held before the block (and the host writes between it and the block before) changed it, and the state trie behind the block's root, which shares every node the block did not change. A block that leaves the window takes both with it. Keys under `local/` are outside history, as outside the commitment (10 §2).

History is also bounded in key writes, so that blocks that write heavily cannot make it outgrow the node's memory: the node keeps at most `512 × state_history` of them (`HISTORY_KEYS_PER_BLOCK`), a key counting once for each block that wrote it. When the blocks of the window wrote more, it drops the oldest of them until the rest fit, and the window holds fewer blocks; the head's state is always kept. Each key write kept costs its old value and the trie nodes on its path, about 1 to 1.5 KB (measured 2026-10-21 over 200 000 entries: 1.4 KB per write at 1 500 writes per block, 1.0 KB at 6 000), so the default window holds at most about 0.5 to 0.75 GB of history whatever its blocks write, while blocks that write 512 keys or fewer each on average keep all 1 024. An archive node has no bound.

The oldest height whose state the node keeps is therefore the head less `state_history − 1`, later when the bound in key writes holds fewer blocks, or 0 while the chain is shorter; the genesis state, height 0, is kept until then. A node started from a snapshot (22 §7) keeps from the snapshot's height on.

A node with a data directory keeps the history and the tries on disk, in the chain store of spec 22, and keeps them across restarts: a restarted node answers at every height it kept before, and an archive node's history is bounded by its disk, not its memory. Without a data directory both stay in memory and end with the process.

### 5.2 Queries at a height

`QueryArgs.at` (06 §3) names the height a query reads. The host runs a query with `at = h` over the committed state as it was right after it executed block `h` (`MemStorage::set_view`), in the discarded overlay layer every query runs in (06 §6); `at` absent, or equal to the head, reads the current state. The kernel reads its own height, block records and accounts from that state, so a call at `h` runs in block `h`'s context (`NUMBER`, `TIMESTAMP`), as geth's call at a block number does. The kernel that answers is the one running now: a query at a height before a kernel switch (06 §7) reads the old state through the new kernel's queries.

The RPC resolves every state method's block parameter (`eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`, `eth_call`, `eth_estimateGas`, `eth_getProof`) as before: the tags `latest`, `pending`, `safe` and `finalized` name the head (08 §8), `earliest` the genesis, and a number or a hash, directly or as an EIP-1898 object, its block. The head reads the current state; an older block within the window reads its state; `eth_getTransactionCount` at `pending` still counts the pool.

### 5.3 Errors

| Block | Error |
|---|---|
| above the head | `-32000`, `header not found` |
| a hash the node does not know | `-32000`, `header for hash not found` |
| below the oldest kept height | `-32000`, `missing trie node <stateRoot without 0x> (path ) state of block <h> is not available, the node keeps the state from block <oldest>` |

The last follows the wording of a pruned geth node, so tools that recognise `missing trie node` retry against an archive node.

## 6. Conformance

The execution-spec state tests run set-code transactions through the kernel's own code (07 §4.2): `tx::decode_signed` recovers each authority through the host, and `native::run_in` hands revm the recovered list. The type-4 entry of the expected failures is gone; type 3 stays. The committed subset carries 35 more set-code cases (`prague/eip7702_set_code_tx`, 40 in all) and now passes 534 cases with 22 expected failures, all blob transactions (before: 490 and 31, 9 of the 31 being type-4 cases: 7 in other categories and 2 among the 5 set-code cases already committed). The full pinned set passes 4 767 cases with 804 expected failures, all blob transactions, and none fail otherwise, on both backends with gate 2 active and inactive (2026-10-21; before: 4 223 and 1 348); every one of its 552 `prague/eip7702_set_code_tx` cases passes.

## 7. Limits of this version

- The genesis header's timestamp is 0: the genesis parameters carry no time, and block 1's is the first proposal's.
- `stateRoot` is not an Ethereum state root (§3.3), and `eth_getProof` answers in Solo's proof format, which Ethereum's verifiers do not read.
- A node without a data directory keeps its history in memory and has none from before it started; while blocks write heavily a window is shorter than `state_history` (§5.1). A node started from a snapshot has no state from before the snapshot (22 §7).
- The pool's rules for delegation are geth's, plus the take's rule for authorities ahead (§2.4); a pool of another host may differ without affecting consensus (14 §1).
- Proposals are not run before they are made: a delegated account's code can spend the account's balance, or move its nonce by creating a contract, during another sender's transaction, and a later transaction of that account in the same block is then recorded as failed (06 §5.1) where a geth builder would have left it out; so is a transaction priced below the base fee of the block it lands in (23 §10).
