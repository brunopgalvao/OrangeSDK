# 20 — Ethereum surface

## 1. Overview

Codex ADR 0003 makes every OrangeSDK chain a Type 2 Ethereum chain: standard EVM bytecode at exact gas, every transaction type a wallet sends, the full RPC, and OrangeSDK's own state tree, consensus and block format underneath. This document specifies where the reference kernel and host meet Ethereum tooling beyond the EVM itself (codex ADR 0033):

- the transaction types the kernel accepts, including EIP-7702 set-code transactions, and the one it refuses, EIP-4844 blob transactions (§2);
- the block header: every block, the genesis block included, has an Ethereum header whose `keccak256` of the RLP is the block hash, with Merkle-Patricia transactions and receipts roots and a logs bloom, while the state root stays OrangeSDK's binary trie (§3); the genesis block's hash and the chain id identify the chain (§3.4);
- `eth_getProof`, which answers with spec 10 proofs in EIP-1186's response shape (§4);
- historical state: the state methods answer at any block within a retention window, or at every block on an archive node (§5);
- the polled filters and the smaller methods standard clients call, the WebSocket server and its subscriptions, the differences from geth that remain, and the suite of standard clients that checks them (§8);
- tracing: geth's `debug_traceTransaction`, `debug_traceBlockByNumber`, `debug_traceBlockByHash` and `debug_traceCall` with `callTracer` and `prestateTracer`, which execute a block or a call again in a query, off the consensus path (§9).

It extends codex ADR 0020, which specified the RPC with state at the head only and OrangeSDK's own block commitments; §3 and §5 replace its points 2 and 5. What this document does not change: proposals, anchors and threshold certificates (spec 08, 12, 17) keep their formats, since none of them carries the block hash or the receipts root; the state commitment is spec 10's.

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

Decoding refuses with reason 1 (`MALFORMED`) a transaction whose RLP nests lists more than 16 deep (`orange_rlp::MAX_DEPTH`). No transaction type nests more than four (a typed transaction's access-list entry's storage keys), so the limit refuses nothing of a valid shape; it bounds the stack of a recursive decoder, which a short string of nested lists could otherwise overflow.

A blob transaction pays for data that a data-availability layer keeps for a while; a solochain has none, so the kernel refuses the type before execution (`orange-eth` decodes it as unsupported). Every header therefore records zero blob gas used and zero excess blob gas (§3.1), and `BLOBBASEFEE` is the minimum, 1.

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

The authorities come from the pool's own recovery of each authorization's signature; one that names no authority is ignored. The pool reads, and so recovers, no set-code transaction with more than 64 authorizations (`MAX_AUTHORIZATIONS`, 14 §2): it is refused with `too many authorizations` before any signature is recovered. The kernel sets no such limit; a block's gas bounds a list at 25 000 gas an authorization (§2.2). After a block, a sender whose code changed keeps its transactions (14 §5).

geth's builder runs each transaction and drops one that fails; the reference driver proposes the pool's take without running anything (06 §5.1), so the take adds a third rule. **Authorities ahead.** Once a set-code transaction is in a take's order, carried in `skip` or taken, the senders its authorizations name contribute nothing more to that answer (14 §3): the authorization can move such a sender's nonce when it runs, after which the sender's pending transaction could not. The transaction stays in the pool; after the block it is dropped if its nonce was used and taken again otherwise. A sender whose transaction comes before the set-code transaction is taken as usual, and the authorization then finds its nonce moved and is skipped. What a delegated account's code does during other senders' transactions stays unforeseen (06 §5.1).

### 2.5 RPC views

A set-code transaction's view has `type` `0x4`, the dynamic-fee fields, `accessList` and `authorizationList`: `{chainId, address, nonce, yParity, r, s}` per authorization, quantities as geth writes them. Its receipt has `type` `0x4`; nothing else in it differs from a dynamic-fee transaction's receipt.

## 3. The block header

### 3.1 Ethereum header and block hash

The kernel stores, for each block, the record `orange_abi::chain::BlockHeader`:

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

The block's **Ethereum header** is the Prague/Osaka header with these values, in RLP order (`orange_eth::header::Header::of`):

| Header field | Value |
|---|---|
| `parentHash` | `parent_hash` |
| `ommersHash` | `keccak256(rlp([]))` = `1dcc4de8…d49347` |
| `beneficiary` | `beneficiary` |
| `stateRoot` | `state_root`: OrangeSDK's binary-trie root, not a Merkle-Patricia root (§3.3) |
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

Both are roots of Ethereum's hexary Merkle-Patricia trie (Yellow Paper, appendices C and D; `orange_eth::mpt::ordered_root`) holding item `i` of a list under the key `rlp(i)`:

- the **transactions root** over the raw transactions the block records, in order, each exactly as received (for a typed transaction its type byte and payload, for a legacy one its RLP list): the bytes whose `keccak256` is the transaction's hash;
- the **receipts root** over their receipts, each in its EIP-2718 encoding: the type byte for a typed transaction, then `rlp([status, cumulative_gas_used, logs_bloom, logs])`, a log being `[address, [topics], data]` and `logs_bloom` the receipt's own.

The block's `logs_bloom` is the OR of its receipts' blooms and, when the block has one, of its system receipt's (§3.5). A transaction the block records that could not run (codex ADR 0022: bytes that do not decode, or a transaction that should not have been included) has status 0, the cumulative gas of the transactions before it, no logs, and type 0. An empty block has the empty-trie root for both.

`ExecuteSummary.receipts_root` (06 §5) is the receipts root, and `ExecuteSummary.logs_bloom` the block's bloom.

### 3.3 State root

`stateRoot` is OrangeSDK's state commitment (spec 10), a binary Merkle trie over the store's entries. It is not, and cannot be checked as, an Ethereum state root: a tool that verifies Ethereum state proofs against it fails, and OrangeSDK's state proofs follow spec 10 (§4). What an Ethereum state root would commit to (accounts, storage) is in OrangeSDK's store under the keys of §4.1, alongside the kernel's other state.

### 3.4 The genesis block

`kernel_init` (06 §2) ends by storing block 0, after everything else it writes (`stf::genesis` in the reference kernel). Its record is

| Field | Value |
|---|---|
| `height` | 0 |
| `parent_hash` | zero |
| `timestamp_ms` | the genesis time, `1 000 × GenesisParams::genesis_time` (below); 0 for a genesis without one |
| `state_root` | the commitment `storage_commit` returns at that point: of everything `kernel_init` wrote |
| `receipts_root`, `transactions_root` | the empty-trie root `56e81f17…b421` |
| `tx_hashes`, `gas_used` | none, 0 |
| `logs_bloom` | 256 zero bytes |
| `gas_limit` | the block gas limit, 30 000 000 |
| `base_fee` | the floor the genesis parameters set, `min_base_fee` (23 §2): the parent at the floor that used nothing from which 23 §3 derives block 1's base fee |
| `beneficiary` | the zero address: no fee is paid at genesis |

and its Ethereum header and hash follow from it exactly as for every block (§3.1): the hash is `keccak256(rlp(header))`, with parent hash zero, so a header chain verifies from block 0. The kernel stores it as it stores every block, under `block/`, `bnum/` and `bhash/` (so `BLOCKHASH(0)` returns it, 19 §4), and its hash as `meta/last_hash`, which becomes block 1's `parent_hash`; `meta/height` stays unset until block 1 executes, so everything that reads the executed height reads none before the first block, as before. The header is a function of the genesis (`Genesis` of 06 §5: the chain id, the parameters, the validators and the allocations) and of the genesis kernel's `kernel_init`, so every node of the chain computes the same one.

The host keeps the trie behind the genesis header's root as version 0 of its state (22 §3), the trie `storage_commit` returned, not the state after the header was stored, exactly as it keeps the trie behind each block's root (§4.3); the genesis root the node and its store report is that root, and `eth_getProof` at block 0 verifies against block 0's `stateRoot`. The RPC serves block 0 from the stored record like any other block: `eth_getBlockByNumber(0)` (and `earliest`), `eth_getBlockByHash` with its hash, `eth_getBlockReceipts` and `eth_getLogs` with its hash (none), and its hash as a state method's block parameter (§5.2). The zero hash names no block.

**Genesis time.** `GenesisParams::genesis_time` (`u64`, Unix seconds) is the chain's genesis time: the genesis block's timestamp, so its header's `timestamp`, and through `meta/params` part of the state the genesis hash commits to. It is the last field of `GenesisParams` and encoded only when it is not zero; parameters that end before it decode with a genesis time of zero. So a genesis without a time encodes, stores and hashes exactly as before the field existed, and its genesis block keeps timestamp 0: every chain made without one is unchanged. A first block is never made before the genesis time: the driver's initial tip carries `max(now, genesis time)` as its timestamp (08 §3), so the first proposal comes one slot after the later of the two, and its timestamp, like every later one an honest leader makes, exceeds the genesis block's. Validators hold every proposal to that: they vote only for a proposal whose timestamp is above its parent's (the genesis block's for block 1) and at most `MAX_DRIFT_MS`, one second, past their own clocks (08 §5), so the timestamps of the blocks a quorum finalizes rise strictly from the genesis block's, whoever proposed them, and none is far ahead of the validators' time. The `orange` command reads it from the genesis JSON as `timestamp`, Unix seconds as geth writes it (a number, or a decimal or `0x` hex string); `orange devnet init` writes the time it ran, or `--genesis-time`; `orange dev` gives a genesis without one the time it starts when it keeps its chain in memory, and takes the file as written with `--data-dir`, so that a restart and the snapshot commands, which read the file, find the same chain. A genesis time in the future delays the first block until then, which is how a chain is launched at an announced time.

**Chain name.** `GenesisParams::name` (`bytes`) is the chain's name for people, such as `tangerine`: empty for a chain without one, otherwise 1 to `MAX_CHAIN_NAME` = 32 bytes of ASCII lower-case letters, digits and `-`, the first a letter (`[a-z][a-z0-9-]*`). It is the last field of `GenesisParams`, after the genesis time, and encoded only when it is not empty, the genesis time then encoded even when it is zero; parameters that end before it decode with no name, so a genesis without one encodes, stores and hashes exactly as before the field existed. `kernel_init` traps on a name that breaks these rules. Through `meta/params` the name is part of the state the genesis hash commits to: two genesis files that differ only in their names are two chains. A name does not identify a chain on its own, and it is not unique: a testnet and the mainnet launched from the same template may share one and are told apart by chain id and genesis hash. The `orange` command reads it from the genesis JSON as `name` and refuses one that breaks the rules before the kernel sees it; a node shows it beside the chain id when it starts and in `/status` (11 §6).

**Chain identity.** A chain is identified by its chain id together with its genesis hash. Through the state root the genesis hash commits to the chain id (`meta/chain_id`), the stored genesis parameters (`meta/params`: fees, governance, staking, upgrades, the genesis time, the name), the genesis validator set (`meta/validators`), every allocated account with its code and storage, the genesis modules and the bridge's configuration: every chain parameter genesis fixes. Two chains that share a chain id but differ in any of these have different genesis hashes and are different chains; a snapshot of one does not import into the other (22 §7.3). The genesis hash does not commit to the genesis kernel's code hash: two kernels whose `kernel_init` writes the same state give the same genesis block, and a node is held to the kernel that wrote its store by the store itself (22 §5).

**Chains that predate the genesis block.** A chain's genesis block is whatever its genesis kernel's `kernel_init` stored; nothing stores it later. A reference kernel built before 2026-10-23 stored none: on a chain whose genesis kernel is such a kernel, block 1's parent hash is zero, `BLOCKHASH(0)` answers zero and the RPC answers `null` for block 0 and for its hash. A kernel upgrade cannot give such a chain a genesis block, since every block hash from block 1 on commits to a parent hash of zero; a later kernel runs on it unchanged, reading `meta/last_hash` as before, and the chain keeps its identity as its chain id and the hash of its block 1. Data directories and devnets made with an earlier kernel fixture are made again (`orange devnet init`), as after any rebuild of the genesis kernel: a node refuses a store written by a kernel that is neither the one it is given nor an upgrade in that store's chain state (22 §5).

### 3.5 System receipts

The end of a block can log: a fast-track proposal executed there (13 §9.2) logs `ProposalExecuted(id)` and its action's logs, and no transaction carries them. They go in the block's *system receipt*, a receipt of no transaction:

| Field | Value |
|---|---|
| `status` | 1 |
| `gas_used`, `value`, `effective_gas_price` | 0 |
| `from` | the zero address |
| `to` | the governance address `0x…5010` |
| `height` | the block's |
| `index` | the number of transactions the block records: it comes after them |
| `cumulative_gas_used` | the block's gas used |
| `contract` | none |
| `logs` | what the end of the block logged, in order |
| `tx_type` | 0 |

It exists only for a block whose end logged something. The kernel stores it after the block's header, under `receipt/` ‖ its hash, the *system receipt hash* `keccak256("orange/system-receipt" ‖ block hash)` (`orange_abi::chain::system_receipt_preimage`), which no transaction hashes to and which names one block of one chain. It is committed by the next block's state root, as the block's header is. Its logs are in the header's logs bloom, which is the bloom of every log of the block (§3.1): a client that skips blocks whose bloom cannot match its filter, as geth's indexed `eth_getLogs` and most indexers do, finds a block whose only matching log is a system log. The rest of the header does not cover it: the transactions root, the receipts root and `gas_used` stay the Ethereum functions of the block's transactions of §3.1–§3.2, so a header rebuilt from `eth_getBlockByNumber` verifies as on any Ethereum chain, and the receipts root from `eth_getBlockReceipts`; only the check that the bloom is the OR of those receipts' blooms fails for a block with a system receipt, whose bloom adds the system receipt's. The block hash depends on the system receipt only through the bloom, and the system receipt hash on the block hash, so the kernel computes the receipt's logs before the header and stores the receipt after it (codex ADR 0058). The system receipt's own `logsBloom` (in `eth_getTransactionReceipt`) is the bloom of its logs, so the header's bloom is the OR of every receipt's bloom the RPC serves for the block.

The RPC serves it the way Polygon PoS serves its state-sync receipts, which Ethereum indexers already read:

- `eth_getLogs` returns its logs after the block's transactions' logs, with `transactionHash` the system receipt hash, `transactionIndex` its `index` and `logIndex` continuing the block's count; a filter by address or topic matches them as any log, and the header's bloom admits every log `eth_getLogs` returns for the block.
- `eth_getTransactionReceipt(system receipt hash)` returns it, `to` the governance address, its logs as `eth_getLogs` numbers them.
- `eth_getTransactionByHash(system receipt hash)` returns `null`: there is no transaction. `eth_getBlockByNumber` and `eth_getBlockReceipts` do not list it, and the block's `transactions` and receipts are its transactions' alone.
- `orange_getProposal(id)` of a fast-track proposal executed at the end of a block names the system receipt hash (13 §9.8).

Choosing a receipt outside the header over a system transaction inside it: a pseudo-transaction in the transactions root would need a transaction type that no Ethereum tool decodes (Optimism's deposit type `0x7E` is the precedent, and tools decode it only with chain-specific code), would put unsigned bytes where every tool expects a signed transaction, and would change what a header commits to for every block. A receipt beside the header changes no header and no transaction, and reaches tools through the one method they use to read logs.

## 4. `eth_getProof`

### 4.1 Request and response

`eth_getProof(address, storageKeys, block)` takes an address, a list of at most 1 024 storage keys (`MAX_PROOF_KEYS`; hex words of at most 32 bytes) and a block parameter as the state methods take one (§5). A longer list is refused with `-32602`, `too many storage keys: <n>, the limit is 1024`. Each key costs a kernel query and a proof on the thread that drives consensus, so the node's background work runs before each, as between the entries of a batch; the head can move meanwhile, and every value and proof in the response is of the block the request named. It returns:

| Field | Content |
|---|---|
| `address` | the address |
| `balance`, `nonce` | the account's, at that block |
| `codeHash` | `keccak256` of the account's code; `keccak256("")` for an account without code |
| `storageHash` | the block's state root (OrangeSDK has no per-account storage trie) |
| `stateRoot` | the block's state root, the header's `stateRoot` |
| `proofFormat` | `orange-binary-trie-v0`: the proofs are spec 10's |
| `accountKey` | the account's state key, `acct/ ‖ address` (`61 63 63 74 2f` then 20 bytes) |
| `accountValue` | the entry's value: the account record, `balance` (16 bytes, little-endian) ‖ `nonce` (8 bytes, little-endian) ‖ `code_hash` (32 bytes, zero for no code), 56 bytes (06 §2); `0x` when the account is not in state |
| `accountProof` | the proof of `accountKey` (§4.2) |
| `storageProof` | per requested key, in order: `{key, value, proof}` with the key as requested, the slot's value as a quantity (0 when unset), and the proof of the slot's state key `slot/ ‖ address ‖ key` (the key left-padded to 32 bytes); a set slot's entry value is its 32 big-endian bytes, an unset slot has no entry |

### 4.2 Proofs

A proof is a list of hex strings: the `d` sibling hashes of spec 10 §5.1 from the root down, then the terminal, `0x00` for an empty subtree or `0x01 ‖ path ‖ value_hash` (65 bytes) for a leaf. It is the spec 10 §5.1 encoding with the count dropped and the parts listed separately, so the count is the list's length less one.

To verify an account: take `stateRoot` from the block's header, `k = accountKey`, and run spec 10 §5.3. The account is present with the response's fields when the outcome is *present* with value hash `keccak256(accountValue)` and `accountValue` decodes to `balance`, `nonce` and `codeHash` (a zero code hash being `keccak256("")`); it is absent, with zero balance and nonce and no code, when the outcome is *absent*. A slot holds `value` when the outcome for its state key is *present* with value hash `keccak256` of `value` as 32 big-endian bytes, and is unset (value 0) when it is *absent*. `crates/orange-rpc/tests/ethereum.rs` checks the responses with a verifier written from spec 10, independent of `orange-trie`.

### 4.3 Heights

A proof is against the trie behind the root of the block's header, which the node keeps for every height within its state history (§5) and for the genesis state. The values are read from the state right after that block, which holds the same accounts and slots: the kernel writes only its block bookkeeping after it asks for the root (06 §5). A height the node does not keep is refused with the error of §5.3.

## 5. Historical state

### 5.1 Retention

The reference node keeps the state of its latest `state_history` executed blocks, 1 024 by default (`STATE_HISTORY`; `orange node --state-history <blocks>`), or of every block from genesis on an archive node (`--archive`, `ARCHIVE`). It keeps, per executed block, the value every committed key held before the block (and the host writes between it and the block before) changed it, and the state trie behind the block's root, which shares every node the block did not change. A block that leaves the window takes both with it. Keys under `local/` are outside history, as outside the commitment (10 §2).

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

- A genesis without a genesis time (§3.4) keeps a genesis header timestamp of 0, as every chain made before the field existed does.
- A system receipt (§3.5) is outside the header's roots and not in `eth_getBlockReceipts`; `eth_getLogs` and `eth_getTransactionReceipt` are the way to it. Its logs are in the header's bloom from the kernel of codex ADR 0058 on; a block an earlier kernel executed has a bloom of its transactions' logs alone, so on such a chain a tool that skips blocks by their bloom misses the system logs of blocks from before that kernel's activation. The node's own `eth_getLogs` reads every block's receipts and does not skip by the bloom, so it finds them in every block.
- `stateRoot` is not an Ethereum state root (§3.3), and `eth_getProof` answers in OrangeSDK's proof format, which Ethereum's verifiers do not read.
- A node without a data directory keeps its history in memory and has none from before it started; while blocks write heavily a window is shorter than `state_history` (§5.1). A node started from a snapshot has no state from before the snapshot (22 §7).
- The pool's rules for delegation are geth's, plus the take's rule for authorities ahead (§2.4); a pool of another host may differ without affecting consensus (14 §1).
- Proposals are not run before they are made: a delegated account's code can spend the account's balance, or move its nonce by creating a contract, during another sender's transaction, and a later transaction of that account in the same block is then recorded as failed (06 §5.1) where a geth builder would have left it out; so is a transaction priced below the base fee of the block it lands in (23 §10).
- The RPC serves no access-list generation (§8.3). Tracing (§9) serves `callTracer`, `prestateTracer` and `noopTracer`, not geth's opcode-level struct logger nor its other tracers, and traces a block only while the node keeps both its parent's state and its body.

## 8. Filters and the client surface

What standard clients call beyond the methods above, as they call it over HTTP and over a WebSocket (§8.7). `tools/ecosystem` runs ethers 6, viem 2 and Foundry (`cast`, `forge create`, `forge script`, `cast run`) against `orange dev`, and CI runs it on every change (§8.4).

### 8.1 Filters

The reference host serves geth's polled filters: `eth_newFilter(filter)`, `eth_newBlockFilter()` and `eth_newPendingTransactionFilter()` return an id, `eth_getFilterChanges(id)` returns what the filter matches since its last poll, `eth_getFilterLogs(id)` every log a log filter matches over its range, and `eth_uninstallFilter(id)` whether the filter existed. ethers' `contract.on`, viem's `createContractEventFilter`, `createBlockFilter` and `watchContractEvent` use them.

- **Ids** are 16 bytes as `0x` hex, the `keccak256` of a per-server random seed and a counter, so that one client cannot guess another's id and drain or remove its filter.
- **Cursor.** A filter remembers the first height it has not reported, the head plus one when it is installed. A poll reports the blocks from there to the head, at most `max_log_range` of them (10 000 by default, as for `eth_getLogs`), and the next poll the rest; a log filter's poll also stops after the block that takes it past `MAX_LOGS` logs (§8.6).
- **Log filters** take `eth_getLogs`' filter object (addresses, topics, `fromBlock`/`toBlock`, or `blockHash`). A poll reports the matching logs of the new blocks within the filter's numeric bounds: `earliest` and a number bound, a tag that moves with the head (`latest`, `pending`, `safe`, `finalized`) or none does not; a `fromBlock` above a numeric `toBlock` is refused with -32602 `invalid block range`. A filter on one block by hash has no changes. `eth_getFilterLogs` answers exactly as `eth_getLogs` with the filter object would, system receipts' logs included (§3.5). Logs never carry `removed: true`: a node executes a block only once it is finalized (spec 08 §5).
- **Block filters** report the hashes of the new blocks, in order.
- **Pending-transaction filters** report the hashes of transactions in the pool or in the new blocks that the last poll did not report, so a transaction mined between two polls is still reported once. One that enters and leaves the pool without being mined between two polls is not.
- **Lifetime and bound.** A filter not polled for 5 minutes (geth's deadline) is dropped; a poll of either kind keeps it. At most 1 024 filters are installed at once; a further install is refused with -32000 `too many filters installed, the limit is 1024`, after expired ones are dropped. An unknown or dropped id gets -32000 `filter not found`, as does `eth_getFilterLogs` of a block or pending-transaction filter.

### 8.2 Block positions and small methods

As the execution API specifies them: `eth_getBlockTransactionCountByNumber` and `…ByHash` (null for a block that does not exist), `eth_getTransactionByBlockNumberAndIndex` and `…HashAndIndex` (the view of `eth_getTransactionByHash`; null for a missing block or index), `eth_getUncleCountByBlockNumber` and `…ByHash` (`0x0`, or null), `eth_getUncleByBlockNumberAndIndex` and `…HashAndIndex` (null: no block has uncles), `web3_sha3`, `net_listening` (true), `net_peerCount` (the handshaken peers of spec 09 §3, `0x0` without a transport) and `eth_blobBaseFee` (`0x1`: no blob transaction is accepted, §2.1).

### 8.3 Compatibility notes

Deliberate differences from geth, each found by the suite of §8.4:

- **Subscriptions over WebSocket only.** An HTTP request is answered and its connection closed (`Connection: close`); `eth_subscribe` and `eth_unsubscribe` sent over HTTP get geth's answer, -32601 `notifications not supported`. Over a WebSocket on the same port (§8.7) they are served. Clients on HTTP poll: ethers' `JsonRpcProvider` and viem's `http` transport do so by default, through the filters of §8.1 or `eth_getLogs` and `eth_blockNumber`; ethers' `WebSocketProvider`, viem's `webSocket` transport and `cast subscribe` subscribe.
- **Subscription kinds.** `newHeads`, `logs` and `newPendingTransactions` (hashes only, as geth sends them without `true`) are served; `syncing` and the full-transaction form of `newPendingTransactions` get -32602 (§8.7.3).
- **Tracing in part; no access-list generation, no simulation.** geth's four tracing methods are served with `callTracer`, `prestateTracer` and `noopTracer` (§9), by `orange dev` and by `orange node --rpc-debug` (§8.5); the other `debug_*` methods, Parity's `trace_*`, `eth_createAccessList` and `eth_simulateV1` get -32601. `cast run` works without them: it replays a transaction in Foundry's own EVM over historical state (§5), and the suite checks it charges the gas the kernel charged. `cast access-list` does not work.
- **Methods geth removed** (`eth_coinbase`, `eth_mining`, `eth_hashrate`, `eth_protocolVersion`) and the node-held-key methods (`eth_sign`, `eth_sendTransaction`, `eth_signTransaction`; `eth_accounts` is empty) are not served.
- **Client caches and short slots.** A block every 400 ms is shorter than some client caches: ethers 6 answers a request identical to one made in the last 250 ms from its cache (`cacheTimeout`), so a script that sends, waits for the receipt and sends again within that can sign with a stale pending nonce, which the node refuses as `nonce too low`, as it does against anvil or hardhat with automine. A client on an OrangeSDK chain sets `cacheTimeout: -1` (or manages nonces, as ethers' `NonceManager` does); viem has no such cache for nonces.

### 8.4 The ecosystem suite

`tools/ecosystem` (its README says how to run it) starts nothing itself: CI builds `orange`, starts `orange dev` with the suite's genesis (chain id 1337, a 1 gwei base-fee floor) and runs `npm test` (ethers 6.17.0 and viem 2.57.7, pinned, with solc-js 0.8.28) and `foundry.sh` (cast and forge) against it. Together they cover the chain id and blocks by number, hash and tag; balances and nonces, `pending` included; signed EIP-1559, EIP-155 legacy, EIP-2930 and EIP-7702 transactions and their receipts; an ERC-20 deployed with `forge create`, `forge script` (several transactions of one sender before any is mined) and both clients' factories, its calls, gas estimates and events through `eth_getLogs`, the filters of §8.1 and both clients' watchers; `eth_feeHistory`, `eth_maxPriorityFeePerGas` and the clients' fee estimates (spec 23 §7); `eth_getProof`; revert reasons, a custom error and a revert string decoded by each client from `eth_call` and `eth_estimateGas`, and a reverted transaction reported as failed; and, over the WebSocket of §8.7, ordinary calls, `newHeads`, the token's events through a `logs` subscription and `newPendingTransactions`, through ethers' `WebSocketProvider` and viem's `webSocket` transport.

### 8.5 Browsers and `orange_stop`

The JSON-RPC server answers on a local address with no authentication, and a web page the node's operator opens can send it requests: a browser lets any page `POST` a `text/plain` body to `http://127.0.0.1:8545` without asking the server first, and lets a page read the answer only when CORS headers allow its origin. So the reference host (`crates/orange-rpc/src/http.rs`):

- **Refuses pages it was not told to serve.** A request with an `Origin` header (browsers send one with every cross-origin request and every `POST`) is answered only when the origin is among those `--rpc-cors <origin>` names (repeatable, compared without case; `*` allows every origin); any other gets `403 Forbidden` and reaches neither JSON-RPC nor telemetry. A request without `Origin`, as curl, ethers and viem under Node, Foundry, Prometheus and `orange` itself send, is answered whatever `--rpc-cors` says. With no `--rpc-cors`, the default, the server sends no CORS headers at all.
- **Sends CORS headers only to allowed origins.** The answer to an allowed origin, the `204` to an `OPTIONS` preflight included, carries `Access-Control-Allow-Origin` (the configured entry, `*` or the origin as configured, never text copied from the request), `Vary: Origin`, `Access-Control-Allow-Headers: content-type` and `Access-Control-Allow-Methods: POST, OPTIONS`. A wallet or a dapp page that talks to the node from a browser needs its origin named.
- **Serves `orange_stop` only when asked to.** `orange_stop` (no parameters, result `true`) ends the node's server loop, after which the node closes its store and exits. A node serves it only when started with `--rpc-stop`; otherwise it answers -32601 `method not found: orange_stop (this node serves it only when started with --rpc-stop)` and is stopped by a signal. `--no-rpc-stop`, which once had to be given to refuse it, is still accepted and refuses it even beside `--rpc-stop`. `orange devnet` starts its nodes with `--rpc-stop` on loopback, which its `stop` and `down` use, and `ops/testnet/orange-host` does for every node whose RPC does not face the public.
- **Serves the `debug` namespace only when asked to.** A trace (§9) holds the node's thread for up to the trace budget, 2^30 kernel gas by default, so `orange node` serves `debug_traceTransaction`, `debug_traceBlockByNumber`, `debug_traceBlockByHash` and `debug_traceCall` only when started with `--rpc-debug`, as geth serves its `debug` namespace only with `--http.api debug`; otherwise every `debug_*` method answers -32601 `method not found: <method> (this node serves the debug namespace only when started with --rpc-debug)`. `orange dev` serves it always: a development chain is a tool's, and Foundry and Hardhat expect tracing of the node they deploy to.

Before 2026-11-05 the server sent `Access-Control-Allow-Origin: *` with every answer and served `orange_stop` unless told not to, so any page an operator opened could stop a node on the same machine, or a validator whose RPC a page could reach, and read every answer.

### 8.6 What one client can cost the node

The methods read the node's state, so they are answered on the thread that drives consensus, between the node's steps; nothing a client does with its connection may hold that thread. The reference host (`crates/orange-rpc/src/http.rs`, its limits in `http::Limits`) therefore splits the server in two:

- **Connections are read and written off the node's thread.** An acceptor thread takes connections and gives each a thread of its own, which reads and parses the request, hands it to the node's thread, and writes the answer it gets back. Each turn of the node's loop answers at most `REQUESTS_PER_TURN` (16) of the requests waiting, running the node's background work (the transport and the clock) after each answer, and once when none waited; between turns the loop checks whether to stop (`orange_stop`, `--blocks`). A request waits for the node's thread in a queue of at most one request per open connection. A client that sends slowly, or reads its answer slowly or never, costs one connection thread and never a step of the node; what the node computes for a request it answers is bounded by the query budget and the bounds of the methods.
- **At most `MAX_CONNECTIONS` (64) connections at once.** One past them is answered at once with `503 Service Unavailable`, without being read, and closed.
- **A deadline for the whole request.** The request line, the headers and the body must arrive within `REQUEST_MS` (10 000 ms) of the connection being accepted, however steadily the bytes come; past it the connection is answered `408 Request Timeout` and closed.
- **Bounded headers.** The request line and each header line are at most `MAX_LINE` (8 192 bytes, the line end included), a request has at most `MAX_HEADERS` (64) header lines, and the request line and headers together are at most `MAX_HEADER_BYTES` (65 536 bytes); a request past one of these is answered `431 Request Header Fields Too Large`. The body is at most `MAX_BODY` (5 MiB, geth's limit), refused from its `Content-Length` alone with `400 Bad Request`.
- **A deadline for the answer.** An answer must be written within `WRITE_MS` (10 000 ms) of the node handing it over; a client that does not take it by then is closed. When the loop stops it waits, at most `WRITE_MS`, for the answers it already gave to be written, so the answer to `orange_stop` reaches its caller before the node exits.

What one request makes the node build is bounded as well (`crates/orange-rpc/src/methods.rs`), so that no answer grows past what the node can hold:

- **Batches.** A batch holds at most `MAX_BATCH` (1 000) requests, as in geth; a longer one is refused whole with one -32600 `batch too large`, under the id of its first request, and runs nothing. Its answers are at most `MAX_RESPONSE_BYTES` (25 000 000 bytes of JSON, geth's `BatchResponseMaxSize`): once the answers so far pass it, each request after is answered, without being run, with -32003 `response too large`, as geth answers it.
- **`eth_getLogs`** searches at most `max_log_range` blocks (10 000 by default, §8.1) and answers at most `MAX_LOGS` (10 000) logs: a query that matches more is refused with -32005 `query returned more than 10000 results`, the words of the hosted providers whose answers clients already split ranges on. `eth_getFilterLogs` answers the same way. `eth_getFilterChanges` reports the logs of whole blocks up to and including the first block that takes it past `MAX_LOGS`, and the next poll the blocks after.
- **Filter objects.** The filter object of `eth_getLogs` and `eth_newFilter` names at most `MAX_FILTER_ADDRESSES` (1 000) addresses and at most `MAX_SUB_TOPICS` (1 000) alternatives in each of its at most 4 topic positions, geth's limits; more are refused with -32602 `exceed max addresses` or `exceed max topics`. A 5 MiB body holds over 100 000 addresses, and the 1 024 filters of §8.1 could otherwise keep gigabytes of them installed; at these limits a filter holds at most about 150 KB.
- **`eth_feeHistory`** takes at most `MAX_REWARD_PERCENTILES` (100) reward percentiles, geth's limit; more are refused with -32602 `invalid reward percentile: over the query limit 100` (23 §7).
- **`txpool_content`** answers at most `MAX_RESPONSE_BYTES` of JSON: a pool whose content is larger (a full pool holds 64 MiB of raw transactions, over twice that as JSON, 14 §4) is refused with -32003 `response too large`; `txpool_status` still counts it (14 §7).

Before 2026-11-06 the server read, answered and wrote each connection on the node's own thread, one at a time, with only a 5 s timeout on each read: a client that sent a byte every 4 s, or never read a large answer, stopped the node from voting, ticking and talking to its peers for as long as it liked; and a 5 MB request of reward percentiles, or a batch of 1 000 `txpool_content` over a full pool, made the node build tens of gigabytes of answer.

### 8.7 WebSocket and subscriptions

Clients that subscribe (ethers' `WebSocketProvider`, viem's `webSocket` transport, `cast subscribe`, wallets and indexers that watch heads and events) need a connection that stays open and a server that sends without being asked. The reference host serves a WebSocket (RFC 6455) on the JSON-RPC port, beside HTTP: `crates/orange-rpc/src/ws.rs` has the frame codec, the handshake and the socket's threads, `crates/orange-rpc/src/subscriptions.rs` what the node's thread keeps and sends. The codec and the SHA-1 the handshake needs are the host's own, about 400 lines with their tests: no crate in the workspace frames WebSocket messages, and the crates that do (`tungstenite` and its kin) bring an HTTP parser, TLS and randomness features of their own beside the server of §8.6, whose bounds the socket must share.

#### 8.7.1 The upgrade

A `GET` request, on any path, whose `Upgrade` header is `websocket` asks for a WebSocket. It is read under the bounds of §8.6 (its deadline, its header limits), decided on the node's thread like any request, and answered, in this order:

1. `400 Bad Request` when its `Connection` header does not list `upgrade`, or its `Sec-WebSocket-Key` is missing or is not the base64 of 16 bytes;
2. `426 Upgrade Required`, with `Sec-WebSocket-Version: 13`, when its `Sec-WebSocket-Version` is not `13`;
3. `403 Forbidden` when it carries an `Origin` that `--rpc-cors` does not allow, under the rule of §8.5. Browsers send `Origin` with every WebSocket upgrade and never preflight one, so this check is all that keeps a page the operator opened off the socket; CORS headers mean nothing to a WebSocket and none are sent. A client outside a browser sends no `Origin` and is answered whatever `--rpc-cors` says, as over HTTP;
4. `503 Service Unavailable` when `MAX_WS_CONNECTIONS` (32) sockets are open;
5. otherwise `101 Switching Protocols` with `Sec-WebSocket-Accept`, the base64 of the SHA-1 of the key followed by RFC 6455's GUID. No extension and no subprotocol is agreed.

An open socket counts against `MAX_WS_CONNECTIONS` and no longer against the `MAX_CONNECTIONS` of HTTP, so open sockets never keep HTTP clients out.

#### 8.7.2 Messages

Each text or binary message the client sends is one JSON-RPC body, a request or a batch, answered with one text message exactly as the same body sent over HTTP would be, the batch limits of §8.6 included, except that `eth_subscribe` and `eth_unsubscribe` are served (§8.7.3). A notification is a text message `{"jsonrpc":"2.0","method":"eth_subscription","params":{"subscription":id,"result":…}}`.

Frames follow RFC 6455. A client's frame that is not masked, has a reserved bit set or an unknown opcode closes the connection with status 1002, and so does a control frame longer than 125 bytes or fragmented, or a continuation that continues nothing or a new message before the last one ended; a text message that is not UTF-8 closes it with 1007. Fragmented messages are assembled. A `Ping` is answered with a `Pong` of the same payload, a `Pong` is taken as a sign of life, and a `Close` is answered with a `Close`, after which the connection ends. The server's frames are unmasked and never fragmented.

A socket's reader hands the node one message at a time and reads the next only once the node has answered it, so one socket has at most one request waiting for the node's thread, as one HTTP connection does (§8.6); a client that sends many requests without waiting has them answered in order.

#### 8.7.3 Subscriptions

`eth_subscribe([kind, options])` answers a subscription id, 16 bytes as `0x` hex drawn as filter ids are (§8.1); `eth_unsubscribe([id])` answers whether this socket held such a subscription, and a socket can remove only its own. A subscription lives until it is removed or its socket closes, and starts with the first block after the head when it was made. The kinds:

- **`newHeads`** announces every block once the node has executed it, in order, as its header: the fields of `eth_getBlockByNumber`'s block without `transactions`, `uncles`, `withdrawals` and `size`. A node executes a block only once it is finalized (spec 08 §5), so the head announced is the executed head, the `latest` of every method and of `eth_blockNumber`; it is never replaced by another block at its height, and no subscription ever reports a reorganization. A block finalized and not yet executed is announced once it is executed.
- **`logs`**, with an optional filter object, announces, one notification per log, every log of every newly executed block that the object's `address` and `topics` match, with `eth_getLogs`' matching and its limits (at most `MAX_FILTER_ADDRESSES` addresses, and `MAX_SUB_TOPICS` alternatives in each of 4 positions, §8.6), system receipts' logs included (§3.5), in the order `eth_getLogs` answers them. The object's `fromBlock`, `toBlock` and `blockHash` are checked as `eth_getLogs` checks them and otherwise ignored, as geth ignores them: a subscription reports new blocks only. No log carries `removed: true`, for the reason above.
- **`newPendingTransactions`** announces the hash of every transaction the pool holds, or a block executed since the last look holds, that the pool did not hold at the last look, once. The pool is looked at at most every `PENDING_MS` (200 ms), and each look reads at most `BLOCKS_PER_TURN` of the blocks executed since the last, the rest at the next; so a transaction pooled and mined between two looks, as one sent shortly before a slot ends is, is still announced, as the pending-transaction filters of §8.1 report it. One that enters and leaves the pool without being mined between two looks is not. With a second parameter `true` (geth's full transactions) it is refused with -32602 `full pending transactions are not served`.

Any other kind, `syncing` included, gets -32602 `unsupported subscription kind: <kind>`. A socket holds at most `MAX_SUBSCRIPTIONS` (128) subscriptions; one more is refused with -32000 `too many subscriptions on this connection, the limit is 128`.

The node's thread sends notifications after the requests of its turn (§8.6), for at most `BLOCKS_PER_TURN` (16) blocks a turn, so a node that executed many blocks at once announces them over several turns and is never held by them. A block is read only for the subscriptions that want it: its header for `newHeads`, its receipts for `logs`.

#### 8.7.4 What one socket can cost the node

- **Messages.** A frame, and a message once its fragments are assembled, is at most `MAX_MESSAGE` (5 MiB, the HTTP body limit); a longer one closes the connection with 1009, from its length alone.
- **Queue.** What the node sends a socket, answers and notifications, is queued for the socket's writer thread, which writes each frame within `WRITE_MS` (§8.6) or closes the socket. At most `WS_QUEUE_BYTES` (32 MiB) is queued for one socket, room for an answer of `MAX_RESPONSE_BYTES` and more: a frame that would take the queue past it closes the socket instead, and ends its subscriptions. A client that subscribes and never reads costs at most that much memory before it is cut off, and the node's thread never waits for a socket.
- **Idle sockets.** A socket from which nothing has been read for `PING_MS` (30 000 ms) is sent a `Ping`; one from which nothing is read for another `PING_MS` after it is closed. A client that answers pings is kept, as geth keeps it.
- **Stopping.** When the server stops it waits, at most `WRITE_MS`, for what is queued on its sockets to be written, then closes them, so the answer to an `orange_stop` sent over a socket reaches its caller.
- **Threads.** An open socket costs two threads, its reader and its writer: at most `MAX_CONNECTIONS` HTTP threads and twice `MAX_WS_CONNECTIONS` socket threads run at once.

Before 2026-11-06 the server had no WebSocket: `eth_subscribe` was refused, and a client that subscribes could not be used against an OrangeSDK node.

## 9. Tracing

Block explorers, Foundry, Hardhat and Tenderly-style tools read what a transaction did through geth's `debug` namespace. The reference host serves its four tracing methods with the two native tracers those tools use, `callTracer` and `prestateTracer`, and `noopTracer`, and writes their results as geth (go-ethereum 1.17, `eth/tracers/native`) does. `crates/orange-rpc/tests/trace.rs` checks them, for the same signed transactions, against the traces of a reference node whose tracers follow geth's (anvil 1.7.1, Osaka, recorded 2026-11-07, in `crates/orange-rpc/tests/fixtures/trace`), with geth's rule applied where that node differs from it: the top frame's `gas` is the transaction's gas limit, `onlyTopCall` counts no frames in a log's `position`, a prestate names `codeHash` beside code and leaves out accounts that were empty before.

### 9.1 Methods

| Method | Executes again | Result |
|---|---|---|
| `debug_traceTransaction(hash, tracer)` | the transaction's block, from its start up to and including the transaction | the transaction's trace |
| `debug_traceBlockByNumber(block, tracer)`, `debug_traceBlockByHash(hash, tracer)` | the block's transactions | `[{txHash, result}]`, one per transaction the block records, in order; `{txHash, error}` for one that could not run (codex ADR 0022) |
| `debug_traceCall(call, block, tracer)` | the call, as `eth_call` runs it at that block (§2.3, §5.2) | the call's trace; a call that reverts or halts is traced, not refused |

The methods are served over HTTP and over the WebSocket of §8.7, which share one dispatcher, and only on a node that serves the `debug` namespace (§8.5): `orange dev` always, `orange node` with `--rpc-debug`; elsewhere they answer -32601.

The tracer object is geth's: `tracer` names the tracer and `tracerConfig` holds its options. `callTracer` takes `onlyTopCall` and `withLog`; `prestateTracer` takes `diffMode`, `disableCode`, `disableStorage` and `includeEmpty`; other options are ignored, as geth ignores options a tracer does not read. `timeout` and `reexec` are accepted and do nothing: the trace budget of §9.4 bounds the work, and the node keeps the state it keeps. Refused:

| Tracer object | Error |
|---|---|
| no `tracer`, which in geth runs the struct logger, opcode by opcode | `-32000`, `opcode-level tracing (the struct logger) is not supported: ask for callTracer or prestateTracer` |
| another tracer, JavaScript tracers included | `-32602`, `tracer not supported: <name> (this node runs callTracer, prestateTracer and noopTracer)` |
| `stateOverrides` or `blockOverrides` (`debug_traceCall`) | `-32602`, `stateOverrides are not supported` (or `blockOverrides`) |
| a field of the wrong JSON type | `-32602` |

The struct logger is refused rather than served: every opcode's record (program counter, gas, cost, depth, stack and memory) would have to leave the kernel's VM through the query's answer, many megabytes for an ordinary transaction, and no tool this specification targets depends on it; Foundry's `cast run` replays opcodes in its own EVM (§8.3).

Other errors: an unknown hash, and a system receipt's hash (§3.5), are `-32000`, `transaction not found`; a block that does not exist is `-32000`, `block not found` by number and `header for hash not found` by hash; a transaction that could not run is `-32000`, `transaction could not run: it fails the kernel's validation`; a block whose parent's state the node no longer keeps gets the error of §5.3 for the parent's height; a traced call gets `eth_call`'s errors for what the kernel would refuse (intrinsic gas, initcode size, funds) and the block parameter's of §5.3.

### 9.2 Where tracing runs

Tracing runs in the kernel, in two queries of `orange_abi::trace` (`trace_block` and `trace_call`), and only there; the path that executes a block is unchanged:

- **The tracer is an option of the message.** Every message the kernel runs carries a `trace` field, empty on the consensus path and in every other query. `evm::run_in` runs a message without a tracer exactly as before, revm's `transact` without an inspector. With `callTracer` it builds the same EVM with an inspector (`trace::CallTracer`) and runs `inspect_tx`, which executes the same instructions at the same gas and calls the inspector around each frame and before each instruction; with `prestateTracer` it runs `transact` and reads revm's state after the transaction. A traced transaction therefore does what it did in its block, and tracing cannot move the gas or the state of consensus.
- **`trace_block` executes the block again from its parent's state.** The host runs it as a query at the height before the block (`QueryArgs.at = h − 1`, 06 §6), in the overlay every query runs in and drops. The kernel takes the block's body, its transactions and participation as the host was asked to execute them, from the proposal the driver finalized at that height, which the driver's tables keep for `DRIVER_RETENTION` heights on a node whose chain state is on disk and for every height otherwise (22 §8.1). It runs `stf::execute_with`, the function `kernel_stf_execute_block` runs: the snapshot record, the precompile gate, the participation (evidence and DKG envelopes), the modules' `begin_block`, then the transactions in order, those to trace with a tracer. It stops after the transaction `debug_traceTransaction` names, or after the block's last transaction, before the end of the block, which no trace shows. A query for a height whose body the tables no longer hold answers status 1, which the RPC answers `-32000`, `the body of block <h> is no longer kept by this node, which cannot trace it`.
- **`trace_call` is `call` with a tracer.** The call runs as `eth_call` runs it (at a gas price of zero, without a nonce check, with at most `MAX_TX_GAS`, a governance call's surcharge counted), but keeps its changes in the query's overlay until the query ends, so that the prestate can read the state after it; a native contract's gas is still capped as in a call (16 §6).
- **The host checks a trace against the block.** Before it answers, the RPC compares what the kernel executed with what the block recorded: the hashes of the traced transactions with the header's `tx_hashes`, and each transaction's gas used and status with its receipt's. A trace that differs, which a kernel upgrade between the block and the trace could cause (the kernel that answers a query is the one running now, §5.2), is refused with `-32000`, `trace diverged from block <h>: …`, rather than served as the block's.

### 9.3 Tracers

**`callTracer`** records a frame for the transaction or call itself and one for every `CALL`, `CALLCODE`, `DELEGATECALL`, `STATICCALL`, `CREATE`, `CREATE2` and `SELFDESTRUCT` below it, as geth's does: a call to a precompile, to an account without code or to a native contract (`0xEF02`, 16 §5) is a frame, and so is a call that fails before it runs (call depth, insufficient balance). What runs outside the EVM is the one frame that called it: a native contract's module, the outbox (17 §2), and the call of a transaction to the governance, module or staking address, whose kernel action (13 §9, 16 §4.2, 15 §3) runs after the EVM call; the logs such an action adds to the receipt (staking and governance events) are not in the trace. Each frame is geth's object:

| Field | Value |
|---|---|
| `from` | the account the calling code runs as; for `DELEGATECALL` and `CALLCODE`, the current contract |
| `gas` | the gas given to the frame, a call's stipend included; for the top frame, the transaction's gas limit (a call's gas) |
| `gasUsed` | what the frame used: all its gas when it failed other than by reverting, none when it never started (call depth, insufficient balance, nonce overflow); for the top frame, the receipt's `gasUsed`, intrinsic gas and refund included |
| `to` | the account whose code runs: the delegate for `DELEGATECALL` and `CALLCODE`, the created contract for a creation that succeeded, the beneficiary for `SELFDESTRUCT`; absent for a creation that failed |
| `input` | calldata or initcode; `0x` for `SELFDESTRUCT` |
| `output` | the return data or, for a creation, the code deployed; for a failed frame, revert data when there is any; absent when empty |
| `error` | absent for success; otherwise geth's text: `execution reverted`, `out of gas`, `max call depth exceeded`, `insufficient balance for transfer`, `contract address collision`, `invalid jump destination`, `invalid opcode: INVALID` (`0xFE`) or `invalid opcode: opcode 0x<op> not defined`, `stack underflow (<len> <=> <required>)`, `stack limit reached <len> (<limit>)`, `write protection`, `return data out of bounds`, `nonce uint64 overflow`, `max code size exceeded`, `invalid code: must not begin with 0xef`, `max initcode size exceeded`, `gas uint64 overflow` |
| `revertReason` | for `execution reverted`, the reason of an `Error(string)` or the meaning of a `Panic(uint256)`, in the words of the call errors of §8.4 |
| `calls` | the frames it opened, in order; absent when none |
| `logs` | with `withLog`, `{address, topics, data, index, position}` per log, `index` being the log's index among the block's logs as its receipt numbers it (among the call's for `debug_traceCall`) and `position` how many frames the frame had opened before the log; none for a frame that failed or has a failed ancestor; absent when none |
| `value` | for every kind but `STATICCALL`: the value sent, the caller's value for `DELEGATECALL`, the balance for `SELFDESTRUCT` |
| `type` | the opcode's name; `CALL` or `CREATE` for the top frame |

`onlyTopCall` records the top frame alone, with the logs it emitted itself. A precompile that fails other than by running out of gas is `precompile failed`, where geth writes each precompile's own text (for example `bn256: malformed point`); a failed native contract or outbox call is `precompile failed` too, as nothing on Ethereum names it. Logs are taken from revm's journal rather than from the `LOG` opcodes, so the outbox's `MessageSent` is a log of the outbox's frame.

**`prestateTracer`** lists every account the message loaded (revm's state after it: the accounts it called, read or wrote, its sender, its recipient or created contract, the authorities of a set-code transaction), the beneficiary and, on a chain whose parameters name a treasury, the treasury, which the kernel pays the base fee after the EVM (23 §4). Each account is geth's object, before the message: `balance` (always), `code` and `codeHash` (when it has code; `code` left out with `disableCode`), `nonce` (when not zero, a JSON number as geth writes it) and `storage`, the slots it read or wrote with their values before, zero values included (left out with `disableStorage`); a native contract has no slots, its storage being its module's namespace. An account that did not exist before the message, a contract it created or an address it only called, is left out, as geth leaves out an account that was empty, unless `includeEmpty` keeps it as `{balance: 0x0}`. With `diffMode` the result is `{post, pre}`, as geth's `processDiffState` makes it: an account that did not change is in neither; `pre` holds each changed account's fields before, with only its slots that changed and were not zero; `post` holds only the fields that changed (`balance`, `nonce`, `code` with `codeHash`, the slots not zero after); an account the message created and destroyed (EIP-6780) has no `post`, and with `includeEmpty` keeps its empty `pre`. The state after is read once the kernel is done with the transaction, so the base fee paid to a treasury and a governance call's surcharge (13 §9.9) are in it.

**`noopTracer`** answers `{}` for each transaction, after executing it.

### 9.4 What a trace may cost

A trace runs on the thread that drives consensus, as every query does (§8.6), and executes up to a whole block again, so the host bounds it:

- **Gas.** A tracing query runs within the node's trace budget, `TRACE_GAS` = 2^30 kernel gas unless changed (`orange node --trace-gas <n>`, `orange dev --trace-gas <n>`), sixteen call budgets: about fifty million EVM gas of plain opcodes, more than a full block of 30 million, and by the measure given for `QUERY_GAS` 5 s to 50 s of the thread on a loaded machine. A trace past it is `-32000`, `execution aborted: the trace ran past the node's trace budget (--trace-gas)`, as a call past its budget is aborted. A node that serves tracing to the public lowers it. A call traced by `debug_traceCall` has `eth_call`'s gas cap, `MAX_TX_GAS`.
- **Size.** The kernel records at most `MAX_TRACE_BYTES` = 12 000 000 bytes of inputs, outputs and logs for one transaction, counting `FRAME_BYTES` = 200 more for each frame: about half of the 25 MB response budget once written as hex. Past it the trace stops recording and is marked truncated. A truncated trace, and any answer whose JSON is longer than `MAX_RESPONSE_BYTES` (§8.6), is `-32003`, `response too large`, geth's answer past its response limit; a block whose trace is too large is traced a transaction at a time.
- **Deadlines.** The deadlines of §8.6 are unchanged: a trace is answered between the node's steps like any request, and its answer must be written within `WRITE_MS`.
