# 14 — Mempool

## 1. Scope

The mempool is the host's store of transactions waiting for a block. It is policy, not validity: the kernel decides whether a transaction is valid (06 §5.1) and checks every transaction again when it executes a block, so a host whose pool differs from this document stays in consensus. This document fixes the policy of the reference host (`orange-node`) so that wallets, scripts and other hosts can rely on its behaviour. It follows geth's transaction pool where the two can be compared.

A pool transaction carries its sender, nonce, fee cap (the gas price, or the maximum fee per gas), tip cap (the gas price, or the maximum priority fee per gas), gas limit and cost (value plus gas limit times fee cap), and for a set-code transaction the authorities its authorizations name (those whose signatures recover, spec 20 §2.2), read from the raw transaction, and the priority the kernel's validation returned. Reading a transaction recovers its signature and every authorization's, so the host reads none that check 2 of §2 refuses. A transaction the host cannot read in this way is handed to the kernel with `Ahead` zero and refused for the reason the kernel gives; if the kernel accepts it anyway, it is refused as malformed.

## 2. Admission

Transactions are kept per sender, ordered by nonce. For each sender the pool holds the account (nonce, balance, code hash) read from the state when the sender's first transaction arrived, or after the last block (§5).

A transaction is *pending* when every nonce from its sender's account nonce up to its own is in the pool: it can run once those before it have. Any other transaction is *queued*: a nonce between is missing.

A submitted transaction:

1. is accepted with no change if the pool holds a transaction with the same hash;
2. is refused with `oversized data` if its raw bytes exceed 128 KiB (geth's `txMaxSize`). The cap keeps every pending transaction small enough for a take (§3): a host's cap MUST NOT exceed the `max_bytes` its kernel's driver asks for, or a transaction no block can carry would stay pending, holding pool capacity and blocking its sender's later nonces, without ever costing its sender anything; and with `too many authorizations` if it is a set-code transaction with more than `MAX_AUTHORIZATIONS` (64) authorizations. Both are checked before the transaction is read (§1), on its length and its decoded authorization list alone: a transaction of 128 KiB could carry about 1 400 authorizations, each a signature to recover before the kernel is asked, and a frame of a peer (09 §2) far more;
3. is refused with `in-flight transaction limit reached for delegated accounts` if its sender's account holds code (a delegation designator, the only code a sender can have) or a pool transaction's authorization names the sender, the pool holds a transaction of the sender, and none with the newcomer's nonce; and with `authority already reserved` if it is a set-code transaction naming an authority that holds more than one transaction in the pool. These are geth's rules: a delegated account's code can spend its balance from other accounts' transactions, so it gets one transaction in flight (spec 20 §2.4);
4. is refused with `replacement transaction underpriced` if the pool holds a transaction of the same sender and nonce and the newcomer does not raise both its fee cap and its tip cap to at least `old + ⌊old × 10 / 100⌋` (geth's price bump);
5. if it replaces a pending transaction, is refused with `insufficient funds for gas * price + value` when the costs of the sender's pending transactions, with the newcomer's in place of the replaced one's, exceed the balance (geth's overdraft check). Otherwise a sender could replace its first transaction with one that spends the balance, leaving the pending ones behind it holding pool capacity without being able to run;
6. is validated by `kernel_stf_validate_tx` with `ahead` computed from the pool as 06 §5.1 says, and refused for the kernel's reason if invalid. A nonce below the account's is invalid (`nonce too low`); a nonce above it is valid when the sender can pay for it after what the pool holds before it;
7. is refused with `txpool is full` if a limit of §4 holds and no eviction can make room;
8. otherwise enters the pool, replacing the transaction with the same sender and nonce if any. A transaction that fills a gap promotes the queued transactions behind it to pending. Each of those was validated without the newcomer's cost reserved, so the pool walks the sender's pending transactions in nonce order adding up their costs and drops the first, behind the newcomer, whose running total exceeds the balance; the ones after it are queued behind the new gap.

Checks 2 to 5 need no kernel and run before check 6.

## 3. Taking transactions for a block

`MempoolTake { max_bytes, max_gas, skip }` is answered with pending transactions only, in an order a block can execute: each sender's in nonce order, and across senders by the tip each sender's next transaction pays under the base fee of the next block, highest first, ties by order of arrival. The tip is `min(tip cap, fee cap − base fee)` (23 §3.1), computed when the take is made: the priority the kernel reported at admission was the tip under the base fee of that moment, and once the base fee moved, a legacy transaction's tip moves with it while a dynamic-fee transaction's stays at its tip cap, so an order fixed at admission would put behind one whose tip is now the larger. The answer's raw bytes total at most `max_bytes` and its gas limits at most `max_gas`. A sender whose next transaction does not fit, whose balance would not cover that transaction's cost after the ones before it, or whose next transaction's fee cap is below the base fee of the next block (23 §8), contributes nothing more to this answer; other senders continue. A transaction priced below the base fee stays in the pool, as geth keeps it, for a block whose base fee is lower.

`skip` lists the hashes of transactions to treat as already taken: those carried by the blocks the driver builds on but the host has not executed yet, which the pool still holds. A skipped transaction is not in the answer and uses none of `max_bytes` or `max_gas`, but its cost counts against its sender's balance and its sender's later transactions may follow it. Without this, a block built on an unexecuted parent would spend its budget on the parent's transactions, which the driver then leaves out, and under load every other block would be empty.

A sender that an authorization of a set-code transaction ahead of it names (spec 20 §2.4) contributes nothing more to the answer. Ahead means in `skip`, whose transactions run before the answer's whatever their priority, or taken earlier in the answer. The authorization can move the sender's nonce when it runs, and the sender's pending transaction could then no longer run.

Taking does not remove anything: transactions stay until a block includes them or they become invalid, so a proposal that never finalizes loses nothing.

## 4. Limits and eviction

| Limit | Value | Applies to |
|---|---|---|
| Transactions in all | 8192 | every insertion |
| Queued transactions | 1024 | every insertion |
| Transactions of one sender | 256 | insertions that are not replacements |
| Bytes of raw transactions | 64 MiB | every insertion |
| Bytes of one raw transaction | 128 KiB | every insertion (§2 check 2) |
| Authorizations of one set-code transaction | 64 | every insertion (§2 check 2) |

A newcomer that would put its sender over the per-sender limit is refused. A newcomer that would put the pool over any other limit evicts queued transactions, cheapest priority first and the latest to arrive among equals, until the pool is within every limit. A pending newcomer may evict any queued transaction; a queued newcomer only those with a strictly lower priority. Pending transactions are never evicted. If no such set of evictions brings the pool within its limits, the newcomer is refused and the pool is left as it was, including a transaction it would have replaced.

Removals can leave more queued transactions than the queued limit, as when a block leaves a gap; the limit binds the next insertion.

## 5. After a block

When a block executes, the pool removes every transaction it carries, whether or not it ran, and every transaction the kernel rejects through `MempoolReject`. Then, for every sender with transactions in the pool, it reads the account from the new state. If the account is unchanged nothing happens. Otherwise the pool:

1. drops the transactions whose nonce is below the account nonce;
2. walks the pending transactions in nonce order adding up their costs, and drops the first whose running total exceeds the balance; the ones after it are queued from then on;
3. drops every queued transaction whose own cost exceeds the balance;
A sender whose code hash changed keeps its transactions. An account that can send has no code or a delegation designator, which only EIP-7702 authorizations write or clear (spec 20 §2.2), and a delegated account still sends.

These checks are the account-dependent part of the kernel's validation, so the kernel is not called again for transactions it already accepted. Transactions that become pending are gossiped (§6).

## 6. Gossip

A transaction is sent to peers (09 §4) when it first becomes pending, at admission or when a block or a later transaction fills the gap before it. Queued transactions stay on the node that received them: a peer would hold them as queued too, and an attacker could otherwise fill every pool with transactions that never run. A transaction is sent once to each peer connected at that moment, and to a peer that connects later with the rest of the pending transactions (09 §4).

## 7. RPC

- `eth_getTransactionCount` at `pending` is the account nonce plus the sender's pending transactions: the nonce of the sender's next transaction. Every other tag gives the account nonce.
- `eth_sendRawTransaction` reports the refusals of §2 and §4 as JSON-RPC error `-32000` with geth's texts: `nonce too low: address …, tx: … state: …`, `nonce has max value: …`, `replacement transaction underpriced`, `insufficient funds for gas * price + value` (the overdraft of §2), `oversized data`, `too many authorizations`, `in-flight transaction limit reached for delegated accounts`, `authority already reserved`, `txpool is full`, `max fee per gas less than block base fee: address …, maxFeePerGas: …, baseFee: …` and `max priority fee per gas higher than max fee per gas: address …, maxPriorityFeePerGas: …, maxFeePerGas: …` (23 §7), and the kernel's other reasons as in `orange-rpc`.
- `eth_getTransactionByHash` finds pool transactions, with null block fields.
- `txpool_status` returns `{"pending": quantity, "queued": quantity}`.
- `txpool_content` returns `{"pending": {address: {nonce: transaction}}, "queued": {…}}`, keyed by the sender in EIP-55 mixed case and the nonce in decimal, as geth does.
