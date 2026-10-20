# 14 — Mempool

## 1. Scope

The mempool is the host's store of transactions waiting for a block. It is policy, not validity: the kernel decides whether a transaction is valid (06 §5.1) and checks every transaction again when it executes a block, so a host whose pool differs from this document stays in consensus. This document fixes the policy of the reference host (`solo-node`) so that wallets, scripts and other hosts can rely on its behaviour. It follows geth's transaction pool where the two can be compared.

A pool transaction carries its sender, nonce, fee cap (the gas price, or the maximum fee per gas), tip cap (the gas price, or the maximum priority fee per gas), gas limit and cost (value plus gas limit times fee cap), read from the raw transaction, and the priority the kernel's validation returned. A transaction the host cannot read in this way is handed to the kernel with `Ahead` zero and refused for the reason the kernel gives; if the kernel accepts it anyway, it is refused as malformed.

## 2. Admission

Transactions are kept per sender, ordered by nonce. For each sender the pool holds the account (nonce, balance, code hash) read from the state when the sender's first transaction arrived, or after the last block (§5).

A transaction is *pending* when every nonce from its sender's account nonce up to its own is in the pool: it can run once those before it have. Any other transaction is *queued*: a nonce between is missing.

A submitted transaction:

1. is accepted with no change if the pool holds a transaction with the same hash;
2. is refused with `oversized data` if its raw bytes exceed 128 KiB (geth's `txMaxSize`). The cap keeps every pending transaction small enough for a take (§3): a host's cap MUST NOT exceed the `max_bytes` its kernel's driver asks for, or a transaction no block can carry would stay pending, holding pool capacity and blocking its sender's later nonces, without ever costing its sender anything;
3. is refused with `replacement transaction underpriced` if the pool holds a transaction of the same sender and nonce and the newcomer does not raise both its fee cap and its tip cap to at least `old + ⌊old × 10 / 100⌋` (geth's price bump);
4. if it replaces a pending transaction, is refused with `insufficient funds for gas * price + value` when the costs of the sender's pending transactions, with the newcomer's in place of the replaced one's, exceed the balance (geth's overdraft check). Otherwise a sender could replace its first transaction with one that spends the balance, leaving the pending ones behind it holding pool capacity without being able to run;
5. is validated by `kernel_stf_validate_tx` with `ahead` computed from the pool as 06 §5.1 says, and refused for the kernel's reason if invalid. A nonce below the account's is invalid (`nonce too low`); a nonce above it is valid when the sender can pay for it after what the pool holds before it;
6. is refused with `txpool is full` if a limit of §4 holds and no eviction can make room;
7. otherwise enters the pool, replacing the transaction with the same sender and nonce if any. A transaction that fills a gap promotes the queued transactions behind it to pending. Each of those was validated without the newcomer's cost reserved, so the pool walks the sender's pending transactions in nonce order adding up their costs and drops the first, behind the newcomer, whose running total exceeds the balance; the ones after it are queued behind the new gap.

Checks 2 to 4 need no kernel and run before check 5.

## 3. Taking transactions for a block

`MempoolTake { max_bytes, max_gas, skip }` is answered with pending transactions only, in an order a block can execute: each sender's in nonce order, and across senders by the kernel's priority, highest first, ties by order of arrival. The answer's raw bytes total at most `max_bytes` and its gas limits at most `max_gas`. A sender whose next transaction does not fit, or whose balance would not cover that transaction's cost after the ones before it, contributes nothing more to this answer; other senders continue.

`skip` lists the hashes of transactions to treat as already taken: those carried by the blocks the driver builds on but the host has not executed yet, which the pool still holds. A skipped transaction is not in the answer and uses none of `max_bytes` or `max_gas`, but its cost counts against its sender's balance and its sender's later transactions may follow it. Without this, a block built on an unexecuted parent would spend its budget on the parent's transactions, which the driver then leaves out, and under load every other block would be empty.

Taking does not remove anything: transactions stay until a block includes them or they become invalid, so a proposal that never finalizes loses nothing.

## 4. Limits and eviction

| Limit | Value | Applies to |
|---|---|---|
| Transactions in all | 8192 | every insertion |
| Queued transactions | 1024 | every insertion |
| Transactions of one sender | 256 | insertions that are not replacements |
| Bytes of raw transactions | 64 MiB | every insertion |
| Bytes of one raw transaction | 128 KiB | every insertion (§2 check 2) |

A newcomer that would put its sender over the per-sender limit is refused. A newcomer that would put the pool over any other limit evicts queued transactions, cheapest priority first and the latest to arrive among equals, until the pool is within every limit. A pending newcomer may evict any queued transaction; a queued newcomer only those with a strictly lower priority. Pending transactions are never evicted. If no such set of evictions brings the pool within its limits, the newcomer is refused and the pool is left as it was, including a transaction it would have replaced.

Removals can leave more queued transactions than the queued limit, as when a block leaves a gap; the limit binds the next insertion.

## 5. After a block

When a block executes, the pool removes every transaction it carries, whether or not it ran, and every transaction the kernel rejects through `MempoolReject`. Then, for every sender with transactions in the pool, it reads the account from the new state. If the account is unchanged nothing happens. Otherwise the pool:

1. drops the transactions whose nonce is below the account nonce;
2. walks the pending transactions in nonce order adding up their costs, and drops the first whose running total exceeds the balance; the ones after it are queued from then on;
3. drops every queued transaction whose own cost exceeds the balance;
4. drops every transaction of a sender whose code hash changed. The reference kernel's transactions cannot set code at a sender's address: it decodes no EIP-7702 transaction, and a delegation designator comes only from genesis, where it never changes. A change therefore means the kernel accepted the transactions for an account state that cannot recur. A kernel that executes EIP-7702 transactions keeps a delegated account able to send, and a host for it MUST keep the transactions of a sender whose new code is a delegation designator.

These checks are the account-dependent part of the kernel's validation, so the kernel is not called again for transactions it already accepted. Transactions that become pending are gossiped (§6).

## 6. Gossip

A transaction is sent to peers (09 §4) when it first becomes pending, at admission or when a block or a later transaction fills the gap before it. Queued transactions stay on the node that received them: a peer would hold them as queued too, and an attacker could otherwise fill every pool with transactions that never run. A transaction is sent once.

## 7. RPC

- `eth_getTransactionCount` at `pending` is the account nonce plus the sender's pending transactions: the nonce of the sender's next transaction. Every other tag gives the account nonce.
- `eth_sendRawTransaction` reports the refusals of §2 and §4 as JSON-RPC error `-32000` with geth's texts: `nonce too low: address …, tx: … state: …`, `nonce has max value: …`, `replacement transaction underpriced`, `insufficient funds for gas * price + value` (the overdraft of §2), `oversized data`, `txpool is full`, and the kernel's reasons as in `solo-rpc`.
- `eth_getTransactionByHash` finds pool transactions, with null block fields.
- `txpool_status` returns `{"pending": quantity, "queued": quantity}`.
- `txpool_content` returns `{"pending": {address: {nonce: transaction}}, "queued": {…}}`, keyed by the sender in EIP-55 mixed case and the nonce in decimal, as geth does.
