# 23 — Fee market

## 1. Overview

Every block of the reference kernel has a base fee per gas that follows demand under EIP-1559's rule, scaled to slot time: a block that uses more than the gas target raises the next block's base fee by at most one hundredth, one that uses less lowers it as much, and a floor keeps it above zero. A transaction pays the base fee on the gas it uses and a priority fee on top. The base fee is burned, or credited to a treasury when the chain says so; the priority fee goes to the stakers through the staking address's reward pool (15 §10). The parameters are set at genesis and changed through governance (13 §9). Codex ADR 0038 records the decisions.

The EVM's gas schedule and the kernel's VM gas schedule (04, 19) do not change: this document prices EVM gas in wei, it does not reprice work.

## 2. Parameters

`GenesisParams::fees` carries, and `fees/params` holds once governance changed them:

```
struct FeeParams { denominator: u64, elasticity: u64, min_base_fee: u64, treasury: [20] }
```

- `denominator`: EIP-1559's base fee change denominator, between `MIN_DENOMINATOR = 100` and `MAX_DENOMINATOR = 125`: a full block raises the next base fee by a `denominator`th (1% at 100, 0.8% at 125), an empty one lowers it as much. Zero turns the market *off*: every block's base fee is `min_base_fee`.
- `elasticity`: EIP-1559's elasticity multiplier, between `MIN_ELASTICITY = 2` and `MAX_ELASTICITY = 4`: the gas target is the block gas limit over it. Zero with a zero denominator.
- `min_base_fee`: the floor, in wei per gas. The base fee of every block while the market is off.
- `treasury`: the account the base fee is credited to; the zero address burns it.

Parameters are *workable* when the market is off with both factors zero, or on with both within their ranges. `kernel_init` traps on parameters that are not, so the chain never starts with them, and the `solo` command refuses such a genesis before a node does.

Ethereum changes its base fee by at most 12.5% per 12-second block. At slots of 400 to 500 ms the same per-block factor would let the fee move by orders of magnitude in seconds; a denominator of 100 to 125 bounds a block's change to 1% or less, which is still several times Ethereum's rate per second. The ranges are the bounds the research behind the design settled on; a chain sets its own values within them.

### 2.1 Defaults

| Chain | `denominator` | `elasticity` | `min_base_fee` | `treasury` |
|---|---|---|---|---|
| `solo dev`, and every genesis without a `fees` object | 0 | 0 | 0 | burn |
| `solo devnet init`, the production defaults (`FeeParams::production`) | 125 | 2 | 1 gwei | burn |

A development chain keeps a zero base fee, so transactions and wallets that pay nothing keep working, and its priority fees go where they went before (§4). The genesis JSON names the parameters as `"fees": {"denominator", "elasticity", "minBaseFee", "treasury"}`; `solo devnet init` funds every validator's account and the governance account, since on its chain their signals and upgrades pay the base fee.

## 3. The base fee of a block

With `L` the block gas limit (`BLOCK_GAS_LIMIT`, 30 000 000) and `T = L / elasticity` the gas target, the base fee of block `h + 1` follows from block `h`'s header, its `base_fee` `b` and `gas_used` `g`:

```
next_base_fee(b, g) =
  min_base_fee                                              if denominator = 0
  max(min_base_fee, b)                                      if g = T
  max(min_base_fee, b + max(1, b · (g − T) / T / denominator))   if g > T
  max(min_base_fee, b − b · (T − g) / T / denominator)      if g < T
```

Divisions round down, as in EIP-1559, whose formula this is with the floor applied last; the result saturates at `2^64 − 1`. The genesis counts as a parent at the floor that used nothing, so block 1's base fee is `min_base_fee`. `solo_abi::fees::FeeParams::next_base_fee` is the one implementation, shared by the kernel, the node and the RPC.

The base fee of block `h` applies to:

- **execution** (`kernel_stf_execute_block`): the kernel reads the parent's header before it writes anything of block `h`, runs every transaction under that base fee, and writes it to the header's `base_fee` (20 §3.1), which the Ethereum header and the block hash carry as `baseFeePerGas`;
- **admission** (`kernel_stf_validate_tx`) and **selection** (`kernel_stf_build_block`), against the executed head: both use the base fee of the next block;
- the **`BASEFEE`** opcode, through revm's block environment, and the **`call` query**, which runs in the head block under the head's base fee at a gas price of zero: like geth's `eth_call`, a call pays nothing whatever the base fee, and `BASEFEE` still reports it.

The parameters in force are read at the same point, so a `setFeeParams` executed in block `h` applies from block `h + 1`: its base fee is computed from block `h`'s header under the new parameters.

### 3.1 Transactions under the base fee

A transaction's *price* `p` is its gas price for a legacy or access-list transaction, and `min(max_fee_per_gas, base_fee + max_priority_fee_per_gas)` for a dynamic-fee or set-code one; its *tip* is `p − base_fee`. The checks of 06 §5.1 that every transaction gets, at admission, selection and execution, refuse

- reason 24, `TIP_ABOVE_FEE_CAP`: a maximum priority fee above the maximum fee;
- reason 8, `FEE_TOO_LOW`: a gas price or maximum fee below the block's base fee.

in that order, after the gas checks and before the checks against the sender's account. The priority admission reports is the tip (06 §5.1). A transaction a block carries that fails them cannot run and gets the failed receipt of codex ADR 0022; a receipt's `effective_gas_price` is `p`.

## 4. Where fees go

The EVM charges the sender `gas_used · p`, credits the block beneficiary `gas_used · (p − base_fee)` and nobody `gas_used · base_fee`; the kernel then routes the two parts:

- the **base fee** is burned, gone from the supply, unless `treasury` is set: then the kernel credits the treasury `gas_used · base_fee` right after the transaction, so the treasury's balance grows transaction by transaction. The treasury of a block is the one the parameters named when the block began, read with the base fee (§3), so a `setFeeParams` in the block changes neither for the block's own transactions;
- the **priority fee** reaches the **fee vault**, `0x0000000000000000000000000000000000004645` (`FEE_VAULT`), the beneficiary of every block on a chain with staking (15 §2: `epoch_blocks > 0`); it is `COINBASE`, and what a contract sends `block.coinbase` lands there too. At the end of the block, after the module hooks (16 §7) and the governance bookkeeping (13 §9.3) and before the staking bookkeeping (15 §4, §10), the kernel moves the vault's whole balance to the staking address and adds it to the reward pool, `stake/pool`, and deletes the vault's account, which holds nothing else. Every wei the vault received in a block is in the pool when the block ends, so the pool's growth over an epoch is exactly the priority fees, and coinbase transfers, of its blocks. On a chain without staking the beneficiary is the zero address, where fees went before this document, and no sweep runs;
- the **surcharges** the kernel adds to a transaction's gas (`REPORT_GAS`, 15 §3.4; `GOVERNANCE_GAS`, 13 §9.9) are charged as the EVM charges gas: the sender pays `surcharge · p`, the beneficiary gets `surcharge · (p − base_fee)`, and the base part is burned or, with a treasury, credited with the rest of the transaction's base fee, since the treasury's credit counts the transaction's whole `gas_used`, surcharge included.

So for every transaction that ran: `sender paid = treasury or burn + beneficiary`, exactly, and the supply shrinks by exactly the burned base fee. Within a block the staking address's balance is the bonded and unbonding stake plus the pool (15 §10.2); the vault's balance is what the block's transactions have paid so far.

## 5. Governance

`setFeeParams(uint64 denominator, uint64 elasticity, uint64 minBaseFee, address treasury)` (selector `0x92106b6c`) is an action governance applies to itself (13 §9.2): `submit` carries it with the governance address as target, under the key track it executes at once, under the stake track it is a normal-track proposal. It fails, reverting the submission or leaving the executed proposal without effect, unless the parameters are workable (§2); otherwise it records them under `fees/params`, from the next block on (§3), and emits

```solidity
event FeeParamsSet(uint64 denominator, uint64 elasticity, uint64 minBaseFee, address treasury);
```

`solo gov set-fee-params <denominator> <elasticity> <minBaseFee wei> <treasury address|burn>` prints the call.

## 6. State

| Key | Value |
|---|---|
| `fees/params` | `FeeParams`, once `setFeeParams` ran; genesis's `GenesisParams::fees` until then |
| `stake/pool` | `u128`, the reward pool (15 §10.2) |

Both committed (10 §2). The base fee of each block is in its header record (20 §3.1); the vault is an ordinary account between the first fee of a block and the block's end, and absent otherwise.

## 7. Queries and RPC

The query `fees` takes nothing and returns `FeeStatus { params: FeeParams, base_fee: u64, pool: u128 }`: the parameters in force, the base fee of the next block (§3) and the reward pool. The node reads it at open and after every block it executes, and uses the base fee for admission's complement, the pool's take (14 §3), for its own gate signals (13 §8.2: a signal is sent at the next block's base fee, so a validator's account on a chain whose floor is above zero holds the funds for `SIGNAL_GAS` at the base fee) and for the RPC.

The JSON-RPC follows geth:

- `eth_gasPrice` is the head block's base fee plus the suggested tip; `eth_maxPriorityFeePerGas` the suggested tip (§7.1);
- `eth_feeHistory(blockCount, newestBlock, rewardPercentiles)` reports, per block, `baseFeePerGas` from its header and, after the newest, the base fee of the block after it (its header's, or the kernel's next base fee when the newest is the head), `gasUsedRatio`, and `reward`: at each percentile, the tip paid by the transaction at that share of the block's gas, the receipts sorted by the tip they paid over the block's base fee; `blockCount` is at most 1 024, as in geth;
- `eth_sendRawTransaction` refuses reason 8 with `max fee per gas less than block base fee: address …, maxFeePerGas: …, baseFee: …` and reason 24 with `max priority fee per gas higher than max fee per gas: address …, maxPriorityFeePerGas: …, maxFeePerGas: …`, geth's texts with its details;
- the synthetic genesis block (20 §3.1) reports the base fee the chain started with, its floor at genesis, and block views report each header's `baseFeePerGas` and `miner`.

### 7.1 The tip oracle

The suggested tip is geth's `SuggestTipCap` over Solo's blocks. Of each of the `ORACLE_BLOCKS = 100` blocks below the head it takes the `ORACLE_SAMPLE = 3` cheapest tips paid by senders other than the beneficiary, leaving out tips below `ORACLE_IGNORE_TIP = 2` wei; a block without any contributes the last suggestion once and makes the oracle look one block further, up to twice as many blocks. The suggestion is the `ORACLE_PERCENTILE = 60`th percentile of the sample (index `⌊(n − 1) · 60 / 100⌋` of the sorted sample), at most `ORACLE_MAX_TIP` = 500 gwei; with no sample it is the last suggestion, and before any block the node's default, 1 gwei. The oracle looks at 100 blocks where geth looks at 20 because Solo's blocks are many times shorter: 20 blocks of 400 ms are eight seconds of history. It is computed once per head; the node's background work runs between the blocks it reads, and a block's sample is kept once read, since an executed block never changes.

## 8. The pool (14 §3)

The reference host's take leaves out a sender whose next pending transaction's fee cap is below the next block's base fee, with the rest of that sender's run behind it, as it leaves out one that does not fit; the transactions stay in the pool for a block whose base fee is lower, as geth keeps them, and count towards its limits (14 §4). A transaction an unexecuted block carries is skipped whatever its price: that block decides. Admission (§3.1) refuses a newcomer below the base fee of the next block, so the pool holds such transactions only after the base fee rose past them.

## 9. Rationale (non-normative)

- **EIP-1559, not a fixed price.** Ethereum tooling estimates fees from `eth_feeHistory` and sends dynamic-fee transactions; a market with the same shape gives them the answers they expect, and a base fee that rises under load is what keeps a block limit from being an auction only in name.
- **A floor.** Ethereum's base fee cannot practically reach zero only because its increase is at least one wei; at a hundred times the block rate a chain should state the least it charges, so that state growth has a price at the quiet end of the day and the dev chain can say zero on purpose.
- **Priority fees to the stakers, through the staking address.** Validators are paid by the chain they secure, delegators with them (15 §10), and the vault makes the accounting exact: the pool grows by what the vault held, not by what the kernel believes transactions paid, so a contract that pays `block.coinbase` pays the stakers too.
- **Burn by default, treasury as a parameter.** Which of the two a chain wants is the chain's call (codex ADR 0038); the kernel offers both and defaults to Ethereum's.
- **Parameters, not forks.** A chain changes its market through the governance it already has, under the bounds this document fixes, without a kernel upgrade.

## 10. Limits of this version

- The block gas limit is fixed (`BLOCK_GAS_LIMIT`); only the base fee moves.
- A proposal is not run before it is made (20 §7): a transaction priced exactly at the base fee of the block the take was made for can land in a later block whose base fee rose past it, and is then recorded as failed instead of left out as a geth builder would.
- The tip oracle reads receipts block by block on the thread that drives consensus; a node with many transactions per block pays for the first `eth_gasPrice` after each head.
- The genesis block has no header (20 §7), so its base fee is the floor the RPC fills in, not a value any hash commits to.
