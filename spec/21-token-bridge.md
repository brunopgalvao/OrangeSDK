# 21 — Canonical token bridge

## 1. Overview

This document specifies the canonical token bridge of codex ADR 0013 between a Solo chain and Ethereum, built on the two verified message channels without changing their trust model: messages from Solo to Ethereum go through the outbox, a light client of threshold certificates and `SoloInbox` (spec 17); messages from Ethereum to Solo go through `EthereumOutbox`, the sync-committee light client and the inbox (spec 18). The decisions behind this document are recorded in codex ADR 0034.

One *token gateway* runs on each chain, and the two are paired: each accepts messages only from the other. A token native to a chain is *locked* in that chain's gateway and *minted* on the other chain as a *wrapped token* that the other gateway creates; burning the wrapped token *releases* the locked token. This works in both directions: ETH and Ethereum's ERC-20s become wrapped tokens on Solo, and Solo's own currency and Solo's ERC-20s become wrapped tokens on Ethereum.

| Piece | Where | Section |
|---|---|---|
| `BridgedToken`, the wrapped token | `contracts/tokens/BridgedToken.sol` | §4 |
| `TokenGateway`, everything about value | `contracts/tokens/TokenGateway.sol` | §5, §6 |
| `TokenGatewayOnEthereum`, deployed on Ethereum | `contracts/tokens/TokenGatewayOnEthereum.sol` | §5.1 |
| `TokenGatewayOnSolo`, deployed on Solo | `contracts/tokens/TokenGatewayOnSolo.sol` | §5.2 |
| Messages, addresses and calldata for users, owners and relayers | `solo_bridge::tokens` | §3, §7 |

Integers in messages and ABI words are big-endian.

## 2. Tokens and where they live

A gateway distinguishes two kinds of token:

- A **native token** of its chain: any ERC-20 there, or the chain's currency, which the gateway names `NATIVE`, the zero address. A deposit of a native token *locks* it in the gateway.
- A **wrapped token**: a `BridgedToken` this gateway created for a token native to the other chain, its *origin*. A deposit of a wrapped token *burns* it.

ETH arrives on Solo as the wrapped token of origin `NATIVE`, an ERC-20 named `Ether` with symbol `ETH` and 18 decimals, not as Solo's currency. Solo's currency is the chain's own: it pays gas and bonds stake (spec 15), and its supply is the chain's to govern. Minting it against ETH locked on Ethereum would put the currency that secures the chain at the mercy of the sync-committee trust of spec 18 §2, and a forged message could mint the stake that decides who validates. As an ordinary ERC-20, wrapped ETH is bounded by its own cap (§6.2) and harms only its holders if the channel is ever forged.

Solo's currency arrives on Ethereum as the wrapped token of origin `NATIVE` there, named and symbolled as the Solo gateway was deployed (§5.2), with 18 decimals. The Solo gateway holds the currency it locks: it does not send it as the value of an outbox message, because the outbox keeps such value for ever (spec 17 §2.3) and the return trip could not release it. Every gateway message carries value 0.

## 3. Messages

A gateway's message is an ordinary message of the channel it sends through, from the gateway to the paired gateway; its payload is one of

```
MINT    = abi.encode(uint8 1, address origin, address from, address to, uint256 amount,
                     string name, string symbol, uint8 decimals)
RELEASE = abi.encode(uint8 2, address token, address from, address to, uint256 amount)
```

`MINT` asks the receiving gateway to mint `amount` of the wrapped token of `origin` (a token native to the sending chain, which `from` locked there) to `to`; `name`, `symbol` and `decimals` describe `origin` and name the wrapped token if this mint creates it (§4). `RELEASE` asks it to release `amount` of `token`, native to the receiving chain and locked there, to `to`; `from` burned the wrapped token on the sending chain. The channel's nonce identifies the message; the payload carries no nonce of its own.

The gateways rely on exactly what the channels guarantee: a message is delivered at most once (spec 17 §6.1, spec 18 §6.5), its sender is authenticated, and a delivery whose recipient reverts is undone and may be retried. They do not rely on order: messages may be delivered in any order, which is why every `MINT` carries the metadata (§4) rather than only a token's first deposit.

`TokenMessage` in `solo_bridge::tokens` encodes and decodes the two payloads; decoding accepts exactly the encoding above, which is what a gateway sends.

## 4. Wrapped tokens

`BridgedToken` is an ERC-20 (`name`, `symbol`, `decimals`, `totalSupply`, `balanceOf`, `allowance`, `transfer`, `approve`, `transferFrom`, the `Transfer` and `Approval` events) whose constructor takes no arguments and records its creator as `gateway`. Only the gateway calls `mint(to, amount)` and `burn(from, amount)`, which burns without an allowance, and `initialize(origin, name, symbol, decimals)`, once; anyone else gets `NotGateway()`, a second initialization `AlreadyInitialized()`. An allowance of `2^256 − 1` is never decreased. Transfers to the zero address revert `ZeroAddress()`; transfers and burns beyond a balance revert `InsufficientBalance()`, `transferFrom` beyond an allowance `InsufficientAllowance()`.

A gateway creates the wrapped token of `origin` with `CREATE2`, with salt `origin` as a 32-byte word, in the delivery of the first `MINT` of `origin` it receives, and initializes it with that message's metadata in the same call. Its address is therefore

```
wrapped_token(gateway, origin) = keccak256(0xff ‖ gateway ‖ uint256(origin) ‖ keccak256(BridgedToken creation code))[12..32]
```

which anyone computes before the token exists: `wrappedToken(origin)` on the gateway, or `solo_bridge::tokens::wrapped_token`. The creation code is the committed fixture `contracts/build/BridgedToken.bin`; the gateway stores its hash as `tokenCodeHash`. There is one wrapped token per origin and gateway, and no other way to create one.

The metadata a deposit carries (§5.3) is the origin's `name()` and `symbol()`, each an ABI string or a `bytes32` (up to its first zero byte), cut to its first `MAX_METADATA = 64` bytes, and empty if the call fails or returns anything else; and `decimals()` if it returns one word below 256, else 18. For `NATIVE` it is the gateway's native name and symbol and 18. Later changes of an origin's metadata do not reach its wrapped token.

## 5. Gateways

Both gateways are `TokenGateway`; the two subcontracts only send and authenticate messages.

### 5.1 `TokenGatewayOnEthereum`

Constructor `(outbox, inbox, soloChainId, soloGateway, owner, guardian, messageGas)`: the Solo chain's `EthereumOutbox`, the `SoloInbox` delivering that chain's messages, the chain's id, the paired gateway on Solo, the roles of §5.6 and the gas each message gives the gateway on Solo (spec 18 §6.5). It reverts `ZeroAddress()` if the outbox, the inbox, the paired gateway, the owner or the guardian is zero, and `MessageGasTooLow()` if `messageGas` is below `MIN_MESSAGE_GAS = 1 000 000`. Its native name and symbol are `Ether` and `ETH`.

It sends with `outbox.send(soloGateway, messageGas, payload)`. `messageGas` must cover the first `MINT` of a token, which creates the wrapped token: that delivery uses about 720 000 gas more than a mint of an existing token (§8); the tests use 1 500 000. The floor `MIN_MESSAGE_GAS` keeps the owner from setting a gas that strands messages: a `RELEASE` needs far less, and a `MINT` sent with too little gas for creation would stay undeliverable only until another message of the same origin, with enough gas, had created the token, after which its mint is cheap. The Solo chain's block gas limit must admit a delivery with `messageGas` (spec 18 §6.5).

`onSoloMessage(sourceChainId, nonce, sender, value, payload)` (`ISoloMessageRecipient`) reverts `NotInbox()` unless the caller is `inbox`, `WrongChain()` unless `sourceChainId` is `soloChainId`, `NotRemoteGateway()` unless `sender` is the paired gateway and `WrongValue()` unless `value` is 0; it then receives the payload (§5.4).

The owner may call `setInbox(inbox)` (never zero), which moves the gateway to a successor `SoloInbox` (spec 17 §6.4), and `setMessageGas(gas)` (at least `MIN_MESSAGE_GAS`), for messages sent from then on.

### 5.2 `TokenGatewayOnSolo`

Constructor `(outbox, inbox, ethereumChainId, ethereumGateway, owner, guardian, nativeName, nativeSymbol)`. On a Solo chain the outbox is `0x0000000000000000000000000000000000004f42` and the inbox `0x0000000000000000000000000000000000004549`; `SoloGatewayConfig::new` fills them in. They are constructor arguments, not constants, so that the same code runs against stand-ins in tests. It reverts `ZeroAddress()` if the outbox, the inbox, the paired gateway, the owner or the guardian is zero. `nativeName` and `nativeSymbol` name the chain's currency on Ethereum.

It sends with `outbox.send(ethereumChainId, ethereumGateway, payload)` and no value, which costs `send_gas(n)` (spec 17 §2.4). `onEthereumMessage(nonce, sender, payload)` (`IEthereumMessageReceiver`) reverts `NotInbox()` unless the caller is the inbox and `NotRemoteGateway()` unless `sender` is the paired gateway, then receives the payload (§5.4). The inbox and outbox are fixed: they are the chain's system addresses, which only a kernel upgrade changes.

### 5.3 Deposits

`deposit(address token, address to, uint256 amount) payable returns (uint64 nonce)` bridges `amount` of `token` to `to` on the other chain and returns the channel's nonce of the message. It reverts `IsPaused()` while paused, `Reentrant()` inside another call into the gateway, `ZeroAddress()` if `to` is zero and `ZeroAmount()` if `amount` is 0. Then:

- **A wrapped token of this gateway**: `WrongValue()` if the call carries value; the token burns `amount` from the caller (reverting `InsufficientBalance()` beyond its balance), and the message is `RELEASE(originOf[token], caller, to, amount)`.
- **Any other token**, native: `CapExceeded(token)` if `locked[token] + amount` exceeds `lockCap[token]`. For `NATIVE` the call's value must be `amount`; for an ERC-20 it must be 0 (`WrongValue()` otherwise), the gateway calls `transferFrom(caller, gateway, amount)` and reverts `TransferFailed()` if that reverts or returns anything but nothing or `true`, and `BalanceMismatch()` unless its own `balanceOf` grew by exactly `amount`. `locked[token]` grows by `amount`, and the message is `MINT(token, caller, to, amount, metadata)` (§4).

The gateway sends the message (§5.1, §5.2) and logs `Deposited(nonce, token, caller, to, amount)`.

### 5.4 Receiving

A message the subcontract authenticated is acted on as follows; the whole delivery reverts, and the message stays undelivered for anyone to deliver again (§3), if the gateway is paused (`IsPaused()`), on reentrance (`Reentrant()`), for a payload whose first word is neither kind (`UnknownMessage()`), for one shorter than a word or that does not decode as its kind (empty revert data), or as each case says:

- **`MINT(origin, from, to, amount, name, symbol, decimals)`**: the wrapped token of `origin`, created and initialized with the metadata if it does not exist (logging `WrappedTokenCreated(origin, token, name, symbol, decimals)`); `CapExceeded(origin)` if its `totalSupply` plus `amount` exceeds `mintCap[origin]`; otherwise it mints `amount` to `to` and logs `Minted(nonce, origin, token, from, to, amount)`.
- **`RELEASE(token, from, to, amount)`**: `locked[token]` shrinks by `amount` (a panic if it would go below zero, which a message of the paired gateway never asks); `InsufficientGas()` if less than `⌊TRANSFER_GAS · 64 / 63⌋ + TRANSFER_RESERVE` gas is left, with `TRANSFER_GAS = 100 000` and `TRANSFER_RESERVE = 60 000`. It then sends `amount` to `to` with `TRANSFER_GAS` gas: the currency by a plain call with value and no data, an ERC-20 by `transfer(to, amount)`, copying at most one word of return data. The release succeeds if the call does not revert and returns a word equal to 1, or returns nothing (for the currency, or from a token that has code), and logs `Released(nonce, token, to, from, amount)`. Otherwise `owed[token][to]` grows by `amount` and it logs `ReleaseFailed(nonce, token, to, from, amount)`; the message counts as delivered.

The gas check keeps a relayer, who chooses the gas of a `SoloInbox` execution, from making a release fail on purpose and so pushing it into `owed`.

### 5.5 Owed releases

`claim(token, recipient)` sends `owed[token][recipient]` to `recipient`; anyone may call it. `claimTo(token, receiver)` sends what the caller is owed to `receiver` instead, for a recipient that can call but cannot receive. Each reverts `IsPaused()` while paused, `Reentrant()` on reentrance, `ZeroAddress()` for a zero receiver, `NothingOwed()` if nothing is owed and `InsufficientGas()` as in §5.4; it zeroes the debt, sends it as §5.4 does and reverts `TransferFailed()`, restoring the debt, if the transfer fails, else logs `Claimed(token, recipient, receiver, amount)`. A failed release is therefore never lost: the gateway keeps holding it, and it stays claimable for ever.

### 5.6 Roles and their limits

| Role | Can | Cannot |
|---|---|---|
| anyone | deposit, deliver (through the channel), claim for a recipient | anything else |
| guardian | `pause()` | unpause, change any parameter, move value |
| owner | `pause()`, `unpause()`, `setLockCap(token, cap)`, `setMintCap(origin, cap)`, `setGuardian` (never zero), `transferOwnership` (never zero); on Ethereum also `setInbox` and `setMessageGas` | mint, release, burn, take locked or owed value, change the paired gateway, the outbox or the creation code |

Others get `NotGuardian()` and `NotOwner()`. Pausing stops deposits, deliveries and claims; deliveries refused while paused wait in their channel. On Solo the owner should be the chain's governance account (spec 13 §1.1). On Ethereum the owner, like `SoloInbox`'s, should be a timelock: `setInbox` is the one power that reaches value, since an inbox the owner chose could deliver anything, and the timelock gives holders time to see a change coming.

### 5.7 Deployment

Both gateways are deployed by ordinary transactions, the one on Solo by any account, not placed by the kernel at genesis like the inbox of spec 18 §4. Each gateway needs the other's address in its constructor; both are known in advance from their deployers' nonces (`CREATE`), so the deployers deploy them in either order. The pair of addresses a chain publishes is its canonical bridge.

Genesis placement would give every Solo chain the gateway at one reserved address, but it would put the gateway's code in the kernel (the inbox's runtime is embedded in it) and its configuration in genesis, make any change to it a kernel upgrade, and require a storage layout written without a constructor. Nothing about the gateway needs the kernel: it holds no privilege, calls the outbox and is called by the inbox as any contract is, and authenticates its peer by address. Unlike the inbox, which every Solo contract must be able to trust at a fixed address, a gateway is trusted only by the holders of its own tokens.

## 6. Safety

### 6.1 The value invariant

For every token native to one side, with `locked` the gateway's `locked[token]` there and `minted` the `totalSupply` of its wrapped token on the other side:

```
locked = minted + Σ amount of MINT of the token not yet delivered + Σ amount of RELEASE of the token not yet delivered
balance of the gateway in the token = locked + Σ owed[token][·]
```

so `minted ≤ locked` always: a `MINT` is sent only after its tokens are locked, a `RELEASE` only after its wrapped tokens are burned, each message acts once, and a failed release keeps its tokens in the gateway. The invariant assumes the channel delivers only messages the paired gateway sent; `crates/solo-bridge/tests/tokens_contracts.rs` checks both equalities after every step of a randomized run of 600 deposits, burns, deliveries in random order (some failing on a pause or a cap and retried), pauses, cap changes and refusing recipients, and `tests/tokens.rs` checks them end to end.

### 6.2 Caps

`lockCap[token]` bounds what the gateway may hold locked of a native token, and a token whose cap is zero cannot be deposited at all: a token is *listed* on a gateway when its lock cap is non-zero, and the owner lists only tokens that behave (§6.3). `mintCap[origin]` bounds the supply of a wrapped token on the receiving side. A cap lowered below what is outstanding refuses new deposits or mints, never touches what exists, and a mint over its cap waits in its channel until the owner raises the cap.

The mint cap is what bounds a forgery. If a channel delivers a message the paired gateway never sent (a dishonest sync-committee supermajority, or a threshold of shareholders certifying a false root), the receiving gateway mints at most up to the cap of each wrapped token, or releases what is locked; the channel's delay, rate limit and pause (spec 17 §6.2, spec 18 §6.3, §6.4) bound how fast. Owners size caps to the value they accept at the channel's trust.

### 6.3 Tokens

- **Fee on transfer.** A deposit is refused (`BalanceMismatch()`) unless the gateway's balance grew by exactly the amount: a token that takes a fee, or credits less than it says, would otherwise mint more than it locks. Fee-taking tokens are not supported.
- **Rebasing and other balance changes.** A token whose balances change without transfers is not supported, and must not be listed. A positive rebase leaves a surplus in the gateway that nobody can take; a negative one makes `balance < locked + owed`, and the last releases fail and are owed until the gateway holds enough. Nothing in the gateway detects a rebase.
- **Tokens that lie.** A token whose `balanceOf` lies, or that moves balances arbitrarily, defeats any check; listing is the defense.
- **Reentrancy.** Every entry point that moves value (`deposit`, receiving, `claim`, `claimTo`) holds one transient-storage lock and reverts `Reentrant()` when entered again, so a token's hook or a recipient cannot re-enter the gateway; state is updated before each external transfer.
- **Recipients that revert or burn gas.** A release calls the recipient or the token with `TRANSFER_GAS` and copies no unbounded return data, so a hostile recipient can neither take the gateway's remaining gas nor make the delivery revert; its release is owed (§5.5).

### 6.4 What the gateways add, and what they do not change

The gateways add per-token caps, their own pause, refusal of unlisted and fee-taking tokens, and owed releases. They change nothing in the channels: the light clients, the inboxes' delays, rate limits, pauses and vetoes, and the roles that govern them apply to token messages as to any other. A `SoloInbox` veto of a token message drops it for ever: a vetoed `RELEASE` leaves its wrapped tokens burned and the origin locked, a vetoed `MINT` leaves its tokens locked. Both keep the invariant (`minted ≤ locked`), and recovering such value is for the owners to decide.

## 7. Relaying

Token messages are relayed exactly as any message of their channel (spec 17 §7, spec 18 §6); a relayer needs nothing token-specific. `solo_bridge::tokens` adds:

- `TokenMessage` (§3), to read what a message asks before relaying it;
- `wrapped_token` (§4);
- calldata for `deposit`, `claim`, `claimTo`, `setLockCap`, `setMintCap` and single-address views (`locked`, `lockCap`, `wrappedToken`, `balanceOf`);
- `EthereumGatewayConfig` and `SoloGatewayConfig`, the constructor arguments.

## 8. Gas

Measured by `crates/solo-bridge/tests/tokens.rs`, which pins each number: on Ethereum on revm 43 at Osaka, on Solo through the reference kernel; contracts compiled by solc 0.8.28 with the optimizer at 200 runs for the Cancun target. Transaction gas used, intrinsic gas and calldata included.

| Transaction | Chain | Gas |
|---|---|---|
| `deposit` of ETH, the gateway's first (two new outbox slots, `locked` from zero) | Ethereum | 118 426 |
| `deposit` of an ERC-20, its first | Ethereum | 159 315 |
| `EthereumInbox.deliver` of the `MINT` that creates wrapped ETH, proofs of a 13-account state | Solo | 822 633 |
| `EthereumInbox.deliver` of a `MINT` of an existing wrapped token | Solo | 103 358 |
| `deposit` of a wrapped token (burn and outbox send) | Solo | 97 525 |
| `deposit` of Solo's currency | Solo | 117 482 |
| `SoloInbox.execute` of a `RELEASE` of ETH | Ethereum | 77 858 |
| `deposit` of a wrapped token (burn and `EthereumOutbox` send) | Ethereum | 86 385 |
| `EthereumInbox.deliver` of a `RELEASE` of Solo's currency | Solo | 96 490 |

Creating a wrapped token costs about 720 000 gas, mostly the code deposit of its 2 779-byte runtime at 200 gas a byte and the initialization's storage writes; the deliveries include the inbox's proof verification (spec 18 §8), which grows with the depth of the Ethereum state. The `MINT` payload is 384 bytes for a name and symbol of up to 32 bytes each, and `send_gas` (spec 17 §2.4) charges for it on Solo.

## 9. Contracts and fixtures

The gateways and the wrapped token are in `contracts/tokens/`; the test contracts `TestToken` (an ERC-20 that can take a fee, revert or call back into the gateway), `TestReceiver` (refuses ETH on request) and `TestMessenger` (stands in for both channels so that both gateways run in one EVM) are in `contracts/test/`. `tools/build-contracts.sh` compiles them with every other contract (spec 17 §9); the tests fail when a source no longer matches `contracts/build/SOURCES`.

## 10. Limits of this version

- **Unsupported tokens** (§6.3): fee-on-transfer, rebasing and otherwise self-changing balances. ERC-777 hooks and ERC-1363 callbacks are harmless (the lock refuses reentrance) but gain nothing.
- **No relayer fee.** Deliveries are paid by whoever relays them; a user can relay their own.
- **No permit, no deposit-and-call.** A deposit needs a prior `approve`; a message carries no call for the recipient to run.
- **Metadata is fixed** at creation (§4); a token that changes its name keeps the old one on the other side.
- **The owner of the Ethereum gateway can change its inbox** (§5.6), which is needed to follow a `SoloInbox` succession but is a power over value; a timelock is the protection.
- **Vetoed messages** (§6.4) leave value locked; nothing retires them.
- `TokenMessage` decodes amounts up to `2^128 − 1`; a larger amount is valid on chain but does not decode in the helper.

## 11. Rationale (non-normative)

- **One gateway contract for both sides.** Locking, minting, burning, releasing, caps, owed releases and the invariant are the same on both chains; only sending and authenticating differ. One audited body of code, two thin adapters.
- **Lock and mint, not mint against the outbox's value.** The outbox keeps value for ever, and Solo's currency must be releasable on the way back; the gateway is the custodian on each side.
- **Refuse instead of measuring.** A gateway could credit the balance delta of a fee-taking token instead of refusing it, but the fee would be taken again on release, and the next holders would bear it; refusing keeps one token in for one minted.
- **Owed instead of reverting.** A release that reverted the whole delivery would leave a message stuck for as long as its recipient refuses, perhaps for ever, with the channel's nonce never consumed. Recording the debt consumes the message and keeps the value claimable.
- **Metadata in every mint.** Channels do not order messages; any mint may be the first to arrive.
