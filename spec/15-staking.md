# 15 — Staking, epochs, slashing and the threshold key

## 1. Overview

This document specifies the validator lifecycle of the reference kernel: how validators bond and unbond stake through an Ethereum-callable system address and other accounts delegate stake behind them (§10), how the validator set of each epoch is decided at the end of the epoch before, how recorded equivocation evidence (08 §9) and evidence of threshold misbehaviour cut the offender's stake, how the priority fees of an epoch's blocks are paid out to its set with stake (§10), how the validators of each epoch generate a fresh threshold key whose certificates (12 §7) the driver produces (08 §6a), and how the active key hands off to the next. The decisions behind it are recorded in codex ADRs 0024, 0025, 0031 and 0038.

Everything here except the keystore (§6.4) is chain state, written by `kernel_stf_execute_block` and therefore identical on every node. The keystore is node-local and lives in the host, behind key role 2 of `sign` (05 §4.3).

Amounts are in wei unless stated otherwise. A validator's *weight*, the number consensus counts (08 §1), is its stake in gwei: `weight = min(stake / 10^9, 2^64 − 1)`.

## 2. Genesis parameters

`GenesisParams::staking` carries

```
struct StakingParams {
  epoch_blocks: u64,        // L; 0 disables everything in this document
  unbonding_epochs: u64,    // whole epochs unbonded stake waits
  min_stake: u128,          // least stake a validator needs to be selected
  max_validators: u32,      // most validators in a set; 0 means no limit
  dkg_phase_blocks: u64,    // P; 0 disables the threshold key
  max_key_age: u64,         // K; epochs past its own that light clients trust a key set (§6.7)
  keys: vec<ValidatorKey { id: [32], dkg_key: bytes }>,   // genesis encryption keys
}
```

With `epoch_blocks = 0` the genesis validator set is the only set, its weights are the ones `Genesis.validators` gives, transactions to the staking address cannot run, and no threshold key exists. Quorums are still weighed (08 §1).

With `epoch_blocks = L > 0`, `kernel_init` registers every member of `Genesis.validators` as a validator (§3.4) with stake `weight × 10^9` wei, its account the last 20 bytes of its id, and its encryption key the `dkg_key` that `keys` lists for its id (none if absent). It credits the total genesis stake to the staking address's balance, stores the genesis set as the set of epoch 0, and, if `P > 0`, schedules epoch 0's DKG run (§6.1). `kernel_init` traps, so the chain never starts, when `4·P > L`, when the genesis set has more than 256 members, when any `dkg_key` that `keys` lists, for a member of the genesis set or not, is not a valid encryption key (§3.2), or, with `P > 0`, when `K = 0` or `unbonding_epochs ≤ K + HANDOFF_EPOCHS`, `HANDOFF_EPOCHS = 1` (§6.7).

## 3. The staking address

### 3.1 Interface

The *staking address* is `0x0000000000000000000000000000000000005354`. A transaction whose `to` is the staking address carries a *staking action* in its calldata, the Solidity ABI encoding of a call to

```solidity
interface ISoloStaking {
    function register(bytes calldata dkgKey) external payable;   // 0x82fbdc9c
    function bond() external payable;                    // 0x64c9ec6f
    function unbond(uint256 amount) external;            // 0x27de9e32
    function withdraw() external;                        // 0x3ccfd60b
    function report(bytes calldata evidence) external;   // 0xb5767166
    function delegate(address validator) external payable;        // 0x5c19a95c (§10.1)
    function undelegate(address validator, uint256 amount) external; // 0x4d99dd16
    event Registered(address indexed validator, bytes32 id);
    event Bonded(address indexed validator, uint256 amount);
    event Unbonded(address indexed validator, uint256 amount, uint64 releaseEpoch);
    event Withdrawn(address indexed validator, uint256 amount);
    event Reported(address indexed validator, uint8 kind, uint64 keySet);
    event Delegated(address indexed delegator, address indexed validator, uint256 amount);
    event Undelegated(address indexed delegator, address indexed validator, uint256 amount, uint64 releaseEpoch);
}
```

so `cast send 0x0000000000000000000000000000000000005354 "bond()" --value 1000gwei` works as is. Calldata is an action only if it is exactly the canonical encoding: `register` is 132 bytes with offset word 32, length word 48, the 48-byte key and 16 zero bytes of padding; `bond` and `withdraw` are the bare selector; `unbond` is the selector and one word whose high 16 bytes are zero; `report` is the selector, offset word 32, a length word of at most `MAX_REPORT = 131 072` with its high 16 bytes zero, the evidence, zero padding to a multiple of 32 bytes, and nothing after; `delegate` is the selector and one address word whose high 12 bytes are zero; `undelegate` the selector, an address word and an amount word whose high 16 bytes are zero.

Only a transaction sent directly to the staking address acts. A message call that reaches it from a contract is a plain value transfer to an account without code.

### 3.2 Encryption keys

A *valid encryption key* is 48 bytes, a compressed G1 point (12 §2) in the prime-order subgroup and not the identity. The kernel checks it with `bls12381_pairing_check` on the pair (key, G2 identity), which holds exactly for a point that decodes and lies in the subgroup, after rejecting any encoding whose identity flag is set.

### 3.3 When an action can run

A transaction to the staking address *can run* in the block at height `h` (for admission, `h` is the executed height plus one) when staking is enabled, it is signed for this chain (a typed transaction or a legacy one with an EIP-155 chain id), its calldata is an action, and:

| Action | Condition |
|---|---|
| `register(key)` | the key is valid; the sender is not jailed; a registered sender sends no value; a sender not yet registered sends a value of at least `max(min_stake, 1 gwei)` that is a multiple of 1 gwei, and needs fewer than 256 registered validators |
| `bond()` | the sender is registered and not jailed; the value is non-zero and a multiple of 1 gwei |
| `unbond(amount)` | no value; the sender is registered; `amount` is non-zero, a multiple of 1 gwei and at most its stake |
| `withdraw()` | no value; the sender is registered with unbonding stake and `epoch(h) ≥ release_epoch`, or holds a delegation (§10.1) with unbonding stake and `epoch(h) ≥` its release epoch |
| `report(evidence)` | no value; the gas limit is at least the transaction's intrinsic gas (with the EIP-7623 floor) plus `REPORT_GAS = 150 000`; `evidence` decodes as `ThresholdEvidence`, its offence is not on record, and it shows an offence in the block at `h` (§5.1). Any sender may report, registered or not |
| `delegate(validator)` | `validator` is the account of a registered validator that is not jailed and is not the sender; the value is non-zero and a multiple of 1 gwei; for the sender's first delegation behind it, the validator has fewer than `MAX_DELEGATORS = 64` delegators and the sender fewer than `MAX_DELEGATIONS = 16` delegations (§10.1) |
| `undelegate(validator, amount)` | no value; `validator` is the account of a registered validator the sender has a delegation behind; `amount` is non-zero, a multiple of 1 gwei and at most the delegation's stake |

Admission (`kernel_stf_validate_tx`, and selection in `kernel_stf_build_block`) rejects one that cannot run with reason 13 (`STAKING_ACTION`), after the checks every transaction gets and before the checks against the sender's account. Execution of one that cannot run changes nothing, like any transaction that should not have been included.

Two of these checks need a pairing: the key check of `register` and the signature check of `report` (§5.1). A transaction that fails them uses no gas, so during execution they draw on a *pairing budget* of `BLOCK_GAS_LIMIT` per block instead. Before either check, execution adds the transaction's gas limit to the gas limits already charged in the block. For `register` this happens first; for `report` it happens after the value, gas, decoding and on-record checks. If the sum would pass `BLOCK_GAS_LIMIT`, the transaction cannot run and the pairing is skipped. Otherwise the sum is kept, whether the check then passes or fails. Admission and selection charge nothing. A block built by the rules keeps the sum of its gas limits within `BLOCK_GAS_LIMIT` and so never exhausts the budget. A leader who fills a proposal with transactions that fail these checks makes every node pay for at most a block's worth of them: about 170 `report` checks, at their least gas limit of about 175 000. The running sum lives under `stake/pairing_gas` and is deleted at the end of every block, so committed state never holds it. The kernel gas these pairings can add to a block is counted in the kernel gas of a block of 19 §5.1; they call `bls12381_pairing_check` and `bls12381_verify` directly, not the precompile path of spec 19, so the budget is the same before and after feature gate 2.

### 3.4 Execution

A transaction that can run executes first as a plain EVM call to the staking address (intrinsic gas, fees, the nonce, and for `bond` and a first `register` the value moving to the staking address's balance). If that call succeeds the action applies, and the receipt carries its events, emitted by the staking address with the sender as the indexed topic:

- `register`: a sender not yet registered becomes a validator: its id is `keccak256` of the public key that signed the transaction (the consensus key, 08 §2), its record is created with the value as its stake, and it is appended to the registration order. Events `Registered(sender, id)` and `Bonded(sender, value)`. A registered sender replaces its encryption key. Event `Registered(sender, id)`.
- `bond`: the stake grows by the value. Event `Bonded(sender, value)`.
- `unbond`: the stake shrinks by `amount`, the unbonding stake grows by it, and `release_epoch` becomes `epoch(h) + 1 + unbonding_epochs`, for all of the unbonding stake. Event `Unbonded(sender, amount, release_epoch)`.
- `withdraw`: every released amount, the sender's own unbonding stake if `epoch(h) ≥ release_epoch` and that of each of its delegations whose release epoch has come, moves from the staking address's balance to the sender's, in one sum. Event `Withdrawn(sender, amount)`.
- `report`: the evidence is recorded and its offender slashed (§5.2). The transaction's gas used is the plain call's plus `REPORT_GAS`, and the sender pays `REPORT_GAS` at its price on top of the plain call's fee, routed like every fee (23 §4). Event `Reported(offender, kind, key_set)`, with the offender's account as the indexed topic.
- `delegate`: the sender's delegation behind the validator (§10.1) grows by the value, and so does the validator's `delegated`; a first delegation adds the sender to the validator's delegators and the validator to the sender's delegations. Event `Delegated(sender, validator, value)`.
- `undelegate`: the delegation's stake shrinks by `amount`, its unbonding stake grows by it, its release epoch becomes `epoch(h) + 1 + unbonding_epochs` for all of its unbonding stake, and the validator's `delegated` shrinks by `amount`. Event `Undelegated(sender, validator, amount, release_epoch)`.

The staking address's balance is therefore always the sum of every validator's and every delegation's bonded and unbonding stake, plus the reward pool (§10.2).

### 3.5 Registration slots

At most 256 validators are registered at once, so the work at each epoch end (§4) stays bounded. A slot costs the stake a first registration bonds, and a validator that holds nothing gives it back: at the end of each epoch, after the next set is decided, every registered validator that is not jailed, has no stake and no unbonding stake, has no delegation behind it (§10.1), and is not in the next set is *pruned*: its record and its address entry are deleted and it leaves the registration order. It can register again later like any other sender. A jailed validator is never pruned, and a pruned one that is later found to have offended is jailed all the same (§5).

## 4. Epochs and validator sets

Epoch `e` holds the heights `e·L + 1` to `(e + 1)·L`, so `epoch(h) = (h − 1) / L` (height 0, the genesis, counts as epoch 0), `start(e) = e·L + 1` and `end(e) = (e + 1)·L`.

At the end of the block at `end(e)`, after its transactions and the upgrade bookkeeping of 13 §8.3 and before the state commitment, the kernel decides the set of epoch `e + 1`:

1. The candidates are the registered validators that are not jailed and whose own stake is at least `max(min_stake, 1 gwei)`: the minimum stake is a self-bond, delegated stake does not meet it.
2. They are ordered by *total stake*, own and delegated (§10.1), largest first, earlier registration first on a tie, and the first `max_validators` are kept (all of them when it is 0).
3. The kept validators, in registration order, each with its weight, its total stake in gwei, are the set of epoch `e + 1`. If no validator qualifies, the set of epoch `e` carries over.

The set is stored as the set of epoch `e + 1` and becomes `meta/validators`, the set feature-gate tallies weigh (13 §8.3). Its order is the leader rotation of epoch `e + 1`'s views (08 §2). If `P > 0`, epoch `e + 1`'s DKG run is scheduled (§6.1). A set never changes within its epoch; stake bonded, unbonded or slashed during epoch `e` counts from epoch `e + 1` on.

## 5. Slashing

Recording a new equivocation offence (08 §9) is the slashing hook. In the same state transition, the offender, the validator its record's index names in the set of the epoch of its view, is slashed unless it is already jailed:

- `SLASH_BPS = 1000`: a tenth of its bonded stake and a tenth of its unbonding stake, and a tenth of the bonded and of the unbonding stake of every delegation behind it (§10.1), each rounded down, are burned: they move from the staking address's balance to the zero address, where nobody can spend them, and the validator's `delegated` shrinks by what its delegations lost;
- it is jailed: it is never selected again (§4), cannot bond or register, and is never slashed again. It can still unbond and withdraw what remains.

An offender whose record was pruned (§3.5) holds nothing to burn; its record is created again, jailed, empty and outside the registration order, with its address entry, so it can never register again.

An offence is recorded once (08 §9), so one offence is never punished twice, and a validator is punished for at most one offence whatever else it signs. Slashing removes it from the next set, not from the current one. Unbonding stake is slashable until it is withdrawn, so unbonding does not escape an offence recorded before the withdrawal.

### 5.1 Threshold misbehaviour

A shareholder's partial signature verifies under its public key share (12 §4), so a partial over a message that no honest shareholder signs proves misbehaviour as surely as two conflicting votes. Evidence of it is

```
struct ThresholdEvidence { kind: u8, key_set: u64, index: u32, signature: bytes, subject: bytes }
```

the partial `signature` (48 bytes) by shareholder `index` of key set `key_set`, over the message its `subject` determines. Judged by the chain state before the block at height `h` that would record it, it *shows an offence* when key set `key_set` was adopted, `1 ≤ index ≤` its number of shareholders, the signature verifies with `bls12381_verify` under public share `index` over the message, and, for its kind:

| Kind | Subject | Message | Offence when |
|---|---|---|---|
| 0, false anchor | an encoded proposal (08 §4), at least 96 bytes | `message_v2` of `key_set`, the proposal's height and `keccak256(subject)` | its anchor height `a` is in `1..h−1`, and the block at `a` has a `state_root` other than the anchor root |
| 1, false rotation | target key set `to` (big-endian u64) ‖ a 96-byte key | `rotation_message` of `to` and the key (12 §7) | key set `to` was adopted with another group key, or it was never adopted and `epoch(h) > to` |
| 2, stale key | an encoded proposal | as for kind 0 | its anchor height `a` is at least 1, and key set `key_set` was replaced by a handoff recorded at a height `r ≤ a` (§6.6) |

None of these is ever signed by an honest shareholder. It adds its partial to a finalize vote only for a proposal whose anchor it executed with exactly that root (08 §6a), so a partial over a false anchor (kind 0) is dishonest. It signs a rotation only to the key the chain adopted under that id (§6.6), so kind 1 is dishonest. It signs finality partials with the key set active in its own chain state, and only after executing the proposal's anchor: if the key set had been replaced at `r ≤ a`, its state after executing `a` already held the next key set, so kind 2 is dishonest; a proposal without an anchor (height 0) never counts, since honest shareholders sign those. The block header of every height stays in chain state for good (06 §5), so the executed root of any anchor stays available for as long as stake is slashable. An anchor ahead of the chain, or a rotation to a key set whose epoch is not over, is not judged yet: the same evidence shows the offence once the chain has executed that height or ended that epoch, while the offender's stake is still slashable (§6.7).

The *offence* is `(kind, key_set, index)`: one record per kind per shareholder of a key set.

### 5.2 Recording and slashing

Threshold evidence reaches the chain in two ways, and both record it identically:

- **In a transaction** to the staking address, as `report(evidence)` (§3.3, §3.4). Admission and execution check that it shows an offence not on record; one that does not cannot run.
- **As consensus participation**, in a DKG envelope of kind 4 (§6.2) that a leader puts in its proposal. A node that receives a finalize vote's partial (08 §6a) over a proposal it holds whose anchor contradicts its own execution (kind 0) or that its key set's handoff makes stale (kind 2), or a rotation share (§6.6) to a key the chain did not adopt (kind 1), checks it and, if it shows an offence, broadcasts the evidence in an envelope and keeps it in its pool until chain state records it. Executing a block records, among its envelopes, each kind-4 envelope whose evidence shows an offence not on record.

Recording stores the evidence under the next index of `tevidence/`, marks its offence in `tevseen/` and, in the same state transition, slashes the shareholder `shareholders[index − 1]` of the key set as §5 slashes an equivocator: a tenth of its bonded and of its unbonding stake burned, and jailed, unless it is jailed already. An offence on record is never recorded again, and a jailed validator is never slashed again, so whatever it signed and however many times it is reported, by transaction or in proposals, a validator is punished once. Evidence that does not show an offence is ignored and never makes a block invalid.

## 6. The threshold key

### 6.1 Runs

When `P > 0`, every epoch `e` has a DKG run of spec 12 §5 for a fresh key, scheduled when its set is decided (at `kernel_init` for epoch 0):

```
struct DkgRun { epoch: u64, session: [32], threshold: u32, dealers: vec<[32]>, recipients: vec<[32]>, keys: vec<bytes>, previous: option<u64> }
```

- The *recipients* are the members of the set of `e` that have an encryption key, in set order; recipient `j` is `recipients[j − 1]` with key `keys[j − 1]`. With no such member there is no run.
- The dealers are the recipients, and `previous` is none: every run makes a fresh key among the epoch's own set, whatever key is active, never a resharing (12 §6). The active key hands off to it once it is adopted (§6.6).
- `threshold = ⌊2N/3⌋ + 1` for `N` recipients.
- `session = keccak256("SOLO-DKG-SESSION" ‖ chain_id ‖ e)`, integers big-endian.

The run has four phases of `P` blocks each, by the height of the block that records a message: dealings in `start(e)` to `start(e) + P − 1`, complaints in the next `P` blocks, justifications in the `P` after, and confirmations from `start(e) + 3P` to `end(e)`.

### 6.2 Envelopes

DKG messages travel inside signed envelopes:

```
struct DkgEnvelope { epoch: u64, kind: u8, body: bytes, signature: [65] }
```

`kind` 0 carries a DKG message of 12 §5 (`Dealing`, `Complaints` or `Justification`, its first byte the phase); `kind` 1 carries a `KeySetVote { key_set: bytes, public_shares: vec<bytes> }`; `kind` 2 a `RotationShare` and `kind` 3 a `RotationCertificate` (§6.6); `kind` 4 a `ThresholdEvidence` (§5.1). The signature is a recoverable secp256k1 signature by the sender's consensus key over the consensus message (08 §4) of kind 3, view `epoch` and hash `keccak256(kind ‖ body)`.

Senders broadcast envelopes as `ConsensusMessage::Dkg` (08 §4). Every node keeps the envelopes it receives in a pool (at most 64), each with its signer, but only those that could still be recorded in the block after its executed head: the envelope names that block's epoch, whose run exists, and its signature recovers to a signer; a `kind` 0 message is of the run's session, of that block's phase or a later one, from the dealer or recipient its sender index names, with nothing recorded for that sender and phase; a `kind` 1 vote is from a member of the epoch's set that has not confirmed, while no key set of the epoch is adopted; a `kind` 3 handoff is from the active key set to the target, the newest adopted key set, and its group signature verifies (§6.6); a `kind` 4 piece of evidence shows an offence not on record (§5.1). The pool keeps one envelope per sender and phase (for votes, per signer; for handoffs, per target; for evidence, per offence), the first it receives, so only the run's participants can fill it, each with one envelope per phase, beside handoffs and evidence whose signatures verify. After every block it drops the envelopes that no longer pass these checks, without verifying signatures again; a leader puts up to `MAX_DKG = 16` of them into its proposal's `dkg` field (never into a suffix proposal, 08 §3a), and execution passes them to the kernel in `Participation.dkg`. `kind` 2 shares never enter the pool or a proposal (§6.6).

Executing a block at height `h` records, of its first 16 envelopes, each that decodes, names `epoch(h)`, whose run exists, and whose signature recovers to a signer:

- `kind` 0: when the message's phase is the phase of `h`, its session is the run's, and its sender index (dealer, accuser) names the signer in the run's dealers (for a dealing or a justification) or recipients (for complaints), the message is stored as that sender's for that phase unless one is already stored. The kernel reads only the message's first 37 bytes (phase, session, index); the rest is checked by every node's keystore when it replays the transcript (§6.4).
- `kind` 1, in the confirmation phase: when no key set of `e` is adopted, the signer is a member of the set of `e` that has not confirmed in `e`, and the body decodes, the vote is recorded and its weight added to the tally of `keccak256(body)`. When that tally exceeds two thirds of the set's total weight, the key set is adopted (§6.3).
- `kind` 3, in any phase, whoever signed it: the handoff is recorded when it is valid (§6.6).
- `kind` 4, in any phase, whoever signed it: the evidence is recorded when it shows an offence not on record (§5.2).

Nothing in `dkg` can make a block invalid.

### 6.3 Duties, confirmation and adoption

After executing each block `h` (and at start), a node with a consensus key looks at the run of `epoch(h + 1)` and the phase `h + 1` falls in, and sends, as long as chain state lacks it:

| Phase | Who | What |
|---|---|---|
| dealing | a dealer | its dealing |
| complaints | a recipient | its complaints, if any of its shares fails the Feldman check |
| justifications | a dealer | its justification, if it was accused |
| confirmation | a member of the set of the run's epoch | a `KeySetVote` of the run's outcome |

Each is computed once, by a keystore request (§6.4) over the messages chain state holds for the earlier phases, and repeated after every block until recorded. The outcome of a finished run is the public key set and every recipient's public key share (12 §4); a node confirms it, and its keystore keeps its own share. A run whose qualified dealers number fewer than the threshold has no outcome and no confirmation.

Adopting a confirmed vote checks its shape (`threshold` points in the key set, one 96-byte share per recipient); a vote that fails is not adopted. Adoption stores

```
struct KeySetRecord { id: u64, key_set: bytes, public_shares: vec<bytes>, shareholders: vec<[32]> }
```

with `id` the run's epoch and the run's recipients as shareholders, and records `id` as the newest adopted key set. The first key set the chain ever adopts becomes *active* at once, in the block that adopts it: it needs no handoff, and a light client starts from it as the bootstrapped key it trusts (spec 17 §5.3). Every later key set becomes active only through a handoff from the active one (§6.6). The chain's *group key* is the group key, the first point, of the active key set.

A run that is not adopted by the end of its epoch fails: the active key set stays active, its shareholders keep signing certificates and rotations with it, and the next epoch's run tries a fresh key again. A key set that stays active for more than `K` epochs past its own is no longer trusted by light clients (§6.7).

### 6.4 The keystore

Key role 2 of `sign` (05 §4.3) is the host's *threshold keystore*. Its request is an encoded

```
enum KeystoreRequest {
  0 EncryptionKey
  1 Dkg(DkgRequest { key_set: u64, session: [32], threshold: u32, dealers: u32, recipients: vec<bytes>,
                     previous: bytes, previous_id: u64, dealer: u32, recipient: u32,
                     transcript: vec<bytes>, upto: u8 })
  2 Sign    { key_set: u64, message: bytes }
  3 Combine { key_set: bytes, message: bytes, partials: vec<PartialShare { key_set: u64, index: u32, signature: bytes }> }
}
```

- `EncryptionKey` answers the node's encryption key, `dk · g1` with `dk = KeyGen(consensus secret, "SOLO-DKG-ENCRYPTION")` (12 §3), the consensus secret being the 32-byte secp256k1 scalar.
- `Dkg` replays the run for this node with its roles (`dealer`, `recipient`, 0 for none): a dealer's polynomial derives (12 §5) from `seed = expand_message_xmd(consensus secret ‖ session, "SOLO-V01-DKG-SEED_XMD:SHA-256", 32)`, so it deals the same dealing however often it is asked; a resharing dealer deals its stored share of key set `previous_id`. The keystore feeds the transcript's messages of each phase before `upto`, ending each phase, and answers a `DkgReply`: `0 Idle`, `1 Message(bytes)` (the message this node broadcasts at that boundary: its dealing for `upto = 0`, its complaints for 1, its justification for 2), or `2 Finished(KeySetVote)` for `upto = 3`, when it also stores this node's share under `key_set`.
- `Sign` answers the partial signature (12 §4) of the stored share of `key_set` over `message`.
- `Combine` needs no key: it combines the partials of distinct indices, verifies the result under the key set's group key and, when that fails, verifies each partial, drops the invalid ones and combines again (12 §7), answering the 48-byte group signature.

The keystore answers nothing (0) when the request does not decode, needs a key the node lacks or a share it does not hold, or the run fails. Shares are kept in memory; a node whose keystore lost a share (a restart) installs it again by replaying the run that made it from chain state, which needs only its decryption key. Secrets never leave the host.

### 6.5 Key sets in force

At any height the chain has at most one *active* key set: the first one adopted, then the target of each recorded handoff in turn. Ids only grow along this chain of handoffs, since a handoff goes to the newest adopted key set, which is newer than the active one. A shareholder signs the version-2 certificate message (12 §7) of a proposal with the key set active in its own chain state, naming its id, as 08 §6a says; it combines partials of a key set only if that key set has been active. The kernel keeps, for every key set that became active, the height of the block that activated it, and for every one that was handed off, the height of the block whose handoff replaced it; together with the handoff records they let a verifier follow the chain of keys and check which key was in force for a proposal (08 §7a, spec 17 §5.3).

### 6.6 Handoffs

While a newer key set is adopted than the active one, a *handoff is due*, to the newest adopted key set, the *target*. After executing each block, a node that holds a share of the active key set signs, through its keystore (`Sign`, §6.4), the rotation message of 12 §7 to the target's id and group key, read from chain state, and broadcasts it as a `kind` 2 envelope:

```
struct RotationShare { to: u64, key: bytes, partial: PartialShare }
```

once per target, repeated after every block until the handoff is recorded. Shareholders that have left the validator set still sign: their nodes must keep running until the handoff of the key they hold is recorded. Every node keeps the shares of the due handoff, one per shareholder index, when the envelope's signer is the shareholder its index names, the share names the active key set, the target and the target's group key; it drops every share once no handoff is due. When it holds the active key set's threshold of them it asks its keystore to combine them (`Combine`, which verifies the result and falls back to verifying each partial, 12 §7) and broadcasts the result as a `kind` 3 envelope, once per target and epoch:

```
struct RotationCertificate { from: u64, to: u64, signature: bytes }
```

Executing a block at height `h` records a `kind` 3 envelope's handoff when `from` is the active key set, `to` is the target (the newest adopted key set, newer than the active one), and `signature` verifies with `bls12381_verify` under the active group key over the rotation message to `to` and its group key. Recording stores

```
struct Handoff { from: u64, to: u64, key: bytes, signature: bytes, height: u64 }
```

under `dkg/handoff/` + `from`, with the target's group key and `h`; stores `h` as the height that replaced `from` and activated `to`; and makes `to` the active key set and its first point the group key, from the next block on. The handoff record is the rotation certificate a relayer submits to a light client (spec 17 §7).

A newer key set adopted before the handoff to an older one is recorded becomes the target instead. The older key set is never activated: a handoff to it is refused even if it arrives later and verifies, so the active key only ever moves to the newest adopted key. Nodes key their own rotation shares by the active key set and the target together, so a share signed for one handoff is never sent for another. The older key set's rotation certificate may still exist off chain if enough shares of it were gossiped. It moves a light client to a key the chain never hands off from, which stops that client (spec 17 §10).

Every handoff, whatever its target, needs the active key set's threshold of shares. A newer target therefore helps only when the handoff failed for a reason that passes, such as shareholders offline for a while. It does not help when more than `N − t` of the active key's shareholders stop for good, for example after they unbond and withdraw. Then no handoff can ever be recorded again. Newer key sets are adopted but never activated, the driver keeps producing certificates under the old key, and those certificates lose the stake behind them once its shareholders withdraw. Light clients refuse them after `K` epochs (§6.7). Only a kernel upgrade through governance (spec 13) gets such a chain out, for example by installing a newer adopted key set directly. This version has no path inside the kernel.

### 6.7 Key age and the unbonding period

The shareholders of key set `k` are members of the set of epoch `k`, chosen at the end of epoch `k − 1` by stake bonded then. Stake unbonded in epoch `k` or later is released at epoch `k + 1 + unbonding_epochs` at the earliest, so every shareholder of `k` holds that stake, bonded or unbonding and slashable, through epoch `k + unbonding_epochs`. A light client trusts key set `k` only for certificates whose anchor lies in an epoch at most `k + K`, and only accepts a handoff from `k` to a key set whose id is at most `k + K` (spec 17 §5.3). `kernel_init` requires `unbonding_epochs > K + HANDOFF_EPOCHS`, `HANDOFF_EPOCHS = 1`, so a false root that key set `k` certifies for a light client lies at a height the chain reaches by the end of epoch `k + K`, and evidence of it (§5.1) can be recorded for at least one more whole epoch, the handoff latency, and one after that, before any shareholder of `k` can withdraw: misbehaviour under a key that light clients still trust always has stake behind it. With threshold keys a chain should hand off well within `K` epochs; runs that fail for `K` epochs in a row leave light clients behind, since the key that hands off is then past its age (spec 17 §10).

## 7. State layout

| Key | Value |
|---|---|
| `stake/v/` + id | `StakeRecord { address: [20], stake: u128, unbonding: u128, release_epoch: u64, dkg_key: bytes, jailed: bool, delegated: u128 }` |
| `stake/a/` + address | id |
| `stake/ids` | `vec<[32]>`, registered ids in registration order |
| `stake/set/` + epoch (big-endian u64) | `ValidatorSet` of that epoch |
| `stake/d/` + id ‖ delegator address | `Delegation { stake: u128, unbonding: u128, release_epoch: u64 }` (§10.1) |
| `stake/dl/` + id | `vec<[20]>`, the validator's delegators, in the order they first delegated |
| `stake/dv/` + delegator address | `vec<[32]>`, the validators the account delegates to, in the order it first did |
| `stake/pool` | `u128`, the reward pool (§10.2); absent when empty |
| `dkg/run/` + epoch | `DkgRun` |
| `dkg/msg/` + epoch ‖ phase (u8) ‖ sender index (big-endian u32) | the DKG message |
| `dkg/vote/` + epoch ‖ id | hash of the `KeySetVote` the validator confirmed |
| `dkg/tally/` + epoch ‖ vote hash | `u128` weight behind it |
| `dkg/keyset/` + id (big-endian u64) | `KeySetRecord` |
| `dkg/active` | `u64`, the active key set's id |
| `dkg/group_key` | the 96-byte group key of the active key set |
| `dkg/adopted` | `u64`, the newest adopted key set's id |
| `dkg/activated/` + id (big-endian u64) | `u64`, the height of the block that made that key set active |
| `dkg/replaced/` + id | `u64`, the height of the block whose handoff replaced that key set |
| `dkg/handoff/` + id | `Handoff` out of that key set |
| `tevidence/` + index (big-endian u64) | `ThresholdEvidence`, indices from 0 in the order recorded |
| `meta/tevidence_count` | `u64`, the number of threshold evidence records |
| `tevseen/` + kind ‖ key set (big-endian u64) ‖ index (big-endian u32) | `u64` index of the record for that offence |

All of it is committed (10 §2).

## 8. Queries

- `staking` takes nothing and returns `StakingStatus { epoch, params, validators, records: vec<StakeEntry { id, record }>, active: option<KeySetRecord>, group_key: bytes, pool: u128 }`: the epoch of the next block, the parameters without the genesis keys, the current set, every registered validator in registration order, the active key set, the group key (empty before the first), and the reward pool (§10.2).
- `staking_set` takes a `u64` epoch and returns that epoch's `ValidatorSet`, status 1 if it is not decided yet, status 2 for malformed parameters.
- `staking_delegations` takes an address and returns `vec<DelegationEntry { validator: [32], delegation: Delegation }>`, the account's delegations in the order it first made them; status 2 for malformed parameters.
- `handoff` takes a `u64` key set id and returns the `Handoff` out of it, status 1 if none is recorded, status 2 for malformed parameters.
- `threshold_evidence` takes a `u64` first index and returns `vec<ThresholdEvidence>`, the records from that index on, at most 64; status 2 for malformed parameters.

## 9. Limits of this version

- Rewards are the priority fees alone (§10): there is no issuance, no commission, and no record of validator participation (codex ADR 0008), so a validator that misses its slots earns like one that does not. A validator has at most `MAX_DELEGATORS = 64` delegators and an account at most `MAX_DELEGATIONS = 16` delegations, which bounds the work of an epoch end and of a `withdraw`; a chain with more delegators than that needs an accounting that pays on demand, a later change. Rewards are paid to accounts at epoch ends and never compound into stake by themselves.
- A jailed validator stays jailed for good; it can only withdraw.
- The threshold counts shareholders, not stake: a certificate proves that `⌊2N/3⌋ + 1` of `N` shareholders signed, while finality needs more than two thirds of the stake (08 §1). Shareholders holding little stake together can therefore sign any block, and seats cost no more than `max(min_stake, 1 gwei)` each when `max_validators` is 0, so a chain that wants its certificates to mean something sets both. Full nodes never rely on a threshold certificate: sync always checks the vote certificate against the stake (08 §7a), and the threshold certificate is only an artifact for light clients and verifiers on other chains. They trust fewer than `N/3` shareholders of each key set to misbehave while that key set is in force, and slashing (§5.1) makes misbehaviour cost a tenth of the stake behind each offending share; how much that deters depends on that stake, which a chain sets with `min_stake` and `max_validators`.
- Shareholders who leave the set must keep their nodes running until the handoff of the key they hold is recorded. Nothing makes them: if fewer than the threshold of them sign, no handoff to any target can be recorded, and the chain stays on that key until enough of them return or a governance kernel upgrade replaces the key (§6.6).
- Slashing is a fixed tenth of the stake and the offender is jailed, whatever the damage of the offence; the slashed stake is burned, not paid to the reporter, so nothing but the reporter's own interest pays for `REPORT_GAS`.
- Equivocation evidence of an epoch is checked against that epoch's set, which chain state keeps for good; there is no bound on how late evidence may arrive. Threshold evidence is likewise judged at any time, but it slashes only stake not yet withdrawn.
- Anyone can send handoff and evidence envelopes, and each costs its receiver one BLS verification before the pool refuses an invalid one; peer scoring for them is left for later.

## 10. Delegation and rewards

### 10.1 Delegation

Any account puts stake behind a registered validator with `delegate(validator)` (§3.3, §3.4) and takes it back with `undelegate(validator, amount)` and, once released, `withdraw()`. A *delegation* is the record `Delegation { stake, unbonding, release_epoch }` under `stake/d/` ‖ id ‖ delegator (§7), one per delegator and validator, deleted once both its stake and its unbonding stake are zero, when it also leaves both lists. A validator's `delegated` is the sum of the bonded stake of the delegations behind it; its *total stake* is `stake + delegated`.

Delegated stake counts: it orders the candidates of an epoch's set and weighs the validator's votes (§4), and it is slashed with the validator's own (§5). It does not meet the minimum stake, which is the validator's own bond, and it earns nothing while unbonding. A validator with a delegation behind it keeps its registration slot (§3.5) until the last delegation is withdrawn, so a delegator can always undelegate and withdraw, from a jailed validator too.

### 10.2 The reward pool

The priority fees of every block on a chain with staking reach the staking address at the end of the block (23 §4): the kernel moves the fee vault's balance there and adds it to the *reward pool*, `stake/pool`. At the end of the block at `end(e)`, before the set of `e + 1` is decided (§4), the pool `P` is paid out to the members of the set of epoch `e`, whose blocks filled it, that are not jailed at that moment:

1. With `W` the sum of the weights of those members, member `v` of weight `w` gets the share `s = ⌊P · w / W⌋`, computed exactly (`solo_abi::fees::mul_div`, a 256-bit product); a validator whose share is zero gets nothing. A member jailed during the epoch, as every slashed validator is (§5, §5.1), gets nothing, nor do the delegations behind it: the others share the whole pool, and with none left (`W = 0`) the pool waits for the next epoch end. The jailed member's delegators chose it and share its slashing (§10.1); they share its forfeited reward too.
2. With `T = stake + delegated` of `v`'s record at that moment, each delegator behind `v` with bonded stake `d` is credited `⌊s · d / T⌋`, and `v`'s account the rest of `s`: its own part and what the delegators' rounding left. With `T = 0` (a member that unbonded everything during the epoch) `v`'s account gets all of `s`. A member whose record is gone is credited at the address its id names.
3. The staking address is debited the sum of the shares, and the pool keeps the remainder `P − Σ s`, less than the number of validators in the set in wei, for the next epoch.

Credits go to account balances at once, not to stake. The sums are exact: after every block, `pool + Σ credits since genesis = Σ priority fees and coinbase transfers since genesis`, and the staking address's balance is at least the stakes plus the pool (§3.4): exactly that unless value reached it outside a staking transaction, by a contract's transfer or a self-destruct, which nothing pays out and which stays there (a treasury cannot be the staking address, 23 §2). With no stake among the members paid (`W = 0`) the pool waits for the next epoch end.

