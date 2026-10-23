# 12 — Threshold BLS finality certificates

## 1. Overview

This document specifies the finality certificate that codex ADR 0008 calls for and the cryptography behind it: BLS signatures over BLS12-381, a `t`-of-`M` threshold key whose `M` shares are dealt to the validators, several to a validator when shares follow stake, the dealerless key generation (DKG) that creates the key, the resharing that hands a key to a new validator set without changing it, the rotation message with which one key hands off to the next, and the procedure an Ethereum contract follows to verify a certificate and a rotation with the EIP-2537 precompiles. The decisions behind it are recorded in codex ADRs 0017, 0031 and 0040.

A certificate verifies with one pairing check against the group public key of the key set that signed it, for about 115 000 gas of precompile calls on Ethereum. The reference kernel generates a fresh key every epoch and the old key hands off to it (spec 15 §6.6), so a version-2 certificate (97 bytes) names the key set that signed it, and a light client on Ethereum (codex ADR 0013, tier 2) follows the chain of rotation messages from the key it trusts. The 89-byte version-1 certificate of a key that never changes stays decodable.

The reference implementation is `crates/solo-bls`. The Simplex driver (08 §6a) produces these certificates once the validators of an epoch have generated a key; spec 15 §6 specifies how the DKG runs inside the reference kernel, with its messages carried in blocks, its phases at fixed heights and the secret halves in the host's keystore, and how keys hand off.

Numbers in this document are big-endian wherever they are part of a signed message or a certificate, because Ethereum contracts rebuild them with `abi.encodePacked`. DKG messages use the canonical encoding of 06 §2 like every other driver message.

## 2. Curve, groups and encodings

The curve is BLS12-381 with its standard generators `g1` and `g2` (draft-irtf-cfrg-pairing-friendly-curves-11, `BLS12_381`).

| Name | Value |
|---|---|
| `p`, base field modulus | `0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab` |
| `r`, group order | `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` |

**Scheme variant.** Signatures and message hashes are G1 points; public keys, public key shares and Feldman commitments are G2 points (the "minimal-signature-size" variant). Verifying on Ethereum then hashes to G1, which costs two `BLS12_MAP_FP_TO_G1` calls instead of two `BLS12_MAP_FP2_TO_G2` calls:

| Per verification (EIP-2537 gas) | Signatures in G1 (chosen) | Signatures in G2 |
|---|---|---|
| Hash to curve | 2 × 5 500 + 375 = 11 375 | 2 × 23 800 + 600 = 48 200 |
| Two-pair pairing check | 102 900 | 102 900 |
| Total of BLS precompiles | **114 275** | 151 100 |
| Signature in calldata | 128 bytes | 256 bytes |
| Group key | 256 bytes | 128 bytes |

The larger key costs little: a verifier of a key that never changes holds it as immutable code constants (version 1), and a light client of a rotating key (version 2, spec 17 §5.3) keeps it in eight storage words that it reads once per certificate and writes once per rotation.

**Point encoding.** A point is encoded compressed in the format of draft-irtf-cfrg-pairing-friendly-curves-11 Appendix C (the format Zcash and the Ethereum consensus layer use): a G1 point is 48 bytes, the big-endian `x`; a G2 point is 96 bytes, `x.c1 ‖ x.c0` for `x = x.c0 + x.c1·u`. The three most significant bits of the first byte are flags: bit 7 is set (compressed), bit 6 marks the identity (then every other bit is zero), bit 5 is set when `y` is the lexicographically larger of the two roots. A decoder MUST reject an encoding whose flags are inconsistent, whose `x` is not below `p`, which is not on the curve, or whose point is not in the subgroup of order `r`.

**Scalar encoding.** A scalar is 32 bytes, big-endian, and MUST be below `r`.

**EIP-2537 encoding.** Ethereum's precompiles take uncompressed points: a base-field element is 64 bytes (16 zero bytes, then the 48-byte big-endian value); a G1 point is `x ‖ y` (128 bytes); an `Fp2` element is `c0 ‖ c1` (128 bytes, note the order); a G2 point is `x ‖ y` (256 bytes); the identity is all zeros.

## 3. Signatures

**Hashing.** `H(m, DST)` is `hash_to_curve` of RFC 9380 with suite `BLS12381G1_XMD:SHA-256_SSWU_RO_`. `hash_to_scalar(m, DST)` is `OS2IP(expand_message_xmd(m, DST, 48)) mod r` with SHA-256 (RFC 9380 §5.2 `hash_to_field` into `F_r` with `L = 48`, one element).

| Tag | Value | Use |
|---|---|---|
| `DST_SIG` | `SOLO-V01-CS01-with-BLS12381G1_XMD:SHA-256_SSWU_RO_` (50 bytes) | every signature and partial signature over a message |
| `DST_POP` | `SOLO-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_` (50 bytes) | proofs of possession |
| `DST_COEFFICIENT` | `SOLO-V01-COEFFICIENT_XMD:SHA-256` | polynomial coefficients derived from a seed (§4, §5) |
| `DST_EPHEMERAL` | `SOLO-V01-DKG-EPHEMERAL_XMD:SHA-256` | a dealer's ephemeral scalar (§5) |
| `DST_PAD` | `SOLO-V01-DKG-PAD_XMD:SHA-256` | share encryption pads (§5) |

**Keys.** `KeyGen(IKM, key_info)` is the function of draft-irtf-cfrg-bls-signature-05 §2.3 (identical to `HKDF_mod_r` of EIP-2333): with `salt = "BLS-SIG-KEYGEN-SALT-"`, repeat `salt = SHA-256(salt)`, `PRK = HKDF-Extract(salt, IKM ‖ 0x00)`, `OKM = HKDF-Expand(PRK, key_info ‖ I2OSP(48, 2), 48)`, `sk = OS2IP(OKM) mod r` until `sk ≠ 0`. `IKM` MUST be at least 32 bytes. The public key is `pk = sk · g2` and MUST NOT be the identity.

**Signing and verifying.** A signature over `m` is `σ = sk · H(m, DST_SIG)`. `σ` is valid under `pk` when both decode (§2), `pk` is not the identity, and

```
e(σ, −g2) · e(H(m, DST_SIG), pk) = 1
```

which an implementation computes as one two-pair multi-Miller loop and one final exponentiation.

**Proofs of possession and aggregation.** A proof of possession of `sk` is `sk · H(encode(pk), DST_POP)`, verified like a signature with `DST_POP`. The sum of signatures by several keys over the same `m` verifies against the sum of the keys (`FastAggregateVerify`) provided every key's proof of possession was verified first. Aggregation is the fallback of ADR 0008 if a DKG proves too costly; certificates use the threshold scheme.

## 4. Threshold keys

A threshold key has `M` shares with indices `1..M` and threshold `t`, `1 ≤ t ≤ M`. Behind it is a secret polynomial `f(x) = a_0 + a_1·x + … + a_{t−1}·x^{t−1}` over `F_r`:

- share `i` is `s_i = f(i)`;
- the group secret is `f(0) = a_0`, which nobody holds, and the group public key is `PK = a_0 · g2`;
- the **public key set** is the Feldman commitment `C = (a_0 · g2, …, a_{t−1} · g2)`: its first point is `PK`, its length is `t`, and `pk_i = Σ_k i^k · C_k` is the public key share of share `i`, equal to `s_i · g2`. It is encoded as the concatenation of its compressed points (`96·t` bytes);
- a share `s` for index `i` passes the **Feldman check** against `C` when `s · g2 = Σ_k i^k · C_k`.

**Shareholders.** A *shareholder* is a party that holds shares, each a run of consecutive indices: with `N` shareholders holding `m_1, …, m_N ≥ 1` shares, `M = Σ m_j`, shareholder `j` holds the indices `o_j + 1` to `o_j + m_j`, `o_j = m_1 + … + m_{j−1}`. With one share each (`m_j = 1`, `M = N`) share `j` is shareholder `j`'s, as in every key before codex ADR 0040. How many shares a party holds is a parameter of the run that makes the key; the reference kernel deals them in proportion to stake (spec 15 §6.1), so that any `t` shares stand for more than two thirds of the stake (15 §6.8). Nothing about a key set, a group signature or its verification depends on who holds which share.

**Partial signatures.** The partial signature of share `i` over `m` is `σ_i = s_i · H(m, DST_SIG)`; it is valid when it verifies (§3) under `pk_i`. A shareholder signs once with each share it holds.

**Combination.** Given partial signatures of a set `S` of `t` distinct nonzero share indices, the group signature is

```
σ = Σ_{i ∈ S} λ_i · σ_i,    λ_i = Π_{j ∈ S, j ≠ i} j / (j − i)  (mod r)
```

When every `σ_i` is valid, `σ = a_0 · H(m, DST_SIG)`: the unique signature of the group key, the same whichever `t` shares signed. Fewer than `t` partial signatures determine nothing about it. A combiner takes the first `t` partial signatures it is given and then verifies either each of them or the result; the reference combiner for certificates verifies the result (§7), and finds the invalid partials, when that fails, with a batched check (§4.1).

### 4.1 Batched checks

A verifier that has many equations of the same kind to check MAY check them as one random linear combination, and SHOULD when that is cheaper (codex ADR 0043). Each equation says that some point of a prime-order group is the identity: `s · g2 − Σ_k x^k · C_k` for a Feldman check, `e(σ_i, −g2) · e(H(m), pk_i)` for a partial signature. The verifier draws one coefficient `ρ_i` per equation, uniform over `[0, 2^64)` and unknown to whoever chose the points, and checks the combination `Σ_i ρ_i · (point_i)`. A combination of identities is the identity, so a batch of valid equations always passes. A batch with an invalid equation passes with probability at most `2^−64`: whatever the other coefficients, at most one value of the coefficient of a point other than the identity cancels the rest. A batch that fails is split in halves, each checked the same way, until every failing equation stands alone, so the verifier learns exactly which equations fail, as checking them one by one would tell it, except with that probability per invalid equation. Batching changes how a verifier computes its answer, never which answer the protocol expects: every message of §5 and every certificate of §7 is the same either way.

- **Partial signatures** over one message `m` with indices `x_j`: the combination is the single pairing check `e(Σ_j ρ_j σ_j, −g2) · e(H(m), Σ_k c_k · C_k) = 1` with `c_k = Σ_j ρ_j x_j^k`, one multi-scalar multiplication over the `t` commitment points instead of one evaluation of the commitment per partial, and one pairing instead of one per partial. A partial naming index 0 fails its batch. The reference combiner (05 §4.3's keystore, spec 15 §6.4) draws `ρ_j` as the first 8 bytes, big-endian, of `expand_message_xmd(seed ‖ I2OSP(j, 8), DST_PARTIAL_BATCH, 8)` with 32 bytes of fresh randomness `seed` from the operating system per check, `j` the partial's position, and `DST_PARTIAL_BATCH = "SOLO-V01-PARTIAL-BATCH_XMD:SHA-256"`.
- **Feldman checks** of one recipient, §5.

A verifier chooses per batch, by an estimate of the group operations each way, whether to combine or to check one by one: a Feldman check at a small index costs a handful of additions, a combination about sixteen per dealer and commitment point. The reference implementation (`solo_bls::batch`) estimates both, checks one by one wherever that is no dearer, and once the batches it has tried cost as much as checking every equation one by one, checks what remains one by one; so senders of invalid shares or partials can make it at most about twice as slow as checking one by one, never more.

### 4.2 Every public key share

A node that needs the public key shares of many consecutive indices `1..M` (the keystore's `KeySetVote`, spec 15 §6.3) MAY compute them together; the points are the same as `pk_x = Σ_k x^k · C_k` evaluated for each `x`. One by one, each is `t` Horner steps, each a multiplication by the small integer `x`, so `M · t` multiplications by integers up to `M`. Together (codex ADR 0044), the committed polynomial `P(x) = Σ_k x^k · C_k` is rewritten by Horner's rule in the falling-factorial basis, `P(x) = Σ_j A_j · x(x − 1)…(x − j + 1)`, using `x · x^(j) = x^(j+1) + j · x^(j)`, which is about `t² / 2` multiplications by integers below `t`. The forward differences of `P` at zero are then `Δ^j P(0) = j! · A_j` (`t` scalar multiplications), and each next share follows from the difference table in `t − 1` additions: `Δ^j P(x + 1) = Δ^j P(x) + Δ^(j+1) P(x)`, with `pk_x = P(x)`. The reference implementation (`PublicKeySet::public_shares`) does this when `M` is at least `⌈t / 2⌉` and evaluates one by one below that. Measured in §10.

**Trusted dealing.** A single operator who holds every share anyway (a development chain) MAY split a secret key `sk` itself: `a_0 = sk`, and for `k ≥ 1`, `a_k = hash_to_scalar(seed ‖ "deal" ‖ I2OSP(k, 4), DST_COEFFICIENT)` with `seed` 32 bytes of fresh randomness. The worked example of §9.2 uses this derivation. Validator sets use the DKG.

## 5. Key generation

The DKG is synchronous Joint-Feldman (Pedersen's DKG) with complaints. It is a pure state machine: each participant's machine consumes broadcast messages and phase boundaries and produces broadcast messages and, at the end, its output. The reference kernel runs it for a fresh key every epoch (spec 15 §6.1).

**Assumptions.** Senders are authenticated by the transport (the driver's signed consensus messages). Every honest participant processes the same messages in the same phase and ends each phase at the same point, as when the messages are carried in finalized blocks and phases end at fixed heights. The faulty participants hold fewer than `t` shares and their dealers weigh less than `t` in all (for a resharing, they are fewer than the previous threshold among the dealers). Under these assumptions every honest participant computes the same qualified set and the same public key set.

**Parameters**, identical at every participant: a 32-byte `session` unique to the run (a driver derives it from the chain id and the epoch); the threshold `t`; the number of dealers `D`, indexed `1..D`, and each dealer's *weight* `v_i ≥ 1`; the recipients' encryption keys `ek_1 … ek_N` (recipient `j` has index `j`) and each recipient's share count `m_j ≥ 1`, so that recipient `j` becomes the shareholder of the indices `X_j = o_j + 1 … o_j + m_j` of §4 and the new key has `M = Σ m_j` shares; and, for a resharing, the previous public key set. Weights and share counts are 1 unless a driver says otherwise; the reference kernel gives each recipient the share count of its stake and each dealer, which is also a recipient, its share count as its weight (spec 15 §6.1). `M` is below `2^32`, `1 ≤ t ≤ M`, and `D` is at least 1 (for a resharing, at least the previous threshold, with every weight 1). Below, `x` ranges over share indices and `owner(x)` is the recipient `j` with `x ∈ X_j`.

**Encryption keys.** A recipient's decryption key is `dk = KeyGen(IKM, "SOLO-DKG-ENCRYPTION")` and its encryption key is `ek = dk · g1`, a G1 point other than the identity, registered before the run.

**Dealing.** Dealer `i` chooses a secret polynomial `f_i` of degree `t − 1` and an ephemeral scalar `e_i`, all uniformly random. The reference derivation from 32 bytes of fresh randomness `seed`, with `context_i = session ‖ I2OSP(i, 4)`, is `a_{i,k} = hash_to_scalar(seed ‖ context_i ‖ I2OSP(k, 4), DST_COEFFICIENT)` and `e_i = hash_to_scalar(seed ‖ context_i, DST_EPHEMERAL)`; other derivations do not affect anyone else. In a resharing `a_{i,0}` is instead the dealer's current share. The dealer computes

```
C_i   = (a_{i,0} · g2, …, a_{i,t−1} · g2)
R_i   = e_i · g1
pad_ix = hash_to_scalar(session ‖ I2OSP(i, 4) ‖ I2OSP(x, 4) ‖ encode(R_i) ‖ encode(e_i · ek_owner(x)), DST_PAD)
c_ix  = f_i(x) + pad_ix  (mod r)          for every share index x in 1..M
```

and broadcasts `Dealing { session, dealer: i, commitment: C_i, ephemeral: R_i, shares: (c_i1, …, c_iM) }`. Recipient `j` recovers each of its shares as `s_ix = c_ix − pad_ix`, `x ∈ X_j`, computing the shared point as `dk_j · R_i`. A pad is a one-time pad over `F_r`, used once per `(session, dealer, share index)`; integrity comes from the Feldman check, not from the encryption. With one share per recipient `x = j`, and the dealing is byte for byte the one earlier versions made.

**Phase 1, dealing.** A machine accepts a `Dealing` only in this phase, and only when its `session` matches, `1 ≤ dealer ≤ D`, it has no dealing from that dealer yet, the commitment has exactly `t` points and the shares exactly `M` scalars, every point and scalar decodes (§2), and, in a resharing, `C_{i,0}` equals the dealer's previous public key share. Anything else is rejected and changes nothing; a dealer without an accepted dealing is absent. At the end of the phase, each recipient `j` decrypts and Feldman-checks each of its shares `x ∈ X_j` from every accepted dealing and, if any fails, broadcasts `Complaints { session, accuser: j, dealers }` listing, ascending and once each, the dealers with a failing share.

**Batched share checks.** A recipient MAY check its shares from many dealers at once (§4.1). With a coefficient `ρ_i` per dealer `i` of a set `S`, its shares hold for every `x ∈ X_j` exactly when, except with probability `2^−64` per failing dealer,

```
(Σ_{i ∈ S} ρ_i · s_ix) · g2  =  Σ_k x^k · A_k,        A_k = Σ_{i ∈ S} ρ_i · C_{i,k}
```

one aggregate commitment `A` of `t` points, each a multi-scalar multiplication over the dealers with 64-bit scalars, then one evaluation of `A` per share index rather than one evaluation per dealer and share index. When the equation fails for some `x`, the recipient splits `S` and checks each half, down to single dealers checked one share at a time, and accuses exactly the dealers it finds. The coefficients must be unknown to the dealers when they deal. The reference recipient derives them from its decryption key: `ρ_i` is the first 8 bytes, big-endian, of `expand_message_xmd(I2OSP(dk_j, 32) ‖ session ‖ I2OSP(i, 4) ‖ encode(R_i), DST_SHARE_BATCH, 8)`, `DST_SHARE_BATCH = "SOLO-V01-DKG-BATCH_XMD:SHA-256"`, which only the recipient can compute, and which gives the same complaints whenever it replays the run (spec 15 §6.4). A dealer that cannot predict `ρ_i` makes a bad share pass a batch with probability at most `2^−64`, once per run, and a share that passes wrongly costs only the recipient that holds it: its partial signatures fail to verify (§4) and the combiner drops them; every participant still computes the same `QUAL`, which depends only on the broadcasts.

**Phase 2, complaints.** A machine accepts the first `Complaints` from each recipient `1 ≤ accuser ≤ N` with a matching `session`, and records a complaint `(i, accuser)` for each listed dealer `i` with an accepted dealing; other listed indices are ignored. At the end of the phase, each dealer with recorded complaints broadcasts `Justification { session, dealer: i, shares }` revealing `f_i(x)` for every share index `x` of every accuser, in ascending order of `x`.

**Phase 3, justifications.** A machine accepts the first `Justification` from each dealer `1 ≤ dealer ≤ D` with a matching `session`. An entry `(x, s)` is *valid* when `x` is a share index, the complaint `(i, owner(x))` was recorded, `s` is a canonical scalar, and `s` passes the Feldman check against `C_i` at `x`; other entries are ignored. The complaint `(i, j)` is *answered* when every `x ∈ X_j` has a valid entry. At the end of the phase every dealer with an unanswered complaint is disqualified, and an accuser whose complaint was answered takes the revealed shares as its `s_ix`.

**Output.** `QUAL` is the accepted dealers that were not disqualified, ascending. The run fails if the weights of `QUAL` sum to less than `t` (for a resharing, if `|QUAL|` is below the previous threshold). Otherwise, for a fresh key

```
C   = Σ_{i ∈ QUAL} C_i   (point-wise)        s_x = Σ_{i ∈ QUAL} s_ix     for each x ∈ X_j
```

and the new public key set is `C`, the group key `C_0`, recipient `j`'s shares the `s_x` of its indices. A recipient that lacks a verified share from some qualified dealer (its complaint was not delivered) ends without any share; everyone else is unaffected.

**Messages.** On the wire, in the canonical encoding of 06 §2:

```
enum DkgMessage {
  0 Dealing       { session: [32], dealer: u32, commitment: vec<[96]>, ephemeral: [48], shares: vec<[32]> }
  1 Complaints    { session: [32], accuser: u32, dealers: vec<u32> }
  2 Justification { session: [32], dealer: u32, shares: vec<RevealedShare { index: u32, share: [32] }> }
}
```

`RevealedShare.index` is a share index; with one share per recipient it is the accuser's index, so the encoding of every message is unchanged from earlier versions.

**Security notes.** An honest dealer is never disqualified, and the faulty dealers weigh less than `t` in all, so a `QUAL` of weight `t` or more contains an honest dealer and the group secret stays unknown. With the reference kernel's weights (a dealer weighs its share count) that is the assumption that the faulty participants hold fewer than `t` shares, which validators holding at most two thirds of the stake always do (15 §6.8). A falsely accused honest dealer reveals only the accuser's shares. Joint-Feldman lets a faulty dealer bias the distribution of the group key by choosing whether to be disqualified; for threshold signatures this bias does not enable forgery (Gennaro, Jarecki, Krawczyk and Rabin, "Secure Applications of Pedersen's Distributed Key Generation Protocol", CT-RSA 2003), which is why the cheaper protocol is used, as drand does for its threshold BLS beacon. Pads are secure under the computational Diffie-Hellman assumption in G1 with the hash modelled as a random oracle; a recipient's decryption key opens every share ever sent to it, so validators rotate encryption keys with the validator set.

## 6. Resharing

A resharing hands an existing key to a new set of recipients, with a new threshold if desired, and keeps the group key. It is a run of §5 with the previous public key set given: the dealers are the previous shares, each of weight 1, so that a party holding several previous shares deals once for each; dealer `i` uses share `s_i` as `a_{i,0}`, and every machine rejects a dealing whose constant term is not `pk_i` of the previous set. With `λ_i` the Lagrange coefficients at zero over `QUAL` (§4),

```
C   = Σ_{i ∈ QUAL} λ_i · C_i        s'_j = Σ_{i ∈ QUAL} λ_i · s_ij
```

Because every `C_{i,0} = s_i · g2` and `|QUAL|` is at least the previous threshold, `C_0 = Σ λ_i · s_i · g2 = PK`: the group key is unchanged, so certificates from the new set verify under the key an Ethereum contract already holds. The new shares are a fresh sharing of the same secret; previous shareholders are asked to erase their old shares once the new set is active, but nothing can enforce it, and old shares still combine into signatures under the same key. That is why the reference kernel no longer reshares (codex ADR 0031): it generates a fresh key each epoch and hands off to it (spec 15 §6.6), so that a key's shareholders can be held to it while their stake is bonded. Resharing stays specified and implemented for chains that want a key that never changes and accept that its former shareholders are trusted for ever.

## 7. Certificates

**Messages.** The message signed for the block with hash `block_hash` at `height` on the chain with id `chain_id` is, in version 1, 62 bytes and, in version 2, 70 bytes that also name `key_id`, the id of the key set that signs (the epoch whose DKG made it, spec 15 §6.1):

```
message_v1 = "SOLO-FINALITY" (13 ASCII bytes) ‖ 1 ‖ chain_id (u64) ‖ height (u64) ‖ block_hash (32 bytes)
message_v2 = "SOLO-FINALITY" (13 ASCII bytes) ‖ 2 ‖ chain_id (u64) ‖ key_id (u64) ‖ height (u64) ‖ block_hash (32 bytes)
```

**Formats.**

```
certificate_v1 = 1 ‖ height (u64) ‖ block_hash (32 bytes) ‖ signature (48 bytes, compressed G1)            (89 bytes)
certificate_v2 = 2 ‖ key_id (u64) ‖ height (u64) ‖ block_hash (32 bytes) ‖ signature (48 bytes)            (97 bytes)
```

A decoder MUST reject a first byte other than 1 or 2 (an unknown version), a length other than 89 for version 1 or 97 for version 2, and a signature that does not decode. The reference driver produces version 2 only; version 1 stays decodable and its verifier (§8, Appendix A) stays deployed for chains whose key never changes. A later signature scheme gets a new version byte, a new message tag and its own Ethereum verifier.

**Producing.** Each shareholder of key set `key_id` signs `message_v2` with each share it holds; any `t` partial signatures of distinct shares combine into the group signature (§4). The combiner verifies the combined signature before emitting the certificate, so an invalid partial never yields an invalid certificate; when that check fails, the driver finds the invalid partials (§4.1: a batched check, split until each invalid one stands alone), drops them and combines again.

**Verifying.** A certificate is valid for `chain_id` under the group key `PK` of the key set it names (version 2) or of the chain (version 1) when its signature verifies (§3) over the message rebuilt from `chain_id`, its key id, its height and its block hash. Inside a kernel this is the host function `bls12381_verify` (05 §4.3) with arguments `message`, `DST_SIG`, the signature and `PK`. Which key sets a verifier accepts for which heights is the verifier's rule: a full node's is spec 08 §7a, a light client's spec 17 §5.3.

**Rotation.** The active key set hands off to the key set `key_id` with group key `key` (compressed, 96 bytes) by signing, with the same tag `DST_SIG`, the 124-byte rotation message

```
rotation_message = "SOLO-ROTATE" (11 ASCII bytes) ‖ 1 ‖ chain_id (u64) ‖ key_id (u64) ‖ key (96 bytes)
```

Its group signature over it is a *rotation certificate*. The version byte 1 lets a later rotation format coexist; the tag differs from the certificate tag in its sixth byte, so no rotation message is a certificate message and no certificate message a rotation message, and both are signed under one `DST_SIG` without ambiguity. A rotation message names the new key, not the old: the old key is whoever signs it, and a verifier checks it against the key it holds.

**Relationship to 08.** A driver that adopts these certificates carries them in `FinalizeBlock.certificate`. A spec 08 finalize certificate opens with its kind byte 2 too, but its encoding is `42 + 69·n` bytes for `n` votes (one byte more from 128 votes on), never 97, and never 89, so a decoder tells the three formats apart by the first byte and the length. A certificate does not say which validators signed; participation is recorded separately (ADR 0008). What a certificate proves about stake follows from how the shares were dealt, never from the certificate: under the reference kernel's dealing, the shares behind any certificate belong to validators holding more than two thirds of the stake of the key set's epoch (15 §6.8), so a verifier, an Ethereum contract included, needs no list of validators or stakes.

## 8. Verification on Ethereum

A verifier contract for version 1 holds as constants the chain id, `PK` in EIP-2537 encoding (256 bytes), `−g2` in EIP-2537 encoding, `DST_SIG` and `p`. A relayer decodes a certificate and submits `height`, `block_hash` and the signature decompressed into EIP-2537 encoding (128 bytes). A verifier for version 2 holds the same constants but no key: the caller, a light client that holds the key set in force, passes `PK` and `key_id` with each certificate. The contract:

1. builds `message` (§7), e.g. `abi.encodePacked(bytes13("SOLO-FINALITY"), uint8(1), chainId, height, blockHash)`, or for version 2 `abi.encodePacked(bytes13("SOLO-FINALITY"), uint8(2), chainId, keyId, height, blockHash)`;
2. computes `uniform = expand_message_xmd(message, DST_SIG, 128)` with the SHA-256 precompile (`0x02`): `b_0 = SHA-256(64 zero bytes ‖ message ‖ 0x0080 ‖ 0x00 ‖ DST_SIG ‖ 0x32)`, `b_1 = SHA-256(b_0 ‖ 0x01 ‖ DST_SIG ‖ 0x32)`, `b_i = SHA-256((b_0 ⊕ b_{i−1}) ‖ i ‖ DST_SIG ‖ 0x32)` for `i = 2, 3, 4`, `uniform = b_1 ‖ b_2 ‖ b_3 ‖ b_4`;
3. reduces each 64-byte half modulo `p` with MODEXP (`0x05`), input `I2OSP(64, 32) ‖ I2OSP(1, 32) ‖ I2OSP(48, 32) ‖ half ‖ 0x01 ‖ p`, and left-pads each 48-byte result with 16 zero bytes, giving `u_0`, `u_1`;
4. calls `BLS12_MAP_FP_TO_G1` (`0x10`) on `u_0` and on `u_1` and `BLS12_G1ADD` (`0x0b`) on the two results, giving `H(message, DST_SIG)` (the map precompile clears the cofactor, and cofactor clearing is linear, so map–map–add equals `hash_to_curve`);
5. calls `BLS12_PAIRING_CHECK` (`0x0f`) on `signature ‖ (−g2) ‖ H ‖ PK` (768 bytes) and accepts exactly when it returns 32 bytes ending in `0x01`. The precompile checks that the signature is on the curve and in the subgroup.

The BLS precompiles cost 114 275 gas; SHA-256 adds 516 and MODEXP 2 × 200 (2 × 500 once EIP-7883 is active). The reference contract of Appendix A spends 126 705 gas of execution per `verify` call on an Osaka EVM, and the version-2 verifier, which receives the key as calldata, 127 264 (spec 17 §8). ADR 0013 makes the verifier immutable per certificate version. Spec 17 builds the light client on it: a certificate signs a proposal hash, and the proposal's anchor carries the state root the certificate vouches for (17 §4).

**Rotations.** A rotation certificate verifies the same way over `rotation_message`, which binds the new key compressed. A light client receives the new key in EIP-2537 encoding, because it needs the uncompressed point for its own pairing checks and cannot decompress cheaply, so it checks the point and compresses it itself:

1. the key is 256 bytes, is not the identity, and comes back unchanged from `BLS12_G2MSM` (`0x0e`) with scalar 1, which rejects points off the curve, outside the subgroup or not canonically encoded;
2. with the key's four 64-byte field elements `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`, each 16 zero bytes and a 48-byte value, the compressed key is the value of `x.c1` followed by the value of `x.c0` (96 bytes), with bit 7 of the first byte set and bit 5 set exactly when `y` is the lexicographically larger root: when `y.c1 > (p − 1) / 2`, or `y.c1 = 0` and `y.c0 > (p − 1) / 2` (§2);
3. it builds `abi.encodePacked(bytes11("SOLO-ROTATE"), uint8(1), chainId, keyId, compressed)` and runs steps 2 to 5 above under the key it currently holds.

The reference version-2 verifier spends 129 098 gas of execution on a rotation (spec 17 §8).

## 9. Worked examples

All values hex. Each is asserted by a test in `crates/solo-bls`.

### 9.1 One key

| Item | Value |
|---|---|
| `IKM` | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| `sk = KeyGen(IKM, "")` | `23360db7e337b0a32b264e06bc11c1b474d16f55665373de1ce93cf15ddb3456` |
| `pk` | `acfd749941a5bea56796745d1fc91668d63f9522374cb6e9c033433e3216dcad48b4fc1ab7000a365f2861565daa6b0819fd041ac58eed8c441c8b3478df6ceeaf89cc02c8119f63891a1368d7ec1d0c7e2abaaae2ac8579b7eece473478dac7` |
| proof of possession | `b49782188d9b8cd027349de393a94f64cb25ace435546b4f353818aaa41b10e3e2f4c4499d6df7672959e2cf777c960f` |
| `chain_id`, `height`, `block_hash` | 1337, 1, 32 bytes of `ab` |
| `message` | `534f4c4f2d46494e414c4954590100000000000005390000000000000001abababababababababababababababababababababababababababababababab` |
| `uniform` | `bdc446043cea64e75bba99c861797d2e6ff18b0e271f5494a991b7fabda3d6c3ae622c2a4aeec19615ce205c056be6421fd819565d0bc5e82c344c22bfe56b3c2689b11499d3120cad3063f378536e212145842b28c31f89bc813f26bc1d2f06d9ca3a0f1caed3d34f7e56696ceb7d73d8abe38cd73f6417dba35cc2f92ea797` |
| `u_0` (EIP-2537) | `0000000000000000000000000000000012c3f5e8c4066b4cd696db337d801d96d7beced4d39fc0956111ecbad7453db0d304073a89f35d138e55d8c41dc0e099` |
| `u_1` (EIP-2537) | `0000000000000000000000000000000008c62b7c08404f2d27c33728d974b7f60106edbaa7d6aa323ed867c86299b83bae05723beabb2c7adb3a1b5bbbcf8859` |
| `MAP_FP_TO_G1(u_0)` | `0000000000000000000000000000000016a93254e3a12bb7e894b846a0c88fd2e6f378daf815a7f57e7714c78277418970cd3c38c61253362197d3003c29bcbf00000000000000000000000000000000018aea46599c41d27bf5681cbe7e5387d85955df9878c14d8d6fc588c4ae7a7af8b8a4e4c491b9256d5d4e8ffc4adbc9` |
| `MAP_FP_TO_G1(u_1)` | `0000000000000000000000000000000010d06185879d996ad023efe43703f2231a8572578ae88d9347e977d755952d0d1e0d4b7e97571a04bc7736c646f16ffe0000000000000000000000000000000005bba03fa8da9f8de383486ca2980298140702023e8dc606e6923068293b2b87b61d8e3dc0e8ba1780dc43bbd4188c7c` |
| `H(message, DST_SIG)`, compressed | `8659bd205ce63c80b808e3c48ab5e8e094c0b101bd8ca8431a4c152a32a884dbb45fef8f591f7b43bf9312d2dae7f06e` |
| `H`, EIP-2537 | `000000000000000000000000000000000659bd205ce63c80b808e3c48ab5e8e094c0b101bd8ca8431a4c152a32a884dbb45fef8f591f7b43bf9312d2dae7f06e000000000000000000000000000000000181bcf42f2563f453593a4015080c9f3f28239883254a4c4ebc1e3d9aa7922593fdb3fb9a75d1ad6a753194e0a29ee5` |
| signature, compressed | `8eedec2ca8e1fedd0f73c3bf8cb1aa078bd9d654f062d2c6f6b3b5566942cda883ca01a4b20c2c40c29490c30f971fa9` |
| signature, EIP-2537 | `000000000000000000000000000000000eedec2ca8e1fedd0f73c3bf8cb1aa078bd9d654f062d2c6f6b3b5566942cda883ca01a4b20c2c40c29490c30f971fa900000000000000000000000000000000089d489ae4c1645bf3e1595dd604ecf61c7a4d9808d28b65d6d1ecb2e085693f14438f699fba721c6b472a9d9e608424` |
| certificate | `010000000000000001abababababababababababababababababababababababababababababababab8eedec2ca8e1fedd0f73c3bf8cb1aa078bd9d654f062d2c6f6b3b5566942cda883ca01a4b20c2c40c29490c30f971fa9` |
| `pk`, EIP-2537 | `0000000000000000000000000000000019fd041ac58eed8c441c8b3478df6ceeaf89cc02c8119f63891a1368d7ec1d0c7e2abaaae2ac8579b7eece473478dac7000000000000000000000000000000000cfd749941a5bea56796745d1fc91668d63f9522374cb6e9c033433e3216dcad48b4fc1ab7000a365f2861565daa6b08000000000000000000000000000000000e7dbc1ef1502e48bb553bcc411d4c42bc70170821815c0a8f1431421a099a45a74efd2d70623f02011040ec965316eb000000000000000000000000000000000f170ab6ff2c30023a686560aea44adbe4d9938f9dd4e761311f23fc91f81b7c6e3037ece5d4428c88a494c65fbd9542` |
| `−g2`, EIP-2537 | `00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed` |

The pairing-check input is `signature ‖ −g2 ‖ H ‖ pk` in EIP-2537 encoding, and `BLS12_PAIRING_CHECK` returns 1 on it.

### 9.2 Three of four

`sk` of §9.1 split by trusted dealing (§4) with `t = 3`, `n = 4`, `seed` = 32 bytes of `42`. The commitment is

```
C_0 = acfd749941a5bea56796745d1fc91668d63f9522374cb6e9c033433e3216dcad48b4fc1ab7000a365f2861565daa6b0819fd041ac58eed8c441c8b3478df6ceeaf89cc02c8119f63891a1368d7ec1d0c7e2abaaae2ac8579b7eece473478dac7
C_1 = a6e79f3daafd1a1fabf18f19136463c07e350920437de17aa2a3729639e13f6c3a446e4c140cbc1aaf1083e29bf2777118d6a2b9b5c614032329d8fdc78a8fbe03a7cb77d02e376b7c12fa05a4d70bada81bb3d310e4dc9bf2368406eed117fb
C_2 = 8aab7972d5154db0f3ca07e776f3992f67d77309e7ec2318f08105d8030de3b64f28c6b9a6e344d4c501bb72d7b0509d04c369e759785860af13e92486e4dcb68594c4978cf187d85f5997881d82137fcf19530322920ec60f5a41f6785d2e6b
```

| `i` | share `s_i` | partial signature over the §9.1 message |
|---|---|---|
| 1 | `2ab5c8f90c03cd350d4abbe108efe1c94fbbb7863c5a1d01e8b4a4dea6ad0602` | `b404d3f192b03c4e28edc13c0de20451876497c11eb999c0a4749a2c4dfb48e96a7c9e1cb594197dba17d49530f8cb58` |
| 2 | `101fb99727f911bcc55edf56ce277db0805013e77bc706619f7b006d13951155` | `ab7856b345ea5f12b6f0a6b496e5ac3370318a33a4d8c89fecc13053bd1b7c4aec42679efc106c3a4f46d0b04cbd4d38` |
| 3 | `476186e560b4fb82869c9070155a6d6f5a4c287c24988bfc413c4f9ba4935650` | `b431eaa15868d4496879cd9275d7ab0f90ce6ca91ec2f881e480fc09599f08f338baf938a8c8b564f42699e5c8ebe67d` |
| 4 | `5c8d89908c9a0d3e1dc9f724d4e6d90089f2514136d051d2cdf8926b59a7d4f2` | `89a3e16d372473c9a45a99a3425305211521de9920d1008d0ea5a2a0b5a1afa54e24a61434d02a92302faa39685d29ef` |

Combining partials 1, 2, 4 (or 4, 3, 2) gives the certificate of §9.1.

### 9.3 A two-party DKG

`t = 2`, `D = N = 2`, `session` = 32 bytes of `5e`; participant `i` is dealer `i` with `seed` = 32 bytes of `100 + i` and recipient `i` with `dk_i = KeyGen(32 bytes of i, "SOLO-DKG-ENCRYPTION")`, so `ek_1 = 96945b435e90ff747ee213c0246c0569388a45fe41b63ddf6360c46ba82a375b35e4cd5ac8fd169f0878fc585a482363`. With the reference derivations, the SHA-256 digests of the two encoded `Dealing` messages are `b0a2f76c7e3326b430b8805568ea72989da5a8a668c378daadd45df302e7d2f8` and `4e6f4c171407144dabc9c38cabd742f877ee899d686f41419f243e0f91fd9034`; nobody complains, and the run ends with

| Item | Value |
|---|---|
| group key | `822bbc35275c08f014e718c9f66fe0ac83943afc0cdc3fd07316cb86bdc358d1b69ccc36c50f0ba06f9d2a5c47c18ee81889cd077e07f0854856cfa804d50e210008424da41554c2e4409d089aceae7298f898636df1836bf31b5af73ff64b66` |
| `s_1` | `4145a604d607404d85870f2a98a82762f22bd6d84d471b63640b0834beec3ba8` |
| `s_2` | `1d90c23af67638a1e5f471c93486d0163ef41c680ee807a57d599431274f522c` |

### 9.4 Standard vectors

The implementation also passes the RFC 9380 vectors of Appendices J.9.1 (`BLS12381G1_XMD:SHA-256_SSWU_RO_`, including the `u` values, through the EIP-2537 encoding), J.10.1 (`BLS12381G2_XMD:SHA-256_SSWU_RO_`) and K.1 (`expand_message_xmd` with SHA-256), and the four master-key vectors of EIP-2333 for `KeyGen`.

### 9.5 Version 2 and a rotation

The key of §9.1 as key set 3 certifies the block of §9.1, and hands off to the group key of §9.3 as key set 4.

| Item | Value |
|---|---|
| `message_v2` (key set 3) | `534f4c4f2d46494e414c49545902000000000000053900000000000000030000000000000001abababababababababababababababababababababababababababababababab` |
| `certificate_v2` | `0200000000000000030000000000000001ababababababababababababababababababababababababababababababababac8b3147a6f437a1f32f35433f4b579f94758b24c9ccae8b19cf19243d17b6cf5aa1491b59a2513432e34f8b9153e6e4` |
| `rotation_message` (to key set 4) | `534f4c4f2d524f544154450100000000000005390000000000000004822bbc35275c08f014e718c9f66fe0ac83943afc0cdc3fd07316cb86bdc358d1b69ccc36c50f0ba06f9d2a5c47c18ee81889cd077e07f0854856cfa804d50e210008424da41554c2e4409d089aceae7298f898636df1836bf31b5af73ff64b66` |
| rotation certificate's signature | `9890904bd14581711fa00553e5a4447d9b2135a5fe02c4cbe3e0ae5989599a9c32c7827f27711ccd8d6d258624d7006a` |

## 10. Limits of this version

- The reference kernel's DKG (15 §6) carries messages in blocks, ends phases at fixed heights and adopts a key set only when more than two thirds of the stake confirm the same public outcome, which is how it checks that every participant derived the same key set. Partial signatures ride on finalize votes, rotation partials on their own envelopes (15 §6.6), and both are combined in the host's keystore (05 §4.3), natively, rather than in the interpreter.
- The threshold counts shares. The reference kernel deals shares in proportion to stake, rounded down, so that `t` of them always stand for more than two thirds of the key set's epoch stake; the rounding costs liveness, never safety (15 §6.8). A recipient's share checks are batched (§5): its work is about sixteen G2 additions per dealer and commitment point, plus one evaluation of the aggregate per share it holds, where checking one by one costs one evaluation per dealer and share, about `1.5 · log2(x)` additions per point at index `x`. Measured on 2026-10-23 (`crates/solo-bls/tests/batch_timing.rs`, release build, one core of an Apple M4 Pro): with 64 members of equal stake (256 shares, threshold 171) a recipient of four shares at indices 125 to 128 checks them in 312 ms instead of 694 ms, one at indices 253 to 256 in 313 ms instead of 769 ms, and one at indices 1 to 4, whose checks one by one are already cheap, in 322 ms either way; a member with 64 of 253 shares checks them in 431 ms instead of 8 196 ms; with 256 members (1 024 shares, threshold 683) a recipient at indices 509 to 512 takes 3.35 s instead of 11.8 s, and at indices 1 021 to 1 024 3.41 s instead of 12.9 s. Finding 2 invalid partials among 685 under a threshold of 683 takes 1.26 s instead of 6.88 s one by one, and among 173 under 171, 290 ms instead of 472 ms. What remains is the aggregate itself, `D · t` short multi-scalar terms, and each node's computation of every public key share of the outcome (15 §6.8). That is computed together by forward differences (§4.2); measured on 2026-10-24 the same way, the 1 024 shares of threshold 683 take 4.06 s instead of 9.93 s one by one (2.4×), and the 256 shares of threshold 171, 279 ms instead of 503 ms (1.8×). The rewriting into the falling-factorial basis, about `t² / 2` small multiples, is most of what is left.
- `bls12381_verify` covers this scheme only. The Ethereum consensus layer's signatures (keys in G1, signatures in G2), which the sync-committee light client of spec 18 checks, have their own host function, `bls12381_fast_aggregate_verify`, behind feature gate 1 (05 §4.3).
- The DKG is synchronous; a run whose messages are not delivered to everyone alike can end with different outputs at different participants. In the reference kernel every participant reads the same messages from chain state, and a key set is adopted only once more than two thirds of the stake confirm it.

## Appendix A. Reference verifier (informative)

The reference verifier is `contracts/SoloFinalityVerifierV1.sol`, compiled by `tools/build-contracts.sh` with solc 0.8.28 (spec 17 §9). It follows §8 step by step: the constructor takes the chain id and `PK` in EIP-2537 encoding, checks the key with `BLS12_G2MSM` and keeps it in eight immutable words; `verify(height, blockHash, signature)` builds `message` with `abi.encodePacked`, expands it with five SHA-256 calls into four words, reduces each 64-byte half with MODEXP, maps both with `BLS12_MAP_FP_TO_G1`, adds them with `BLS12_G1ADD` and runs `BLS12_PAIRING_CHECK` on `signature ‖ −g2 ‖ H ‖ PK`. `crates/solo-bridge/tests/contracts.rs` runs it on revm at Osaka against the example of §9.1: `verify(1, 0xabab…ab, signature)` returns true for 126 705 gas of execution, and false for another height, block or chain id, a signature by another key, or a signature off the curve; a signature that is not 128 bytes reverts. An earlier draft of this appendix copied the halves of `uniform` byte by byte and spent 152 755 gas on a Prague EVM.

The version-2 verifier is `contracts/SoloFinalityVerifierV2.sol`: the same steps with the key and its id as arguments, `isValidKey` and `compress` of the rotation procedure above, and `verifyRotation(key, keyId, newKey, signature)`. `crates/solo-bridge/tests/contracts_v2.rs` runs it against §9.5: the certificate verifies as key set 3 and not as key set 4, the rotation verifies to key set 4 and not to 5, and `compress` agrees with the compressed encoding of twelve keys, with both values of the sort flag among them.
