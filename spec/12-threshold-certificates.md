# 12 — Threshold BLS finality certificates

## 1. Overview

This document specifies the finality certificate that codex ADR 0008 calls for and the cryptography behind it: BLS signatures over BLS12-381, a `t`-of-`n` threshold key shared among the validators, the dealerless key generation (DKG) that creates the key, the resharing that hands it to a new validator set without changing it, and the procedure an Ethereum contract follows to verify a certificate with the EIP-2537 precompiles. The decisions behind it are recorded in codex ADR 0017.

A certificate is 89 bytes and verifies with one pairing check against a group public key that never changes, so a light client on Ethereum (codex ADR 0013, tier 2) stores the key once and verifies every certificate for about 115 000 gas of precompile calls.

The reference implementation is `crates/solo-bls`. The Simplex driver (08 §6a) produces these certificates once the validators of an epoch have generated a key; spec 15 §6 specifies how the DKG runs inside the reference kernel, with its messages carried in blocks, its phases at fixed heights and the secret halves in the host's keystore.

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
| Group key | 256 bytes, a contract constant | 128 bytes, a contract constant |

The larger key costs nothing at verification time because resharing (§6) keeps it fixed, so a contract holds it as immutable code constants.

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

A threshold key has `n` shareholders with indices `1..n` and threshold `t`, `1 ≤ t ≤ n`. Behind it is a secret polynomial `f(x) = a_0 + a_1·x + … + a_{t−1}·x^{t−1}` over `F_r`:

- shareholder `i` holds the share `s_i = f(i)`;
- the group secret is `f(0) = a_0`, which nobody holds, and the group public key is `PK = a_0 · g2`;
- the **public key set** is the Feldman commitment `C = (a_0 · g2, …, a_{t−1} · g2)`: its first point is `PK`, its length is `t`, and `pk_i = Σ_k i^k · C_k` is shareholder `i`'s public key share, equal to `s_i · g2`. It is encoded as the concatenation of its compressed points (`96·t` bytes);
- a share `s` for index `i` passes the **Feldman check** against `C` when `s · g2 = Σ_k i^k · C_k`.

**Partial signatures.** Shareholder `i`'s partial signature over `m` is `σ_i = s_i · H(m, DST_SIG)`; it is valid when it verifies (§3) under `pk_i`.

**Combination.** Given partial signatures from a set `S` of `t` distinct nonzero indices, the group signature is

```
σ = Σ_{i ∈ S} λ_i · σ_i,    λ_i = Π_{j ∈ S, j ≠ i} j / (j − i)  (mod r)
```

When every `σ_i` is valid, `σ = a_0 · H(m, DST_SIG)`: the unique signature of the group key, the same whichever `t` shareholders signed. Fewer than `t` partial signatures determine nothing about it. A combiner takes the first `t` partial signatures it is given and then verifies either each of them or the result; the reference combiner for certificates verifies the result (§7).

**Trusted dealing.** A single operator who holds every share anyway (a development chain) MAY split a secret key `sk` itself: `a_0 = sk`, and for `k ≥ 1`, `a_k = hash_to_scalar(seed ‖ "deal" ‖ I2OSP(k, 4), DST_COEFFICIENT)` with `seed` 32 bytes of fresh randomness. The worked example of §9.2 uses this derivation. Validator sets use the DKG.

## 5. Key generation

The DKG is synchronous Joint-Feldman (Pedersen's DKG) with complaints. It is a pure state machine: each participant's machine consumes broadcast messages and phase boundaries and produces broadcast messages and, at the end, its output.

**Assumptions.** Senders are authenticated by the transport (the driver's signed consensus messages). Every honest participant processes the same messages in the same phase and ends each phase at the same point, as when the messages are carried in finalized blocks and phases end at fixed heights. Fewer than `t` participants are faulty (for a resharing, fewer than the previous threshold among the dealers). Under these assumptions every honest participant computes the same qualified set and the same public key set.

**Parameters**, identical at every participant: a 32-byte `session` unique to the run (a driver derives it from the chain id and the epoch); the threshold `t`; the number of dealers `D`, indexed `1..D`; the recipients' encryption keys `ek_1 … ek_N` (recipient `j` has index `j`); and, for a resharing, the previous public key set. `1 ≤ t ≤ N`, and `D` is at least 1 (for a resharing, at least the previous threshold).

**Encryption keys.** A recipient's decryption key is `dk = KeyGen(IKM, "SOLO-DKG-ENCRYPTION")` and its encryption key is `ek = dk · g1`, a G1 point other than the identity, registered before the run.

**Dealing.** Dealer `i` chooses a secret polynomial `f_i` of degree `t − 1` and an ephemeral scalar `e_i`, all uniformly random. The reference derivation from 32 bytes of fresh randomness `seed`, with `context_i = session ‖ I2OSP(i, 4)`, is `a_{i,k} = hash_to_scalar(seed ‖ context_i ‖ I2OSP(k, 4), DST_COEFFICIENT)` and `e_i = hash_to_scalar(seed ‖ context_i, DST_EPHEMERAL)`; other derivations do not affect anyone else. In a resharing `a_{i,0}` is instead the dealer's current share. The dealer computes

```
C_i   = (a_{i,0} · g2, …, a_{i,t−1} · g2)
R_i   = e_i · g1
pad_ij = hash_to_scalar(session ‖ I2OSP(i, 4) ‖ I2OSP(j, 4) ‖ encode(R_i) ‖ encode(e_i · ek_j), DST_PAD)
c_ij  = f_i(j) + pad_ij  (mod r)          for every recipient j
```

and broadcasts `Dealing { session, dealer: i, commitment: C_i, ephemeral: R_i, shares: (c_i1, …, c_iN) }`. Recipient `j` recovers its share as `s_ij = c_ij − pad_ij`, computing the shared point as `dk_j · R_i`. A pad is a one-time pad over `F_r`, used once per `(session, dealer, recipient)`; integrity comes from the Feldman check, not from the encryption.

**Phase 1, dealing.** A machine accepts a `Dealing` only in this phase, and only when its `session` matches, `1 ≤ dealer ≤ D`, it has no dealing from that dealer yet, the commitment has exactly `t` points and the shares exactly `N` scalars, every point and scalar decodes (§2), and, in a resharing, `C_{i,0}` equals the dealer's previous public key share. Anything else is rejected and changes nothing; a dealer without an accepted dealing is absent. At the end of the phase, each recipient `j` decrypts and Feldman-checks its share from every accepted dealing and, if any fails, broadcasts `Complaints { session, accuser: j, dealers }` listing those dealers.

**Phase 2, complaints.** A machine accepts the first `Complaints` from each recipient `1 ≤ accuser ≤ N` with a matching `session`, and records a complaint `(i, accuser)` for each listed dealer `i` with an accepted dealing; other listed indices are ignored. At the end of the phase, each dealer with recorded complaints broadcasts `Justification { session, dealer: i, shares }` revealing `f_i(j)` for every accuser `j`, in ascending order of `j`.

**Phase 3, justifications.** A machine accepts the first `Justification` from each dealer `1 ≤ dealer ≤ D` with a matching `session`. An entry `(j, s)` answers the complaint `(i, j)` when that complaint was recorded, `s` is a canonical scalar, and `s` passes the Feldman check against `C_i` at `j`; other entries are ignored. At the end of the phase every dealer with an unanswered complaint is disqualified, and an accuser whose complaint was answered takes the revealed share as `s_ij`.

**Output.** `QUAL` is the accepted dealers that were not disqualified, ascending. The run fails if `|QUAL|` is below `t` (for a resharing, below the previous threshold). Otherwise, for a fresh key

```
C   = Σ_{i ∈ QUAL} C_i   (point-wise)        s_j = Σ_{i ∈ QUAL} s_ij
```

and the new public key set is `C`, the group key `C_0`, recipient `j`'s share `s_j`. A recipient that holds no verified share from some qualified dealer (its complaint was not delivered) ends without a share; everyone else is unaffected.

**Messages.** On the wire, in the canonical encoding of 06 §2:

```
enum DkgMessage {
  0 Dealing       { session: [32], dealer: u32, commitment: vec<[96]>, ephemeral: [48], shares: vec<[32]> }
  1 Complaints    { session: [32], accuser: u32, dealers: vec<u32> }
  2 Justification { session: [32], dealer: u32, shares: vec<RevealedShare { recipient: u32, share: [32] }> }
}
```

**Security notes.** An honest dealer is never disqualified, so with fewer than `t` faulty participants `QUAL` contains an honest dealer and the group secret stays unknown. A falsely accused honest dealer reveals only the accuser's share. Joint-Feldman lets a faulty dealer bias the distribution of the group key by choosing whether to be disqualified; for threshold signatures this bias does not enable forgery (Gennaro, Jarecki, Krawczyk and Rabin, "Secure Applications of Pedersen's Distributed Key Generation Protocol", CT-RSA 2003), which is why the cheaper protocol is used, as drand does for its threshold BLS beacon. Pads are secure under the computational Diffie-Hellman assumption in G1 with the hash modelled as a random oracle; a recipient's decryption key opens every share ever sent to it, so validators rotate encryption keys with the validator set.

## 6. Resharing

A resharing hands an existing key to a new set of recipients, with a new threshold if desired, and keeps the group key. It is a run of §5 with the previous public key set given: the dealers are the previous shareholders, dealer `i` uses its current share `s_i` as `a_{i,0}`, and every machine rejects a dealing whose constant term is not `pk_i` of the previous set. With `λ_i` the Lagrange coefficients at zero over `QUAL` (§4),

```
C   = Σ_{i ∈ QUAL} λ_i · C_i        s'_j = Σ_{i ∈ QUAL} λ_i · s_ij
```

Because every `C_{i,0} = s_i · g2` and `|QUAL|` is at least the previous threshold, `C_0 = Σ λ_i · s_i · g2 = PK`: the group key is unchanged, so certificates from the new set verify under the key an Ethereum contract already holds. The new shares are a fresh sharing of the same secret; previous shareholders erase their old shares once the new set is active.

## 7. Certificates

**Message.** The message signed for the block with hash `block_hash` at `height` on the chain with id `chain_id` is 62 bytes:

```
message = "SOLO-FINALITY" (13 ASCII bytes) ‖ version (1 byte, 1) ‖ chain_id (u64) ‖ height (u64) ‖ block_hash (32 bytes)
```

**Format.** A version-1 certificate is 89 bytes:

```
certificate = version (1 byte, 1) ‖ height (u64) ‖ block_hash (32 bytes) ‖ signature (48 bytes, compressed G1)
```

A decoder MUST reject a first byte other than 1 (an unknown version), a length other than 89, and a signature that does not decode. A later signature scheme gets a new version byte, a new message tag and its own Ethereum verifier.

**Producing.** Each validator signs `message` with its share; any `t` partial signatures combine into the group signature (§4). The combiner verifies the combined signature before emitting the certificate, so an invalid partial never yields an invalid certificate; when that check fails, the driver verifies the partials one by one, drops the invalid ones and combines again.

**Verifying.** A certificate is valid for `chain_id` under the group key `PK` when its signature verifies (§3) over the message rebuilt from `chain_id`, its height and its block hash. Inside a kernel this is the host function `bls12381_verify` (05 §4.3) with arguments `message`, `DST_SIG`, the signature and `PK`.

**Relationship to 08.** A driver that adopts these certificates carries the 89 bytes in `FinalizeBlock.certificate`. Their first byte, 1, never equals the kind byte 2 that opens a spec 08 finalize certificate, so the two formats are distinguishable. A certificate does not say which validators signed; participation is recorded separately (ADR 0008).

## 8. Verification on Ethereum

A verifier contract for version 1 holds as constants the chain id, `PK` in EIP-2537 encoding (256 bytes), `−g2` in EIP-2537 encoding, `DST_SIG` and `p`. A relayer decodes a certificate and submits `height`, `block_hash` and the signature decompressed into EIP-2537 encoding (128 bytes). The contract:

1. builds `message` (§7), e.g. `abi.encodePacked(bytes13("SOLO-FINALITY"), uint8(1), chainId, height, blockHash)`;
2. computes `uniform = expand_message_xmd(message, DST_SIG, 128)` with the SHA-256 precompile (`0x02`): `b_0 = SHA-256(64 zero bytes ‖ message ‖ 0x0080 ‖ 0x00 ‖ DST_SIG ‖ 0x32)`, `b_1 = SHA-256(b_0 ‖ 0x01 ‖ DST_SIG ‖ 0x32)`, `b_i = SHA-256((b_0 ⊕ b_{i−1}) ‖ i ‖ DST_SIG ‖ 0x32)` for `i = 2, 3, 4`, `uniform = b_1 ‖ b_2 ‖ b_3 ‖ b_4`;
3. reduces each 64-byte half modulo `p` with MODEXP (`0x05`), input `I2OSP(64, 32) ‖ I2OSP(1, 32) ‖ I2OSP(48, 32) ‖ half ‖ 0x01 ‖ p`, and left-pads each 48-byte result with 16 zero bytes, giving `u_0`, `u_1`;
4. calls `BLS12_MAP_FP_TO_G1` (`0x10`) on `u_0` and on `u_1` and `BLS12_G1ADD` (`0x0b`) on the two results, giving `H(message, DST_SIG)` (the map precompile clears the cofactor, and cofactor clearing is linear, so map–map–add equals `hash_to_curve`);
5. calls `BLS12_PAIRING_CHECK` (`0x0f`) on `signature ‖ (−g2) ‖ H ‖ PK` (768 bytes) and accepts exactly when it returns 32 bytes ending in `0x01`. The precompile checks that the signature is on the curve and in the subgroup.

The BLS precompiles cost 114 275 gas; SHA-256 adds 516 and MODEXP 2 × 200 (2 × 500 once EIP-7883 is active). The reference contract of Appendix A spends 126 705 gas of execution per `verify` call on an Osaka EVM (spec 17 §8). ADR 0013 makes the verifier immutable per certificate version. Spec 17 builds the light client on it: a certificate signs a proposal hash, and the proposal's anchor carries the state root the certificate vouches for (17 §4).

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

## 10. Limits of this version

- The reference kernel's DKG (15 §6) carries messages in blocks, ends phases at fixed heights and adopts a key set only when more than two thirds of the stake confirm the same public outcome, which is how it checks that every participant derived the same key set. Partial signatures ride on finalize votes and are combined in the host's keystore (05 §4.3), natively, rather than in the interpreter.
- The threshold counts shareholders, not stake (15 §9).
- `bls12381_verify` covers this scheme only. Verifying the Ethereum consensus layer's signatures (keys in G1, signatures in G2) for the sync-committee light client of ADR 0013 needs its own host function.
- The DKG is synchronous; a run whose messages are not delivered to everyone alike can end with different outputs at different participants. In the reference kernel every participant reads the same messages from chain state, and a key set is adopted only once more than two thirds of the stake confirm it.

## Appendix A. Reference verifier (informative)

The reference verifier is `contracts/SoloFinalityVerifierV1.sol`, compiled by `tools/build-contracts.sh` with solc 0.8.28 (spec 17 §9). It follows §8 step by step: the constructor takes the chain id and `PK` in EIP-2537 encoding, checks the key with `BLS12_G2MSM` and keeps it in eight immutable words; `verify(height, blockHash, signature)` builds `message` with `abi.encodePacked`, expands it with five SHA-256 calls into four words, reduces each 64-byte half with MODEXP, maps both with `BLS12_MAP_FP_TO_G1`, adds them with `BLS12_G1ADD` and runs `BLS12_PAIRING_CHECK` on `signature ‖ −g2 ‖ H ‖ PK`. `crates/solo-bridge/tests/contracts.rs` runs it on revm at Osaka against the example of §9.1: `verify(1, 0xabab…ab, signature)` returns true for 126 705 gas of execution, and false for another height, block or chain id, a signature by another key, or a signature off the curve; a signature that is not 128 bytes reverts. An earlier draft of this appendix copied the halves of `uniform` byte by byte and spent 152 755 gas on a Prague EVM.
