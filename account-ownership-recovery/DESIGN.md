# Design: ZK Proof of Cardano Account Ownership via Seed-Derivation Knowledge

**Status:** Implemented and verified on-chain (2026-07-08)
**Motivation:** SecondFi (EMURGO) wallet exploit, June 2026
**Author:** ZeroJ team

> Prove you are the **real owner** of a Cardano address — because you know the seed/root
> key it was derived from — **without disclosing the seed phrase**, and even after an
> attacker has stolen the address's spending key.

This document explains the **problem** and **why the solution works** (the incident, the
owner/attacker knowledge asymmetry, the threat model, the ZK statement, and the security
analysis). For **how to run it** — the pipeline, commands, and measured numbers — see the
[README](./README.md). The original pre-implementation feasibility study (constraint
estimates, design alternatives, phased plan) is preserved in git history.

---

## Table of Contents

- [1. The Incident and Its Root Cause](#1-the-incident-and-its-root-cause)
- [2. The Core Insight: Owner vs. Attacker Knowledge](#2-the-core-insight-owner-vs-attacker-knowledge)
- [3. Problem Statement & Threat Model](#3-problem-statement--threat-model)
- [4. What We Prove (The ZK Statement)](#4-what-we-prove-the-zk-statement)
- [5. Cardano Key Derivation (What the Circuit Reproduces)](#5-cardano-key-derivation-what-the-circuit-reproduces)
- [6. The Implemented Solution](#6-the-implemented-solution)
- [7. Security Analysis & Limitations](#7-security-analysis--limitations)
- [Appendix A: Sources](#appendix-a-sources)

---

## 1. The Incident and Its Root Cause

**SecondFi** is EMURGO's rebrand (April 2026) of the **Yoroi** Cardano wallet. In June 2026
its web wallet was drained of **~16M ADA (~$2.4M) across 374 addresses**; SecondFi itself
swept a further **~129M ADA (~$18–20M)** from still-vulnerable wallets into custody as an
emergency white-hat measure.

**Root cause (per Tibane Labs forensics):** an experimental third-party signing SDK
(`trantor`, published to npm) replaced EMURGO's audited signer on **8 June 2026**. Its
Ed25519 signer **dropped the per-key secret ("prefix") that the standard mixes into each
signature's nonce.** In correct Ed25519 (RFC 8032):

```
seed --SHA512--> (s = clamped scalar) || (prefix = secret nonce material)
nonce   r = H(prefix ‖ M)        <-- secret BECAUSE prefix is secret
        R = r·B
        k = H(R ‖ A ‖ M)
        S = (r + k·s) mod L
signature = (R, S)
```

With the prefix dropped, the nonce collapsed to `r = H(M)` — computable by **anyone** from
the public transaction body. Then, from a **single** on-chain signature:

```
S = (r + k·s) mod L     with r, S, k = H(R‖A‖M) all public
  ⇒  s = (S − r) · k⁻¹  mod L        <-- the private spending scalar, recovered
```

No nonce *reuse*, no second transaction, no lattice attack — one signature leaked the key.
The wallet's default address (index 0), which usually has transaction history, was reliably
drainable. Ledger CTO Charles Guillemet summarized it: *"When the nonce is predictable, the
key is public."*

**What the attacker obtained:** the derived **private signing scalar** `s` (Cardano's `kL`
for that leaf address) — confirmed across all sources. SecondFi's own guidance: **do not
restore your recovery phrase into another wallet**, because the compromise "exists at the
address and private key level" and restoring "recreates identical addresses with identical
exposure." Signatures are therefore **worthless as proof of ownership** post-exploit — which
is exactly why SecondFi fell back to off-chain accounting-firm verification.

**This is the gap a ZK ownership proof fills.**

---

## 2. The Core Insight: Owner vs. Attacker Knowledge

The exploit leaked exactly one thing per compromised address: the leaf spending scalar
`kL_leaf`. Everything the owner uniquely knows lives **above** that leaf in the HD tree.

| Secret | Real owner has it? | Attacker has it? | Verifiable against public chain data? |
|--------|:---:|:---:|:---:|
| BIP39 mnemonic / entropy | ✅ | ❌ | Indirectly (derives to address) |
| Root extended key `(kL, kR, chainCode)` | ✅ | ❌ | Indirectly (derives to address) |
| Account / role intermediate ext. key | ✅ | ❌ | Indirectly (derives to address) |
| Chain codes of any node | ✅ | ❌ | ❌ (never on chain) |
| `kR_leaf` (nonce prefix) | ✅ | ❌ | ❌ (no public commitment) |
| **`kL_leaf` (leaf spending scalar)** | ✅ | **✅ (leaked)** | ✅ (`blake2b224(kL·B)` = address key hash) |
| Leaf public key `A_leaf = kL_leaf·B` | ✅ | ✅ | ✅ (revealed in any spent tx witness) |

**Consequence for proof design:**
- Proving knowledge of `kL_leaf` (a signature, or a hash preimage of it) is **useless** — the attacker can do it too.
- `kR_leaf` and chain codes are secret to the attacker but have **no public anchor**, so a bare "I know `kR`" claim is unfalsifiable (attacker could assert any value) — unusable without a pre-existing commitment.
- The **only** owner-exclusive secret that is *also* verifiable against public chain data is a **derivation ancestor** (root / account / role extended key). Verifying it requires **reproducing the derivation in-circuit** down to the leaf, whose public key hash is the address's payment credential.

Ancestor derivation is one-way with respect to the leaf: from `kL_leaf` you cannot recover
any parent `kL`, chain code, or `kR` (the child mixes in `HMAC-SHA512(chainCode, …)` which
the attacker never saw). So **"I know an ancestor that derives to this address"** is a clean
owner/attacker discriminator.

---

## 3. Problem Statement & Threat Model

**Goal.** Given a public Cardano address `addr` (equivalently its 28-byte payment key hash
`pkh`), let a claimant convince a verifier that they know the HD-wallet secret that derives
to `pkh`, **without revealing** that secret, in a way an attacker holding only `kL_leaf`
cannot forge.

**Assets & actors.**
- `pkh` — public (in the address; part of every UTxO at that address).
- `A_leaf`, `kL_leaf` — public post-exploit (revealed in tx witnesses / leaked by the bug).
- Witness (secret): the root extended key `(kL, kR, chainCode)`.

**Adversary capabilities (this exploit).**
1. Holds `kL_leaf` (can sign arbitrary messages/txs as the address).
2. Can observe any proof the owner publishes (so proofs must be **replay-bound**).
3. Does **not** hold the mnemonic, root/intermediate keys, chain codes, or `kR`.

**Adversary capabilities we do NOT defend against (out of scope).**
- An attacker who also stole the mnemonic/root key (not this exploit) — indistinguishable from the owner by *any* method.
- Addresses not produced by standard CIP-1852 HD derivation (e.g. raw/script keys) — no ancestor to prove.

**Security goals.**
- **Soundness:** only a party holding a valid ancestor witness can produce an accepting proof.
- **Zero-knowledge:** the proof reveals nothing about the mnemonic/ancestor key beyond "it derives to `pkh`".
- **Replay/front-running resistance:** a proof is bound to a fresh challenge (off-chain) or the spending transaction context (on-chain), so an observing attacker cannot reuse it.

---

## 4. What We Prove (The ZK Statement)

As implemented ([`OwnershipProof`](src/main/java/com/bloxbean/cardano/zeroj/usecases/recovery/circuit/OwnershipProof.java)),
the circuit proves:

> "I know a root extended key `(kL, kR, chainCode)` such that applying BIP32-Ed25519
> derivation along the full CIP-1852 path `m/1852'/1815'/0'/0/0` yields a leaf public key
> whose `blake2b-224` hash equals the public payment key hash `pkh` of the target address."

- **Public inputs:** `pkh` — the 28 payment-key-hash bytes (one field element per byte;
  carried as the datum of the on-chain gate).
- **Private witness:** the root extended key `(kL, kR, chainCode)`.
- **Anchor level:** the **root key** — the strongest claim (control of the whole wallet,
  not just one branch). The mnemonic itself is *not* the anchor: the PBKDF2 (4096-iteration)
  mnemonic→root step is ~1.26B constraints and infeasible in-circuit; the root key is the
  highest practical anchor and is exactly what the attacker lacks.
- **Replay binding:** the demo validator checks the proof against the datum-pinned `pkh`
  only; a production validator must additionally bind the **transaction context**
  (`ScriptContext`/TxOutRef) so an observed proof cannot be replayed in a different
  transaction (see §7).

---

## 5. Cardano Key Derivation (What the Circuit Reproduces)

Cardano wallets (Yoroi/Yaci/Daedalus Shelley, "Icarus") use:

1. **Mnemonic → root key (Icarus / CIP-3):**
   `PBKDF2-HMAC-SHA512(password = passphrase, salt = entropy, iterations = 4096, dkLen = 96)`
   then bit-clamping → root `(kL 32B, kR 32B, chainCode 32B)`.
   *(Note: Cardano uses the **entropy** with **4096** iterations, not the BIP39 64-byte seed.)*

2. **CIP-1852 path** `m / 1852' / 1815' / account' / role / index`
   (`role`: 0 = external/payment, 1 = internal/change, 2 = staking).
   Payment credential of a base/enterprise address = `blake2b-224(A)` where
   `A = kL_leaf · B` (Ed25519 basepoint `B`) at `1852'/1815'/account'/0/index`.

3. **BIP32-Ed25519 child derivation** (Khovratovich–Law), per step from parent `(kL,kR,cc)` to child `i`:
   - **Hardened** (`i ≥ 2³¹`, uses the private key, **no EC op**):
     `Z = HMAC-SHA512(cc, 0x00 ‖ kL ‖ kR ‖ LE32(i))`,
     `cc_child = HMAC-SHA512(cc, 0x01 ‖ kL ‖ kR ‖ LE32(i))[32:]`
   - **Soft** (`i < 2³¹`, uses the parent **public** key `A = kL·B` → **needs one scalar mult**):
     `Z = HMAC-SHA512(cc, 0x02 ‖ A ‖ LE32(i))`,
     `cc_child = HMAC-SHA512(cc, 0x03 ‖ A ‖ LE32(i))[32:]`
   - `kL_child = 8·(Z_L[0:28] as LE int) + kL`, &nbsp; `kR_child = (Z_R as LE int) + kR (mod 2²⁵⁶)`

**Cost anatomy per step:** each step = **2 HMAC-SHA512 calls** (`Z` and `cc_child`);
each HMAC-SHA512 over ≤128-byte data ≈ **4 SHA-512 compressions** → **~8 SHA-512
compressions per derivation step**. The three hardened steps (`1852'`,`1815'`,`account'`)
need **no** EC ops; the two soft steps (`role`,`index`) **each** need a fixed-base Ed25519
scalar mult to form the parent public key `A`; forming the leaf public key for the
address needs one more.

All of this — SHA-512, HMAC-SHA512, Blake2b-224, the `GF(2^255−19)` field, Ed25519 point
arithmetic, and the composed derivation — is implemented as native ZeroJ symbolic gadgets
(**ADR-0027**) over the BLS12-381 scalar field, each differentially validated against
JCA/BouncyCastle/cardano-client-lib.

---

## 6. The Implemented Solution

| Aspect | As built |
|---|---|
| Circuit | [`OwnershipProof`](src/main/java/com/bloxbean/cardano/zeroj/usecases/recovery/circuit/OwnershipProof.java) — **19,075,097 constraints** (3 hardened + 2 soft derivation steps + leaf pubkey + blake2b-224, in-circuit; ~90M naive, reduced by ADR-0028 windowing/lazy-reduction) |
| Proof system / curve | **Groth16 over BLS12-381** — the Cardano-native curve (CIP-0381), so the same proof verifies off-chain (pure Java) and on-chain (Plutus V3) |
| Prover | ZeroJ's own prover (ADR-0029): one-time trusted setup **~47 min**, proving key persisted (**~23 GB**, `Groth16PkStore`) and mmap'd back in ~2 min; **~2 min per proof** (blst FFM backend, multi-core; pure-Java multi-core also works). Peak ~70 GB heap on a 12-core/128 GB box |
| On-chain gate | [`OwnershipProofValidator`](src/main/java/com/bloxbean/cardano/zeroj/usecases/recovery/onchain/OwnershipProofValidator.java) — a 1 KB Julc/Plutus V3 validator parameterized with the circuit's verification key; datum = the 28 `pkh` bytes; redeemer = the proof |
| Measured on-chain cost | **fee ≈ 0.95 ADA** on Yaci DevKit (tx `73495f35b390caaa62e407a9b97865ca7d04a40ebf12ac3a2ad2f3d74a259703`) — **independent of the circuit's 19M constraints** (Groth16 verification is O(#public inputs)) |
| Flow | Lock a gate UTxO with `datum = pkh` → claimant proves the derivation from their root key → unlock with the proof; the validator verifies it on-chain. A recovery contract can then act on the unlocked gate (release escrowed funds, rotate rights, …) |

The recovery *policy* — what an accepted proof authorizes, challenge periods, escrow
mechanics — is deliberately out of scope; the gate provides the trustless **authorization
primitive**.

---

## 7. Security Analysis & Limitations

**What the proof guarantees.**
- **Soundness:** only a holder of a valid root-key witness produces an accepting proof; the attacker (with only `kL_leaf`) cannot, because `kL_leaf` does not reveal any ancestor key/chain code.
- **Zero-knowledge:** reveals nothing about the mnemonic/root key beyond "derives to `pkh`".
- **Address binding:** the proof only verifies against the datum-pinned `pkh` (the circuit's public inputs).

**What it does NOT do (state these plainly to users).**
1. **It is not fund recovery by itself.** It *authorizes* a recovery mechanism (off-chain attestation, or an on-chain vault/owner-NFT). Who honors the proof and how funds move is a separate governance/protocol decision. For already-drained funds, nothing on-chain can claw them back; this proves ownership for **remaining** assets or for an off-chain reimbursement process.
2. **It cannot distinguish owner from an attacker who also stole the mnemonic.** This exploit did **not** leak the mnemonic, so the mechanism fits; a future seed-phrase phishing would defeat it (as it defeats everything).
3. **Only standard CIP-1852 HD addresses** have an ancestor to prove. Raw/script/hardware-derived-differently keys need a different anchor.
4. **Trusted setup.** Groth16 requires a per-circuit trusted setup; a compromised setup breaks soundness. The in-repo setup is **single-party, dev-only** — production needs an MPC ceremony for this circuit.
5. **Replay binding is a production gate.** The demo validator does not bind `ScriptContext`; production must (ZeroJ's `Groth16BLS12381TxOutRefBindingVerifier` pattern) so an observed proof cannot be lifted into another transaction.
6. **The gadget suite is not yet externally audited.** The ADR-0027 in-circuit primitives (SHA-512/HMAC/Blake2b/Ed25519/BIP32 over BLS12-381) are differentially tested against JCA/BouncyCastle/cardano-client-lib, but an independent circuit audit (under-constrained-signal review) is mandatory before real value depends on this. ZeroJ's hint-based optimizations stay disabled by default pending that audit (the deterministic path is used).

**Attack surface to watch.**
- Under-constrained circuit signals → forgeable proofs. Independent circuit audit before production.
- Proof replay → enforce single-use challenges off-chain and TxOutRef binding on-chain.
- Big-int reductions (`mod 2²⁵⁶`, `mod r`) must be range-checked (255-bit field caveat on BLS12-381).

---

## Appendix A: Sources

**Exploit (SecondFi / EMURGO, June 2026):**
- SecondFi incident report — https://kb.secondfi.io/en/article/security-incident-update-dxv72a/
- The Block (Tibane Labs / `trantor` SDK) — https://www.theblock.co/post/406457/
- CoinDesk — https://www.coindesk.com/business/2026/06/24/
- Bitquery on-chain investigation — https://bitquery.io/investigations/cardano-secondfi-129m-drain
- AMBCrypto (private-key-level compromise, seed warning) — https://ambcrypto.com/cardano-wallet-exploit-secondfi-traces-attack-to-private-key-flaw/
- Charles Guillemet (Ledger CTO) thread — https://x.com/P3b7_/status/2070121675102863721

**Cardano on-chain ZK:**
- CIP-0381 (BLS12-381 builtins, mainnet since Chang) — https://cips.cardano.org/cip/CIP-0381
- IntersectMBO plutus-benchmark Groth16 example — IntersectMBO/plutus

**Key-derivation standards:**
- BIP32-Ed25519 (Khovratovich–Law) — hierarchical deterministic keys over a non-linear keyspace
- CIP-1852 (`m/1852'/1815'/…`) & CIP-3 (Icarus master key, PBKDF2 4096 iters)

**ZeroJ:**
- ADR-0027 — in-circuit SHA-512 / HMAC / Blake2b / Ed25519 / BIP32 gadgets
- ADR-0028 — DSL optimization (windowing, lazy reduction) & hint soundness
- ADR-0029 — Groth16 prover performance (memory, mmap'd proving key, multi-core, blst)
