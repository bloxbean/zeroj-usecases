# Design & Feasibility: ZK Proof of Cardano Account Ownership via Seed-Derivation Knowledge

> **Status update (2026-07-08):** implemented. The full-derivation ownership proof (the primary
> design) is practical — 19,075,097 constraints, ~47 min one-time setup, ~2 min per proof
> (ADR-0029), **verified on-chain** (Yaci DevKit, fee ≈ 0.95 ADA). The §14 proactive-commitment
> (Poseidon) stand-in was implemented first, then **removed** once the real derivation gate landed;
> §14 remains below as design history. See the [README](./README.md) for the working end-to-end.

**Status:** Implemented (see status update above)
**Motivation:** SecondFi (EMURGO) wallet exploit, June 2026
**Author:** ZeroJ team
**Date:** 2026-07-06

> Prove you are the **real owner** of a Cardano address — because you know the seed/root
> key it was derived from — **without disclosing the seed phrase**, and even after an
> attacker has stolen the address's spending key.

---

## Table of Contents

- [1. Executive Summary & Verdict](#1-executive-summary--verdict)
- [1a. Measured Outcomes vs. Design Estimates (2026-07-08)](#1a-measured-outcomes-vs-design-estimates-2026-07-08)
- [2. The Incident and Its Root Cause](#2-the-incident-and-its-root-cause)
- [3. The Core Insight: Owner vs. Attacker Knowledge](#3-the-core-insight-owner-vs-attacker-knowledge)
- [4. Problem Statement & Threat Model](#4-problem-statement--threat-model)
- [5. What We Prove (The ZK Statement)](#5-what-we-prove-the-zk-statement)
- [6. Cardano Key Derivation (What the Circuit Must Reproduce)](#6-cardano-key-derivation-what-the-circuit-must-reproduce)
- [7. Feasibility Analysis (Measured Constraint Counts)](#7-feasibility-analysis-measured-constraint-counts)
- [8. Design: Circuit Variants & Anchoring Levels](#8-design-circuit-variants--anchoring-levels)
- [9. Off-Chain Verification Design](#9-off-chain-verification-design)
- [10. On-Chain Verification Design](#10-on-chain-verification-design)
- [11. Curve & Prover Decision Matrix](#11-curve--prover-decision-matrix)
- [12. What ZeroJ Provides Today vs. What Must Be Built](#12-what-zeroj-provides-today-vs-what-must-be-built)
- [13. Security Analysis & Limitations](#13-security-analysis--limitations)
- [14. Alternative: Proactive Commitment (Prevention, Not Recovery)](#14-alternative-proactive-commitment-prevention-not-recovery)
- [15. Implementation Plan (Phased)](#15-implementation-plan-phased)
- [16. Recommendation](#16-recommendation)
- [Appendix A: Sources](#appendix-a-sources)

---

## 1. Executive Summary & Verdict

**Yes — a zero-knowledge proof of Cardano account ownership is cryptographically sound and
technically feasible for this scenario, and it works because of a precise asymmetry the
exploit left behind.** The attacker recovered the address's *derived spending scalar*
(`kL`), but **not** the BIP39 mnemonic, root key, chain codes, or the `kR` nonce prefix.
Because plain message-signing uses only `kL` — which the attacker now has — signatures
**cannot** distinguish owner from attacker. A ZK proof of knowledge of a **secret higher in
the derivation tree** (which the attacker provably lacks) can.

| Question | Verdict |
|----------|---------|
| Is the idea cryptographically sound? | **Yes** — proving knowledge of an ancestor derivation key that the attacker cannot possess is a valid owner/attacker discriminator. |
| Prove from the **mnemonic** (seed phrase → root, PBKDF2 4096 iters)? | **No.** ~1.26 **billion** R1CS constraints. Infeasible in any current SNARK; no one has ever proven PBKDF2/BIP39 in ZK. |
| Prove from the **root / intermediate extended key**? | **Yes, but heavy.** ~1.8M–6.9M constraints depending on anchor level. Buildable; needs `snarkjs` proving (minutes, tens of GB RAM). |
| **Off-chain** verification (recovery portal)? | **Ready path.** ZeroJ verifies Groth16 over **BLS12-381** in pure Java today — the *same* proof that verifies on-chain. |
| **On-chain** verification (trustless recovery contract)? | **Feasible.** ZeroJ's Julc `Groth16BLS12381Verifier` verifies BLS12-381 Groth16 on Plutus V3 (~20–29% CPU, proven E2E). On-chain cost is **independent of circuit size**. |
| Which curve? | **BLS12-381 only** — the Cardano-native curve (ADR-0016 doctrine). One proof serves both off-chain and on-chain. **No BN254 path** (a BN254 proof can never be promoted on-chain). |
| Which circuit authoring path? | **ZeroJ symbolic DSL with new native gadgets ([ADR-0027](../../zeroj/docs/adr/0027-real-world-crypto-gadgets-sha512-hmac-blake2b-ed25519.md))** as the strategic target; circom-on-BLS12-381 available as an early spike. See §11–§12. |
| Biggest technical risks | (1) authoring/auditing a **non-native Ed25519 + SHA-512 + Blake2b gadget suite** over the BLS12-381 field (ADR-0027); (2) **scaling ZeroJ's Groth16 prover** to ~2M–7M constraints. |

**Recommended first deliverable:** an **off-chain recovery-portal PoC** using the lighter
"recovery-mode" circuit (see §8) on **BLS12-381**, so the exact same proof artifact later
verifies on-chain unchanged. The heavy primitives (SHA-512/HMAC/Blake2b/Ed25519) are built
as **native ZeroJ symbolic gadgets** under ADR-0027 — a reusable core-library investment,
not a throwaway.

## 1a. Measured Outcomes vs. Design Estimates (2026-07-08)

What was actually built, and how the measurements compare to the estimates in the rest of this
document (which are kept unedited as design history):

| Design-time estimate / plan | Measured / actual outcome |
|---|---|
| Anchor level: role-anchor Mode A first (~1.8M), full path later | **Root-key anchor, full `m/1852'/1815'/0'/0/0` path to pkh (Mode B)** built directly — the strongest statement |
| Circuit size ~1.8M–6.9M (anchor-dependent); full path "~90M naive" | **19,075,097 constraints** measured (ADR-0028 windowing + lazy reduction; hints off) |
| "Needs `snarkjs` proving (minutes, tens of GB RAM)" | **ZeroJ's own prover** — no snarkjs: setup **~47 min one-time** (proving key persisted, 23 GB, `Groth16PkStore`), then **~2 min per proof** (blst FFM backend, multi-core; ADR-0029), peak ~70 GB heap on a 12-core/128 GB box |
| Risk: "ZeroJ prover doesn't scale past ~4k-proven circuits" (top risk, High) | **Resolved** — ADR-0029 (flat/mmap/parallel + blst): the 19M circuit proves end-to-end on one JVM |
| On-chain verification "feasible, ~20–29% CPU" | **Done on Yaci DevKit**: `OwnershipProofValidator` (Julc Plutus V3, 1 KB script) verified the real derivation proof — **fee ≈ 0.95 ADA**, tx `73495f35b390caaa62e407a9b97865ca7d04a40ebf12ac3a2ad2f3d74a259703`; cost independent of circuit size (28 pkh-byte public inputs) |
| §14 proactive-commitment (Poseidon) as the practical on-chain gate | **Superseded and removed** — the real derivation gate is practical; §14 remains as design history |
| Curve / authoring path | As designed: **BLS12-381 only**, **ZeroJ symbolic gadgets** (ADR-0027), Groth16 |

Remaining production gates (unchanged from design): MPC trusted-setup ceremony for the 19M circuit,
`ScriptContext` binding in the validator (anti-replay), and the recovery *policy* layer.

---

## 2. The Incident and Its Root Cause

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

## 3. The Core Insight: Owner vs. Attacker Knowledge

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
- Proving knowledge of `kL_leaf` (a signature, or a Poseidon preimage of it) is **useless** — the attacker can do it too.
- `kR_leaf` and chain codes are secret to the attacker but have **no public anchor**, so a bare "I know `kR`" claim is unfalsifiable (attacker could assert any value). Unusable *without a pre-existing commitment* (see §14).
- The **only** owner-exclusive secret that is *also* verifiable against public chain data is a **derivation ancestor** (root / account / role extended key). Verifying it requires **reproducing the derivation in-circuit** down to the leaf, whose public key hash is the address's payment credential.

Ancestor derivation is one-way with respect to the leaf: from `kL_leaf` you cannot recover
any parent `kL`, chain code, or `kR` (the child mixes in `HMAC-SHA512(chainCode, …)` which
the attacker never saw). So **"I know an ancestor that derives to this address"** is a clean
owner/attacker discriminator.

---

## 4. Problem Statement & Threat Model

**Goal.** Given a public Cardano address `addr` (equivalently its 28-byte payment key hash
`pkh`), let a claimant convince a verifier that they know the HD-wallet secret that derives
to `pkh`, **without revealing** that secret, in a way an attacker holding only `kL_leaf`
cannot forge.

**Assets & actors.**
- `pkh` — public (in the address; part of every UTxO at that address).
- `A_leaf`, `kL_leaf` — public post-exploit (revealed in tx witnesses / leaked by the bug).
- Witness (secret): an ancestor extended key `(kL, kR, chainCode)` + derivation indices.

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

## 5. What We Prove (The ZK Statement)

Informally, the circuit proves:

> "I know an extended private key `(kL_a, kR_a, cc_a)` at derivation node `a` of the
> CIP-1852 path `m/1852'/1815'/account'/role/index`, and the remaining indices, such that
> applying BIP32-Ed25519 derivation from `a` down to the leaf yields a public key whose
> `blake2b-224` hash equals the public payment key hash `pkh` of the target address —
> and this proof is bound to challenge `c`."

Public inputs / outputs (exact set depends on variant, see §8):
- `pkh` (28 bytes → 1 field element) **or** `kL_leaf` (256 bits → 2 field elements, recovery-mode).
- `challenge` `c` (1 field element) — freshness/replay binding.
- (optional) `accountIndex`, `role`, `index` if they should be publicly pinned.

Private witness:
- Ancestor extended key `(kL_a, kR_a, cc_a)`.
- Derivation indices for each remaining step.

---

## 6. Cardano Key Derivation (What the Circuit Must Reproduce)

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

---

## 7. Feasibility Analysis (Measured Constraint Counts)

All figures are **non-linear R1CS constraints**, measured by compiling the referenced
circom circuits (circom 2.2.3 + `snarkjs r1cs info`), unless noted. See Appendix A.

### 7.1 Primitive costs

| Primitive | Constraints | Source |
|-----------|-------------|--------|
| SHA-512, per 1024-bit block | **~66k–77k** (bkomuves 66k; Electron-Labs 77k; solarity 82.5k) | measured |
| Ed25519 **scalar mult** (generic, **no fixed-base opt.**) | **~1.23M** each | measured (Electron-Labs) |
| Ed25519 full signature verify | ~2.56M | Electron-Labs README |
| Blake2b, per 128-byte block | **~77k** (blake2b-256; **-224 not yet implemented**, trivial adapt) | measured (bkomuves) |
| PBKDF2-HMAC-SHA512, Icarus (4096 iters × 2 blocks × ~2 compressions ≈ 16,384 compressions) | **~1.26 BILLION** | derived |

### 7.2 The mnemonic wall (hard no)

Reproducing `mnemonic → root key` in-circuit is **~1.26 billion constraints** — larger than
the biggest public powers-of-tau (`2²⁸ ≈ 268M`). BIP39's own 2048-iter PBKDF2 (~316M) is
also hopeless. **No ZK system has ever proven PBKDF2-with-thousands-of-iterations or BIP39.**
The closest working precedent (`roasbeef/bip32-pq-zkp`, RISC Zero, Oct 2026) **deliberately
starts from the 64-byte seed and skips PBKDF2** — 6 HMAC-SHA512 + 2 SHA-256 took ~55s on an
M4 Max. zkVMs (SP1/RISC Zero) have **no SHA-512 precompile** and wrap to **BN254** Groth16,
which Cardano's BLS12-381 builtins **cannot** verify.

➡️ **Take the root key (or an intermediate extended key) as the private witness. Never the mnemonic.**

### 7.3 From-key circuit totals (buildable)

| Anchor (witness) | Soft steps to leaf | SHA-512 compressions | Ed25519 scalar mults | ~Total constraints |
|------------------|:---:|:---:|:---:|:---:|
| **Root** `(kL,kR,cc)` | full path (3 hardened + 2 soft) | ~40 (~3.1M) | 3 (leaf pubkey incl.) → ~3.7M | **~6.9M** |
| **Account** `account'` node | role, index (+ leaf pubkey) | ~16 (~1.2M) | 2–3 → ~2.5–3.7M | **~3.7M–5M** |
| **Role** `1852'/1815'/acct'/0` node | index only | ~8 (~0.6M) | 1–2 → ~1.2–2.5M | **~1.8M (recovery) – ~3.1M (general)** |

Notes:
- **On-chain verification cost is independent of these numbers** — it depends only on the
  proof system (Groth16) and public-input count. A 6.9M-constraint circuit still verifies
  in ~4 pairings on Plutus V3 (§10). The entire cost is **off-chain proving**.
- The **Ed25519 scalar mult dominates.** The published circom gadget has **no fixed-base
  optimization** even though `B` is constant; a windowed fixed-base gadget (to be built)
  could cut ~1.23M substantially — a high-value optimization.

### 7.4 Proving performance & tooling reality

- **`--prime bls12381` (circom) and Groth16 over BLS12-381 (snarkjs): confirmed working**; ptau up to `2²⁸`.
- **rapidsnark is BN254-only** — no fast prover exists for BLS12-381. On BLS12-381 you are on
  **snarkjs (wasm)**: estimate **~0.5–5 min/proof + a BLS12-381 penalty, tens of GB Node heap**
  at 2²²–2²³ (no published benchmark — plan conservatively). Browser proving at this size is out.
- **circomlib is not safely portable to the 255-bit BLS12-381 field** as-is (`CompConstant`,
  `*_strict` bit-decomposition, Poseidon/EdDSA constants are BN254-specific). The Ed25519
  circom circuit is **BN254-native and unaudited (archived Mar 2025, alleged under-constrained
  signals)**. **Compiling it over BLS12-381 is unverified by anyone** — this is the single
  biggest R&D unknown.
- **BLS12-381 powers-of-tau:** none hosted by snarkjs (its table is BN254-only). Zcash Sapling
  (2²¹) and Filecoin (2²⁷) ceremonies exist but there is **no public converter** to snarkjs
  `.ptau`. Self-generated works to `2²⁸` but a solo ceremony is **not trustless** → for
  production you need an MPC ceremony (a known ZeroJ gap, see [production-readiness review]).

---

## 8. Design: Circuit Variants & Anchoring Levels

Two orthogonal knobs: **(a) anchor level** (root / account / role — strength vs. size, §7.3)
and **(b) address-binding mode** (recovery vs. general). Address-binding mode is the key
lever for both circuit size and where verification happens.

### Mode A — Recovery mode (`kL_leaf` is public; lightest)

Applicable **when `A_leaf`/`kL_leaf` are already public** (post-exploit, or any address that
has spent at least once, revealing its vkey). We **do not** derive the leaf public key or
hash the address inside the circuit — those are public facts checked cheaply **outside** it.

- **Public IO:** `kL_leaf` (2 field elements), `challenge`.
- **Circuit proves:** ancestor `(kL_a,kR_a,cc_a)` soft/hardened-derives to **this** `kL_leaf`.
- **Verifier checks outside the circuit** (plain Ed25519 + blake2b in Java): `blake2b224(kL_leaf·B) == pkh(addr)`.
- **Cost:** role-anchor ≈ **~1.8M** (one soft step: `A_role=kL_role·B` + 2 HMAC-SHA512). No leaf pubkey mult, no in-circuit blake2b.
- **Best for:** the **off-chain recovery portal** (§9). Smallest circuit → the natural first target on BLS12-381.

### Mode B — General mode (`pkh` is the public output; on-chain-friendly)

Applicable to **any** address (including never-spent ones, where only `pkh` is public) and
required for **on-chain** binding (Plutus has no Ed25519 scalar-mult builtin, so the leaf
pubkey→pkh step must live inside the proof).

- **Public IO:** `pkh` (1 field element), `challenge`.
- **Circuit proves:** ancestor derives to leaf, computes `A_leaf = kL_leaf·B`, `pkh = blake2b224(A_leaf)`; `kL_leaf` stays **secret**.
- **Cost:** role-anchor ≈ **~3.1M** (adds leaf-pubkey scalar mult + in-circuit blake2b-224 vs. Mode A).
- **Best for:** the **on-chain recovery contract** (§10). Public input is a 28-byte hash the validator compares to the address credential — trivial and cheap on-chain.

### Anchor-level guidance

- **Role-level anchor** is the sweet spot for a first PoC (smallest circuit). It is a valid
  discriminator here because the attacker cannot derive the role key from `kL_leaf`.
- **Root-level anchor** is the strongest ownership statement (proves control of the whole
  wallet) and is what a production recovery flow should ultimately use; ~6.9M constraints.
- Present the anchor level as a **configurable depth** so the same circuit template scales
  from PoC (role) to production (root).

### Freshness / nullifier

Bind `challenge` into the proof (Groth16 public inputs are non-malleable, so a proof for
`c1` will not verify against `c2`). Optionally emit `nullifier = Poseidon(kL_a, challenge)`
as a public output for one-time-use tracking, reusing ZeroJ's `NullifierClaimVerifier`
(off-chain) or the sorted-linked-list nullifier registry pattern (on-chain, per
`nft-ownership`).

---

## 9. Off-Chain Verification Design

The **recovery portal** — a Spring Boot backend (mirroring `proof-of-reserves` /
`nft-ownership` conventions) that a wallet vendor, exchange, or recovery service runs.

```
┌──────────────────────────────────────────────────────────────┐
│  CLAIMANT (browser / wallet)                                  │
│   1. Enters address to recover                                │
│   2. Provides mnemonic/root key LOCALLY (never leaves device) │
│   3. Fetches challenge, generates ZK proof locally            │
│   4. Submits (proof, publicInputs) — NOT the secret           │
└───────────────────────┬──────────────────────────────────────┘
                        │ REST
                        ▼
┌──────────────────────────────────────────────────────────────┐
│  RECOVERY BACKEND (Spring Boot, Java 25)                      │
│   • ChallengeService  — issues fresh nonce, TTL, single-use   │
│   • VerifierService   — ZeroJ VerifierOrchestrator.verify()   │
│   • AddressBindingSvc — blake2b224(kL_leaf·B) == pkh (Mode A)  │
│                         via cardano-client-lib (host Ed25519)  │
│   • NullifierClaimVerifier — replay protection                │
└──────────────────────────────────────────────────────────────┘
```

**Proving happens on the claimant's device** (snarkjs/rapidsnark + witness generator);
the secret never touches the network. The backend only **verifies**, which is ZeroJ's
core strength: `VerifierOrchestrator.verify(ZkProofEnvelope)` routes to the Groth16
verifier by `(proofSystem, curve)` and returns a `VerificationResult`.

**Flow:**
1. `GET /challenge?addr=…` → `{ challenge, ttl }` (bound to `addr`, single-use).
2. Claimant loads the address's `pkh` (and, Mode A, the leaked `kL_leaf`/`A_leaf`) from chain.
3. Claimant runs the circuit locally → `{ proof, publicInputs }`.
4. `POST /verify` → backend:
   - `VerifierOrchestrator.verify(...)` (cryptographic validity),
   - checks `challenge` is live + matches, marks it used,
   - Mode A: recomputes `blake2b224(kL_leaf·B)` with cardano-client-lib and checks `== pkh`,
   - `NullifierClaimVerifier.verifyAndAccept(nullifier)`.
5. On success → issue a signed recovery attestation / unlock the off-chain recovery step.

**Why this is the first build:** Mode A is the smallest circuit (~1.8M) and needs no
in-circuit address hashing. Built on **BLS12-381** (per §11), the same proof artifact later
drops into the on-chain contract unchanged — no second circuit, no second trusted setup.
The cost of committing to BLS12-381 (rather than a throwaway BN254 shortcut) is that proving
runs on ZeroJ's own BLS12-381 prover / snarkjs, which is heavier — hence the prover-scale
benchmark is on the critical path (ADR-0027 M7).

---

## 10. On-Chain Verification Design

For a **trustless, on-chain recovery gate** (a Plutus V3 contract that authorizes a recovery
action only against a valid ownership proof), use **Mode B + BLS12-381**.

**ZeroJ already ships the verifier.** `zeroj-onchain-julc`'s `Groth16BLS12381Verifier`
(`@SpendingValidator`) bakes the verification key as `@Param`, supports **arbitrary
public-input count** (`vk_x = IC[0] + Σ pubᵢ·IC[i+1]`), and runs the pairing check with
Plutus V3 BLS12-381 builtins (`bls12_381_millerLoop`, `finalVerify`). Proven end-to-end on
Yaci DevKit.

**Measured budget (prior art + ZeroJ estimator):** Groth16/BLS12-381 verify ≈ **~2.0–2.9B
CPU (~20–29% of the 10B mainnet limit)**, memory **< 0.5%**, ≤ **3 proofs per tx**. Public
inputs are plain `Integer`s in the redeemer/datum. **Fits mainnet comfortably**, and — the
crucial point — **this cost is the same whether the circuit is 10k or 7M constraints.**

```
Recovery transaction:
  Redeemer: { piA, piB, piC (compressed BLS12-381), publicInputs = [pkh, challenge] }
  Datum:    { addressBeingRecovered / pkh, recoveryPolicy }
  Context:  spends a recovery-vault UTxO / mints a "verified-owner" token

  Validator (Julc):
    1. Groth16BLS12381Lib.verify(vk@Param, proof, publicInputs)      // ZK soundness
    2. publicInputs.pkh == datum.pkh                                  // binds proof→address
    3. challenge bound to THIS tx (see below)                         // anti-replay
    4. authorize recovery action (mint owner-NFT / release vault)
```

**Replay / front-running.** An attacker can observe the owner's proof in the mempool. Bind
the proof to the spending transaction so it cannot be lifted into another tx: reuse ZeroJ's
`Groth16BLS12381TxOutRefBindingVerifier` pattern, which forces a public input to equal
`blake2b_256(txId ‖ index) mod r` of a consumed input. The attacker cannot reconstruct the
proof for a different `txId` because they lack the witness. *(Note: the shipped non-binding
validators ignore `ScriptContext` — promoting the tx-binding validator to main is a tracked
ZeroJ P0; this use case depends on it.)*

**Address-credential nuance.** `pkh` is 28 bytes = 224 bits < 254, so it fits a single field
element and maps directly to the address's payment credential — clean on-chain comparison.

---

## 11. Curve & Authoring-Path Decision

### Curve: BLS12-381 only (settled)

Earlier drafts floated BN254 for a fast off-chain-only PoC (rapidsnark is BN254-only; the
public Ed25519 circom circuit is BN254-native). **That is rejected.** It contradicts ZeroJ's
own curve doctrine (**ADR-0016**: BabyJubJub/BN254 "inside a Cardano-verifiable SNARK … no
Plutus builtin; unverifiable on Cardano") and it forks the work into two circuits, two
trusted setups, and two verification keys — a BN254 proof can *never* be promoted on-chain.
**BLS12-381 is the standard on Cardano; we commit to it for both paths.** One proof artifact
verifies off-chain (ZeroJ pure-Java `Groth16BLS12381Verifier`) *and* on-chain (Julc
`Groth16BLS12381Verifier`).

The honest cost of this choice: we forgo the BN254 rapidsnark shortcut, so proving is heavier
(no fast native prover exists for BLS12-381), making **prover scaling** (ADR-0027 §6/M7) a
first-class task rather than something a BN254 detour could have hidden. That trade is worth
it — the detour produced a dead-end artifact.

### Off-chain vs on-chain: same curve, different binding mode & trust model

| Dimension | Off-chain portal (first) | On-chain contract |
|-----------|--------------------------|-------------------|
| Curve | **BLS12-381** | **BLS12-381** |
| Binding mode | Mode A (`kL_leaf` public, address bound in Java) | Mode B (`pkh` is the public output) |
| Circuit size (role anchor) | ~1.8M | ~3.1M |
| Verifier | ZeroJ pure-Java `Groth16BLS12381Verifier` | Julc `Groth16BLS12381Verifier` (Plutus V3) |
| Trust model | Portal operator honors attestation | Fully trustless (on-chain) |
| Extra blockers | prover scale | + MPC ceremony, + tx-binding validator promoted to main |

### Authoring path: ZeroJ symbolic gadgets (strategic) vs circom (spike)

| Path | What it is | Pros | Cons |
|------|------------|------|------|
| **S — ZeroJ symbolic DSL + native gadgets ([ADR-0027](../../zeroj/docs/adr/0027-real-world-crypto-gadgets-sha512-hmac-blake2b-ed25519.md))** — *strategic target* | Author SHA-512/HMAC/Blake2b/Ed25519 as native BLS12-381 gadgets; circuit is annotated Java; proven with ZeroJ's prover | No circom port; Java DX; **reusable core-library asset** (unlocks zkLogin, cross-chain, KYC — §12.1); single toolchain; native BLS12-381 | Must build + audit the gadget suite; must scale ZeroJ's Java prover |
| **C — circom on BLS12-381** — *optional early spike* | `circom --prime bls12381` + snarkjs; ZeroJ imports & verifies (proven flow: `CircomToOnChainE2ETest`) | Reuses existing SHA-512/Ed25519 circom code (logic already written); fastest to a *first* end-to-end proof | Porting BN254-native circomlib to the 255-bit field is **unverified**; snarkjs-only prover; two toolchains; not the strategic direction |

**Plan:** pursue **Path S** as the shipped implementation (it *is* the strategic ZeroJ
investment the gadget ADR funds). Use **Path C** only as a throwaway Phase-0 spike if we want
an early end-to-end proof (does the derivation logic + on-chain verify work at all?) while the
gadgets are being built — not as shipped code.

---

## 12. What ZeroJ Provides Today vs. What Must Be Built

**Provided (verified in codebase):**
- ✅ Off-chain Groth16 verify, pure Java — BLS12-381 (`Groth16BLS12381Verifier`) and legacy BN254.
- ✅ On-chain Groth16 verify, Plutus V3 BLS12-381 — `zeroj-onchain-julc` `Groth16BLS12381Verifier` (+ TxOutRef-binding variant), proven E2E on Yaci DevKit; arbitrary public-input count.
- ✅ snarkjs/circom import — `ZkeyImporterBLS381`, `R1CSImporter`, `SnarkjsToCardano`, and `CircomToOnChainE2ETest` (circom `.zkey` → import → prove → on-chain verify).
- ✅ Verifier-first API — `VerifierOrchestrator`, `VerificationKeyRegistry`.
- ✅ Replay utilities — `zeroj-patterns` `NullifierClaimVerifier`; on-chain nullifier sorted-list pattern.
- ✅ Host-side Cardano crypto — BIP39 / CIP-1852 / Ed25519 / blake2b via cardano-client-lib (through `zeroj-ccl`).

**Must be built (the real work):**
- ❌ **The gadget suite — [ADR-0027](../../zeroj/docs/adr/0027-real-world-crypto-gadgets-sha512-hmac-blake2b-ed25519.md).** ZeroJ's DSL has **no** SHA-512, HMAC, Blake2b, Ed25519, or non-native-field gadgets (only Poseidon/MiMC + Jubjub, whose base field *is* BLS12-381 Fr — the wrong curve for Cardano's Ed25519 keys). Authored as **native ZeroJ symbolic gadgets** over BLS12-381:
  - SHA-512 compression + HMAC-SHA512 (PBKDF2 **avoided** — anchor at the key, never the mnemonic).
  - Blake2b-**224**.
  - **Non-native `GF(2²⁵⁵−19)` field layer** (the delicate, audit-critical piece; reusable for secp256k1 later).
  - Ed25519 point ops + **fixed-base** scalar mult (`A = kL·B`) — ZeroJ can add the fixed-base optimization the public circom gadget lacks.
  - BIP32-Ed25519 hardened + soft derivation composition.
- ⚠️ **Scale ZeroJ's Groth16 prover** to ~2M–7M constraints — no ZeroJ test has proven a circuit above ~4k today. Pure-Java baseline; **`zeroj-blst` native MSM/FFT** as the performance path. Benchmark early (ADR-0027 M7 gates the full circuit). This is the top risk.
- ❌ **Witness generator** — root/intermediate key + address → circuit input (host-side, cardano-client-lib).
- ⚠️ **MPC trusted-setup ceremony** for the production VK at ~2²³ (ZeroJ ships only a dev-only, flag-gated setup; ties to ADR-0013/0025).
- ⚠️ **Promote the tx-binding on-chain validator to main** (currently example/test only).

### 12.1 Why this is a strategic ZeroJ investment, not a one-off

The gadget suite (ADR-0027) is the primitive layer that moves ZeroJ **from "ZK over
ZK-friendly abstractions" to "ZK over real-world cryptographic facts."** Today every usecase
models real crypto as `Poseidon(secret, …)` or a Jubjub signature; the moment ZeroJ can
compute *standard* SHA-2/Blake2b/HMAC and the *real* signing curves in-circuit, a whole
family of **high-value** scenarios opens up — and they all reuse the same gadgets:

- **Wallet ownership / account recovery** (this usecase).
- **zkLogin / OIDC** — prove possession of a Google/Apple-signed JWT (SHA-256/RS256) without revealing it.
- **Cross-chain proof of ownership** — prove control of a BTC/ETH address in ZK (secp256k1 via the same non-native field layer).
- **KYC / selective disclosure over *real* X.509 / JWT credentials**, **proof-of-solvency over real signatures**.

These are exactly the high-stakes use cases where ZK carries economic weight. Framing the
work as a **reusable core-library asset** (one gadget suite, many usecases) is the right lens
for the investment — and it is precisely why the effort is justified despite the heavy
circuits: the cost is amortized across the roadmap, not spent on a single demo.

---

## 13. Security Analysis & Limitations

**What the proof guarantees.**
- **Soundness:** only a holder of a valid ancestor witness produces an accepting proof; the attacker (with only `kL_leaf`) cannot, because `kL_leaf` does not reveal any ancestor key/chain code.
- **Zero-knowledge:** reveals nothing about the mnemonic/ancestor beyond "derives to `pkh`".
- **Replay-bound:** challenge (off-chain) / TxOutRef context (on-chain) stops proof lifting.

**What it does NOT do (state these plainly to users).**
1. **It is not fund recovery by itself.** It *authorizes* a recovery mechanism (off-chain attestation, or an on-chain vault/owner-NFT). Who honors the proof and how funds move is a separate governance/protocol decision. For already-drained funds, nothing on-chain can claw them back; this proves ownership for **remaining** assets or for an off-chain reimbursement process.
2. **It cannot distinguish owner from an attacker who also stole the mnemonic.** This exploit did **not** leak the mnemonic, so the mechanism fits; a future seed-phrase phishing would defeat it (as it defeats everything).
3. **Only standard CIP-1852 HD addresses** have an ancestor to prove. Raw/script/hardware-derived-differently keys need a different anchor.
4. **Anchor strength = claim strength.** A role-level proof shows control of that branch, not necessarily the whole wallet. Use root-level anchoring for the strongest production claim.
5. **Trusted setup.** Groth16 requires a per-circuit trusted setup; a compromised setup breaks soundness. Production needs an MPC ceremony.
6. **Unaudited Ed25519 circom code.** The only public gadget is archived/unaudited with alleged under-constraint bugs — must be audited (and, for on-chain, re-verified on BLS12-381) before any real value depends on it.

**Attack surface to watch.**
- Under-constrained circuit signals (the classic circom footgun) → forgeable proofs. Independent circuit audit is mandatory before production.
- Challenge reuse / weak nonce → replay. Enforce single-use + TTL server-side and TxOutRef binding on-chain.
- Big-int reductions (`mod 2²⁵⁶`, `mod r`) must be range-checked (255-bit field caveat on BLS12-381).

---

## 14. Alternative: Proactive Commitment (Prevention, Not Recovery)

The heavy derivation circuit is only needed **retroactively**, because SecondFi victims never
pre-registered anything. For **new** wallets/addresses going forward, a vastly cheaper design
exists:

At address creation, the wallet publishes `commitment = Poseidon(recoverySecret, pkh)` (in
CIP-68 datum / metadata / a registry). Ownership recovery then proves a **Poseidon preimage**
(~1k constraints, instant, browser-provable) instead of reproducing HD derivation. This is
essentially the `nft-ownership` Approach 2/3 pattern applied to account recovery.

- **Pro:** trivial circuit, instant proofs, no BLS12-381 Ed25519 port.
- **Con:** requires prior enrollment — **does nothing for already-deployed addresses** (the SecondFi victims). Ship it as the *forward-looking* companion to the retroactive circuit.

**Recommendation:** build the retroactive derivation circuit for the SecondFi-class problem
*and* propose the proactive commitment as a wallet-standard improvement so this class of
incident is cheaply recoverable in future.

---

## 15. Implementation Plan (Phased)

Each phase is independently valuable and de-risks the next. Prove performance and the
Ed25519 port **early** — they are the long poles.

This usecase depends on the **ADR-0027 gadget suite** (SHA-512/HMAC/Blake2b/Ed25519 +
non-native field + prover scaling). The two efforts run together: ADR-0027 M1–M7 build and
benchmark the primitives; the usecase phases below consume them and add the
application/on-chain layer.

### Phase 0 — Spike: settle the two long poles (1–2 weeks)
- [ ] **Prover scale (ADR-0027 M7):** benchmark ZeroJ's Groth16 setup+prover at 2²¹/2²²/2²³ constraints (wall-clock, peak RAM, PK size), pure-Java vs `zeroj-blst` MSM. **This is the primary go/no-go.**
- [ ] *(Optional)* **Path C spike:** compile a `--prime bls12381` circom Ed25519 + SHA-512 stack for **one soft derivation step**; record what breaks in the 255-bit field. Gives an early end-to-end proof to validate the derivation logic while Path S gadgets are built — throwaway, not shipped.
- **Exit criteria:** a proving-time/memory verdict at ~2M constraints, and a validated single-step derivation witness.

### Phase 1 — Off-chain recovery portal PoC (BLS12-381, Mode A, role anchor) (3–5 weeks)
- [ ] Symbolic `@ZKCircuit`: role-key → one soft step → `kL_leaf` (public), `challenge`, using ADR-0027 gadgets (HMAC-SHA512 + fixed-base Ed25519).
- [ ] Host witness generator (cardano-client-lib): address + root/role key → circuit inputs.
- [ ] ZeroJ BLS12-381 Groth16 prove + verify in a Spring Boot backend (mirror `proof-of-reserves` layout).
- [ ] `ChallengeService` + `NullifierClaimVerifier`; `AddressBindingService` (`blake2b224(kL_leaf·B) == pkh`, host-side).
- [ ] Svelte 5 frontend — **local proving, secret never leaves device**.
- [ ] `YaciE2ETest`-style integration test.
- **Deliverable:** end-to-end off-chain "prove I own this address" demo against real SecondFi-shaped inputs. *The proof is BLS12-381 — the same artifact Phase 3 verifies on-chain.*

### Phase 2 — Strengthen the circuit (root anchor, Mode B) (2–4 weeks)
- [ ] Extend to **root-level** anchor (full CIP-1852 path: 3 hardened + 2 soft steps).
- [ ] Add **Mode B**: in-circuit leaf pubkey + blake2b-224 → public `pkh`.
- [ ] Tune the fixed-base Ed25519 window (ADR-0027 M5) to minimize the scalar-mult cost.
- **Deliverable:** a circuit whose public input is the address credential, ready for on-chain.

### Phase 3 — On-chain recovery contract (3–5 weeks)
- [ ] Feed the Phase 2 BLS12-381 proof into the Julc `@SpendingValidator` (`Groth16BLS12381Verifier`) + **TxOutRef binding**; recovery action = mint a "verified-owner" NFT / release a recovery vault.
- [ ] Cardano tx building with cardano-client-lib (lock/unlock), Yaci DevKit E2E (use DevKit 0.11 / Ogmios-mode; DevKit ≥0.12 blst/native-image bug is a known blocker per production-readiness review).
- **Deliverable:** trustless on-chain ownership-recovery gate — no new circuit, same proof as Phase 1/2.

### Phase 4 — Production hardening
- [ ] Independent **circuit audit** (under-constraint review) + BLS12-381 correctness re-verify.
- [ ] **MPC trusted-setup ceremony** (real VK, pinned artifact).
- [ ] Prover UX (proving is minutes on BLS12-381 — server-assisted proving option, progress UI).
- [ ] Propose the **proactive commitment** wallet standard (§14).

### Cross-cutting risks & mitigations

| Risk | Likelihood | Mitigation |
|------|:---:|-----------|
| **ZeroJ prover doesn't scale** to ~2M–7M constraints | **High** | Phase 0 / ADR-0027 M7 benchmark **first**; `zeroj-blst` native MSM/FFT; server-side (not browser) proving |
| Gadget build (esp. non-native field) slips or has bugs | Med-High | ADR-0027 milestones with per-step host cross-check + audit; fixed-base Ed25519 to cut cost |
| Under-constrained circuit → forgeable proof | Med | Mandatory audit before any value at stake; thousands of random cross-checks vs `BigInteger` |
| No trustless BLS12-381 ptau at 2²³ | Med | Self-gen for dev; MPC ceremony for prod (tracked ZeroJ gap, ADR-0013/0025) |
| Users mis-derive (wrong account/path) | Med | Witness generator tries standard paths; clear UX |

---

## 16. Recommendation

1. **Build it — the concept is sound and ZeroJ is the right platform** (it already verifies
   BLS12-381 Groth16 both off-chain and on-chain; the missing pieces are the gadgets and the
   circuit, not the verifier).
2. **Anchor at the root/intermediate key, never the mnemonic.** PBKDF2 is a hard wall.
3. **Commit to BLS12-381 for both paths — no BN254 detour** (ADR-0016 doctrine). One proof
   artifact serves the off-chain portal and the on-chain contract.
4. **Build the primitives as native ZeroJ symbolic gadgets ([ADR-0027](../../zeroj/docs/adr/0027-real-world-crypto-gadgets-sha512-hmac-blake2b-ed25519.md))**,
   treating them as a **reusable core-library asset** that also unlocks zkLogin, cross-chain
   ownership, and real-credential KYC — not a one-off for this demo (§12.1).
5. **Settle the prover-scale question first (Phase 0 / ADR-0027 M7).** ZeroJ proving at
   ~2M–7M constraints is the single long pole; benchmark it before committing timelines.
6. **Ship the off-chain portal first (Phases 0–1), then the on-chain contract (Phase 3).**
   Because both are BLS12-381, the on-chain phase reuses the same circuit and proof.
7. **Pair it with the proactive-commitment wallet standard (§14)** so future addresses get
   cheap, instant recoverability — turning a post-mortem into an ecosystem improvement.

---

## Appendix A: Sources

**Exploit (SecondFi / EMURGO, June 2026):**
- SecondFi incident report — https://kb.secondfi.io/en/article/security-incident-update-dxv72a/
- The Block (Tibane Labs / `trantor` SDK) — https://www.theblock.co/post/406457/
- CoinDesk — https://www.coindesk.com/business/2026/06/24/
- Bitquery on-chain investigation — https://bitquery.io/investigations/cardano-secondfi-129m-drain
- AMBCrypto (private-key-level compromise, seed warning) — https://ambcrypto.com/cardano-wallet-exploit-secondfi-traces-attack-to-private-key-flaw/
- Charles Guillemet (Ledger CTO) thread — https://x.com/P3b7_/status/2070121675102863721

**ZK primitives & feasibility (measured with circom 2.2.3 + snarkjs `r1cs info`):**
- circom compilation options (`--prime bls12381`) — https://docs.circom.io/getting-started/compilation-options/
- snarkjs (BN254 + BLS12-381, ptau to 2²⁸) — https://github.com/iden3/snarkjs
- rapidsnark (BN254-only) — https://github.com/iden3/rapidsnark/blob/main/src/fullprover.cpp
- Electron-Labs ed25519-circom (2.56M verify; ~1.23M/scalar-mult; base 2⁸⁵) — https://github.com/Electron-Labs/ed25519-circom
- Electron-Labs sha512 — https://github.com/Electron-Labs/sha512
- bkomuves hash-circuits (SHA-512 ~66k/block; blake2b) — https://github.com/bkomuves/hash-circuits
- dl-solarity circom-lib — https://github.com/dl-solarity/circom-lib
- circom BLS12-381 portability issue — https://github.com/iden3/circom/issues/298
- roasbeef/bip32-pq-zkp (RISC Zero, starts from seed, skips PBKDF2) — reference precedent

**Cardano on-chain ZK:**
- CIP-0381 (BLS12-381 builtins, mainnet since Chang) — https://cips.cardano.org/cip/CIP-0381
- Modulo-P ak-381 (Aiken Groth16 BLS12-381, snarkjs-compatible) — https://github.com/Modulo-P/ak-381
- IntersectMBO plutus-benchmark Groth16 example (CPU ~2.0B) — IntersectMBO/plutus

**Key-derivation standards:**
- BIP32-Ed25519 (Khovratovich–Law) — hierarchical deterministic keys over a non-linear keyspace
- CIP-1852 (`m/1852'/1815'/…`) & CIP-3 (Icarus master key, PBKDF2 4096 iters)
