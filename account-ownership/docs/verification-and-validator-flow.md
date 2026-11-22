# Account-Ownership — Verification & On-Chain Validator Flow

**Targets circuit:** `account-ownership-proof` (v4, packed public inputs)  ·  **Status:** implemented; voucher payouts per [ADR-0009](../../docs/adr/0009-privacy-and-binding-hardening-of-the-original-demos.md) D6 (on-chain measured ~2.3×10⁹ steps)

Reference for how a proof is produced and verified — off-chain and on-chain. Generic — no specific
operator is assumed.

---

## 1. What the proof attests

The proof attests two things at once: **"I know the seed that derives `pkh`, and I authorise a
payout to `recipient`."**

- **`pkh`** (public) — the 28-byte payment key hash of the address being proven. The circuit
  re-derives it from the secret root key via the full CIP-1852 path, so a passing proof *is* proof
  of seed ownership (an attacker holding only a leaf address key cannot produce it).
- **`recipient`** (public) — the 28-byte payment key hash of the address the funds must go to. It is
  bound into the proof, so a copied proof **cannot be redirected**; the on-chain validator enforces
  that the payout goes to `recipient` for the datum's amount.
- The full derivation path (**`account`, `role`, `index`**) is a **secret** witness, so the proof
  covers any `m/1852'/1815'/account'/role/index` address while keeping the path private from chain
  observers; the public `pkh` pins the exact one. Anyone holding the account's xpub can derive its
  addresses and so find the path of `pkh`.

---

## 2. Circuit public interface

| signal | kind | size | meaning |
|---|---|---|---|
| `pkh` | **public** | 1 field element (packed 28 bytes) | payment key hash of the address being proven |
| `recipient` | **public** | 1 field element (packed 28 bytes) | payment key hash of the payout address (chosen by the prover) |
| `rootKL, rootKR, rootChainCode` | secret witness | 3×32 bytes | the wallet root extended key |
| `account` | secret witness | 4 bytes | CIP-1852 account (hardened in-circuit; private) |
| `role, index` | secret witness | 4 bytes each | the CIP-1852 soft path (private) |
| `recipientBytes` | secret witness | 28 bytes | the recipient bytes, constrained to pack to the public `recipient` |

- `recipient` is a **carried, bound tag**: it is *not* derived from the seed. Being a public input
  makes it part of the proof's public-input vector, so it cannot be altered without invalidating the
  proof.
- **Packed encoding:** each 28-byte hash is packed **big-endian into one field element**
  (`Σ bᵢ·256^(27-i)`; 224 bits fit in the ~253-bit scalar field), so the circuit has **2 public
  inputs**. On-chain verification is O(#public inputs), so the claim tx costs **~2.3×10⁹ CPU steps**
  — comfortably under the ~10×10⁹ per-tx limit (packing the two hashes is what keeps it there; one
  field element per byte would be 56 inputs and would not fit). The prover packs with
  `new BigInteger(1, bytes)`; the validator re-derives the same scalars with
  `byteStringToInteger(bigEndian=true, …)`; the circuit packs with a Horner chain over the bytes — all
  three must agree (differential-tested).

---

## 3. Prove flow (where the recipient is chosen)

1. The user enters the wallet mnemonic **and a recipient address** (bech32).
2. Decode the recipient bech32 → extract its **payment credential** (the 28-byte payment key hash —
   present in both **base** and **enterprise** addresses; the staking part is not bound).
3. Build the witness: root key + **account/role/index** (all secret) and public inputs
   `[pkh, recipient]`.
4. Generate the proof (~1 min, pure Java).
5. Write:
   - `proof.json` — the Groth16 proof points.
   - `public-inputs.json` — `pkh`, the recipient **payment key hash** (the public input) **and** the
     recipient **bech32** (kept for transaction construction — see §6), plus the circuit fingerprint.

Because the recipient is fixed at prove time, changing the destination means **re-proving** — that
is the intended single-purpose property.

---

## 4. Off-chain verification

The pure-Java pairing check — sub-second, no network. The two public inputs are **recomputed** from
the proven address and the recipient (`pack(pkh)`, `pack(recipient)`), the same way the on-chain
validator derives them — *not* trusted from the file's `publicInputs` array. So the result is tied
to those values: an edited `pkh`/`recipient`/`publicInputs` is caught (the recomputed pair must
equal the stored array in default mode), and a verifier can pass **`--expect-address` /
`--expect-recipient`** (bech32, or the two prefilled UI fields) to check the proof against values
they know independently — the real assurance, since a file's labels are only as trustworthy as its
author. The tool reports the address → recipient it validated against.

---

## 5. On-chain artifacts

**Datum** (on the gate / refund-voucher UTxO):

| field | type | meaning |
|---|---|---|
| `pkh` | 28 bytes | the account this voucher refunds (must equal the proof's `pkh` public input) |
| `refundAmount` | integer (lovelace) | the amount the recipient must receive |
| `funderPkh` | 28 bytes | the payment key hash of whoever funded the voucher; it gets the remainder back |
| `maxFee` | integer (lovelace) | the fee slack: how much of the voucher need not go back to the funder |

(The `recipient` is **not** in the datum — it comes from the *proof*, so the destination is the
prover's choice, not fixed by whoever created the voucher.)

The voucher holds only ADA. Creation refuses `refundAmount < 0`, `maxFee < 0`,
`refundAmount + maxFee > voucher`, and a remainder `voucher − refundAmount − maxFee` that is positive
but below the min-UTxO of its tagged output. The demo locks 10 ADA with a 2 ADA refund and
`maxFee` = 2 ADA, so 6 ADA goes back to the funder.

> **No claim deadline by default.** The genuine owner should be able to claim **whenever** they
> want — a hard deadline would *lock the user's own refund away* if they are slow to claim, which is
> user-hostile for a recovery flow. A deadline is therefore **not** a mandatory validator check;
> it is at most an **optional operator policy** (e.g. a very long expiry plus an operator-multisig
> reclaim path for truly abandoned vouchers). Off by default — funds stay claimable indefinitely.

**Redeemer:** `OwnershipRedeemer(piA, piB, piC, recipient)` — the compressed proof and the 28-byte
recipient payment key hash it is bound to.

---

## 6. On-chain validator flow (the core)

On spend, the validator (parameterized with the circuit VK) checks **all** of:

1. **Proof valid.** `Groth16.verify([pkh, recipient], piA, piB, piC, vk)` — the pairing check over
   the two public inputs. `pkh`/`recipient` are read from the datum + the transaction (see step 2),
   in circuit public-input order.
2. **Exact payout, tagged with this voucher** (ADR-0009 D6). Only outputs whose inline datum is
   exactly the spent voucher's `TxOutRef` (`Constr 0 [txId, index]`) count as its payments:
   - tagged outputs to the **payment credential `recipient`** (the proof's second public input)
     sum to at least `refundAmount`;
   - tagged outputs to the **payment credential `funderPkh`** sum to at least the remainder
     `voucher − refundAmount − maxFee`, and none is needed when it is 0;
   - if `recipient == funderPkh`, the combined tagged sum covers both;
   - the voucher's value is ADA-only, and `refundAmount ≥ 0`, `maxFee ≥ 0`,
     `refundAmount + maxFee ≤ voucher`.

   A *presence-only* check would let a front-running submitter pay the recipient a token amount and
   skim the rest; a refund-only check would let it keep the remainder; an untagged check would let
   one output pay two vouchers in one transaction. The tag is unique per voucher, so no output counts
   for two vouchers of tag-enforcing validators (this one and the reusable-KYC voucher), whatever
   their stake credentials. Spending a voucher together with a script that counts any paying output
   is unsafe: that script may count the voucher's outputs.
3. **Right account.** `datum.pkh == pkh` public input (the voucher is for this account).

**No claim deadline** and **no recipient signature** are required (see §8 for why). Anyone —
including a fee-sponsor — may submit; the funds still land with the bound recipient and the funder
at the enforced amounts, whenever the owner chooses to claim. The submitter can keep `maxFee` minus
the actual fee, so a funder sets `maxFee` close to the expected fee.

The transaction builder constructs the recipient output from the **bech32 in `public-inputs.json`**;
the validator independently recomputes/compares the payment credential against the proof's public
input, so a tampered stored address simply fails the check. The service pays the funder's remainder
to its enterprise address, apart from the change address, so fee balancing never draws on a tagged
output.

---

## 7. Packed public inputs — why, and how it's done

Each 28-byte hash (224 bits) fits comfortably in one BLS12-381 scalar (~253 usable bits), so the
circuit **packs each hash into a single field element** rather than spending one field element per
byte:

```
packed = b0·256²⁷ + b1·256²⁶ + … + b27      // 28 bytes → 1 field element, big-endian
```

That keeps the public-input count at **2** (pkh → 1, recipient → 1). This matters because on-chain
verification does one G1 scalar-multiplication **per public input** in `vk_x = IC[0] + Σ pubᵢ·IC[i+1]`
at **~0.195×10⁹ CPU steps each**, so the input count is the cost lever:

| Public inputs | On-chain CPU steps | Fits `maxTxExUnits` (10×10⁹)? |
|---|---|---|
| **2 (packed — shipped)** | **~2.3×10⁹** | ✅ **yes (4× margin)** |
| 56 (one field element per byte) | ~13.4×10⁹ | ❌ no — ~34% over |

Measured in the UPLC evaluator (`OwnershipProofValidatorVmTest`, which runs the compiled validator
locally): the packed claim tx is ~2.3×10⁹ steps, mem ~0.35M ≪ the 14M limit. Without
packing (one field element per byte) it would be 56 inputs → ~13.4×10⁹ steps and a mainnet claim tx
would be **rejected** for exceeding the per-tx limit. Implementation:

- **Circuit** (`OwnershipProof.java`): a Horner chain over the derived pkh bytes and the recipient
  bytes → two `@Public ZkField`. Uses only existing DSL ops (`ZkContext.constant`, `ZkUInt.asField`,
  `ZkField.mul/add`) — **no zeroj change**. (A reusable `bytesToField` gadget could be promoted to
  `zeroj-circuit-lib` in a future zeroj release; the usecase inlines it for now.)
- **Validator** (`OwnershipProofValidator.java`): two `byteStringToInteger(bigEndian=true, …)` calls
  on the datum's `pkh` and the redeemer's `recipient` bytes, built into the public-input list.
- **Prover** (`OwnershipCircuitService.java`): `new BigInteger(1, bytes)` for each public input.

**All three pack the same way (big-endian)** — the VM test proves they agree (a mismatch would fail
verification). Two constraints on the scheme:

- A 32-byte value would **not** fit in one field element (256 > ~253 bits); the bound values are
  28-byte payment key hashes (blake2b-224), which do.
- The two hashes **cannot** be merged into a *single* field element (2×28 = 56 bytes), and must stay
  separate anyway (the validator checks `recipient` against the payout independently of `pkh`).

---

## 8. Security properties & rationale

- **Recipient binding (anti front-run / replay):** the proof authorizes a payout only to `recipient`.
  A copied proof cannot change `recipient` (invalidates it) and cannot be re-proven (no seed), so a
  stolen proof only ever pays the genuine recipient.
- **Amount enforcement (anti-skim):** the tagged payout to `recipient` must be **≥ `refundAmount`**
  and the tagged payout to the funder ≥ the remainder, so a submitter can keep at most `maxFee`
  minus the fee it paid.
- **No recipient signature — deliberate:** once the amount is enforced, a front-runner gains nothing
  (funds go to the recipient; they only pay the fee), so a signature adds no security. Requiring one
  would instead **reintroduce fee-starvation** — the recipient is often a fresh/empty address whose
  owner has no ADA to sign or post collateral. "Anyone may submit; funds go to the bound recipient"
  is both secure and lets a third party sponsor the fee for the recipient.
- **No claim deadline — deliberate:** the refund belongs to the owner, so it should stay claimable
  **whenever** they get to it; a hard deadline would lock the user's own funds away on a timer. A
  deadline is an optional operator convenience (reclaiming abandoned vouchers), never a security
  requirement, and is off by default.
- **Double-claim (nullifier):** recipient binding does **not** prevent claiming twice. That is
  handled out-of-band by making the refund a **single-use voucher UTxO** — the eUTxO can be consumed
  exactly once, so the UTxO *is* the nullifier. Recipient binding and the voucher are complementary.
- **Privacy:** `pkh` and `recipient` are public inputs and therefore public — but both are already
  public on-chain (the address, and the payout output). The **seed stays secret**. The new
  disclosure is the linkage "owner of X → payout to R", which is expected for a refund, so a
  claimant should use a **fresh recipient** address that isn't linked to their other wallets. The
  derivation path is private from observers, but not from anyone holding the account's xpub.

### Threat coverage

| threat | covered by |
|---|---|
| copy proof, redirect to attacker | recipient binding (§6.2 credential check) |
| copy proof, pay recipient a little & skim | amount enforcement (§6.2 value check) |
| copy proof, pay the recipient & keep the remainder | funder remainder check (§6.2) |
| one output paying two vouchers | outref tags (§6.2) |
| claim twice | single-use voucher UTxO (nullifier) |
| claim a non-affected account | voucher exists only for affected accounts + `datum.pkh == pkh` |
| recover the seed from the proof | zero-knowledge (seed is a secret witness) |

---

## 9. Status

Implemented: circuit (v4) + prover + CLI/UI + on-chain validator. `OwnershipProofValidatorVmTest`
runs the compiled validator: the valid claim, a zero remainder, funder = recipient, and two
separately paid vouchers are accepted; underpay, wrong payee, wrong recipient, wrong pkh, a third
party keeping the remainder, outputs shared between two vouchers (same validator with another stake
part, or a reusable-KYC voucher), untagged payouts, funder = recipient with one obligation paid, a
non-ADA voucher and out-of-range terms are refused. The at-scale 19M setup → prove → off-chain
verify passes at `-Xmx8g`; on-chain cost measured ~2.3×10⁹ steps.
