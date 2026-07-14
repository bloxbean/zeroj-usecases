# Account-Ownership — Verification & On-Chain Validator Flow

**Version:** 3.0  ·  **Targets circuit:** `account-ownership-proof` **v3** (recipient-bound)  ·  **Status:** design (in progress on `feat/circuit-v3-recipient`)

Reference for how a proof is produced and verified — off-chain and on-chain — once the recipient is
bound into the circuit. This supersedes the v2 flow, where the proof committed only to the pkh and
the on-chain validator bound nothing (demo scope). Generic — no specific operator is assumed.

---

## 1. What changed from v2 → v3

- **v2:** public input = the 28-byte payment key hash (pkh) only. The proof attested "someone who
  knows the seed behind pkh X exists" — a **bearer credential**, replayable from the mempool.
- **v3:** a **second public input, `recipient`**, is added — the 28-byte **payment key hash of the
  address the funds must go to**. The proof now attests "the owner of pkh X **authorizes a payout to
  recipient R**." It is bound to a destination, so a copied proof cannot be redirected, and the
  on-chain validator is upgraded to **enforce the payout goes to R for the correct amount**.

---

## 2. Circuit v3 public interface

| signal | kind | size | meaning |
|---|---|---|---|
| `pkh` | **public** | 28 bytes (28 inputs) | payment key hash of the address being proven |
| `recipient` | **public** | 28 bytes (28 inputs) | payment key hash of the payout address (chosen by the prover) |
| `rootKL, rootKR, rootChainCode` | secret witness | 3×32 bytes | the wallet root extended key |
| `role, index` | secret witness | 4 bytes each | the CIP-1852 soft path (kept private since v2) |

- `recipient` is a **carried, bound tag**: it is *not* derived from the seed and is *not* hashed
  in-circuit. The prover supplies it; being a public input makes it part of the proof's public-input
  vector, so it cannot be altered without invalidating the proof.
- Encoding for now is **byte-per-input** (one field element per byte), consistent with the existing
  pkh — so v3 has **56 public inputs** (28 + 28). See §7 for packing this down in a future version.

---

## 3. Prove flow (where the recipient is chosen)

1. The user enters the wallet mnemonic **and a recipient address** (bech32).
2. Decode the recipient bech32 → extract its **payment credential** (the 28-byte payment key hash —
   present in both **base** and **enterprise** addresses; the staking part is not bound).
3. Build the witness: root key + role/index (secret) and public inputs `[pkh, recipient]`.
4. Generate the proof (~1 min, pure Java).
5. Write:
   - `proof.json` — the Groth16 proof points.
   - `public-inputs.json` — `pkh`, the recipient **payment key hash** (the public input) **and** the
     recipient **bech32** (kept for transaction construction — see §6), plus the circuit fingerprint.

Because the recipient is fixed at prove time, changing the destination means **re-proving** — that
is the intended single-purpose property.

---

## 4. Off-chain verification

The pure-Java pairing check against `public-inputs.json` — sub-second, no network. It reads both
public inputs (`pkh`, `recipient`) from the file; **no extra user input is required** (the recipient
is already part of the proof). The UI can display the bound recipient for confirmation.

---

## 5. On-chain artifacts

**Datum** (on the gate / refund-voucher UTxO):

| field | type | meaning |
|---|---|---|
| `pkh` | 28 bytes | the account this voucher refunds (must equal the proof's `pkh` public input) |
| `refundAmount` | integer (lovelace) | the amount the recipient must receive |
| `deadline` | POSIX time | claim expiry (enforced via the tx validity interval) |

(The `recipient` is **not** in the datum — it comes from the *proof*, so the destination is the
prover's choice, not fixed by whoever created the voucher.)

**Redeemer:** `Groth16Proof(piA, piB, piC)`.

---

## 6. On-chain validator flow (the core)

On spend, the validator (parameterized with the circuit VK) checks **all** of:

1. **Proof valid.** `Groth16.verify([pkh, recipient], piA, piB, piC, vk)` — the pairing check over
   the two public inputs. `pkh`/`recipient` are read from the datum + the transaction (see step 2),
   in circuit public-input order.
2. **Correct recipient, correct amount.** There exists a transaction **output** whose **payment
   credential == `recipient`** (the proof's second public input) and whose **value ≥
   `refundAmount`** (datum). This is the critical check: a *presence-only* check would let a
   front-running submitter pay the recipient a token amount and skim the rest — the **amount bound
   closes that**.
3. **Right account.** `datum.pkh == pkh` public input (the voucher is for this account).
4. **Within deadline.** The transaction validity interval ends before `datum.deadline`.

**No recipient signature is required** (see §8 for why). Anyone — including a fee-sponsor — may
submit; the funds still land with the bound recipient at the enforced amount.

The transaction builder constructs the recipient output from the **bech32 in `public-inputs.json`**;
the validator independently recomputes/compares the payment credential against the proof's public
input, so a tampered stored address simply fails the check.

---

## 7. Future (v4): packing the public inputs

v3 uses **56 public inputs** (28-byte pkh + 28-byte recipient, one field element per byte). Each
28-byte value is 224 bits, which fits comfortably in a single BLS12-381 scalar field element
(~253 usable bits). So in a later revision each value can be **packed into one field element** by
bit-composition:

```
packed = b0 + b1·256 + b2·256² + … + b27·256²⁷      // 28 bytes → 1 field element
```

That takes the count from **56 → 2 public inputs** (pkh → 1, recipient → 1), removing ~54 of the
per-input G1 scalar-multiplications in `vk_x = IC[0] + Σ pubᵢ·IC[i+1]`. Note this shrinks only the
**linear** part of Groth16 verification (the fixed pairing cost dominates and does not change), so
the fee reduction is modest — hence it is deferred, not required. Two constraints when doing it:

- **Both sides must pack identically** — the prover's packing and the validator's on-chain packing
  must use the same byte order, or every verification fails (guard with a differential test).
- A 32-byte value would **not** fit in one field element (256 > ~253 bits); keep the bound values at
  28 bytes (payment key hash / blake2b-224).

The two values **cannot** be merged into a *single* field element (2×28 = 56 bytes > 31), and they
must stay separate anyway (the validator checks `recipient` against the payout independently of
`pkh`).

---

## 8. Security properties & rationale

- **Recipient binding (anti front-run / replay):** the proof authorizes a payout only to `recipient`.
  A copied proof cannot change `recipient` (invalidates it) and cannot be re-proven (no seed), so a
  stolen proof only ever pays the genuine recipient.
- **Amount enforcement (anti-skim):** the payout to `recipient` must be **≥ `refundAmount`**, so a
  submitter cannot pay a token amount and keep the rest.
- **No recipient signature — deliberate:** once the amount is enforced, a front-runner gains nothing
  (funds go to the recipient; they only pay the fee), so a signature adds no security. Requiring one
  would instead **reintroduce fee-starvation** — the recipient is often a fresh/empty address whose
  owner has no ADA to sign or post collateral. "Anyone may submit; funds go to the bound recipient"
  is both secure and lets a third party sponsor the fee for the recipient.
- **Double-claim (nullifier):** recipient binding does **not** prevent claiming twice. That is
  handled out-of-band by making the refund a **single-use voucher UTxO** — the eUTxO can be consumed
  exactly once, so the UTxO *is* the nullifier. Recipient binding and the voucher are complementary.
- **Privacy:** `pkh` and `recipient` are public inputs and therefore public — but both are already
  public on-chain (the address, and the payout output). The **seed stays secret**. The only new
  disclosure is the linkage "owner of X → payout to R", which is expected for a refund.

### Threat coverage

| threat | covered by |
|---|---|
| copy proof, redirect to attacker | recipient binding (§6.2 credential check) |
| copy proof, pay recipient a little & skim | amount enforcement (§6.2 value check) |
| claim twice | single-use voucher UTxO (nullifier) |
| claim a non-affected account | voucher exists only for affected accounts + `datum.pkh == pkh` |
| claim after the window | deadline (§6.4) |
| recover the seed from the proof | zero-knowledge (seed is a secret witness) |

---

## 9. Changelog

- **3.0** — recipient bound as a second public input (28-byte payment key hash); validator enforces
  payout to the recipient for `refundAmount` within `deadline`; no recipient signature. Byte-per-input
  encoding (56 inputs); packing to 2 inputs noted for a future version.
- **2.0** (prior) — pkh-only public input; role/index secret; demo validator (proof-validity only,
  no context binding).
