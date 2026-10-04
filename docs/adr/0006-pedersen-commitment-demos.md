# ADR-0006: Pedersen commitment demos — confidential points, committed credentials, hidden-liability solvency

- **Status:** Proposed. Implementation is on `feat/pedersen-private-ballot-and-demos`.
- **Date:** 2026-10-04 (r2: amended after the design review)
- **Related:**
  - ZeroJ ADR-0051 and its specs, `pedersen-jubjub-v1` and `pedersen-jubjub-vector-v1`.
  - ZeroJ's reference validators `ConfidentialNoteValidator` and
    `VectorCommitmentConsumerValidator`.
  - [ADR-0005](0005-private-ballot-homomorphic-tally.md), for the homomorphic tally.
- **Risk:** R2. These are application protocols and on-chain integrations built on
  primitives ZeroJ has already reviewed. No primitive is implemented here.

## Context

ZeroJ ADR-0051 added hiding-safe Pedersen commitments, homomorphic balance checks without
wraparound, and schema-bound vector commitments. This ADR adds three demos. Each shows a
different property of the commitment, and each runs end to end on Yaci DevKit.

| Demo | Property shown | ZeroJ API used |
|---|---|---|
| A. Confidential points | Additive homomorphism: conservation of hidden amounts, mixed with public amounts | `ZkPedersenCommitment.commit`, `ZkPedersen.assertBalanced`, `Term.amount` |
| B. Committed credential gate | One commitment to several attributes; predicates over a subset; schema binding and provenance | `ZkPedersenVector.bindSchema` / `commit`, `PedersenVectorSchema` |
| C. Hidden-liability solvency | Hiding per-customer commitments, checked by each customer; the aggregate opened only to an auditor | `ZkPedersenCommitment.commit`, host-side `PedersenCommitment` |

The demos live in `pedersen-commitments/`, a single Gradle project with one package per demo. It
has no web UI. It provides a runnable walkthrough, Plutus VM tests and DevKit end-to-end tests.

**Common rules,** taken from AGENTS.md ("proof validity is not authorization"):
- Every public input comes from script parameters or the ledger, never from the redeemer alone.
  The one exception is demo A's redeemed `price`, which the proof binds and the receipt records.
- Every on-chain integer is checked to be canonical (`< p`).
- Script inputs are counted by payment credential, so the same script under another staking key
  cannot double-satisfy.
- A policy's own mint entry is checked exactly, not just "contains".
- Every key comes from a dev trusted setup. That is demo-only.

## Threat model

| Demo | Adversary | Goal | Trusted |
|---|---|---|---|
| A | A note holder or an outsider | Create points from nothing; spend someone else's note; spend twice; forge a redemption receipt; overflow an amount. | The issuer, for supply. The dev setup. |
| B | A non-qualifying holder or a third party | Obtain a badge without a qualifying, issued credential; re-label a credential under another schema; use someone else's credential. | The bureau's key. The dev setup. |
| C | The exchange | Attest with liabilities greater than reserves; understate or omit a customer; count reserves twice; change an attestation after proving it. | Nobody beyond the dev setup. Customers must check their own entry. |

Out of scope throughout:
- network-level privacy;
- delivery of openings and credentials, which happens off-chain;
- front-running of the demo's own transactions.

---

## A. Confidential points

A retailer's loyalty points are notes whose amounts are Pedersen commitments. Holders move
points between themselves privately, and spend points at the retailer for a public price.

**Script.** `PointsLedger`, a multi-validator, so its hash is both the note address's payment
credential and the points policy id.
- Parameters: `issuerPkh`, the transfer key and the redeem key.
- A **note** is an output whose payment credential is the script, carrying exactly one `PTS`
  token and nothing else under the policy, with inline datum `Note(owner: B28, u, v)`.
- A **receipt** is an output whose payment credential is the issuer's key. It holds one receipt
  token, named `blake2b_256(txId ‖ I2OSP2(index))` of the redeemed note, with inline datum
  `Receipt(owner, price)`.

**Circuits.**
- `PointsTransferProof`, public `[in.u, in.v, o1.u, o1.v, o2.u, o2.v]`: proves
  `in = o1 + o2` over 64-bit amounts.
- `PointsRedeemProof`, public `[in.u, in.v, out.u, out.v, price]`, where `price` is a public
  32-bit amount: proves `in = out + price`.
- Both use 252-bit blindings and `assertBalanced`, so wraparound is refused when the circuit is
  defined (ADR-0051 D3a).

**Minting purpose.** For each redeemer, the policy's own mint entry must be exactly as listed.

- `Issue`:
  - the mint entry is exactly `{PTS: n}`, with `n ≥ 1`;
  - the issuer signs;
  - no input carries the script credential;
  - exactly `n` outputs carry the script credential, each one a well-formed note.
- `Split`:
  - the mint entry is exactly `{PTS: 1}`;
  - exactly one input carries the script credential. That input's spending purpose enforces the
    transfer.
- `Receipt`:
  - the mint entry is exactly `{receiptName: 1}`;
  - exactly one input carries the script credential, and `receiptName` is derived from that
    input's reference. That input's spending purpose enforces the redemption.

**Spending purpose.** Datum `Note`. Both redeemers require that the owner signs and that the
transaction spends exactly one script-credential input, holding exactly one `PTS`.

- `Transfer(proof)`:
  - exactly two script-credential outputs, both notes, in order;
  - the policy mint entry is exactly `{PTS: 1}`;
  - the transfer proof verifies over the input datum and the two output datums.
- `Redeem(price, proof)`:
  - exactly one script-credential output, a note;
  - `1 ≤ price < 2^32`;
  - the policy mint entry is exactly `{receiptName(own input): 1}`;
  - an output to `issuerPkh` holds that receipt token, with inline datum `Receipt(owner, price)`;
  - the redeem proof verifies.

The retailer honours a redemption only for a receipt that holds a receipt token under the
points policy, and only once per token name. Only a valid `Redeem` can mint one, and each note
can be redeemed once.

| ID | Invariant |
|---|---|
| P1 | Supply: `PTS` comes into existence only through an issuer-signed `Issue`, or the `+1` of a proved transfer. |
| P2 | Conservation: `in = o1 + o2` and `in = out + price`, as integers over 64-bit amounts. |
| P3 | Authorization: the note's owner signs. |
| P4 | One note per transaction, counted by payment credential. |
| P5 | State binding: commitments come from datums; `price` is bound by the proof and recorded in the receipt. |
| P6 | Only outputs at the script credential with exactly one `PTS` are notes. Anything else is ignored by wallets. |
| P7 | Receipts cannot be forged, because the receipt token is minted only with a valid redemption. |
| P8 | Canonical coordinates and price; owners are exactly 28 bytes. |

**Copying commitments.** The sender knows the opening of every output it creates, including the
recipient's. It can therefore later create its own notes with the same commitment, funded from
its own value. Transfer proofs bind commitments, not UTxOs (as `ConfidentialNoteValidator`
documents), so a proof for the recipient's note also verifies against such a copy. Nothing is
stolen, but notes with equal commitments become linkable. A recipient who wants unlinkability
should re-split its note.

**Not hidden:**
- the owners, which are key hashes in datums, so the transfer graph is public;
- the redeemed price;
- the number of notes.

Points cannot be burned, so zero-value notes, and the min-ADA they hold, accumulate. Openings are
given to recipients off-chain; that delivery channel is out of scope.

---

## B. Committed credential gate

A credit bureau issues one vector commitment to a holder's profile. The schema is
`zeroj.demo.credit-profile` v1, with entries `income/64, credit_score/16, birth_year/16,
country/16`. A lender's gate mints an access badge when the holder proves
`income ≥ minIncome ∧ credit_score ≥ minScore`. The proof reveals nothing else, and in particular
not `birth_year` or `country`.

**Issuance record.**
- The bureau's native-script policy mints a record token named
  `blake2b_256(I2OSP32(u) ‖ I2OSP32(v) ‖ I2OSP32(σ) ‖ holderPkh)`.
- The token sits at an output with inline datum `Record(u, v, σ, holderPkh)`.
- This is the authenticated issuance record that `pedersen-jubjub-vector-v1` §6 requires,
  extended with the holder. Because the name commits to the datum, a record cannot be relabelled.

**Gate.** `CreditGatePolicy`, a minting policy.
- Parameters: `σ`, `issuerPolicyId`, `minIncome`, `minScore` and the verification key.
- Redeemer: `Claim(holderPkh, u, v, proof)`.

The gate checks:
- the holder signs;
- the lengths are right and `σ`, `u`, `v` are canonical;
- a reference input holds the exact record token, with the exact record datum;
- the gate's mint entry is exactly `{holderPkh: 1}`;
- the badge is paid to an output whose payment credential is the holder's key;
- Groth16 verifies over `[σ, u, v, minIncome, minScore]`, with every value from the parameters
  or the record.

**Circuit.** `CreditProfileProof` does three things:
1. binds `σ` as a public input with `ZkPedersenVector.bindSchema`;
2. commits to the four attributes with a 252-bit blinding;
3. asserts the two predicates against the public thresholds.

**Consumer rule.** A lender that admits badge holders checks that the badge's name equals a key
that signed the presenting transaction. Badges can be moved like any token, so holding one proves
nothing on its own.

| ID | Invariant |
|---|---|
| C1 | Statement binding: `σ` is a public input fixed by the gate's parameters. |
| C2 | Provenance: no record, no badge. The record token name commits to `(u, v, σ, holder)` (fail closed). |
| C3 | Holder binding: the record names the holder; the holder signs; the badge is named after the holder and paid to the holder. |
| C4 | Predicates: `income ≥ minIncome` and `credit_score ≥ minScore`, with the thresholds from the parameters. |
| C5 | Canonical integers and exact lengths. |

**Not provided:**
- **Unlinkability:** presentations reuse `(u, v)`, so they can be linked. The BBS-based
  `reusable-kyc` demo shows unlinkable presentations.
- **One-time use:** a holder can mint more badges for itself. That is harmless under the consumer
  rule.
- **Revocation:** out of scope; see ADR-0004 for a status registry.

---

## C. Hidden-liability solvency (Provisions-style)

An exchange publishes one Pedersen commitment per customer balance, and proves that the hidden
total is at most the reserves it **locks** for the attestation period. Each customer checks their
own entry. Nobody learns another customer's balance or the total liabilities. The total can be
opened to an auditor through homomorphism, without opening any single entry. This follows the
Provisions approach [DBB+15].

The existing `proof-of-reserves` demo publishes the total liabilities, and its Merkle sum tree
reveals partial sums along each path. This demo hides both.

**Script.** `SolvencyVault`, a multi-validator, so the attestation policy and the vault address
share one hash.
- Parameters: `exchangePkh` and the verification key for `N` entries (`N = 4` in the demo).

**Attest (minting purpose).**
- The exchange signs.
- The policy's mint entry is exactly one attestation token, with quantity 1.
- The output holding it has the vault's payment credential.
- Its inline datum is `Attestation(unlockAfter, [Entry(idHash: B32, u, v)] × N)`.
- Its lovelace is the attested reserve `R`, with `R < 2^64`.
- The entry count is exactly `N`, and every value is canonical.
- Groth16 verifies over `[R, u_1, v_1, …, u_N, v_N]`.

**Release (spending purpose).**
- The validity range starts at or after `unlockAfter`.
- The exchange signs.
- The attestation token is burned.

While an attestation is live, neither its reserves nor its datum can change. Each attestation
locks its own `R`, so reserves cannot be counted twice: attestations that split the customers
between them are covered by the sum of their locked reserves.

**Circuit.** `HiddenLiabilitySolvencyProof(N)` does three things:
1. commits each balance (64 bits) with a 252-bit blinding;
2. binds each commitment to its public coordinates;
3. proves `Σ b_i ≤ R`.

The sum cannot wrap, because `N·2^64 ≪ p`.

**Customer check (off-chain).**
- `idHash = blake2b_256(I2OSP2(len(id)) ‖ UTF-8(id) ‖ salt)`, with a 32-byte salt that the
  exchange gives each customer. The length prefix and fixed-size salt make the encoding
  unambiguous, so two different ids cannot share an `idHash`.
- The customer finds the live vault outputs, those that hold an attestation token, and checks
  that their `idHash` appears **exactly once** across them.
- That entry must open to the customer's `(balance, blinding)`.

**Auditor check (off-chain).** The exchange hands the auditor `(L, Σ r_i mod l)`. The auditor
checks `Σ C_i = Commit(L, Σ r_i)` against the on-chain entries and learns `L` and nothing else.

| ID | Invariant |
|---|---|
| S1 | Solvency: `Σ b_i ≤ R`, where `R` is the lovelace locked in the attestation output until `unlockAfter`. |
| S2 | No negative balances: each `b_i < 2^64`, proved. |
| S3 | Binding: the proof covers exactly the datum's entries, in order. The datum cannot change while the attestation is live. |
| S4 | Provenance: the exchange signs the attestation. |
| S5 | Canonical integers. |
| S6 | Inclusion is detected by customers, not prevented on-chain. |

**Not provided:**
- **Borrowed reserves:** an exchange can borrow funds for the lock period.
- **After unlock:** once `unlockAfter` passes, the attestation ends.
- **Omission and understatement:** these are caught only by customers who check.
- **The customer count:** `N` is public. Padding with commitments to 0, which are
  indistinguishable from any other commitment, hides the true count.
- **Linkage across periods:** a persistent salt links a customer's entries across periods. Use a
  fresh salt each period.

## Alternatives considered

- **Re-using ZeroJ's reference validators as-is.** They are references for statement and context
  binding. They deliberately have no issuance control and no business rules. Demos A and B add
  those.
- **A sealed-bid auction.** Making it complete needs either an auctioneer who sees every bid, or
  an on-chain auction state machine. It was deferred as larger than a demo.
- **Demo C as a mint-only attestation, with the token at the exchange's own address.** Rejected
  in review. The exchange could move the token and swap the datum after proving, and it could
  reuse the same reserves for several attestations.

## Milestones

| Milestone | Scope |
|---|---|
| D0 | This ADR. |
| D1 | Project skeleton, shared helpers, and demo A (circuits, script, VM mutations, DevKit). |
| D2 | Demo B. |
| D3 | Demo C. |
| D4 | README, walkthrough runner, and `build-all.sh`. |

## Verification

- **Circuit negatives:**
  - unbalanced or overflowing amounts;
  - a wrong commitment;
  - a predicate just below the threshold;
  - the wrong schema digest;
  - liabilities greater than reserves.
- **Plutus VM mutation tests** for each invariant, as in ZeroJ's M4 tests:
  - a missing signer;
  - a tampered proof;
  - swapped or extra outputs;
  - an extra staked script input;
  - extra mint entries;
  - a missing or relabelled record;
  - a forged or unbound receipt;
  - a badge sent elsewhere;
  - the wrong entry count;
  - an early release;
  - a datum changed on release;
  - non-canonical values.
- **DevKit end-to-end** for each demo, with at least one on-ledger rejection.

## References

- [DBB+15] G. G. Dagher, B. Bünz, J. Bonneau, J. Clark, D. Boneh. *Provisions: Privacy-preserving
  proofs of solvency for Bitcoin exchanges.* ACM CCS 2015.
- ZeroJ `docs/specs/pedersen-jubjub-v1.md` and `docs/specs/pedersen-jubjub-vector-v1.md` (§5–§6).
