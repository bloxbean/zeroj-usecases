# Pedersen Commitment Demos on Cardano

Three small use cases built on ZeroJ's Pedersen commitments (`pedersen-jubjub-v1` and
`pedersen-jubjub-vector-v1`, ZeroJ ADR-0051). Each one runs end to end on Yaci DevKit:
- circuits proved with pure-Java Groth16 on BLS12-381;
- Plutus V3 validators written in Java with Julc;
- transactions built with cardano-client-lib.

Design and threat model: [ADR-0006](../docs/adr/0006-pedersen-commitment-demos.md).

## Why Pedersen commitments

A Pedersen commitment `C = [v]·G + [r]·H` locks in a value `v` with a random blinding `r`. It
has three properties:

| Property | Meaning | Where it shows |
|---|---|---|
| **Hiding** | `C` reveals nothing about `v`. | Every demo: balances, amounts and attributes stay off-chain. |
| **Binding** | Nobody can later open `C` to a different value. | Proofs are about the committed value, not a claimed one. |
| **Additive** | `C(a) + C(b) = C(a+b)`. | Demo A: hidden amounts balance. Demo C: an auditor opens a total. |

A commitment on its own proves nothing. The ZK proof is what shows a hidden value satisfies a
rule, such as "these amounts balance", "this income is at least X", or "these balances sum to at
most R". The validator is what ties the proof to the transaction: signatures, outputs, issuance
records and time locks.

---

## A. Confidential points

A retailer's loyalty points are **notes** whose amounts are commitments.

| Step | On-chain | Hidden |
|---|---|---|
| The retailer issues Alice 1,000 points | Owner and commitment | 1,000 |
| Alice sends Bob 700 and keeps 300 | Two new commitments and a proof that `in = out1 + out2` | 1,000 / 700 / 300 |
| Bob pays 120 at the retailer and keeps 580 | Price 120, a change commitment, and a receipt token for the retailer | 700 / 580 |

`PointsLedger` is one multi-validator: the points policy and the note address. It enforces:
- only the retailer issues points;
- a split mints exactly one note token, and only alongside a proved transfer;
- only the owner spends a note, and one note per transaction;
- amounts are 64-bit and balance as integers, so they cannot wrap around the curve order;
- a receipt token, named after the redeemed note, can be minted only by a valid redemption, so
  receipts cannot be forged or replayed.

**Not hidden:** owners, so the transfer graph is public; and the redeemed price.

## B. Committed credential gate

A credit bureau commits to Alice's whole profile in **one vector commitment**, under the schema
`zeroj.demo.credit-profile` v1: income, credit score, birth year and country. It records the
issuance on-chain with a token whose name binds the commitment, the schema digest and Alice's key.

Alice proves `income ≥ 50,000 ∧ credit_score ≥ 650` to a lender's `CreditGatePolicy` and
receives an access badge. The lender learns that she qualifies, and not her income, score, birth
year or country.

The gate refuses:
- a claim without the issuance record (fail closed);
- a commitment relabelled under another schema, or recorded for another holder;
- proofs for weaker thresholds;
- a badge that is not paid to the holder.

**Not provided:** unlinkability, since presentations reuse the commitment. The BBS-based
`reusable-kyc` demo shows unlinkable presentations.

## C. Solvency with hidden liabilities

An exchange publishes one commitment per customer balance. It locks reserves `R` in a vault and
proves that the hidden total is at most `R`. This follows the Provisions approach from CCS 2015.

| | Merkle sum tree (`proof-of-reserves`) | Pedersen (this demo) |
|---|---|---|
| Total liabilities | Public | Hidden |
| Other customers' balances | Partial sums leak along the path | Hidden |
| A customer's check | Merkle path | Opens their own commitment |
| Auditor | Sees the total | Opens the sum of commitments, by homomorphism |

- Each customer finds their entry by `blake2b(len(id) ‖ id ‖ salt)`, checks it appears exactly
  once, and opens it.
- `SolvencyVault` keeps the reserve and the attestation fixed until `unlockAfter`. Each
  attestation locks its own reserve, so the same funds cannot back two attestations.

**Not provided:**
- borrowed reserves;
- omission, which only the customers who check will catch;
- the customer count, which is public (pad with commitments to 0 to hide it).

---

## Run

```bash
# Yaci DevKit running (yaci-cli devkit start); Java 25
sdk use java 25.0.2-graal

./gradlew test                       # circuits, checks, Plutus VM mutation tests
ZEROJ_YACI_E2E=true ./gradlew test   # + the three DevKit end-to-end tests
./gradlew run                        # narrated walkthrough of all three demos on DevKit
```

Set `ZEROJ_YACI_STORE_URL` / `ZEROJ_YACI_ADMIN_URL` if DevKit uses non-default ports. The first
run performs single-party development setups (cached in `data/`); this needs
`-Dzeroj.allowInsecureTrustedSetup=true`, which the build passes for tests and `run`.

## Measured

| Circuit | Constraints | On-chain verification (CPU / mem) |
|---|---:|---|
| `points-transfer` (in = out1 + out2) | 7,231 | 3.85e9 / 1.19M |
| `points-redeem` (in = change + price) | 4,886 | 3.64e9 / 1.08M |
| `credit-profile-check` (4 attributes, 2 predicates) | 3,047 | 3.52e9 / 0.67M |
| `hidden-liability-solvency-n4` | 10,042 | 4.41e9 / 1.25M |

## Layout

```
src/main/java/.../pedersen/
  common/       KeyedCircuit (dev keys, JSON verification), DevKit, Plutus encodings
  points/       ConfidentialPoints; circuit/PointsTransferProof, PointsRedeemProof; onchain/PointsLedger
  credential/   CreditGate; circuit/CreditProfileProof; onchain/CreditGatePolicy
  solvency/     SolvencyAttestation; circuit/HiddenLiabilitySolvencyProof; onchain/SolvencyVault
  PedersenDemos.java   the walkthrough (./gradlew run)
```

## Important

- **Dev trusted setup only.** Whoever holds the toxic waste can forge proofs. Production needs
  an MPC ceremony.
- **Openings are delivered off-chain.** The demos hand them over in-process.
- **Not audited.** These are demos of protocol patterns, not production systems; see the
  "Not provided" lists above and ADR-0006.
