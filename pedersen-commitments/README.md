# Pedersen Commitment Demos on Cardano

Three small use cases built on ZeroJ's Pedersen commitments (`pedersen-jubjub-v1` and
`pedersen-jubjub-vector-v1`, ZeroJ ADR-0051). Each one runs end to end on Yaci DevKit:
- circuits proved with pure-Java Groth16 on BLS12-381;
- Plutus V3 validators written in Java with Julc;
- transactions built with cardano-client-lib.

A web UI (Spring Boot + Svelte, port **8093**) has one tab per demo. Each tab shows the
**private** side (the openings the wallets hold) next to the **on-chain** side (what anyone can
read), and offers "try to cheat" actions that end in "no proof possible" or a validator
rejection. A CLI walkthrough and the test suites run the same flows.

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

- Solvency is attested for a public **period**, and each period has its own vault script.
  Attestations can be made only **before** the period starts and released only **after** it
  ends. So every attestation of the period is locked at the same time, and the same funds cannot
  back attestations one after another.
- During the period each customer derives the period's vault script themselves and reads every
  attestation it holds. They check that their entry, found by `blake2b(len(id) ‖ id ‖ salt)`,
  appears exactly once, and then open it.

**Not provided:**
- borrowed reserves, held for the period;
- protection against a setup the exchange ran itself: the verification key must come from a
  setup the exchange cannot subvert;
- omission, which only the customers who check will catch;
- the customer count, which is public (pad with commitments to 0 to hide it).

---

## Run

Yaci DevKit must be running (`yaci-cli devkit start`), with Java 25 (`sdk use java 25.0.2-graal`).

**Web UI.**

```bash
./gradlew clean bootJar -PwithFrontend      # builds the Svelte UI into the jar
java --enable-native-access=ALL-UNNAMED -Dzeroj.allowInsecureTrustedSetup=true \
  -jar build/libs/pedersen-commitments-*.jar
# open http://localhost:8093
```

You can also start it from the repository root with Docker: `./demo.sh pedersen` (add `--run`
for a scripted happy path). The image needs a ZeroJ release that includes the Pedersen
commitment profiles (ADR-0051). Until that release, use the jar above, which builds against the
version in `version.properties`.

On first start the app compiles the four circuits and runs single-party **development** setups,
cached in `data/` and keyed by an R1CS digest. It also creates and funds its demo wallets with
DevKit's top-up API. `/api/status` reports each demo as `ready`; the UI waits for that.

What each tab does:

| Tab | Steps | Try to cheat |
|---|---|---|
| A. Confidential points | The retailer issues points; holders transfer them (amounts hidden) and redeem at a public price (a receipt token goes to the retailer). | Transfer more than the largest note holds: no proof possible. Spend someone else's note: the script rejects it. |
| B. Committed credential | The bureau issues a profile (four attributes, one commitment) and records it; Alice claims a badge against the lender's thresholds. | A threshold above her profile: no proof possible. Mallory presents Alice's commitment with a valid proof: the gate rejects it, because the record names Alice. |
| C. Hidden-liability solvency | Edit the book (4 customers); attest with locked reserves for a period that starts about 45 s later and lasts 180 s; customers check; the auditor opens the total; release after the period. | Lock less than the book: no proof possible. Attest again, or release, inside the period: the vault rejects it. |

Configuration (`application.yml`, or environment variables with Spring's relaxed binding):
- `cardano.yaci.base-url` and `cardano.yaci.admin-url`;
- `cardano.blockfrost.base-url`, which overrides the provider;
- `solvency.period-lead-seconds` and `solvency.period-length-seconds`.

**CLI walkthrough and tests.**

```bash
./gradlew walkthrough                # narrated run of all three demos on DevKit (no UI)
./gradlew test                       # circuits, checks, Plutus VM mutation tests
ZEROJ_YACI_E2E=true ./gradlew test   # + the three DevKit end-to-end tests
```

The walkthrough and the tests read `ZEROJ_YACI_STORE_URL` / `ZEROJ_YACI_ADMIN_URL` when DevKit
uses non-default ports. Script rejections in the tests are the scripts failing in local Julc
evaluation of the real transaction, as the node would run them; rejected transactions are not
submitted.

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
  web/          Spring services and REST API behind the UI (PointsService, CreditService,
                SolvencyService, DemoController, DemoErrors, Funding)
  PedersenCommitmentsApplication.java   the web app (port 8093)
  PedersenDemos.java                    the CLI walkthrough (./gradlew walkthrough)
frontend/       Svelte 5 + Vite UI, built into src/main/resources/static
```

## Important

- **Dev trusted setup only.** Whoever holds the toxic waste can forge proofs. Production needs
  an MPC ceremony.
- **Openings are delivered off-chain.** The demos hand them over in-process. The web demo's
  server holds every wallet's keys and openings on the users' behalf, and its API is
  unauthenticated.
- **Not audited.** These are demos of protocol patterns, not production systems; see the
  "Not provided" lists above and ADR-0006.
