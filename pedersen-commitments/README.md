# Pedersen Commitment Demos on Cardano

Five use cases built on ZeroJ's Pedersen commitments (`pedersen-jubjub-v1` and
`pedersen-jubjub-vector-v1`, ZeroJ ADR-0051), confidential notes (`confidential-note-jubjub-v1`,
ZeroJ ADR-0055) and exponential ElGamal (`elgamal-jubjub-v1`, ZeroJ ADR-0052). Each one runs end to end on Yaci DevKit:
- circuits proved with pure-Java Groth16 on BLS12-381;
- Plutus V3 validators written in Java with Julc;
- transactions built with cardano-client-lib.

A web UI (Spring Boot + Svelte, port **8093**) has one tab per demo. Each tab shows the
**private** side (the openings the wallets hold) next to the **on-chain** side (what anyone can
read), and offers "try to cheat" actions that end in "no proof possible" or a validator
rejection. A CLI walkthrough and the test suites run the same flows.

Design and threat model: [ADR-0006](../docs/adr/0006-pedersen-commitment-demos.md),
[ADR-0007](../docs/adr/0007-confidential-notes-in-pedersen-demos.md) (notes, payroll, solvency
deliveries) and [ADR-0008](../docs/adr/0008-sealed-bid-auction-enforced-disclosure.md) (auction).

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

## A. Confidential points — notes with on-chain delivery and an enforced auditor amount

A retailer's loyalty points are **notes** (ZeroJ ADR-0055 `confidential-note-jubjub-v1`; this repo's
ADR-0007). Each note carries:
- the owner and the Pedersen commitment `C = [v]·G + [r]·H` to its amount;
- the opening `(v, r)` encrypted on-chain to the owner and to an **auditor** (Sapling-style
  key agreement, BLAKE2b KDF, ChaCha20-Poly1305): wallets and the auditor recover every note from
  chain data alone;
- the amount as two 32-bit `elgamal-jubjub-v1` limb ciphertexts to the auditor, which the transfer
  proof binds to the commitment (ADR-0055 D3a): the auditor's amount is **enforced**, not just
  delivered.

| Step | On-chain | Hidden |
|---|---|---|
| The retailer issues Alice 1,000 points | Owner, commitment, limbs, deliveries | 1,000 |
| Alice sends Bob 700 and keeps 300 | Two new notes and a proof that `in = out1 + out2` and that both notes' limbs encrypt their amounts | 1,000 / 700 / 300 |
| Bob pays 120 at the retailer and keeps 580 | Price 120, a change note, a receipt token for the retailer | 700 / 580 |

`NoteLedger` is one multi-validator: the note policy and the note address. It enforces:
- only the retailer issues (trusted for supply and for issued notes' audit data);
- every note output sits at the ledger's **exact** address with exactly one token and the
  current auditor key generation (no stake-credential variants: ADR-0055 M3 criterion (a));
- transfers and redemptions prove the balance and the auditor limbs, against the key read from
  the auditor's registry (`AuditorRegistry`: a singleton entry whose two possession proofs are
  verified on-chain, rotated under the auditor's signature);
- only the owner spends a note, one note per transaction; receipts cannot be forged or replayed.

Wallets count a note only if its delivery opens **and** it names them as owner; an owned note
that does not open is reported as **unopenable**. The auditor reads each amount from the limbs
and labels it *proof-enforced* or *issuer-claimed*.

**Not hidden:** owners (the transfer graph), the redeemed price, the reader policy.

## Confidential payroll — proof-enforced issuance

The same ledger with **proved issuance** (ADR-0055 Q9 (b)): the employer pays one or two salaries
per transaction with a proof that each salary note's limbs encrypt its committed amount to the
tax authority's registered key. The tax authority reads every salary from the chain — including
payslips already transferred or cashed out — and an employer that tries to under-report one has
no proof. Employees read their payslips with their viewing keys.

## Sealed-bid auction — enforced bid disclosure (ADR-0008)

Each bid is encrypted to the auctioneer with a proof that it lies between the reserve and the
common deposit, so a bidder cannot refuse to reveal (there is no reveal phase). The lot is one
state UTxO; bids are appended with their deposits. After the bidding window the auctioneer
decrypts every bid and proves — reusing the ElGamal encryption relation with its own secret as the
randomness and each bid's handle as the key — that the named bid is the earliest highest one at
its amount. Losers get their deposits back, the seller the price, the winner the item and the
change; every payout is tagged with the lot's unique token. If the auctioneer never settles,
anyone can refund after the deadline.

**Trust:** the auctioneer sees every bid (it could leak them); losing bids never appear on chain.
Three distinct keys can fill a lot (no sybil protection in the demo).

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
  appears exactly once, and open its **on-chain delivery** with their own viewing key: the opening
  comes from the chain, not from the exchange, and an entry that does not open is evidence.
- The attestation also carries the total's opening encrypted to the auditor's registered key; the
  auditor opens it against the sum of the on-chain commitments.

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

On first start the app compiles the circuits and runs single-party **development** setups,
cached in `data/` and keyed by an R1CS digest. It also creates and funds its demo wallets with
DevKit's top-up API. `/api/status` reports each demo as `ready`; the UI waits for that.

What each tab does:

| Tab | Steps | Try to cheat |
|---|---|---|
| A. Confidential points | The retailer issues points; holders transfer them (amounts hidden) and redeem at a public price; wallets and the auditor read everything from the chain; the auditor can rotate its keys. | Transfer more than the largest note holds: no proof. A garbage delivery: unopenable for the recipient, the auditor still reads the amount. Under-report an issuance: accepted but flagged issuer-claimed. Limbs to the retired key, or a note at a stake-variant address: the ledger rejects it. Spend someone else's note: rejected. |
| Confidential payroll | The employer pays salaries (proved issuance); employees read payslips; the tax authority sees every salary and its history. | Under-report a salary: no proof. A garbage payslip, or limbs to the retired key, as above. |
| Sealed-bid auction | The seller lists an item; three bidders bid sealed amounts within a 2-minute window; the auctioneer settles with a proof; refund after the deadline. | Bid above the deposit: no proof. Copy another bidder's proof: rejected. Name a later or lower bid as the winner: no proof. |
| B. Committed credential | The bureau issues a profile (four attributes, one commitment) and records it; Alice claims a badge against the lender's thresholds. | A threshold above her profile: no proof possible. Mallory presents Alice's commitment with a valid proof: the gate rejects it, because the record names Alice. |
| C. Hidden-liability solvency | Edit the book (4 customers); attest with locked reserves for a period that starts about 45 s later and lasts 180 s; customers decrypt their entries from the chain; the auditor opens the total from its delivery; release after the period. | Lock less than the book: no proof. A garbage delivery for one customer: their check reports it unopenable. Attest again, or release, inside the period: the vault rejects it. |

Configuration (`application.yml`, or environment variables with Spring's relaxed binding):
- `cardano.yaci.base-url` and `cardano.yaci.admin-url`;
- `cardano.blockfrost.base-url`, which overrides the provider;
- `solvency.period-lead-seconds` and `solvency.period-length-seconds`;
- `auction.bidding-seconds` and `auction.settle-seconds`.

**CLI walkthrough and tests.**

```bash
./gradlew walkthrough                # narrated run of demos A–C on DevKit (no UI)
./gradlew test                       # circuits, checks, Plutus VM mutation tests
ZEROJ_YACI_E2E=true ./gradlew test   # + the DevKit end-to-end tests (points, payroll, auction, credit, solvency)
```

The walkthrough and the tests read `ZEROJ_YACI_STORE_URL` / `ZEROJ_YACI_ADMIN_URL` when DevKit
uses non-default ports. Script rejections in the tests are the scripts failing in local Julc
evaluation of the real transaction, as the node would run them; rejected transactions are not
submitted.

## Measured

Complete transactions (every script purpose), as a share of `maxTxExecutionUnits` (10e9 steps,
16.5e6 memory); ADR-0055 adopts its auditor relation only within 80%.

| Transaction | Constraints | Steps | Memory |
|---|---:|---|---|
| Points/payroll transfer (`note-transfer`, 24 public inputs) | 34,184 | 76.8% (DevKit) | 16.2% |
| Points/payroll redeem (`note-redeem`, 15) | 18,366 | 58.3% (DevKit) | 12.7% |
| Payroll pay run, 1 / 2 salaries (`note-issue`) | 15,890 / 31,773 | 50.8% / 71.8% (VM) | 9.0% / 13.7% |
| Auction bid (`sealed-bid`) | 7,011 | 51.0% (VM) | 22.0% |
| Auction settle, 3 bids (`sealed-bid-settle-n3`) | 19,710 | 65.6% (VM) | 25.4% |
| Auditor registry Init / Rotate (two possession proofs) | 6,548 each | 77.8% / 78.3% (DevKit) | 8.6% / 9.5% |
| `credit-profile-check` | 3,047 | 3.52e9 | 0.67M |
| `hidden-liability-solvency-n4` | 10,042 | 4.41e9 | 1.25M |

## Layout

```
src/main/java/.../pedersen/
  common/       KeyedCircuit (dev keys, JSON verification), DevKit, Plutus encodings
  notes/        confidential notes (ADR-0007): AuditorRegistry, NoteLedger, VkLib (on-chain);
                note-transfer/redeem/issue and key-possession circuits; wallet (NoteWallet),
                auditor (AuditorView), keys and registry admission, transaction builders
  auction/      sealed-bid auction (ADR-0008): SealedBidAuction, bid and settle circuits, AuctionScript
  credential/   CreditGate; circuit/CreditProfileProof; onchain/CreditGatePolicy
  solvency/     SolvencyAttestation; circuit/HiddenLiabilitySolvencyProof; onchain/SolvencyVault
  web/          Spring services and REST API behind the UI (NoteDemo with PointsService and
                PayrollService, AuctionService, CreditService, SolvencyService, DemoController)
  PedersenCommitmentsApplication.java   the web app (port 8093)
  PedersenDemos.java                    the CLI walkthrough (./gradlew walkthrough)
frontend/       Svelte 5 + Vite UI, built into src/main/resources/static
```

## Important

- **Dev trusted setup only.** Whoever holds the toxic waste can forge proofs. Production needs
  an MPC ceremony.
- **Demo custody.** The web demo's server holds every wallet's spending and viewing keys and the
  auditors' keys, and scans the chain on their behalf; its API is unauthenticated. Real wallets
  scan in their own process (ADR-0055 D9: never as a shared or network-facing service).
- **Unreviewed assumptions.** The note delivery profile rests on ADR-0055's assumptions A1–A3,
  and the auction's settlement relation is this repo's own composition (ADR-0008); both need
  external review.
- **Not audited.** These are demos of protocol patterns, not production systems; see the
  "Not provided" lists above and ADR-0006.
