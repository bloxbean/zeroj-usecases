# Digital Product Passport Demo: claims proved against auditor commitments

EU ESPR-style product passports on Cardano. An auditor measures a product and commits to each
measurement with a **Pedersen vector commitment** (`pedersen-jubjub-vector-v1`); the manufacturer
proves claims about the committed values ("carbon ≤ 50 kg", "recycled content ≥ 30 %", "made in
the EU", "three approved inspections in order") without revealing them. The passport is a public
record at its own script address: its datum carries the commitments, never the values.

Built with [ZeroJ](https://github.com/bloxbean/zeroj) (annotation circuits, Groth16 over
BLS12-381, the on-chain Groth16 verifier) and Julc. The design is
[ADR-0009](../docs/adr/0009-privacy-and-binding-hardening-of-the-original-demos.md) D1, D10 and
D11.

## Why the old design leaked

The previous version published, in each minting datum, `[productId, threshold, auditorHash,
isCompliant]` with `auditorHash = Poseidon(auditorSecret, Poseidon(productId, m))`, where `m` is
the measurement.

- `auditorSecret` was a **prover input**, so every manufacturer that proved had to know it, and
  the demo hard-coded it (`777777`) in its source.
- `m` is small: carbon and recycled content are 16-bit numbers, and a country is one of about 250
  codes. Anyone could compute `auditorHash` for all 65,536 candidates and read `m` off the chain.
  A hash of a small value with a known key hides nothing.
- The minting policy fixed neither the threshold nor `auditorHash`, so a manufacturer could prove
  against a threshold, or a value, of its own choosing. The token name was not tied to the
  product, and the same name could be minted again.
- The product registry (an MPF trie) stored every product's measurements, and `/api/dpp/status`
  returned them.

`PassportBruteForceTest` runs that 65,536-value search: it recovers the carbon value from an old
datum, and nothing from a new passport.

## The design

### Roles

| Role | Does | Trusted for |
|------|------|-------------|
| **Auditor** | Measures, commits each claim with a fresh 252-bit blinding (`SecureRandom`), gives the opening `(m…, r)` to the manufacturer, and co-signs the passport transaction after checking it against its report. Can revoke. | Measuring honestly, keeping measurements confidential, co-signing at most one passport per product. |
| **Manufacturer** | Proves claims from the opening and builds the passport transaction. | Nothing about its measurements. |
| **Reader** (customs, buyer, regulator) | Reads the passport from the chain and verifies claim proofs against its commitments. | — |

### Schemas

Each claim is one `pedersen-jubjub-vector-v1` commitment `C = (u, v)` under its own schema. The
labels and widths are normative (ADR-0009 D1).

| Claim (id) | Schema id | Entries |
|---|---|---|
| carbon ≤ (0) | `zeroj.demo.dpp.carbon`, v1 | `carbon_kg`/16 |
| recycled content ≥ (1) | `zeroj.demo.dpp.recycled`, v1 | `recycled_pct`/16 |
| origin (2) | `zeroj.demo.dpp.origin`, v1 | `country`/16 |
| inspections (3) | `zeroj.demo.dpp.inspections`, v1 | `inspector_0`/8, `time_0`/32, `inspector_1`/8, `time_1`/32, `inspector_2`/8, `time_2`/32 |

The auditor commits only passed inspections, so there is no `passed` entry.

### Circuits

Each circuit binds its schema (`ZkPedersenVector.bindSchema`: `σ` is a public input constrained to
the schema digest), opens `C` in-circuit with the witness `(m…, r)` (`commit` range-constrains each
entry to its width), and proves its rule. There is no secret shared between parties, and no
`isCompliant` output: every rule is an assertion, so a claim that does not hold has no proof.

| Circuit | Public, in order | Rule | Constraints |
|---|---|---|---|
| `CarbonClaimProof` | `σ, u, v, threshold` | `carbon_kg ≤ threshold` | 2,192 |
| `RecycledClaimProof` | `σ, u, v, threshold` | `recycled_pct ≥ threshold` | 2,192 |
| `OriginClaimProof` | `σ, u, v, countryRoot` | `country` is a leaf of `countryRoot` (depth 5, the 27 EU states) | 3,344 |
| `InspectionClaimProof` | `σ, u, v, inspectorRoot` | each `inspector_i` is a leaf of `inspectorRoot` (depth 3), and `time_0 < time_1 < time_2` | 5,094 |

- **Tree padding.** Unused leaves of the approved-set trees hold the sentinel `2^k`, where `k` is
  the committed entry's width (`2^16` for countries, `2^8` for inspectors). A committed value is
  at most `k` bits, so it never equals padding. The old trees padded with 0, which made 0 a member
  of every set (`ClaimCircuitTest` shows both).
- **Repeats.** An inspector may appear at more than one checkpoint.

### The passport transaction

One transaction, built by the manufacturer and co-signed by the auditor. Both signatures are
required; in this demo the server holds both keys (custodial, see Limitations).

`DppPassport` is a Julc multi-validator: its hash is both the passport policy and the passport
address. Its parameters are `manufacturerPkh`, `auditorPkh`, the gated claim (carbon) with its `σ`
and `threshold` (50 kg), and the carbon circuit's verification key. It mints one token named
`productId` into an output at its own address with the inline datum

```
Passport(productId: B, manufacturerPkh: B28, claims: List<Claim(claim: I, σ: B32, u: I, v: I)>)
```

listing every claim the auditor attests (at most 4). The mint redeemer carries only the proof.

**Mint checks:**
- **(a)** the manufacturer and the auditor both sign;
- **(b)** the mint map under the policy is exactly `{productId: 1}`, with a 1–32 byte `productId`;
- **(c)** exactly one output holds the token: at the passport address (payment credential, no
  stake credential), with no reference script, holding only ADA and the token, and with an inline
  datum of exactly the shape above: the product id equal to the token name, `manufacturerPkh`
  equal to the parameter, every claim entry with canonical `u, v` and a 32-byte `σ`, distinct claim
  ids, and the gated claim present with the parameter `σ`;
- **(d)** the Groth16 proof verifies against `[σ, u, v, threshold]`, with `u, v` from the gated
  claim's entry and `σ`, `threshold` from the parameters.

**Spend.** The only spend is `Revoke`: the auditor signs and the transaction burns exactly that
passport's token, `{productId: −1}`. A passport is never moved and its datum never changes, so the
datum a reader sees is the one the mint transaction checked.

Before co-signing, the auditor's signer (`CoSignGuard`) checks the finished transaction:
- the mint is exactly `{productId: 1}`, exactly one output holds the token at the passport
  address, its datum is exactly the auditor's own commitments for this product and manufacturer,
  and the auditor is a required signer;
- the auditor's signature authorises nothing else: no input or collateral at an address whose
  payment or stake credential is the auditor's key hash, and no withdrawal, certificate, vote or
  proposal (an input it cannot resolve is refused);
- the transaction has a TTL (the issue transaction is valid for 180 slots);
- the policy's mint history for the product is empty; an unavailable history refuses, which also
  covers a lost local database.

It then reserves the product for the transaction's body hash with one atomic compare-and-set in
its database, and only then signs, so concurrent or retried `/mint` requests get at most one
signature. A reservation is never released early: if its transaction reaches the chain it is
confirmed; if it does not, it is released only after its TTL has passed, when the ledger can no
longer accept it. A failed or timed-out mint therefore blocks a new attempt for that product for
up to three minutes.

### Off-chain claims and the reader

Only carbon is gated on-chain. Recycled content, origin and inspections are proved off-chain,
against the commitments in the passport datum. The datum is the authenticated issuance record
the vector spec (§6) requires: it exists only at the passport address, minted in a transaction the
auditor signed. A reader never accepts a commitment from the manufacturer's API.

The reader (`PassportReader`, `GET /api/dpp/passport/{id}`):
- finds the passport token at the passport address, and nowhere else;
- reads the policy's complete mint history for the token from the chain indexer and refuses a
  product with more than one passport ever minted, including a burn followed by a re-mint; an
  unavailable or incomplete history fails closed. The history is read in Yaci Store's format
  (`assets/{unit}/history`, every page), so this check, and the auditor's, work on **DevKit
  only**; against Blockfrost they fail closed;
- takes each claim's expected `σ` from its own schema registry, compares it with the datum's, and
  never takes `σ` from the datum;
- verifies each published proof against `[σ, u, v, param]` (threshold or approved-set root).

### Registry and API (D10)

The MPF registry (Poseidon, RocksDB) stores `productId → passport outref` and nothing else (see
[`docs/mpf-architecture.md`](docs/mpf-architecture.md)). `/api/dpp/status`, `/api/dpp/products`
and `/api/dpp/verify` return no measurements. The manufacturer's own values appear only under
`/api/dpp/manufacturer/{id}`, shown in the UI as the panel "manufacturer (private)".

The API is the operator's view of a custodial demo: the server holds the manufacturer's and the
auditor's keys and the openings. It allows no cross-origin requests (the UI is served from the
same origin). Privacy holds against chain and mempool observers, not against
this server. Authenticated operator access is the first change a real deployment needs.

### Keys (D11)

The manufacturer's and auditor's wallet keys are random 24-word wallets (256 bits of
`SecureRandom` entropy) generated on first start. They are never derived from anything published,
and their key hashes are `DppPassport` parameters.

- **Storage.** `data/manufacturer.mnemonic` and `data/auditor.mnemonic`, written atomically
  (temporary file, then rename) with owner-only permissions, next to the deployment state
  `data/dpp-deployment.properties` (both key hashes and the passport policy id).
- **Restart.** Both keys are loaded and checked against the deployment state.
- **Reset.** Only together with the deployment state: `./demo.sh dpp --clean-cache`, or delete
  `./data` when running locally.
- **Fail closed.** If the deployment state exists and a key is missing, unreadable or does not
  match the recorded key hash, or the passport policy differs from the recorded one, the demo
  stops with an error. It never silently creates a new key.
- **Funding.** On DevKit both wallets are funded through DevKit's top-up endpoint when they run
  low (`DEMO_TOPUP_ENABLED`, default `true`); elsewhere, from the funding wallet.

**Deliberately public role.** The funding wallet (`cardano.yaci.mnemonic`, DevKit's well-known
test mnemonic) pays for registry anchoring and, off DevKit, funds the two role wallets. It signs
no passport and gates nothing the demo claims about privacy or attestation; anyone can sign as it
on a devnet, and a real deployment must replace it.

## Script budget

Julc VM, the mint of a passport with four claims and the revocation, as a share of the
per-transaction limits (10,000,000,000 CPU steps, 16,500,000 memory units). Printed by
`DppPassportVmTest`.

| Transaction | CPU steps | % CPU | Memory | % memory |
|---|---|---|---|---|
| Issue (mint, Groth16 verification, 4 claims) | 2,789,042,135 | 27.9 % | 1,390,848 | 8.4 % |
| Revoke (spend + burn) | 151,057,197 | 1.5 % | 561,045 | 3.4 % |

## Migration

Demo state does not survive this upgrade. The product database (`data/dpp-passport-db`), the MPF
registry (`data/dpp-passport-registry`) and their passport references are new; files of the old
version (`data/dpp-db`, `data/dpp-trie*`, `data/setup-threshold-*.bin` and the other old circuit
keys) are not read. Start fresh: `./demo.sh dpp --clean-cache`, or delete `./data` when running
locally. Old passports minted under the previous policy are not recognised.

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Java (GraalVM) | 25 (`sdk install java 25.0.2-graal`) |
| Yaci DevKit | Latest |

## Quick Start

```bash
yaci-cli devkit start
sdk use java 25.0.2-graal
cd digital-product-passport

# Top up the funding wallet (used for registry anchoring); the manufacturer and auditor
# wallets are topped up automatically on DevKit.
curl -X POST http://localhost:10000/local-cluster/api/addresses/topup \
  -H "Content-Type: application/json" \
  -d '{"address":"addr_test1qryvgass5dsrf2kxl3vgfz76uhp83kv5lagzcp29tcana68ca5aqa6swlq6llfamln09tal7n5kvt4275ckwedpt4v7q48uhex","adaAmount":10000}'

./gradlew clean bootJar
java --enable-native-access=ALL-UNNAMED \
  -Dzeroj.allowInsecureTrustedSetup=true \
  -jar build/libs/digital-product-passport-*.jar
```

Open **http://localhost:8088**. The first start runs a single-party development setup for the
four circuits (cached in the data directory, `dpp.data-dir`); these keys are not for production.

The UI is built from `frontend/` into `src/main/resources/static` (committed): rebuild with
`./gradlew buildFrontend`, or build it with the jar using `./gradlew bootJar -PwithFrontend`.

## Demo Products

| Product | Carbon | Recycled | Country | Inspections | Outcome |
|---|---|---|---|---|---|
| BAT-SN001 (battery) | 7 kg | 45 % | DEU | 11, 13, 11 in order | passport; all four claims verify |
| BAT-SN002 (battery) | 12 kg | 38 % | DEU | 12, 14, 15 in order | passport; all four claims verify |
| BAT-SN003 (battery) | 65 kg | 20 % | DEU | 11, 12, 13 in order | no carbon proof exists, so no passport; "Skip off-chain check" submits a proof against a threshold the manufacturer chose, and the policy refuses it |
| TEX-B2024-001 (100 units) | 3 kg | 42 % | FRA | — | passport; three claims verify |
| TEX-B2024-002 (200 units) | 8 kg | 65 % | FRA | — | passport; three claims verify |
| TEX-B2024-003 (500 units) | 15 kg | 5 % | CHN | — | passport (carbon passes); recycled content and origin cannot be proved, and the reader shows no proof for them |

The table is the manufacturer's private data; the UI shows these values only in the
"manufacturer (private)" panel.

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dpp/status` | Products and batches (no values), passport policy and address, thresholds, approved-set roots, registry root |
| GET | `/api/dpp/products` | Paginated product list (no values) |
| POST | `/api/dpp/products/add` | Add random products (`count`, `type`: battery/textile) |
| POST | `/api/dpp/verify` | The auditor attests (once) and the manufacturer proves each claim (`id`); returns which claims hold, not the values |
| POST | `/api/dpp/mint` | Mint the passport (`id`, `forceOnChain`) |
| POST | `/api/dpp/revoke` | The auditor revokes the passport (`id`) |
| GET | `/api/dpp/passport/{id}` | The reader's check from chain data |
| GET | `/api/dpp/manufacturer/{id}` | The manufacturer's own values ("manufacturer (private)") |
| GET | `/api/dpp/registry`, POST `/api/dpp/anchor` | Registry root and count; anchor the root on-chain |

## Tests

```bash
./gradlew test                          # circuits, VM, keys, reader, API, brute force
ZEROJ_YACI_E2E=true ./gradlew test      # also the DevKit end-to-end test
```

| Test | Covers |
|---|---|
| `ClaimCircuitTest` | over and under the threshold, a wrong blinding, another value under the same blinding, an aliased opening `m + ℓ` (the same point), a wrong schema digest, an unlisted country, 0 against the padded tree (every path, for countries and inspectors), an unlisted inspector, equal or decreasing times: each violates a constraint in the witness calculator; honest claims prove and bind every public input |
| `DppPassportVmTest` | the honest mint is accepted; refused: no auditor or no manufacturer signature, another manufacturer's policy replaying a proof, a manufacturer impostor, a datum naming another manufacturer or product, a token name ≠ productId, an empty or 33-byte id, an extra mint entry, quantity 2, a proof for a looser threshold or another commitment, a malformed proof, non-canonical coordinates, a 31-byte `σ`, a wrong gated `σ`, a missing gated claim, duplicate claims, five claims, an unknown claim id, the passport at the manufacturer, with a stake credential or at another script, the token in two outputs, an extra token, a hashed datum, extra fields; any spend but an auditor-signed burn (transfer, datum change, revoke without the auditor, burning another token, burn and mint, burn of 2); an auditor-only revoke is accepted |
| `PassportBruteForceTest` | the 65,536-value search over every published field (datum, token name, redeemer) recovers nothing; it recovers the value from an old datum |
| `RoleKeysTest` | random 24-word owner-only keys, unique per install; survive a restart; a deleted, corrupted or mismatched key with deployment state fails closed; the policy id is bound |
| `PassportReaderTest` | duplicate and re-minted passports are refused; the mint history is paged and fails closed; σ comes from the reader's registry |
| `AuditorCoSignTest` | the auditor refuses another datum, another address, an extra mint, two tokens, a missing signer slot, an input or collateral at its own address or stake credential, an unresolvable input, a withdrawal or a certificate |
| `CoSignGuardTest`, `AuditorReservationTest` | concurrent co-sign requests (in memory, and racing on the auditor's database) yield exactly one signature; a retry after an unknown outcome is refused until the TTL has passed off-chain; a landed transaction is confirmed and never released; a non-empty or unavailable mint history, or a missing TTL, refuses |
| `DppApiPrivacyTest` | `/status`, `/products`, `/verify`, `/passport/{id}` and `/registry` return no measurement, as a number or a string; only the private panel does |
| `DppPassportDevKitE2ETest` | on DevKit: refused mints (no auditor, another manufacturer's policy, the manufacturer's own threshold), the auditor refusing a datum that is not its report, the passport, the auditor refusing a second passport, a refused transfer and manufacturer revoke, the auditor's revoke, and the mint history |

## Limitations

- **The auditor** sees every measurement, could collude with a manufacturer, and alone ensures one
  passport per product (it co-signs once). A second passport under the same policy is publicly
  visible, and readers refuse the product.
- **A passport reveals which product has which claims**, but not the values. A very small approved
  set (one country) reveals the value.
- **Custodial demo.** This server holds the manufacturer's and the auditor's keys and the
  openings; its API is the operator's view.
- **Delivering openings to a regulator** is not part of this demo (ADR-0009 D1 item 6: vector
  openings need their own reviewed design).
- **Development setup.** The circuit keys come from a single-party setup
  (`-Dzeroj.allowInsecureTrustedSetup=true`); production needs keys from an MPC ceremony.
- **Not externally reviewed.** The ZeroJ profiles keep their own restrictions and audit gates
  (`pedersen-jubjub-v1` §9).

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Commitments | ZeroJ `pedersen-jubjub-vector-v1` |
| ZK proofs | ZeroJ annotation circuits, Groth16, BLS12-381, pure Java |
| On-chain | Julc → Plutus V3 multi-validator `DppPassport` |
| Registry | MPF + Poseidon + RocksDB |
| Backend | Spring Boot 3.5.0-M3 |
| Frontend | Svelte 5 + Vite |
| Cardano client | cardano-client-lib |
