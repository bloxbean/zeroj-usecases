# Proof of Reserves Demo — ZK Solvency on Cardano

A custodian proves that its declared reserves cover the sum of its customers' balances **without
publishing any balance**, and each customer checks against the chain that their balance is in the
attested tree. Uses a salted Poseidon Merkle tree and a Groth16 proof that is verified by the
minting policy of an on-chain attestation token.

Built with [ZeroJ](https://github.com/bloxbean/zeroj) — a pure Java ZK toolkit for Cardano. The
design is [ADR-0009](../docs/adr/0009-privacy-and-binding-hardening-of-the-original-demos.md) D4,
D10 and D11.

## What This Demo Does

1. **Register accounts** with balances (simulated customer deposits).
2. **Build a salted tree.** Every snapshot gives every account a fresh 252-bit salt; the leaf is
   `Poseidon(Poseidon(idTag, salt), balance)`.
3. **Prove solvency.** The proof shows declared reserves ≥ the sum of the balances, every balance
   is a 64-bit non-negative value, and the balances are the tree's leaves.
4. **Attest on-chain.** The custodian mints this period's attestation token. The minting policy
   verifies the proof against the token's own datum, so only a solvent statement mints.
5. **Customer check.** The customer page recomputes the root in the browser, reads the period's
   attestation token from the chain indexer (Yaci Store), refuses a period that was attested more
   than once, and compares the roots.

## Who sees what (demo operator view)

- The demo server is the custodian. It holds every balance and the custodian key, and its API
  answers anyone. **`/accounts` and `/verify/{id}` are the demo custodian's operator view**: they
  list every balance and hand out any customer's salt (as does the H2 console at `/h2-console`). In a real deployment a customer would get
  only their own inclusion data, after authenticating; authenticated operator access is the first
  production change.
- Privacy in this demo holds **against chain observers**, not against the demo server.
- The API sends no CORS headers, so other websites open in the operator's browser can't read it;
  the UI is served from the same origin (and the Vite dev server proxies `/api`).

## Quick Start

```bash
yaci-cli devkit start
sdk use java 25.0.2-graal
cd proof-of-reserves

./gradlew clean bootJar
java --enable-native-access=ALL-UNNAMED \
  -Dzeroj.allowInsecureTrustedSetup=true \
  -jar build/libs/proof-of-reserves-*.jar
```

Open **http://localhost:8089** (or run `./demo.sh proof-of-reserves` from the repo root).

- On first start the demo creates, in `./data/`:
  - a development Groth16 setup cache (a few minutes for the default depth-4 circuit; later runs
    reuse it);
  - the custodian's wallet key `custodian-wallet.key` (random, owner-only);
  - the attestation deployment `reserves-deployment.properties` (custodian key hash, `genesisMs`,
    `periodMs`, policy id). `genesisMs` is the chain tip's time at first deployment, because
    periods are judged against chain time;
  - after each attestation, `attested-snapshot.json` (owner-only): the attested tree's salts,
    salted ids and balances, so `/verify` still serves the attested tree after a restart. A file
    that does not reproduce its own root stops startup.
- The custodian wallet is funded through DevKit's top-up API (`cardano.yaci.admin-url`) before its
  first transaction. Set `DEMO_TOPUP_ENABLED=false` to fund it yourself.
- **Reset.** Delete `./data/` (or `./demo.sh proof-of-reserves --clean-cache`). The key, the
  deployment state and the attested snapshot are always removed together; that is a fresh
  deployment with a new policy id.
- Every file above is written atomically (temporary file, fsync, rename, directory fsync).
  The snapshot is written right after the attestation is minted; a crash between the two loses
  it, and customers then can't check that period.
- **Fail closed.** If the deployment state exists but the key is missing, corrupt or does not match
  it, or the state does not reproduce its policy id (for example after the setup cache was
  regenerated), the demo refuses to start. It never creates a replacement key for an existing
  deployment.
- **Upgrading from an earlier version.** Leaves, scripts and the custodian key changed, so earlier
  demo state does not carry over: clear `./data/` (or the Docker volume with `--clean-cache`).

The customer page reads Yaci Store directly from the browser at `reserves.customer-indexer-url`
(default `http://localhost:8080/api/v1/`, the same indexer as `cardano.yaci.base-url`). Yaci
Store allows cross-origin reads; if the indexer can't be reached, the check fails.

To run the gated Yaci DevKit E2E test:

```bash
ZEROJ_YACI_E2E=true ./gradlew test --tests '*ProofOfReservesYaciE2ETest'
```

## Test Scenarios

| Scenario | Reserves | Liabilities | Result |
|----------|----------|------------|--------|
| Solvent | 10,000 ADA | 8,500 ADA | ✅ attestation token minted (policy verified the proof) |
| Insolvent | 5,000 ADA | 8,500 ADA | ❌ refused off-chain; with "skip off-chain check", the minting policy rejects |
| Second attestation in the same period | — | — | ❌ refused by the custodian service (and every customer page would refuse the period) |
| Customer check | — | — | ✅ Alice's leaf recomputes to the attested root, read from Yaci Store |

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/reserves/status` | Account count, total liabilities, tree status |
| GET | `/api/reserves/deployment` | Attestation policy id, script address, `genesisMs`, `periodMs`, custodian key hash, customer indexer URL |
| GET | `/api/reserves/accounts?page=0&size=20` | Paginated account list (**operator view**) |
| POST | `/api/reserves/accounts/add` | Add random accounts (`count`) |
| POST | `/api/reserves/build-tree` | Build a fresh salted tree |
| POST | `/api/reserves/prove` | Prove solvency and mint the current period's attestation (`reservesAda`, `forceOnChain`) |
| GET | `/api/reserves/verify/{accountId}` | The account's salt, balance, leaf index and sibling path (**operator view**) |

## How It Works

### Salted tree

```
idTag    = fold(Poseidon2, tag("zeroj.reserves.id.v1"), [len, c_0, …, c_k])
leaf     = Poseidon(Poseidon(idTag, salt), balance)
node     = Poseidon(left, right)
root     = the top node
```

- `tag(s)` is the integer of `blake2b_256(UTF-8(s))` with its top byte cleared; `Poseidon2` is
  ZeroJ's `PoseidonHash` over `PoseidonParamsBLS12_381T3`.
- `len` is the account id's UTF-8 byte length and `c_i` are its bytes in 31-byte big-endian chunks,
  the last right-padded with zeros (an empty id has no chunks);
  `fold(f, a, [x_0, …]) = f(…f(f(a, x_0), x_1)…)`.
- `salt` is 252 bits from `SecureRandom`, fresh for every account in every snapshot. Unused leaves
  get a random id and balance 0, so they look like any other leaf.
- **Internal nodes carry no sums.** They hash their two children only. The total of the balances is
  not stored in the tree; the circuit proves it equals the published `totalLiabilities`.

Without the salt, anyone holding a neighbour's leaf (a sibling on their own path) could try every
plausible balance. With it, a leaf reveals nothing guessable
(`NeighbourBalanceBruteForceTest`).

### ZK circuit (`SolvencyProof`, unchanged)

Public inputs `[totalReserves, liabilitiesRoot, totalLiabilities, isSolvent]`; the witness is the
salted ids (`Poseidon(idTag, salt)`) and the balances. It proves:

1. every balance is a 64-bit non-negative value;
2. the Poseidon tree of `Poseidon(saltedId, balance)` leaves has root `liabilitiesRoot`;
3. the balances sum to `totalLiabilities`;
4. `isSolvent = (totalReserves ≥ totalLiabilities)`.

### On-chain attestation (`ReserveAttestation`)

One Julc multi-validator is the attestation policy and the attestation address. Parameters: the
custodian's key hash, `genesisMs`, `periodMs` (> 0) and the verification key. Period `p` is
`[genesisMs + p·periodMs, genesisMs + (p+1)·periodMs)` in POSIX ms.

- **Mint (attest).** With the custodian's signature, the mint map under the policy is exactly
  `{I2OSP8(p): 1}` (8-byte big-endian period), and the token goes to the single output at exactly
  the script's enterprise address (payment credential, no stake credential), holding lovelace and
  the token only, with inline datum `Attestation(period, liabilitiesRoot, totalLiabilities,
  totalReserves)`. The Groth16 proof (the redeemer) must verify against
  `[totalReserves, liabilitiesRoot, totalLiabilities, 1]` read from that datum, so an insolvent
  statement cannot mint.
- **Spend (release).** The only spend is a custodian-signed burn of the spent output's token
  (`{I2OSP8(p): −1}`) in a transaction whose validity range has a finite lower bound at or after the
  period's end. An unbounded lower bound is refused. The datum never changes while the token exists.
- A datum at the address without the token proves nothing; readers look only for the token.

### Customer check

The customer page (and `CustomerCheck.java`, which runs the same fixtures):

1. gets its salt, balance, leaf index and path from `/verify/{id}`, and recomputes the root in the
   browser;
2. takes the current period from the indexer's latest block and the **pinned** policy id,
   `genesisMs` and `periodMs` (stored in the browser on first use; the page warns if the custodian
   later reports different ones). The indexer URL is not pinned: it defaults to the configured
   `reserves.customer-indexer-url` and the customer can override it;
3. looks up the unspent output holding `policyId ‖ I2OSP8(p)` in Yaci Store: exactly one, at the
   script's enterprise address, with a well-formed `Attestation` datum for period `p`;
4. reads the token's whole mint history, page by page, and refuses the period unless it shows
   exactly one mint of quantity 1 and no burn (so two separate mints, or a burn followed by a
   re-mint, are refused). An unavailable, inconsistent or over-long history fails closed;
5. compares the attested root with its own.

The customer also compares the balance shown with their own records.

## Limitations

- **The proof checks the sum, not that the balances are true.** The custodian chooses the balances
  it puts in the tree; a customer's check covers only their own leaf.
- **`totalReserves` is declared by the custodian.** Nothing checks it against on-chain holdings.
- **One attestation per period is the custodian's word.** The script does not prevent a second
  mint for a period; it is publicly visible, and the customer check refuses such a period. Without
  that check, a custodian could split liabilities across several trees against the same reserves.
  The script also does not tie the mint to the period's time window; the customer check looks only
  at the current period.
- **The proof is not bound to its period.** The period appears only in the token name and datum,
  not in the proof's public inputs. A custodian could therefore re-attest an old solvent tree for
  a new period (the same root, liabilities and reserves), and customers would see their old
  balances. The customer's comparison of the balance with their own records is what catches it.
- **Indexer and page trust.** The customer trusts the indexer they point the page at to report the
  chain faithfully. In this demo the customer page itself is served by the custodian, and the
  policy id and clock it pins on first load come from the custodian's own `/deployment`. A custodian
  that served a different page or policy on first load would defeat the check. A real customer
  takes the policy id and clock from a published, independent source, and runs the check from code
  they trust (a wallet, an extension, or a page from a third party).
- **Operator view.** As above, the demo server holds all balances and salts and answers anyone.
- **Development trusted setup.** The Groth16 setup is single-party and for development only.
- Not externally reviewed.

## Tests

- `ReserveAttestationVmTest` — the validator in the Plutus VM with real proofs: an honest mint and
  a burn from exactly the period end are accepted; a bad proof, an insolvent statement, two tokens,
  a wrong datum, an output outside the script address (or with a stake part), a spend without a
  burn, a lower bound of `end − 1` and an unbounded lower bound are among the rejected mutations.
- `CustomerCheckTest` and `frontend/test/customerCheck.test.mjs` (`npm test`) — the Java and
  browser checks over `src/test/resources/customer-check-fixtures.json`: a correct path passes; a
  tampered path, a fake attestation, a stale period, duplicate mints (also across pages and after a
  burn) and unavailable or incomplete history fail.
- `ReserveLeavesTest` — id-encoding vectors (empty id, 31 and 32 bytes, leading zero bytes) from
  ZeroJ's Poseidon; fresh salts per snapshot.
- `NeighbourBalanceBruteForceTest` — guessing a neighbour's balance from its leaf fails without
  the salt.
- `CustodianKeyStoreTest`, `ReserveDeploymentTest` — the custodian key is random and owner-only,
  survives a restart, and a deleted, corrupt or mismatched key fails closed.
- `BrowserPoseidonParamsTest` — the browser's Poseidon constants are ZeroJ's.

Run `./gradlew test` (and `./gradlew test -PwithFrontend` to rebuild the UI and run the browser
tests too).

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Spring Boot 3.5.0-M3, H2 (persistent accounts) |
| ZK Proofs | ZeroJ (Groth16, BLS12-381, pure Java, Groth16SetupCache) |
| On-chain | Julc → Plutus V3 multi-validator (minting policy + spending validator) |
| Frontend | Svelte 5 + Vite; customer check in plain JS (BigInt Poseidon) |
| Devnet | Yaci DevKit, Yaci Store |
