# Account-Ownership Proof CLI

Prove — in zero knowledge — that you know the HD-wallet **root key** behind a Cardano address, and
verify that proof **off-chain** or **on-chain**. The circuit re-derives the full CIP-1852 path
(`m/1852'/1815'/account'/0/index`) from your secret root key and checks it reaches the address's
payment key hash. The proof reveals nothing about your seed.

Built on [ZeroJ](https://github.com/bloxbean/zeroj) (Groth16 over BLS12-381, Java 25). Design
rationale: `docs/adr/0001-account-ownership-proof-cli.md`.

---

## Commands

| command | who / when | what |
|---|---|---|
| `export-r1cs` | coordinator, once | export the circuit `.r1cs` for an **external** snarkjs ceremony |
| `import`      | coordinator, once | import a finalized ceremony `.zkey` → key bundle (no snarkjs) |
| `setup`       | anyone, testing   | generate a **local, dev-only** key bundle (single-party) |
| `prove`       | user, each proof  | generate a proof from your mnemonic |
| `verify`      | user, each proof  | check a proof off-chain (default) or on-chain |
| `info`        | anyone            | inspect a key bundle |

## Where each step runs

- **Externally (outside this tool):** the multi-party **phase-2 ceremony** — `snarkjs groth16 setup`
  / `zkey contribute` / `zkey beacon`. This CLI never runs snarkjs. Feed it with `export-r1cs`, run
  the ceremony wherever you like, then `import` the finalized `.zkey`.
- **Locally (this tool, pure Java):** `export-r1cs`, `import`, `setup`, `prove`, `verify`, `info`.
  No snarkjs, no powers-of-tau, no downloads.
- **For a quick demo:** run `setup` **once** to generate the `.bin` key bundle, then **keep/cache it**
  and reuse it forever — anyone with the bundle can `prove`/`verify` in ~5 min with no setup. (This
  is a dev-only key; for production, publish a bundle from the ceremony `import` path instead.)

---

## Quick start (user)

```bash
unzip account-ownership-recovery-cli-*.zip && cd account-ownership-recovery-cli

# drop the published key bundle into ./keys  (pointsA.bin … pointsL.bin, aux.bin, vk.json,
# bundle.properties, SHA256SUMS), then:
bin/account-ownership-recovery-cli info                 # inspect the bundle
bin/account-ownership-recovery-cli prove --account 0 --index 0   # prompts for mnemonic (hidden)
bin/account-ownership-recovery-cli verify               # off-chain, <1 s
bin/account-ownership-recovery-cli verify --onchain     # on-chain (defaults to local Yaci DevKit)
```

Your mnemonic is read from a **hidden prompt only** — never a command-line argument, environment
variable, or file — and never leaves the process. Only `proof.json` + `public-inputs.json` are written.

---

## Producing a key bundle (coordinator)

**Real, trustworthy bundle — ceremony runs externally:**
```bash
# 1. export the circuit for the ceremony
bin/account-ownership-recovery-cli export-r1cs --out circuit.r1cs

# 2. run the phase-2 ceremony EXTERNALLY with a prepared BLS12-381 ptau (power >= 25):
#      snarkjs groth16 setup circuit.r1cs pot25_final.ptau circuit_0000.zkey
#      snarkjs zkey contribute circuit_0000.zkey circuit_0001.zkey --name="c1" -v   (one per contributor)
#      snarkjs zkey beacon     circuit_0001.zkey circuit_final.zkey <hashHex> 10
#      snarkjs zkey verify     circuit.r1cs pot25_final.ptau circuit_final.zkey

# 3. import the finalized key (pure Java, no snarkjs)
bin/account-ownership-recovery-cli import --zkey circuit_final.zkey
```
The `.ptau` (phase 1) is universal — **reuse** an attested BLS12-381 one (Filecoin, Zcash), you don't
generate it. A BN254 ptau (e.g. the PSE Perpetual Powers of Tau) is the wrong curve and won't work.

**Local dev bundle — for testing/demo only:**
```bash
bin/account-ownership-recovery-cli setup --i-understand-insecure
```
Single-party setup (~6–7 min, ~12 GB heap — ADR-0035; a 16 GB machine works). **Insecure:** this machine learns the setup randomness and
could forge proofs. Generate once, cache the bundle, reuse for demos. Never publish a production
bundle from this path.

See **USAGE.md** for every command and option.

---

## Measured performance (19,075,097-constraint circuit, 12-core / 128 GB box)

| step | time | notes |
|---|---|---|
| `setup` (local) | **~6.3 min** | one-time, ~12 GB heap — fits a 16 GB machine (ADR-0035); also writes `r1cs.bin` so the first prove skips its compile |
| key bundle on disk | **~9.6 GB** (sparse, the default — ADR-0035 M6; ~57% of points are infinity and are stored as 1 bit each) | mmap-loaded (instant), not read into the JVM heap; dense ~24 GB via `setup --dense`, imports stay dense |
| `prove` (first run) | **~2.4 min** | ~17 s compile (then cached to `keys/r1cs.bin`, ~0.9 GB) + witness + ~1.9 min prove |
| `prove` (cached) | **~2.1 min** | compile skipped — ~14 s witness + ~1.9 min prove (ADR-0033/0034; java and blst backends measure the same) |
| `verify` (off-chain) | **~0.2 s** | reads the small `vk.json` |
| `verify --onchain` | **~5 s** | one lock + one unlock tx on Yaci DevKit |

**Hardware:** proving needs **~10 GB+ RAM** (measured floor: 8 GB heap on the first run, 7 GB once
`r1cs.bin` is cached; 6 GB does not work — ADR-0034. This was ~70 GB before ADR-0033/0034). The
23 GB key bundle is memory-mapped, so it uses the page cache, not the heap — **an ordinary 16 GB
machine proves in ~2.6 min** (validated under a hard 16 GiB memory cap). The default prover is
pure Java (same speed as blst at this size, no native memory); `--backend blst` opts into the
native MSM, which needs ~10 GB beyond the heap and suits ≥24 GB machines. `setup` still needs a
~12 GB of heap (ADR-0035) — the same 16 GB machine that proves. Verification is light.

---

## Distributions

| distribution | build | best for |
|---|---|---|
| **fat-jar zip** (`./gradlew distZip`) | any JDK 25 | everything — especially `prove`/`setup` (fast blst prover, auto-sized heap) |
| **native binary zip** (`./gradlew nativeDistZip`, GraalVM) | GraalVM JDK 25 | `verify` + `info` — single file, no JVM, instant startup (verify ~0.1 s) |
| **Docker** (`docker/` — Dockerfile + compose) | Docker only, **no Java** | non-Java devs trying it out; bind-mount host `keys/` to reuse a bundle. Light commands anywhere; heavy `prove`/`setup` only on a big Linux host (see USAGE) |

The native zip ships a launcher (`account-ownership-recovery-cli`) that **auto-sizes the heap** for
the heavy commands (`prove`/`setup`) and runs the light ones (`verify`/`info`) with the default heap
— so no manual `-Xmx`. The raw binary is `account-ownership-recovery-cli.bin` for advanced use.
Proving on the native binary uses the pure-Java backend (blst reaches `libblst` via FFM, not wired
into the image) and is slower — **use the fat jar for heavy proving**; the native binary is best for
`verify`/`info`.

## Requirements

- **Java 25** (GraalVM or any JDK 25). The fat-jar launcher auto-sizes the heap to ~80 % of RAM;
  override with `AOR_JAVA_OPTS`, e.g. `AOR_JAVA_OPTS="-Xmx12g"`.
- **snarkjs + Node** — only for the **external** ceremony (never invoked by this CLI). `export-r1cs`,
  `import`, `setup`, `prove`, `verify` need no snarkjs.
- **A node/Blockfrost endpoint** — only for `verify --onchain`. Defaults to a local
  [Yaci DevKit](https://github.com/bloxbean/yaci-devkit) at `http://localhost:8080/api/v1/`.

---

## Security notes

- Mnemonic: hidden prompt only; the derived root key stays in memory and is never persisted or sent.
- `setup` (local) keys are development-trust only — whoever ran the setup can forge proofs. Production
  bundles must come from the ceremony `import` path.
- Bundle integrity: `SHA256SUMS` (checked with `info --verify-integrity`) and a circuit fingerprint
  that pins the exact circuit the keys belong to.
- The on-chain demo validator checks the proof against the datum-pinned pkh; a production validator
  must also bind the spending transaction context (replay protection).
