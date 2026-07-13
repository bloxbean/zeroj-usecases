# Account-Ownership Proof CLI

Prove — in zero knowledge — that you know the HD-wallet **root key** behind a Cardano address, and
verify that proof **off-chain** or **on-chain**. The circuit re-derives the CIP-1852 path
(`m/1852'/1815'/0'/role/index`) from your secret root key and checks it reaches the address's
payment key hash. Only the payment key hash is public — the proof reveals nothing about your seed,
and since circuit v2 the derivation path (`role`, `index`) is a secret witness too.

Built on [ZeroJ](https://github.com/bloxbean/zeroj) (Groth16 over BLS12-381, Java 25). Design
rationale: `docs/adr/0001-account-ownership-proof-cli.md`.

---

## Try it now — download from [Releases](https://github.com/bloxbean/zeroj-usecases/releases)

Every option below runs the same self-contained flow on your machine: a one-time **local** key
setup (~6 min), then prove and verify. Nothing is downloaded besides the release artifact, and
your mnemonic never leaves the process (hidden prompt only).

> **Local setup vs production:** `setup` generates a **single-party, dev/testing** key — the
> machine that ran it could forge proofs. It's perfect for trying the tool. For production, the
> phase-2 ceremony runs **externally with snarkjs** and the finalized `.zkey` is brought in with
> `import` — see [Producing a key bundle](#producing-a-key-bundle-coordinator).

### Option 1 — Java zip (recommended: fastest prover)

Needs only Java 25 ([Temurin](https://adoptium.net/) or GraalVM). Download
`account-ownership-recovery-cli-<version>.zip`, then:

```bash
unzip account-ownership-recovery-cli-*.zip && cd account-ownership-recovery-cli-*/

# 1. one-time LOCAL trusted setup — dev/testing only (~6 min, ~10 GB free disk; 16 GB RAM is enough)
bin/account-ownership-recovery-cli setup --i-understand-insecure

# 2. prove — prompts for your mnemonic (hidden); ~1.5 min
bin/account-ownership-recovery-cli prove --role 0 --index 0

# 3. verify off-chain (<1 s)
bin/account-ownership-recovery-cli verify

# 4. verify on-chain — local Yaci DevKit devnet (default endpoint http://localhost:8080/api/v1/)
bin/account-ownership-recovery-cli verify --onchain

# 5. verify on-chain — public preprod via Blockfrost (needs a funded preprod payer wallet)
BLOCKFROST_PROJECT_ID=preprod... bin/account-ownership-recovery-cli verify --onchain --network preprod
```

The launcher auto-sizes the heap (~80 % of RAM; override with `AOR_JAVA_OPTS="-Xmx8g"`). For the
on-chain steps the transaction payer's mnemonic comes from `AOR_ADMIN_MNEMONIC` or a hidden
prompt; a local [Yaci DevKit](https://github.com/bloxbean/yaci-devkit) devnet needs no Blockfrost
key. `--role 0 --index 0` is the default first address; any soft path works (`--role 1` = change
addresses) — the path stays private, only the pkh is in the proof.

### Option 2 — Docker (no Java install)

```bash
docker pull ghcr.io/bloxbean/account-ownership-recovery-cli
mkdir -p keys proofs

# 1. one-time LOCAL setup (dev/testing only; give the container ~16 GB — Linux hosts map this directly)
docker run --rm -e JAVA_OPTS="-Xmx8g" -v "$PWD/keys:/work/keys" \
  ghcr.io/bloxbean/account-ownership-recovery-cli:<version> setup --i-understand-insecure

# 2. prove (-it for the hidden mnemonic prompt)
docker run --rm -it -e JAVA_OPTS="-Xmx8g" -v "$PWD/keys:/work/keys" -v "$PWD/proofs:/work/proofs" \
  ghcr.io/bloxbean/account-ownership-recovery-cli:<version> prove --role 0 --index 0

# 3. verify off-chain
docker run --rm -v "$PWD/keys:/work/keys" -v "$PWD/proofs:/work/proofs" \
  ghcr.io/bloxbean/account-ownership-recovery-cli:<version> verify

# 4. verify on-chain — Yaci DevKit running on the HOST (inside the container, localhost is not the host)
docker run --rm -it -e AOR_ADMIN_MNEMONIC="word1 … word24" -v "$PWD/keys:/work/keys" -v "$PWD/proofs:/work/proofs" \
  ghcr.io/bloxbean/account-ownership-recovery-cli:<version> verify --onchain --bf-url http://host.docker.internal:8080/api/v1/

# 5. verify on-chain — preprod via Blockfrost
docker run --rm -it -e BLOCKFROST_PROJECT_ID=preprod... -e AOR_ADMIN_MNEMONIC="word1 … word24" \
  -v "$PWD/keys:/work/keys" -v "$PWD/proofs:/work/proofs" \
  ghcr.io/bloxbean/account-ownership-recovery-cli:<version> verify --onchain --network preprod
```

The heavy steps (`setup`, `prove`) fit a hard 16 GiB container (measured — see USAGE.md). On a
16 GB **Docker Desktop** machine (mac/win) the VM keeps a few GB from the host — prefer Option 1
there; verify-only works anywhere.

### Option 3 — Native binaries (coming soon — not recommended yet)

OS-specific zips (`…-macos-arm64.zip`, `…-linux-arm64.zip`, `…-windows-x86_64.zip`) with a single
executable — no JVM, instant startup. Same five commands as Option 1 (binary:
`account-ownership-recovery-cli`, `.exe` on Windows). Today they are best for `verify`/`info`:
**proving is noticeably slower than the Java zip** (the JIT beats the native image on the big
multi-scalar multiplications), and on **Windows proving always uses the pure-Java backend** (the
optional blst native library isn't packaged for Windows — it's the default backend everywhere
anyway). Grab Option 1 for real proving.

---

## Commands

| command | who / when | what |
|---|---|---|
| `export-r1cs` | coordinator, once | export the circuit `.r1cs` for an **external** snarkjs ceremony |
| `import`      | coordinator, once | import a finalized ceremony `.zkey` → key bundle (no snarkjs) |
| `setup`       | anyone, testing   | generate a **local, dev-only** key bundle (single-party) |
| `prove`       | user, each proof  | generate a proof from your mnemonic (`--role`, `--index`; account fixed at `0'`) |
| `verify`      | user, each proof  | check a proof off-chain (default) or on-chain |
| `info`        | anyone            | inspect a key bundle |

## Where each step runs

- **Externally (outside this tool):** the multi-party **phase-2 ceremony** — `snarkjs groth16 setup`
  / `zkey contribute` / `zkey beacon`. This CLI never runs snarkjs. Feed it with `export-r1cs`, run
  the ceremony wherever you like, then `import` the finalized `.zkey`.
- **Locally (this tool, pure Java):** `export-r1cs`, `import`, `setup`, `prove`, `verify`, `info`.
  No snarkjs, no powers-of-tau, no downloads.
- **For a quick demo:** run `setup` **once**, then keep/cache the `keys/` bundle and reuse it —
  anyone with the bundle proves/verifies in minutes with no setup.

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
# (or use zeroj's own `zeroj-ceremony` tool for contributions — snarkjs-compatible transcript)

# 3. import the finalized key (pure Java, no snarkjs)
bin/account-ownership-recovery-cli import --zkey circuit_final.zkey
```
The `.ptau` (phase 1) is universal — **reuse** an attested BLS12-381 one (Filecoin, Zcash), you don't
generate it. A BN254 ptau (e.g. the PSE Perpetual Powers of Tau) is the wrong curve and won't work.

**Local dev bundle — for testing/demo only:**
```bash
bin/account-ownership-recovery-cli setup --i-understand-insecure
```
Single-party setup (~6–7 min; `-Xmx8g` is the measured heap floor — ADR-0035; a 16 GB machine works). **Insecure:** this machine learns the setup randomness and
could forge proofs. Generate once, cache the bundle, reuse for demos. Never publish a production
bundle from this path.

See **USAGE.md** for every command and option.

---

## Measured performance (~19M-constraint circuit, 12-core / 128 GB box)

| step | time | notes |
|---|---|---|
| `setup` (local) | **~6 min** | one-time, 8 GB heap (measured floor; 12 GB validated under a hard 16 GiB cap) — fits a 16 GB machine (ADR-0035); also writes `r1cs.bin` so the first prove skips its compile |
| key bundle on disk | **~9.6 GB** (sparse, the default — ADR-0035 M6; ~57% of points are infinity and are stored as 1 bit each) | mmap-loaded (instant), not read into the JVM heap; dense ~24 GB via `setup --dense`, imports stay dense |
| `prove` (first run) | **~1.5 min** | ~17 s compile (then cached to `keys/r1cs.bin`, ~0.9 GB) + witness + ~56 s prove — a `setup`-produced bundle already ships `r1cs.bin`, so its first prove is the cached case |
| `prove` (cached) | **~1.1 min** | compile skipped — ~14 s witness + ~56 s prove (ADR-0033/0034; java and blst backends measure the same) |
| `verify` (off-chain) | **~0.2 s** | reads the small `vk.json` |
| `verify --onchain` | **~5 s** | one lock + one unlock tx on Yaci DevKit |

**Hardware:** proving needs **~10 GB+ RAM** (measured floor: 8 GB heap on the first run, 7 GB once
`r1cs.bin` is cached; 6 GB does not work — ADR-0034. This was ~70 GB before ADR-0033/0034). The
~9.6 GB (sparse) key bundle is memory-mapped, so it uses the page cache, not the heap — **an
ordinary 16 GB machine proves in ~2.6 min** (validated under a hard 16 GiB memory cap). The
default prover is pure Java (same speed as blst at this size, no native memory); `--backend blst`
opts into the native MSM, which needs ~10 GB beyond the heap and suits ≥24 GB machines. `setup`
runs in **8 GB of heap** (measured: `-Xmx8g` — ADR-0035) — the same 16 GB machine that
proves. Verification is light.

---

## Distributions

| distribution | release asset | best for |
|---|---|---|
| **Java zip** (`./gradlew distZip`) | `account-ownership-recovery-cli-<v>.zip` | everything — especially `prove`/`setup` (fastest prover, auto-sized heap); needs Java 25 |
| **Docker** (`docker/`) | `ghcr.io/bloxbean/account-ownership-recovery-cli` | non-Java users; bind-mount `keys/`/`proofs/`; heavy steps need a ~16 GB Linux host |
| **Native zips** (`./gradlew nativeDistZip`, GraalVM) | `…-macos-arm64.zip`, `…-linux-arm64.zip`, `…-windows-x86_64.zip` — **coming soon** | `verify` + `info` — single file, no JVM, instant startup; proving slower than the Java zip, Windows proves pure-Java only |

The Java zip's launcher **auto-sizes the heap** for the heavy commands (`prove`/`setup`) and runs
the light ones (`verify`/`info`) with the default heap — no manual `-Xmx`.

## Requirements

- **Java 25** (any JDK 25; GraalVM only if you build native images yourself) — Option 1/coordinator
  flows. Docker needs none. Override heap with `AOR_JAVA_OPTS`, e.g. `AOR_JAVA_OPTS="-Xmx8g"`.
- **snarkjs + Node** — only for the **external** ceremony (never invoked by this CLI). `export-r1cs`,
  `import`, `setup`, `prove`, `verify` need no snarkjs.
- **A node/Blockfrost endpoint** — only for `verify --onchain`. Defaults to a local
  [Yaci DevKit](https://github.com/bloxbean/yaci-devkit) at `http://localhost:8080/api/v1/`.

---

## Security notes

- Mnemonic: hidden prompt only; the derived root key stays in memory and is never persisted or sent.
- The derivation path (`--role`, `--index`) is a **secret** circuit input since v2 — it is not
  written to `public-inputs.json` and cannot be read from the proof; only the payment key hash is
  public. The CIP-1852 account is fixed at `0'` in circuit v2.
- `setup` (local) keys are development-trust only — whoever ran the setup can forge proofs. Production
  bundles must come from the ceremony `import` path.
- Bundle integrity: `SHA256SUMS` (checked with `info --verify-integrity`) and a circuit fingerprint
  that pins the exact circuit the keys belong to.
- The on-chain demo validator checks the proof against the datum-pinned pkh; a production validator
  must also bind the spending transaction context (replay protection).
