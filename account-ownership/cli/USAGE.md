# Usage Guide

`account-ownership-recovery-cli <command> [options]` — run any command with `--help` for its options.

Commands: `export-r1cs` · `import` · `setup` · `prove` · `verify` · `info`.

The fat-jar launcher auto-sizes the JVM heap to ~80 % of RAM; override with
`AOR_JAVA_OPTS="-Xmx8g"` (8 GB is the measured floor for both `setup` and `prove`). The native
binary takes `-Xmx…` before the subcommand for store-loading commands.

**Where things run:** the phase-2 **ceremony is external** (snarkjs, outside this tool). Everything
this CLI does is pure Java — no snarkjs, no ptau, no downloads.

---

## Directory layout

```
account-ownership-recovery-cli/
├── bin/account-ownership-recovery-cli      # launcher (fat-jar zip)
├── lib/account-ownership-recovery-cli-*-all.jar
├── keys/                # the key bundle (from `setup`/`import`, or downloaded from the coordinator)
│   ├── pointsA.bin … pointsL.bin, aux.bin   # proving-key store (mmap-loaded; sparse by default)
│   ├── r1cs.bin                             # packed-constraint cache (proves skip the compile)
│   ├── vk.json                              # verification key (small; used by verify)
│   ├── bundle.properties                    # mode, circuit fingerprint, version
│   ├── manifest.properties                  # store dimensions
│   └── SHA256SUMS                           # per-file integrity digests
└── proofs/              # prove output: proof.json + public-inputs.json
```

---

# Making a key bundle (coordinator, once)

Two ways to fill `keys/`. Both produce the same bundle shape.

## A. Real ceremony — `export-r1cs` → external snarkjs → `import`

```bash
# 1. export the circuit for the ceremony
setup-cli export-r1cs --out circuit.r1cs

# 2. run phase 2 EXTERNALLY with a prepared BLS12-381 ptau (power >= 25):
snarkjs groth16 setup circuit.r1cs pot25_final.ptau circuit_0000.zkey
snarkjs zkey contribute circuit_0000.zkey circuit_0001.zkey --name="c1" -v   # one per contributor
snarkjs zkey beacon     circuit_0001.zkey circuit_final.zkey <beaconHashHex> 10
snarkjs zkey verify     circuit.r1cs pot25_final.ptau circuit_final.zkey

# 3. import the finalized key (pure Java — no snarkjs)
setup-cli import --zkey circuit_final.zkey [--keys keys] [--force]
```

- **`export-r1cs`** (`--out circuit.r1cs`) compiles the circuit and writes the iden3 `.r1cs`, then
  prints the exact snarkjs commands to run.
- **`import`** (`--zkey <file>`) imports a finalized ceremony key into the bundle. It checks the zkey
  is for *this* circuit and fails early otherwise. No snarkjs needed.
- The `.ptau` (phase 1) is **universal — reuse** an attested BLS12-381 one (Filecoin, Zcash); you
  don't generate it. A BN254 ptau (e.g. PSE Perpetual Powers of Tau) is the wrong curve.
- For a multi-party ceremony, each contributor runs `zkey contribute` in turn (snarkjs, or the
  `zeroj-ceremony` tool); the coordinator applies the final beacon and imports.

## B. Local dev bundle — `setup` (testing/demo only)

```bash
setup-cli setup --i-understand-insecure [--keys keys] [--force]
```

Single-party setup (~6–7 min; `-Xmx8g` is the measured heap floor — ADR-0035; a 16 GB machine works). **Insecure:** this machine learns the setup randomness and
could forge proofs. Requires the `--i-understand-insecure` acknowledgement.

**Demo tip:** run this **once**, then keep/cache the `keys/` bundle and reuse it — anyone can
`prove`/`verify` against it in ~5 min with no setup. Never publish a production bundle from here.

---

# Using a bundle (user)

## `prove` — generate a proof

```bash
setup-cli prove --recipient <bech32-address> [--keys keys] [--out proofs] \
    [--account 0] [--role 0] [--index 0] [--mainnet] [--backend blst|java] [--no-self-verify]
```

Checks the circuit fingerprint (compiling only if `keys/r1cs.bin` is absent), prompts for your
**mnemonic (hidden)**, derives the root key + target address
(`m/1852'/1815'/<account>'/<role>/<index>`), mmap-loads the proving key, proves, writes
`proofs/proof.json` + `proofs/public-inputs.json`, and self-checks off-chain.

**Recipient (`--recipient`, required):** the bech32 address the refund must go to. The CLI decodes
it to its 28-byte payment key hash and binds it into the proof, so the proof authorises a payout
**only** to that address — a copied proof cannot be redirected. It is recorded in
`public-inputs.json` and enforced on-chain by the validator.

**Path (`--account`, `--role`, `--index`):** pick any address — `--account 0 --role 0 --index 0`
(defaults) is the first external address; `--role 1` is the internal/change chain, `--account 1` a
second account. The **full path is a secret witness**: only the payment key hash and the recipient
are public inputs, and the path is not written to `public-inputs.json`.

`--backend` picks the prover. The default is **`java`** (pure-Java multi-core): same speed as
blst at this circuit size since ADR-0033/0034, no native lib, and safe on small-memory machines.
`--backend blst` opts into the native MSM — possibly faster on some hardware, but its native
buffers need ~10 GB beyond the heap (OOM risk under ~24 GB total memory — ADR-0034 M5). Takes
~2–4 min end-to-end and needs **~10 GB+ RAM** (measured floor: 8 GB first run, 7 GB once the
constraint cache exists; a 16 GB machine proves in ~2.6 min, validated under a hard memory cap).
The first prove writes `keys/r1cs.bin` (~0.9 GB) so later proves skip the circuit compile;
`--no-cache` disables it. The mnemonic is never accepted as an argument — always the hidden
prompt.

## `verify` — check a proof

```bash
# off-chain (default): pure-Java pairing check against vk.json — sub-second, no network
setup-cli verify [--keys keys] [--proof proofs]

# verify the proof is for a SPECIFIC address / recipient you know (bech32)
setup-cli verify --expect-address addr_test1... --expect-recipient addr_test1...

# on-chain, Yaci DevKit (default: --network devnet) — auto-funds the admin account
setup-cli verify --onchain

# on-chain, hosted Blockfrost — --network auto-sets the URL; pass the key (flag or env)
setup-cli verify --onchain --network preprod --bf-key preprod...
BLOCKFROST_PROJECT_ID=preprod...  setup-cli verify --onchain --network preprod
```

**What `verify` checks against (`--expect-address`, `--expect-recipient`):** the public inputs are
**recomputed** from the proven address and the recipient — not blindly trusted from the file's
`publicInputs` array. By default those come from `public-inputs.json`, and the stored array must
match (a hand-edited `pkh`, `recipient`, or `publicInputs` is rejected as inconsistent). Pass
`--expect-address`/`--expect-recipient` (bech32) to check the proof against values **you** know
independently — the real assurance, since a file's own labels are only as trustworthy as whoever
produced it. Both off-chain and on-chain honour these, and `verify` prints the address → recipient
it validated against.

**Backend (`--network`):** `devnet | preview | preprod | mainnet` selects **both** the Cardano
network **and** the default Blockfrost URL:
- `devnet` (default) → local **Yaci DevKit** (`http://localhost:8080/api/v1/`), no key.
- `preview`/`preprod`/`mainnet` → the matching **Blockfrost** endpoint. Pass the project key via
  `--bf-key` **or** the `BLOCKFROST_PROJECT_ID` env var. Override the URL with `--bf-url` if needed.

**Admin / funding account:** on-chain verify locks a gate UTxO and pays fees + collateral from an
**admin account** — the account of the mnemonic in the **`AOR_ADMIN_MNEMONIC`** env var, else the
**hidden prompt** (base address `m/1852'/1815'/0'/0/0`). To use a different admin, use a different
mnemonic. This is a **funding wallet, not the wallet being proven** — use a low-value account. On
`devnet` it's auto-funded; elsewhere it must **already hold ADA**. It only submits the demo
transactions — the proof itself establishes ownership.

## `info` — inspect a bundle

```bash
setup-cli info [--keys keys] [--verify-integrity]
```

Shows mode, circuit fingerprint, size, and whether `vk.json` is present. `--verify-integrity`
recomputes `SHA256SUMS` over the whole bundle (~10 GB sparse / ~24 GB dense — slow).

---

## End-to-end (local Yaci DevKit, using a local dev bundle)

```bash
AOR_JAVA_OPTS="-Xmx8g" setup-cli setup --i-understand-insecure    # once, ~6-7 min (8g = measured floor)
setup-cli info
setup-cli prove --recipient <bech32-address>                      # bind the payout address
setup-cli verify
setup-cli verify --onchain
```

## Docker (no Java install)

For trying the tool without installing Java — great for the light commands (`verify` / `info` /
`import` / `export-r1cs`). Bind-mount a host `keys/` folder to **reuse an existing bundle**.

**Published image (no build)** — once the GHCR image is pushed (Actions ▸ *account-ownership-recovery-cli
— GHCR image*):
```bash
docker run --rm -v $PWD/keys:/work/keys -v $PWD/proofs:/work/proofs \
  ghcr.io/bloxbean/account-ownership-recovery-cli verify
```

**Build locally** (from source):
```bash
# build the fat jar once, then the image
./gradlew fatJar
KEYS_DIR=$PWD/keys docker compose -f docker/docker-compose.yml build

# run any command; KEYS_DIR/PROOFS_DIR point at your host folders (absolute paths)
KEYS_DIR=$PWD/keys PROOFS_DIR=$PWD/proofs docker compose -f docker/docker-compose.yml run --rm aor info
KEYS_DIR=$PWD/keys PROOFS_DIR=$PWD/proofs docker compose -f docker/docker-compose.yml run --rm aor verify
```

**On-chain verify from Docker** — the compose passes `BLOCKFROST_PROJECT_ID` and `AOR_ADMIN_MNEMONIC`
through (no prompts):
```bash
# hosted Blockfrost (public URL — works directly)
KEYS_DIR=$PWD/keys PROOFS_DIR=$PWD/proofs \
BLOCKFROST_PROJECT_ID=preprod... AOR_ADMIN_MNEMONIC="word1 … word24" \
  docker compose -f docker/docker-compose.yml run --rm aor verify --onchain --network preprod

# a LOCAL Yaci DevKit on the host — reach it via host.docker.internal (inside the container
# `localhost` is the container, not the host):
KEYS_DIR=$PWD/keys PROOFS_DIR=$PWD/proofs AOR_ADMIN_MNEMONIC="…" \
  docker compose -f docker/docker-compose.yml run --rm aor \
  verify --onchain --bf-url http://host.docker.internal:8080/api/v1/
```

- **Light commands work anywhere** (verify only needs the tiny `vk.json`).
- **`prove` / `setup` are the exception:** `prove` needs ~10 GB heap (ADR-0034) and memory-maps the
  ~9.6 GB sparse store; `setup` needs ~8 GB heap (measured floor; ADR-0035). For either, set `mem_limit` in the compose file and
  `JAVA_OPTS="-Xmx8g"`. Measured (ADR-0035): the **whole loop fits a hard 16 GiB cap with zero
  swap** — one container chained `setup` (9.6 min) → `prove` (2.7 min, self-check PASS) →
  `verify` (VALID) at `-Xmx8g` for both heavy steps, sparse bundle on a Docker volume,
  **12.6 min total**. On a **Linux 16 GB host** that maps directly. On a 16 GB **Docker Desktop**
  machine (mac/win) the VM keeps ~3-4 GB from the host, so the heavy steps get tight — prefer
  the fat jar on the host there. Writing the bundle to a **named volume** (VM-native disk) is
  noticeably faster than a bind mount (VirtioFS write penalty on ~10 GB of output); the CLI
  auto-selects the pure-Java backend under a 16 GB cap (blst's native MSM buffers don't fit).

## Exit codes
`0` success · `1` verification failed / internal error · `2` bad usage / missing bundle / missing
acknowledgement.

> In the examples, `setup-cli` is shorthand for `bin/account-ownership-recovery-cli` (fat-jar zip) or
> `./account-ownership-recovery-cli` (native zip).
