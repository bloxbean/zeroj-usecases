# Usage Guide

`account-ownership-recovery-cli <command> [options]` — run any command with `--help` for its options.

Commands: `export-r1cs` · `import` · `setup` · `prove` · `verify` · `info`.

The fat-jar launcher auto-sizes the JVM heap to ~80 % of RAM; override with
`AOR_JAVA_OPTS="-Xmx110g"`. The native binary takes `-Xmx…` before the subcommand for store-loading
commands.

**Where things run:** the phase-2 **ceremony is external** (snarkjs, outside this tool). Everything
this CLI does is pure Java — no snarkjs, no ptau, no downloads.

---

## Directory layout

```
account-ownership-recovery-cli/
├── bin/account-ownership-recovery-cli      # launcher (fat-jar zip)
├── lib/account-ownership-recovery-cli-*-all.jar
├── keys/                # the key bundle (from `setup`/`import`, or downloaded from the coordinator)
│   ├── pointsA.bin … pointsL.bin, aux.bin   # proving-key store (mmap-loaded)
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

Single-party setup (~47 min, ~90 GB heap). **Insecure:** this machine learns the setup randomness and
could forge proofs. Requires the `--i-understand-insecure` acknowledgement.

**Demo tip:** run this **once**, then keep/cache the `keys/` bundle and reuse it — anyone can
`prove`/`verify` against it in ~5 min with no setup. Never publish a production bundle from here.

---

# Using a bundle (user)

## `prove` — generate a proof

```bash
setup-cli prove [--keys keys] [--out proofs] [--account 0] [--index 0] [--mainnet] \
    [--backend blst|java] [--no-self-verify]
```

Compiles the circuit + checks its fingerprint, prompts for your **mnemonic (hidden)**, derives the
root key + target address (`m/1852'/1815'/<account>'/0/<index>`), mmap-loads the proving key, proves,
writes `proofs/proof.json` + `proofs/public-inputs.json`, and self-checks off-chain.

`--backend blst` (default) is the fast native prover (~2–3 min); `--backend java` is pure-Java (~9
min, no native lib). Takes ~5 min and needs ~64 GB+ RAM. The mnemonic is never accepted as an
argument — always the hidden prompt.

## `verify` — check a proof

```bash
# off-chain (default): pure-Java pairing check against vk.json — sub-second, no network
setup-cli verify [--keys keys] [--proof proofs]

# on-chain: lock a gate UTxO (datum = pkh) at the bundled validator, unlock it with the proof
setup-cli verify --onchain [--bf-url http://localhost:8080/api/v1/] [--bf-key <project-id>]
```

On-chain defaults to a local **Yaci DevKit** (auto-funds the payer). Against a hosted network pass
`--bf-url`/`--bf-key`; the funding wallet (prompted, hidden) must already hold ADA — it only submits
the demo transactions; the proof itself establishes ownership.

## `info` — inspect a bundle

```bash
setup-cli info [--keys keys] [--verify-integrity]
```

Shows mode, circuit fingerprint, size, and whether `vk.json` is present. `--verify-integrity`
recomputes `SHA256SUMS` over the whole ~23 GB bundle (slow).

---

## End-to-end (local Yaci DevKit, using a local dev bundle)

```bash
AOR_JAVA_OPTS="-Xmx110g" setup-cli setup --i-understand-insecure   # coordinator, once
setup-cli info
setup-cli prove
setup-cli verify
setup-cli verify --onchain
```

## Docker (no Java install)

For trying the tool without installing Java — great for the light commands (`verify` / `info` /
`import` / `export-r1cs`). Bind-mount a host `keys/` folder to **reuse an existing bundle**.

```bash
# build the fat jar once, then the image
./gradlew fatJar
KEYS_DIR=$PWD/keys docker compose -f docker/docker-compose.yml build

# run any command; KEYS_DIR/PROOFS_DIR point at your host folders (absolute paths)
KEYS_DIR=$PWD/keys PROOFS_DIR=$PWD/proofs docker compose -f docker/docker-compose.yml run --rm aor info
KEYS_DIR=$PWD/keys PROOFS_DIR=$PWD/proofs docker compose -f docker/docker-compose.yml run --rm aor verify
```

- **Light commands work anywhere** (verify only needs the tiny `vk.json`).
- **`prove` / `setup` are the exception:** they need ~80 GB and memory-map the 23 GB store. That's only
  practical on a big **Linux** host — set `mem_limit` in the compose file and `JAVA_OPTS="-Xmx80g"`.
  On Docker Desktop (mac/win) the VM RAM cap + slow mmap over bind-mounts make heavy proving
  impractical; use the fat-jar or native distribution directly for that.

## Exit codes
`0` success · `1` verification failed / internal error · `2` bad usage / missing bundle / missing
acknowledgement.

> In the examples, `setup-cli` is shorthand for `bin/account-ownership-recovery-cli` (fat-jar zip) or
> `./account-ownership-recovery-cli` (native zip).
