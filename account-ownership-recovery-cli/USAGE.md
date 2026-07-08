# Usage Guide

`account-ownership-recovery-cli <command> [options]`

Commands: `setup` · `prove` · `verify` · `info`. Run any with `--help` for its full option list.

The launcher auto-sizes the JVM heap to ~80 % of RAM. Override for a specific run:
`AOR_JAVA_OPTS="-Xmx110g" bin/account-ownership-recovery-cli prove`.

---

## Directory layout

The app works with two directories (both default to the current working directory):

```
account-ownership-recovery-cli/
├── bin/account-ownership-recovery-cli      # launcher
├── lib/account-ownership-recovery-cli-*-all.jar
├── keys/                # the key bundle (from setup, or downloaded from the coordinator)
│   ├── pointsA.bin … pointsL.bin, aux.bin   # proving key store (mmap-loaded)
│   ├── vk.json                              # verification key (small; used by verify)
│   ├── bundle.properties                    # setup mode, circuit fingerprint, version
│   ├── manifest.properties                  # store dimensions (domain, public count)
│   └── SHA256SUMS                           # per-file integrity digests
└── proofs/              # prove output: proof.json + public-inputs.json
```

---

## `info` — inspect a key bundle

```bash
bin/account-ownership-recovery-cli info [--keys keys] [--verify-integrity]
```
Shows setup mode, circuit fingerprint, size, and whether `vk.json` is present.
`--verify-integrity` recomputes `SHA256SUMS` over the whole ~23 GB bundle (slow).

---

## `prove` — generate a proof (user)

```bash
bin/account-ownership-recovery-cli prove \
    [--keys keys] [--out proofs] [--account 0] [--index 0] [--mainnet] \
    [--backend blst|java] [--no-self-verify]
```

`--backend blst` (default) uses the fast native prover (~2–3 min); `--backend java` uses the
pure-Java multi-core prover (~9 min, no native library needed). If the blst native library can't
load, blst mode automatically falls back to pure-Java with a warning.

1. compiles the circuit and checks its fingerprint against the bundle,
2. prompts for your mnemonic (**hidden**),
3. derives the root key + target address (`m/1852'/1815'/<account>'/0/<index>`),
4. mmap-loads the proving key and proves with the blst multi-core backend,
5. writes `proofs/proof.json` + `proofs/public-inputs.json`,
6. self-checks the proof off-chain (skip with `--no-self-verify`).

Takes ~5 min and needs a large-memory machine (~64 GB+ RAM). The mnemonic is never accepted as an
argument — always the hidden prompt.

---

## `verify` — check a proof

```bash
# off-chain (default): pure-Java pairing check against vk.json — sub-second, no network
bin/account-ownership-recovery-cli verify [--keys keys] [--proof proofs]

# on-chain: lock a gate UTxO (datum = pkh) at the bundled validator, unlock it with the proof
bin/account-ownership-recovery-cli verify --onchain \
    [--bf-url http://localhost:8080/api/v1/] [--bf-key <project-id>]
```

On-chain defaults to a local **Yaci DevKit** (auto-funds the payer). Against a hosted network pass
`--bf-url`/`--bf-key`; the funding wallet (prompted, hidden) must already hold ADA. On-chain verify
prompts for a **funding** mnemonic only to submit the demo transactions — the proof itself is what
establishes ownership.

---

## `setup` — produce the key bundle (coordinator, one-time)

```bash
bin/account-ownership-recovery-cli setup --tau <local|ptau|filecoin> [options] [--keys keys]
```

Common options: `--keys <dir>` (output), `--force` (overwrite), `--work-dir <dir>` (ceremony
scratch), `--timeout-hours <n>` (per snarkjs step).

### `--tau local` (dev/testing)
```bash
setup --tau local --i-understand-insecure
```
Single-party setup (~47 min, ~90 GB heap). **Insecure**: this machine learns the setup randomness and
could forge proofs. Requires the `--i-understand-insecure` acknowledgement. Never publish a
production bundle from this mode.

### `--tau ptau` (real phase-2 ceremony)
```bash
# run the phase-2 ceremony here from a prepared powers-of-tau (>= 2^25)
setup --tau ptau --ptau powersOfTau25.ptau [--contributions 1]

# or import a finalized .zkey from a ceremony run elsewhere (snarkjs or zeroj-ceremony)
setup --tau ptau --zkey circuit_final.zkey [--ptau powersOfTau25.ptau]
```
With `--ptau`: exports the circuit R1CS, runs `snarkjs groth16 setup`, `--contributions` coordinator
contributions, a finalization beacon, and `snarkjs zkey verify` (the independent check), then imports
the key. With `--zkey`: imports an already-finalized ceremony key (and verifies it if `--ptau` is
also given). Requires snarkjs on PATH for the snarkjs steps.

### `--tau filecoin` (attested phase-1, best effort)
```bash
setup --tau filecoin --filecoin-url <url> --i-understand-filecoin-cost [--truncate-to 25]
setup --tau filecoin --phase1-file phase1.ptau --i-understand-filecoin-cost   # skip download
```
Downloads (resumable) a publicly-attested BLS12-381 phase-1, converts to `.ptau` if needed, runs
`powersoftau verify`, optionally truncates, and `prepare phase2`, then continues as `ptau`.
**Coordinator-grade, best effort:** the phase-1 is tens of GB and `prepare phase2` at 2^25 is a
one-time multi-hour job (cached forever). If your ceremony's phase-1 needs a specific
download/convert step, prepare the `.ptau` out of band and pass it via `--tau ptau --ptau`.

---

## End-to-end (against a local Yaci DevKit)

```bash
# coordinator (once) — dev bundle for testing
AOR_JAVA_OPTS="-Xmx110g" bin/account-ownership-recovery-cli setup --tau local --i-understand-insecure

# user
bin/account-ownership-recovery-cli info
bin/account-ownership-recovery-cli prove
bin/account-ownership-recovery-cli verify
bin/account-ownership-recovery-cli verify --onchain
```

## Exit codes
`0` success · `1` verification failed / internal error · `2` bad usage / missing bundle / missing
acknowledgement.
