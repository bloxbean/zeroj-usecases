# Account-Ownership Proof CLI

Prove — in zero knowledge — that you know the HD-wallet **root key** behind a Cardano address, and
verify that proof **off-chain** or **on-chain**. The circuit re-derives the full CIP-1852 path
(`m/1852'/1815'/account'/0/index`) from your secret root key and checks it reaches the address's
payment key hash. The proof reveals nothing about your seed.

Built on [ZeroJ](https://github.com/bloxbean/zeroj) (Groth16 over BLS12-381, Java 25). See
`docs/adr/0001-account-ownership-proof-cli.md` for the design rationale.

---

## Two roles

| role | does | time |
|---|---|---|
| **Coordinator** (once) | runs the trusted `setup`, publishes the *key bundle* | ~47 min + a big machine |
| **User** (each proof) | downloads this app + the published key bundle, runs `prove` then `verify` | ~5 min |

Most people are **users** and start at `prove`. The one-time setup produces a ~23 GB proving-key
bundle that the coordinator publishes for download.

---

## Quick start (user)

```bash
# 1. unzip the app
unzip account-ownership-recovery-cli-*.zip && cd account-ownership-recovery-cli

# 2. drop the published key bundle into ./keys  (the coordinator gives you this directory)
#    keys/ should contain pointsA.bin … pointsL.bin, aux.bin, vk.json, bundle.properties, SHA256SUMS
bin/account-ownership-recovery-cli info                    # inspect it

# 3. generate a proof (prompts for your mnemonic — hidden input)
bin/account-ownership-recovery-cli prove --account 0 --index 0

# 4. verify
bin/account-ownership-recovery-cli verify                  # off-chain, <1s
bin/account-ownership-recovery-cli verify --onchain        # on-chain (defaults to local Yaci DevKit)
```

Your mnemonic is read from a hidden prompt only — never a command-line argument, environment
variable, or file — and never leaves the process. Only `proof.json` + `public-inputs.json` are
written.

---

## Measured performance (19,075,097-constraint circuit, 12-core / 128 GB box)

| step | time | notes |
|---|---|---|
| `setup --tau local` | ~47 min | one-time, ~90 GB heap |
| key bundle on disk | ~23 GB | mmap-loaded, not fully read into RAM |
| `prove` | **~4.7 min** | ~100 s mmap key load + ~2 s witness + ~165 s blst prove |
| `verify` (off-chain) | **~0.2 s** | reads the small `vk.json` |
| `verify --onchain` | **~5 s** | one lock + one unlock tx on Yaci DevKit |

**Hardware:** proving needs a large-memory machine — **~64 GB+ RAM** (measured ~66–70 GB peak).
On smaller machines `prove`/`setup --tau local` will run out of memory. Verification is light.

---

## Install / requirements

- **Java 25** (GraalVM or any JDK 25). The bundled launcher auto-sizes the heap to ~80 % of RAM;
  override with `AOR_JAVA_OPTS`, e.g. `AOR_JAVA_OPTS="-Xmx110g"`.
- **snarkjs + Node** — only for `setup --tau ptau|filecoin` (a real ceremony). Not needed to prove
  or verify. `npm install -g snarkjs`.
- **A node/Blockfrost endpoint** — only for `verify --onchain`. Defaults to a local
  [Yaci DevKit](https://github.com/bloxbean/yaci-devkit) at `http://localhost:8080/api/v1/`.

---

## Setup modes (coordinator)

```bash
# local  — single-party, DEV/TESTING ONLY (this machine could forge proofs)
bin/account-ownership-recovery-cli setup --tau local --i-understand-insecure

# ptau   — real phase-2 ceremony from a prepared powers-of-tau (needs snarkjs)
bin/account-ownership-recovery-cli setup --tau ptau --ptau powersOfTau25.ptau

# ptau   — import a finalized .zkey produced by a real multi-party ceremony
bin/account-ownership-recovery-cli setup --tau ptau --zkey circuit_final.zkey

# filecoin — auto-download an attested phase-1, convert/verify/prepare (coordinator-grade, best effort)
bin/account-ownership-recovery-cli setup --tau filecoin --filecoin-url <url> --i-understand-filecoin-cost
```

For anything beyond testing, publish a bundle from the `ptau`/`filecoin` path (ideally a proper
multi-party ceremony) — not `--tau local`.

See **USAGE.md** for every command and option.

---

## Security notes

- Mnemonic: hidden prompt only; the derived root key stays in memory and is never persisted or sent.
- `--tau local` keys are development-trust only — whoever ran the setup can forge proofs.
- Bundle integrity: `SHA256SUMS` (checked with `info --verify-integrity`) and a circuit fingerprint
  that pins the exact circuit the keys belong to.
- The on-chain demo validator checks the proof against the datum-pinned pkh; a production validator
  must also bind the spending transaction context (replay protection).
