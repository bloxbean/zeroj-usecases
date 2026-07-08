# ADR-0001: Account-Ownership Proof CLI — a Standalone Distributable for Proof Generation & Verification

## Status
Proposed (2026-07-08) — awaiting review; implementation starts after approval.

## Context

The **account-ownership proof** usecase lets the holder of an HD wallet prove — in zero knowledge —
that they know the **root key** behind a given address: the circuit re-derives the full CIP-1852
path (`m/1852'/1815'/account'/role/index`) in-circuit from the secret root key and asserts it
reaches the address's public payment key hash. The proof reveals nothing about the seed and can be
verified **off-chain** (pure Java pairing check) or **on-chain** (a Plutus V3 validator,
cost-independent of circuit size). This is a general primitive: address-ownership attestation,
account recovery authorization, credential binding, and similar flows where a signature from the
leaf key is unavailable or insufficient.

Today the full flow works end to end, but only for developers: the circuit, services, and on-chain
validator live in `account-ownership-recovery` and are driven by `main`-class harnesses and gradle
test tasks inside this repository. There is no artifact an end user can download and run.

**Goal:** a self-contained CLI app — `account-ownership-recovery-cli` — distributed as a zip on the
zeroj-usecases GitHub release page. A user extracts it and drives everything from the command line:
one-time trusted setup (normally done by a coordinator team), proof generation, and off-chain or
on-chain verification.

### Measured realities that shape the design (from the ZeroJ ADR-0029/0031 work)

| fact | value |
|---|---|
| circuit | 19,075,097 constraints / 43.7M wires / evaluation domain 2²⁵ |
| one-time trusted setup (local single-party) | ~47 min, needs ~90 GB heap |
| proving key on disk (`Groth16PkStore`) | ~23 GB |
| proof generation (warm keys) | ~2 min mmap key load + ~2.3 min prove (blst multi-core) ≈ **4.5 min** |
| prove peak memory | ~66–70 GB heap → needs a **~64 GB+ RAM machine** |
| on-chain verification | one transaction, fee ≈ 0.95 ADA (measured on a local devnet) |
| prepared 2²⁵ `.ptau` (universal phase-1 powers) | ~32 GB — **cannot be bundled** with the app |
| snarkjs at 2²⁵: per contribution / one-time `prepare phase2` | ~2.5–3 h / ~60–105 h (cacheable forever) |

Two consequences follow directly:

1. **A coordinator/user split is unavoidable.** Setup is expensive and produces a 23 GB key; it is
   done **once** by the team operating the flow, and the exported key bundle is published for
   users to download. Users start at proof generation and finish in ~3–5 minutes.
2. **No tau can ship inside the zip.** The "quick testing" path is therefore the *local
   single-party* setup (which needs only a generated tau scalar — no download at all), while
   real-trust setups consume an external prepared `.ptau`.

## Decision

### 1. Standalone application, self-contained by construction

A new independent gradle project at `zeroj-usecases/account-ownership-recovery-cli/`:

- Own `settings.gradle`, own gradle 9.2.0 wrapper — the established pattern in this repository
  (every usecase and example is already an independent build; the root includes nothing).
- **All dependency versions inlined** in the app's own `gradle.properties`
  (`zeroj 0.1.0-pre5` — resolved from mavenLocal for now, Maven Central later —
  `julc 0.1.0-pre14`, `ccl 0.8.0-pre4`). No reliance on the repo-root version script: the project
  builds identically if copied out of the repository.
- Plain `java` application with **picocli** (no Spring Boot). JVM flags baked into the start
  script: `--enable-native-access=ALL-UNNAMED` (blst FFM), large default heap, and the
  insecure-setup system property applied **only** for `setup --tau local`.
- **Self-contained sources**: the six classes of the library usecase (circuit `OwnershipProof`,
  on-chain `OwnershipProofValidator`, services `OwnershipCircuitService`, `OnChainOwnershipService`,
  `ProofCompressor`, `LocalJulcEvaluator`) are **copied** into the app's package — no gradle
  dependency on any other project in this repository. Both annotation processors run at build time
  (zeroj circuit processor → generated `*Circuit`; julc processor → compiled Plutus validator).

### 2. Command surface

```
account-ownership-recovery-cli
├── setup    --tau local|ptau|filecoin [--ptau <file>] [--keys <dir>]     (coordinator, one-time)
├── prove    [--keys <dir>] [--out <dir>] [--account N] [--index N]       (user, ~3–5 min)
├── verify   [--offchain] [--proof <file>]                                 (user, seconds)
│            --onchain [--bf-url <url>] [--bf-key <key>]
└── info     [--keys <dir>]                                                (bundle status / fingerprint)
```

**`setup`** — produces and exports everything proving/verification needs into `keys/`:
the proving-key store (~23 GB, mmap-loadable), the verification key, the circuit fingerprint
(constraint count + hash of the exported R1CS), and a `manifest.sha256` for integrity checking.

| mode | what happens | trust level | cost |
|---|---|---|---|
| `local` (default) | single-party setup from a generated tau scalar; no downloads | **dev/testing only** — the machine that ran it could forge proofs; the CLI prints an explicit warning and requires a `--i-understand-insecure` acknowledgement | ~47 min on a ~90 GB-heap machine |
| `ptau` | real phase 2 from a user-supplied **prepared** `.ptau` (≥ 2²⁵): CLI exports the circuit R1CS, orchestrates `snarkjs groth16 setup` (+ prints contribution/beacon guidance for running a proper ceremony per ZeroJ ADR-0031), finalizes via the streaming zkey importer | as strong as the ptau + phase-2 ceremony used | minutes past the ptau; requires `snarkjs` on PATH |
| `filecoin` | fetches the publicly attested BLS12-381 phase-1 (Filecoin ceremony, 2²⁷) automatically, then: convert → `snarkjs powersoftau verify` (mandatory — validates the conversion independently) → truncate to 2²⁵ → `prepare phase2` → continue as `ptau` mode | strongest phase-1 available (~20 attested independent participants) | **honest costs:** ~50–100 GB download; the one-time `prepare phase2` measured ~60–105 h in Node at 2²⁵; conversion tooling not yet proven against the real files (open item in ZeroJ ADR-0031). Best-effort in v1, coordinator-only, and the prepared ptau is cached forever once produced |

**`prove`** — prompts for the mnemonic with hidden input (**never** accepted as a CLI argument,
environment variable, or file); derives the root key in-process; computes the witness; loads the
mmap'd proving key; proves with the blst multi-core backend; writes `proofs/proof.json` +
`public-inputs.json` (+ the address/pkh it binds to). Seed material never touches disk or network.

**`verify`** — off-chain (default): pairing check against the bundle's VK — seconds, no network.
On-chain: locks a gate UTxO with datum = the address pkh at the bundled Plutus validator and
unlocks it with the proof via a Blockfrost-compatible API; `--bf-url` defaults to a local Yaci
DevKit (`http://localhost:8080/api/v1/`), `--bf-key` optional (required by hosted providers).

### 3. Directory layout (predefined, documented)

```
account-ownership-recovery-cli/          ← extracted zip
├── bin/account-ownership-recovery-cli   ← start script (heap + native-access flags)
├── lib/account-ownership-recovery-cli-all.jar
├── README.md  USAGE.md
├── keys/                                ← the published key bundle goes here (manual download)
│   ├── pointsA.bin … pointsB2.bin       ← proving-key store (mmap-loaded)
│   ├── aux.bin  manifest.properties     ← VK + dimensions
│   ├── circuit.fingerprint              ← constraint count + R1CS hash
│   └── manifest.sha256                  ← integrity manifest (checked by prove/verify/info)
└── proofs/                              ← prove output
```

The coordinator publishes the `keys/` bundle (e.g. release asset or storage bucket); users drop it
into the extracted app directory. `info` and every command validate the manifest before use.

### 4. Distribution

Gradle `distZip` produces `account-ownership-recovery-cli-<version>.zip` containing the fat jar,
start scripts (unix + windows), README and USAGE guide — uploaded to the zeroj-usecases GitHub
release. Follow-ups (out of scope for v1): GraalVM native-image distribution and a Docker image.

## Security considerations

- **Seed handling:** mnemonic via hidden interactive prompt only; root key derived in-process;
  nothing secret is written or transmitted. The proof + public inputs are the only outputs.
- **Setup trust:** `local` keys are for development/testing — whoever ran the setup can forge
  proofs. Any production deployment must publish a bundle produced from the `ptau`/`filecoin` path,
  ideally with a multi-party phase-2 ceremony (ZeroJ ADR-0031 tooling: snarkjs or the
  `zeroj-ceremony` native contributor; verification always via stock `snarkjs zkey verify`).
- **Bundle integrity:** users verify `manifest.sha256` (automated by the CLI) against the hashes
  the coordinator publishes; the circuit fingerprint pins the exact R1CS the keys bind to.
- **On-chain gate:** the demo validator verifies the proof against the datum-pinned pkh; it does
  not bind the spending transaction context — production validators must add that (replay
  protection), as already documented in the usecase.

## Limitations (stated plainly)

- **Proving hardware:** ~64 GB+ RAM required today (measured ~66–70 GB peak). Mitigations tracked
  upstream: hint-based circuit reduction (~19M → ~11–12M) once the gadget audit clears; witness
  streaming; optionally a remote-proving deployment of this same app on a server.
- **Filecoin mode** is coordinator-grade, not consumer-grade (download size + one-time prepare
  time) — by design it exists so the *published key bundle* can carry real phase-1 trust.
- The app pins one derivation path shape (`account'/0/index`, configurable indices); other roles
  or multi-address batching are follow-ups.

## Implementation milestones (post-review)

| # | milestone | exit criteria |
|---|---|---|
| M1 | scaffold (standalone gradle + picocli) + `setup --tau local` + keys export/manifest | fresh checkout builds independently; setup produces a loadable bundle; `info` validates it |
| M2 | `prove` | proof generated from a real mnemonic against M1 keys in ≤ 5 min warm; secrets never persisted |
| M3 | `verify` off-chain + on-chain | off-chain pairing check green; on-chain verify green against Yaci DevKit with default endpoint |
| M4 | `setup --tau ptau` | snarkjs-orchestrated phase 2 from a small prepared ptau on a rehearsal circuit + the real circuit path wired |
| M5 | `setup --tau filecoin` | download/convert/verify/truncate/prepare orchestration with resume support; costs surfaced to the operator before starting |
| M6 | `distZip` + README/USAGE + release upload wiring | zip installs + runs on a clean machine; docs cover both roles end to end |

Each milestone: implement → test → iterate before moving on.

## References

- ZeroJ ADR-0029 (prover performance: mmap'd key store, multi-core blst prover — the numbers above)
- ZeroJ ADR-0031 (MPC trusted-setup ceremony: r1cs export, streaming zkey import, native contributor, phase-1 source analysis)
- `account-ownership-recovery/README.md` + `DESIGN.md` (the underlying usecase and its security analysis)
