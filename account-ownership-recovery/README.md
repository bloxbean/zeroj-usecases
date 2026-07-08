# Account Ownership Recovery (ZK)

Prove you are the **real owner** of a Cardano address — because you know the seed/root key it was
derived from — **without revealing the seed**, and even after an attacker has stolen the address's
spending key. Motivated by the **SecondFi (EMURGO) wallet exploit** (June 2026), where a signing
bug leaked each address's *leaf spending key* but not the BIP39 mnemonic / root key.

See [`DESIGN.md`](./DESIGN.md) for the problem analysis, threat model, and feasibility study, and
ZeroJ **ADR-0027** (in-circuit crypto gadgets) + **ADR-0029** (prover performance) for the
machinery this builds on.

## The statement proven

> *"I know a root key (kL, kR, chain code) that derives, via the full CIP-1852 path
> `m/1852'/1815'/0'/0/0`, to this address's payment key hash."*

Only the true seed holder can prove this — the exploit's attacker (holding just the leaf spending
key) cannot. The statement is proven with a Groth16 (BLS12-381) zero-knowledge proof of the
[`OwnershipProof`](src/main/java/com/bloxbean/cardano/zeroj/usecases/recovery/circuit/OwnershipProof.java)
circuit — **19,075,097 constraints** (BIP32-Ed25519 hardened+soft derivation steps, HMAC-SHA512,
Blake2b-224, all in-circuit over the BLS12-381 field; ~90M naive, reduced by ADR-0028
windowing/lazy-reduction) — and verified **on-chain** by a Plutus V3 validator. The root key never
leaves the prover; on-chain sees only the proof and the address's pkh.

## How it works, end to end

```
 ONE-TIME (per circuit)                          PER RECOVERY (per proof)
 ┌──────────────────────────────┐                ┌──────────────────────────────────┐
 │ 1. compile OwnershipProof    │                │ 4. lock gate UTxO                │
 │    → R1CS (19M, ~20s)        │                │    datum = pkh bytes (28)        │
 │ 2. trusted setup (~47min)    │                │ 5. witness from root key (~2s)   │
 │    → proving key + VK        │                │ 6. Groth16 prove (~2min, blst)   │
 │ 3. persist PK (~23GB) via    │                │ 7. unlock with proof → validator │
 │    Groth16PkStore; embed VK  │                │    verifies ON-CHAIN (~0.95 ADA) │
 │    in OwnershipProofValidator│                │                                  │
 └──────────────────────────────┘                └──────────────────────────────────┘
```

1. **Compile** — `OwnershipCircuitService.init()` builds the annotation-DSL circuit and compiles it
   to R1CS (19,075,097 constraints / 43.7M wires / 28 public inputs — the pkh bytes). ~20 s.
2. **Trusted setup (one-time)** — produces the **proving key** (PK, used by the prover) and the
   **verification key** (VK, a few curve points). ~47 min multi-core at 19M; dev-only single-party
   here (`-Dzeroj.allowInsecureTrustedSetup=true`) — production must use an MPC ceremony.
3. **Persist** — the PK (~23 GB) is written once via ZeroJ's `Groth16PkStore`; later runs mmap it
   back in ~2 min instead of re-running setup. The VK is compressed and baked into the
   `OwnershipProofValidator` script (script parameterization → a 1 KB Plutus V3 validator).
4. **Lock the gate** — a UTxO is locked at the validator address with **datum = the 28 pkh bytes**
   (the circuit's public inputs). This pins *which address* the gate is about.
5. **Witness** — the claimant supplies root `kL`/`kR`/chain code (secret) + the pkh (public); the
   circuit re-derives the full CIP-1852 path in-circuit and asserts it reaches that pkh.
6. **Prove** — Groth16 prove over the mmap'd PK: **~2 min** with the blst multi-core backend
   (`BlstProverBackend.create()`, ADR-0029; pure-Java multi-core also works, slower). Peak ~70 GB
   heap on a 12-core/128 GB box.
7. **Verify on-chain** — the unlock transaction carries the proof as redeemer; the validator runs
   Groth16 verification (pairings + the 28 public-input scalar-muls) **on-chain**. Measured on Yaci
   DevKit: fee ≈ **0.95 ADA**, independent of the circuit's 19M constraints —
   tx `73495f35b390caaa62e407a9b97865ca7d04a40ebf12ac3a2ad2f3d74a259703`.

A recovery contract can then act on the unlocked gate (e.g. release funds swept to escrow, rotate
staking rights, etc.) knowing the spender proved seed ownership — trustlessly.

## Run it

Requires a running **Yaci DevKit** (admin `http://localhost:10000`, Blockfrost
`http://localhost:8080/api/v1/`), Java 25, and for the fast prover the bundled blst
(`--enable-native-access`).

```bash
# fast-ish sanity check: the in-circuit derivation reproduces the pkh (witness only, no proof)
./gradlew test --tests '*OwnershipProofWitnessTest' -PzerojHeavy=true

# full end-to-end (heavy). Standalone java — gradle's daemon does not survive long heavy-heap runs.
./gradlew compileTestJava printTestCp
java -Xmx90g --enable-native-access=ALL-UNNAMED \
  -Dzeroj.allowInsecureTrustedSetup=true -Dzeroj.pkcache=/tmp/zeroj-pk-derivation \
  -cp "$(cat build/test-classpath.txt)" \
  com.bloxbean.cardano.zeroj.usecases.recovery.OwnershipGateOnChainE2ETest
# first run: setup ~47min then persists the PK; warm runs: ~2min load + ~2min prove + on-chain verify

# per-stage timing/memory benchmark of the same pipeline (no on-chain step)
java -Xmx90g --enable-native-access=ALL-UNNAMED \
  -Dzeroj.derivbench=true -Dzeroj.allowInsecureTrustedSetup=true -Dzeroj.pkcache=/tmp/zeroj-pk-derivation \
  -cp "$(cat build/test-classpath.txt)" \
  com.bloxbean.cardano.zeroj.usecases.recovery.DerivationProofBenchmark
```

## Key components

- [`circuit/OwnershipProof`](src/main/java/com/bloxbean/cardano/zeroj/usecases/recovery/circuit/OwnershipProof.java)
  — the CIP-1852 derivation circuit (annotation DSL, one line of logic thanks to `ZkCip1852`).
- [`service/OwnershipCircuitService`](src/main/java/com/bloxbean/cardano/zeroj/usecases/recovery/service/OwnershipCircuitService.java)
  — compile → PK persist/load (`Groth16PkStore`) → prove (pluggable `ProverBackend`).
- [`onchain/OwnershipProofValidator`](src/main/java/com/bloxbean/cardano/zeroj/usecases/recovery/onchain/OwnershipProofValidator.java)
  — Plutus V3 Julc validator parameterized with the circuit's VK; datum = pkh bytes.
- [`service/OnChainOwnershipService`](src/main/java/com/bloxbean/cardano/zeroj/usecases/recovery/service/OnChainOwnershipService.java)
  — deploys the gate, locks it, verifies by unlocking with the proof.
- `OwnershipGateOnChainE2ETest` — the end-to-end above (standalone `main`);
  `DerivationProofBenchmark` — ADR-0029 per-stage numbers; `OwnershipProofWitnessTest` — witness sanity.

The in-circuit CIP-1852 / BIP32-Ed25519 derivation gadgets (SHA-512, HMAC-SHA512, Blake2b, the
`GF(2^255-19)` field, Ed25519, and the composed derivation) live in ZeroJ's `zeroj-circuit-lib`
under ADR-0027.

## Production caveats

- The in-repo trusted setup is **single-party (dev only)** — a production gate needs an MPC
  ceremony for the 19M circuit.
- The demo validator verifies the proof but does not bind `ScriptContext` (tx outputs/inputs) —
  production validators must, to prevent proof replay in a different transaction (see ZeroJ's
  `Groth16BLS12381TxOutRefBindingVerifier` pattern).
- Recovery *policy* (what unlocking the gate authorizes, challenge periods, etc.) is deliberately
  out of scope here; `DESIGN.md` discusses the options.

> **Note:** an earlier iteration also shipped a lightweight `Poseidon(secret, addr) == commitment`
> stand-in gate, from before the 19M derivation was practically provable (pre-ADR-0029). It has
> been removed — the real derivation gate above supersedes it.
