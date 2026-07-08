# Account Ownership Recovery (ZK)

Prove you are the **real owner** of a Cardano address — because you know the seed/root key it was
derived from — **without revealing the seed**, and even after an attacker has stolen the address's
spending key. Motivated by the **SecondFi (EMURGO) wallet exploit** (June 2026), where a signing
bug leaked each address's *leaf spending key* but not the BIP39 mnemonic / root key.

See [`DESIGN.md`](./DESIGN.md) for the full problem analysis, threat model, and feasibility study,
and ZeroJ **ADR-0027** for the in-circuit crypto gadgets this builds on.

## What this demonstrates

| Layer | What | Circuit | Where verified |
|-------|------|---------|----------------|
| **Ownership gate** (the practical gate) | The claimant's **root key** derives, via the full `m/1852'/1815'/0'/0/0` path, to the address's payment key hash | `OwnershipProof` — **19,075,097 constraints** (3 hardened + 2 soft in-circuit Ed25519 derivation steps + blake2b-224; ~90M naive, reduced by ADR-0028 windowing/lazy-reduction) | **on-chain** via the `OwnershipProofValidator` Julc validator (Groth16 BLS12-381) on Yaci DevKit — fee ≈ 0.95 ADA |
| **Recovery gate** (lightweight alternative) | Knowledge of the recovery secret behind the address's registered commitment | `Poseidon(secret, addrKeyHash) == commitment` (829 constraints) | **on-chain** via the `RecoveryProofValidator` Julc validator on Yaci DevKit |

The ownership gate verifies the *real* ownership statement on-chain: a passing proof **is** proof of
seed ownership — no registered secret. Proving the 19M-constraint derivation is practical with
ZeroJ's ADR-0029 prover: **one-time trusted setup ~47 min** (proving key persisted, ~23 GB), then
**~2 min per proof** (blst backend, multi-core, warm key; ~70 GB peak heap on a 12-core/128 GB box).
On-chain verification cost is independent of circuit size (O(#public inputs): the 28 pkh bytes).
The Poseidon-commitment gate remains as the lightweight variant for constrained provers.

## Run it

Requires a running **Yaci DevKit** (admin `http://localhost:10000`, Blockfrost
`http://localhost:8080/api/v1/`).

```bash
# Fast: recovery-commitment circuit proves for an address
./gradlew test --tests '*AccountOwnershipRecoveryYaciE2ETest.recoveryCommitment_provesForAddress'

# On-chain recovery gate end-to-end on Yaci DevKit (submits real txs)
ZEROJ_YACI_E2E=true ./gradlew test --tests '*AccountOwnershipRecoveryYaciE2ETest.recoveryGate_verifiesOnChain'

# Off-chain ownership witness check (fast sanity: derivation reproduces the pkh)
./gradlew test --tests '*AccountOwnershipRecoveryYaciE2ETest.ownershipProof_rootKeyDerivesToAddress' -PzerojHeavy=true
```

**The real ownership gate** (heavy: 19M-constraint prove + on-chain verify) runs **standalone** —
gradle's daemon does not survive long heavy-heap runs:

```bash
./gradlew compileTestJava printTestCp
# one-time setup (~47 min, ~90G heap) happens automatically if the key cache is empty;
# warm runs: load key ~2 min + prove ~2 min + on-chain verify seconds.
java -Xmx90g --enable-native-access=ALL-UNNAMED \
  -Dzeroj.allowInsecureTrustedSetup=true -Dzeroj.pkcache=/tmp/zeroj-pk-derivation \
  -cp "$(cat build/test-classpath.txt)" \
  com.bloxbean.cardano.zeroj.usecases.recovery.OwnershipGateOnChainE2ETest

# per-stage timing/memory benchmark of the same pipeline (no on-chain step)
java -Xmx90g --enable-native-access=ALL-UNNAMED \
  -Dzeroj.derivbench=true -Dzeroj.allowInsecureTrustedSetup=true -Dzeroj.pkcache=/tmp/zeroj-pk-derivation \
  -cp "$(cat build/test-classpath.txt)" \
  com.bloxbean.cardano.zeroj.usecases.recovery.DerivationProofBenchmark
```

## Key components

- `circuit/OwnershipProof` — the 19M-constraint CIP-1852 derivation circuit (annotation DSL, `ZkCip1852`).
- `service/OwnershipCircuitService` — compiles the circuit, persists/loads the proving key (`Groth16PkStore`), proves (pluggable backend; blst for speed).
- `onchain/OwnershipProofValidator` — Plutus V3 Julc validator; verifies the derivation proof on-chain (datum = the 28 pkh bytes).
- `service/OnChainOwnershipService` — deploys the ownership gate, locks it, and verifies by unlocking with the proof.
- `OwnershipGateOnChainE2ETest` — the practical-gate E2E (standalone `main`).
- `service/RecoveryCircuitService` + `onchain/RecoveryProofValidator` + `service/OnChainRecoveryService` — the lightweight Poseidon-commitment gate.
- `AccountOwnershipRecoveryYaciE2ETest` — commitment-gate E2E; `DerivationProofBenchmark` — ADR-0029 per-stage benchmark.

The in-circuit CIP-1852 / BIP32-Ed25519 derivation gadgets (SHA-512, HMAC-SHA512, Blake2b, the
`GF(2^255-19)` field, Ed25519, and the composed derivation) live in ZeroJ's `zeroj-circuit-lib`
under ADR-0027.
