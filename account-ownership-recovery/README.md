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
| **Ownership proof** (off-chain) | The claimant's **root key** derives, via the full `m/1852'/1815'/0'/0/0` path, to the address's payment key hash | `Cip1852Derivation` (~90M constraints: 3 hardened + 2 soft steps, each an in-circuit Ed25519 scalar mult, + blake2b-224) | in-circuit witness, cross-checked vs cardano-client-lib |
| **Recovery gate** (on-chain) | Knowledge of the recovery secret behind the address's registered commitment | `Poseidon(secret, addrKeyHash) == commitment` (829 constraints, provable) | **on-chain** via the `RecoveryProofValidator` Julc validator (Groth16 BLS12-381) on Yaci DevKit |

The ownership proof establishes *who the real owner is* (only they know the seed); the on-chain
recovery gate is the provable, trustless authorization a recovery contract can act on. Because
proving the full ~90M-constraint derivation circuit at scale is not yet practical (see ADR-0027
§6.1 — gated on the blst prover + field/windowing optimizations), the **on-chain** gate uses the
lightweight proactive-commitment circuit (DESIGN §14), while the derivation proof is established at
the witness level today.

## Run it

Requires a running **Yaci DevKit** (admin `http://localhost:10000`, Blockfrost
`http://localhost:8080/api/v1/`).

```bash
# Fast: recovery-commitment circuit proves for an address
./gradlew test --tests '*AccountOwnershipRecoveryYaciE2ETest.recoveryCommitment_provesForAddress'

# On-chain recovery gate end-to-end on Yaci DevKit (submits real txs)
ZEROJ_YACI_E2E=true ./gradlew test --tests '*AccountOwnershipRecoveryYaciE2ETest.recoveryGate_verifiesOnChain'

# Off-chain ownership proof: root key -> address payment key hash (heavy, ~90M constraints, 48G heap)
./gradlew test --tests '*AccountOwnershipRecoveryYaciE2ETest.ownershipProof_rootKeyDerivesToAddress' -PzerojHeavy=true
```

## Key components

- `service/RecoveryCircuitService` — builds/sets-up/proves the recovery-commitment Groth16-BLS12381 circuit.
- `onchain/RecoveryProofValidator` — Plutus V3 Julc validator; verifies the Groth16 proof on-chain.
- `service/OnChainRecoveryService` — deploys the validator, locks the attestation, and verifies by unlocking with the proof.
- `AccountOwnershipRecoveryYaciE2ETest` — the three-part E2E above.

The in-circuit CIP-1852 / BIP32-Ed25519 derivation gadgets (SHA-512, HMAC-SHA512, Blake2b, the
`GF(2^255-19)` field, Ed25519, and the composed derivation) live in ZeroJ's `zeroj-circuit-lib`
under ADR-0027.
