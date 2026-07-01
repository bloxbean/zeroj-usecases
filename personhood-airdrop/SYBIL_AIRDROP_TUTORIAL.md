# Sybil-Resistant Airdrop — Tutorial

Shows how to build a **one-per-human faucet** on Cardano using ZK proofs:
each personhood credential can claim ADA once per epoch. The ZK circuit
proves "I hold an issuer-signed personhood credential" + publishes a
deterministic nullifier; Cardano's NFT asset-name uniqueness (per policy
ID) prevents any second claim for the same (credential, epoch) pair.

## 1. Why this is different from an "age/country KYC" gate

ADR-0016's `identity-kyc` demo proves eligibility (age ≥ X, country ∈ Y).
Proofs there can be reused indefinitely — one credential always verifies.

This demo adds a **rate limit per credential**: the holder proves
possession *and* binds the proof to (credential × epoch) via a
deterministic nullifier. Attempting to claim twice with the same
credential in the same epoch produces the same nullifier → the mint
would try to mint an NFT that already exists → tx fails.

This is the ZK building block underneath: Semaphore signals, Tornado
Cash withdrawals, Worldcoin claim tokens, every airdrop that wants
sybil resistance.

## 2. Architecture

```
 ┌────────────────┐       ┌────────────────┐       ┌──────────────────┐
 │ Personhood     │       │  Holder        │       │  Cardano         │
 │ Issuer         │─────▶ │  (UI)          │─────▶ │  Faucet minting  │
 │ (e.g. BrightID)│  sig  │  proof + mint  │       │  policy (Plutus) │
 │ sk, pk         │       │                │       │                  │
 └────────────────┘       └────────────────┘       └──────────────────┘
                                 │                          │
                                 ├─ (personhoodId)        ─ Groth16 BLS12-381
                                 │  EdDSA(sk, Poseidon     verification
                                 │  (personhoodId, 0))      +
                                 │                          NFT name = nullifier
                                 ▼                          + mint qty == 1
                          nullifier = Poseidon(
                              personhoodId, epoch)
```

### Components

| Piece | Role |
|---|---|
| `PersonhoodIssuerService` | Holds the issuer's Jubjub keypair; signs one credential per enrolled person |
| `PersonhoodAirdropProof` | In-SNARK: EdDSA verify + `nullifier == Poseidon(personhoodId, epoch)` + binds recipient |
| `AirdropProofService` | Compiles circuit, runs Powers-of-Tau + Phase-2 setup, generates claim proofs |
| `FaucetMintingPolicy` (Plutus V3) | Parameterized by Groth16 vk; gates 1 NFT mint per claim, asset name = nullifier |
| `OnChainAirdropService` | Submits the proof as a `mintAsset` tx; maintains off-chain used-nullifier cache |

## 3. End-to-end flow

### 3.1 Issuer setup (once)

```java
BigInteger sk = secureRandomScalar();
JubjubPoint pk = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(sk);
// Publish pk.u, pk.v
```

### 3.2 Credential issuance (per person)

```java
BigInteger personhoodId = newUnique256Bits(); // issuer tracks real-human uniqueness
BigInteger msg = Poseidon(personhoodId, 0);    // BLS12-381 scalar
EdDSAJubjub.Signature sig = EdDSAJubjub.sign(sk, msg);
// Deliver (personhoodId, sig) privately to the person
```

### 3.3 Claim (per epoch, per person)

```
input  (public):  pkU, pkV, epoch, nullifier, recipient, eligible
input  (secret):  personhoodId, sigRU, sigRV, sigS, kModL, kQuotient

circuit:
    claimsMsg = Poseidon(personhoodId, 0)
    InCircuitEdDSAJubjub.verify(pk, claimsMsg, sigR, sigS)  // asymmetric sig check
    assert nullifier == Poseidon(personhoodId, epoch)       // sybil binding
    recipient bound as public input (tx-shape commitment)
    eligible = 1
```

Plutus V3 minting policy verifies the Groth16 proof over BLS12-381 with 6
public inputs and mints 1 NFT whose asset name = nullifier bytes. A second
claim with the same personhoodId in the same epoch produces the same
nullifier → mint of existing NFT name = tx build fails.

## 4. API

Base URL (default): `http://localhost:8086`

### GET `/api/airdrop/status`

```json
{
  "issuerPkU": "0x…",
  "issuerPkV": "0x…",
  "currentEpoch": 1,
  "adaPerClaim": 2,
  "policyId": "c6c019a9…",
  "totalClaims": 2,
  "users": [
    { "name": "Alice", "personhoodId": "0x…", "alreadyClaimedThisEpoch": true },
    …
  ]
}
```

### POST `/api/airdrop/claim`

```
{ "name": "Alice", "recipient": "addr_test1…" (optional) }
```

Generates ZK proof + submits `mintAsset` tx. Returns tx hash, nullifier,
proving time. Rejects with HTTP 409 if the nullifier was already claimed.

### GET `/api/airdrop/history`

Session-local claim history (list of `(name, nullifier, txHash, provingMs)`).

## 5. Running

```
# Prereqs: Java 25, yaci-devkit on localhost
cd zeroj-usecases/personhood-airdrop
./gradlew bootRun
```

First boot runs Powers of Tau (~3 min) + Groth16 Phase-2 setup (~4 min)
for the 20k-constraint circuit. Subsequent boots load the cached setup
from `./data/` in <1s.

### Minimal demo script

```bash
# 1. Alice claims 2 ADA
curl -X POST -H 'Content-Type: application/json' \
  http://localhost:8086/api/airdrop/claim \
  -d '{"name": "Alice"}'

# 2. Alice attempts double-claim (fails with 409 — same nullifier)
curl -X POST -H 'Content-Type: application/json' \
  http://localhost:8086/api/airdrop/claim \
  -d '{"name": "Alice"}'

# 3. Bob claims (different nullifier — succeeds)
curl -X POST -H 'Content-Type: application/json' \
  http://localhost:8086/api/airdrop/claim \
  -d '{"name": "Bob"}'
```

Or open <http://localhost:8086> for the UI and click through.

## 6. Nullifier anatomy

`nullifier = Poseidon(personhoodId, epoch)` — 32 bytes. Deterministic in
both inputs, secret in personhoodId, public in epoch. The nullifier
reveals *nothing* about personhoodId (Poseidon is one-way). All that
leaks publicly is "this nullifier has been used" — i.e., "someone holding
some credential has claimed in this epoch".

Each epoch reset produces a fresh nullifier space; the same credential
can claim again next epoch with a completely different nullifier. No
linkability across epochs.

## 7. What this does NOT yet defend against

- **Stolen credentials**: if `personhoodId` leaks (compromised issuer,
  user shares credential bundle), attacker can claim once per epoch.
  Standard credential-system risk; mitigate via revocation lists (not
  demonstrated here).
- **Double-claim enforcement is off-chain in this demo.** The faucet
  minting policy verifies the Groth16 proof and requires `eligible == 1`,
  but it does **not** currently enforce either (a) that the minted NFT
  asset name equals the nullifier bytes, or (b) that the datum-carrying
  output is at a specific index. The real double-claim gate is the
  service's in-memory `claimedNullifiersHex` set plus Cardano's own
  "this asset name already exists in one of our UTxOs" check during
  tx build. Consequences:
  - If the service restarts, the in-memory set is lost. The ledger's
    UTxO set still holds the previously-minted NFT under the policy,
    so a second mint of the same asset name is still rejected at tx
    build — but this requires the builder to see the prior UTxO.
  - Concurrent claim requests for the same credential may race past
    the in-memory check; resolution depends on mempool ordering.
  - A production deployment should tighten the minting policy to
    assert `assetName(mintedToken) == nullifierBytes` and add a
    state-thread token (DST) carrying a Merkle set of used nullifiers
    for adversarial-signer defense.
- **Sybil at the issuer layer**: the demo simulates issuer uniqueness
  via an in-memory map. Real BrightID / Worldcoin / proof-of-personhood
  systems do biometric / social-graph checks; that's orthogonal to
  what's verified on Cardano.
- **Static epoch**: `currentEpoch` is read from `application.yml`, not
  from the chain. Bump it manually or wire it to the live Cardano
  epoch before a long-running deployment.

## 8. Where to go next

- Add a state-thread token to the minting policy for adversarial-signer
  defense.
- Rate-limit per epoch × recipient (currently one-per-credential, not
  one-per-wallet).
- Wire W3C VC issuance so the credential can be presented to non-Cardano
  services as well.
- Wallet integration via CIP-30: holder signs the claim tx locally
  rather than the service wallet-as-faucet.
