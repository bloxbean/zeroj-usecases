# Sybil-Resistant Airdrop — Tutorial

Shows how to build a **one-per-human faucet** on Cardano using ZK proofs:
each personhood credential can claim ADA once per airdrop round. The ZK
circuit proves "I hold an issuer-signed personhood credential" and publishes
a nullifier; the minting policy checks the proof and that the payout goes to
the proved recipient. The faucet records every nullifier it pays and refuses
to pay it twice. The receipt token is a public record; its uniqueness is not
enforced on-chain (see §7).

The design follows ADR-0009 D3 and D11
([docs/adr/0009](../docs/adr/0009-privacy-and-binding-hardening-of-the-original-demos.md)).

## 1. Why this is different from an "age/country KYC" gate

ADR-0016's `identity-kyc` demo proves eligibility (age ≥ X, country ∈ Y).
Proofs there can be reused indefinitely — one credential always verifies.

This demo adds a **rate limit per credential**: the holder proves
possession *and* binds the proof to (credential × round) via a
deterministic nullifier. A second claim with the same credential in the
same round produces the same nullifier, and the faucet refuses to pay it.

This is the ZK building block underneath: Semaphore signals, Tornado
Cash withdrawals, Worldcoin claim tokens, every airdrop that wants
sybil resistance.

## 2. Architecture

```
 ┌────────────────┐  m = Poseidon(pid, 0)  ┌────────────────┐       ┌──────────────────┐
 │ Personhood     │ ◀───────────────────── │  Holder        │       │  Cardano         │
 │ Issuer         │ ─────────────────────▶ │  wallet        │─────▶ │  FaucetMinting   │
 │ (one-human     │      sig over m        │  keeps pid     │ proof │  Policy (Plutus) │
 │  check)        │                        │                │       │                  │
 └────────────────┘                        └────────────────┘       └──────────────────┘
                                                  │                          │
                                  nullifier = Poseidon(pid, policyEpoch)     ├─ Groth16 BLS12-381
                                                                             ├─ issuer key, epoch pinned
                                                                             ├─ receipt name = nullifier
                                                                             └─ ≥ payout to recipient key
```

The holder samples its own `personhoodId` (`pid`, 252 bits from
`SecureRandom`) and sends the issuer only `m = Poseidon(pid, 0)`. The issuer
signs `m` and never sees `pid`, so it cannot compute `Poseidon(pid, epoch)`
and cannot link claims to persons. The circuit is the same as before: it
proves knowledge of a `pid` whose `Poseidon(pid, 0)` the issuer signed.

### Components

| Piece | Role |
|---|---|
| `PersonhoodIssuerService` | Signs `m` for a person, once. Keeps a durable record of persons issued to and refuses a second issuance. Never receives `pid`. |
| `HolderWallet` | Holder side: samples `pid`, sends `m`, keeps `pid` and the signature. **Custodial in this demo** (the server holds it). |
| `PersonhoodAirdropProof` | In-SNARK: EdDSA verify + `nullifier == Poseidon(personhoodId, epoch)` + binds recipient |
| `AirdropProofService` | Compiles circuit, runs Powers-of-Tau + Phase-2 setup, generates claim proofs |
| `FaucetMintingPolicy` (Plutus V3) | Parameterised by the Groth16 vk, the issuer key, `policyEpoch` and `payout`. Mints one receipt per claim, named after the nullifier, and requires `payout` lovelace to the recipient's key credential. |
| `OnChainAirdropService` | Deploys (seed outref), records each paid nullifier before signing, refuses recorded or on-chain-receipted nullifiers, submits the claim. |
| `AirdropKeys` | Random, persisted issuer key and faucet admin wallet (ADR-0009 D11). |

## 3. End-to-end flow

### 3.1 Keys and deployment (once)

On first start the demo generates, with `SecureRandom`:

- the issuer's EdDSA-Jubjub key (`EdDSAJubjub.generateKeypair`), whose
  public key is a policy parameter;
- the faucet admin wallet, which holds the faucet's ADA. It is funded through
  Yaci DevKit's top-up API (`demo.topup.enabled`).

Both are written atomically (temp file and rename), owner-only, to the demo
data directory (`airdrop.data-dir`, default `./data`; `/app/data` in Docker).
The faucet then picks a **seed outref** from its admin wallet and records it,
with the keys' public parts, in `airdrop-deployment.json`.

A restart loads the keys. If deployment state exists but a key file is
missing, unreadable or does not match the recorded deployment, the demo
stops with an error; it never creates a replacement key. The only reset is
`./demo.sh airdrop --clean-cache` (outside Docker: delete the `airdrop-*.json`
files together), which is a fresh deployment with new keys and a new policy id.

There is no published issuer seed any more. A credential signed with the old
seed (`deadbeef…`) is refused by the policy, which pins the random issuer key.

### 3.2 The epoch is a domain tag

```
policyEpoch  = Poseidon2(Poseidon2(tag("zeroj.airdrop.epoch.v1"), deploymentId), n)
tag(s)       = integer(blake2b_256(UTF-8(s))), top byte cleared
deploymentId = integer(blake2b_256(txId ‖ I2OSP2(index))), top byte cleared,
               over the faucet's seed TxOutRef
n            = faucet.round, 1 ≤ n < 2^32
```

`Poseidon2` is ZeroJ's `PoseidonHash` over `PoseidonParamsBLS12_381T3`. Two
deployments, two sibling seed outputs `(T, 0)` and `(T, 1)`, or two rounds of
one deployment never share a nullifier. The policy refuses `policyEpoch = 0`
and any epoch `≥ r` (the BLS12-381 scalar field order).

### 3.3 Credential issuance (per person, once)

```java
// Holder
BigInteger pid = new BigInteger(252, secureRandom);       // holder's secret
BigInteger m = Poseidon(pid, 0);
EdDSAJubjub.Signature sig = issuer.issue(person, m);      // the issuer sees person and m only

// Issuer, after its one-human check (out of band)
if (issued(person)) throw new AlreadyIssuedException(person);
record(person);                                           // durable, before signing
return EdDSAJubjub.signCompatibilityOffline(keypair, JubjubMessage(m));
```

### 3.4 Claim (per round, per person)

```
input  (public):  pkU, pkV, epoch, nullifier, recipient, eligible
input  (secret):  personhoodId, sigRU, sigRV, sigS, kModL, kQuotient

circuit:
    claimsMsg = Poseidon(personhoodId, 0)
    ZkEdDSAJubjub.verifyWithRegisteredKey(
        pkU, pkV, claimsMsg, sigRU, sigRV, sigS, kModL, kQuotient)
    assert nullifier == Poseidon(personhoodId, epoch)       // sybil binding
    recipient bound as public input
    eligible = 1
```

`recipient` is the integer of the recipient's 28-byte payment key hash. The
API accepts only addresses whose payment credential is a key hash; script
addresses, stake addresses and Byron addresses are refused, with no fallback.

The minting policy requires, for the 6 public inputs in the receipt's datum:

1. the mint map under the policy is exactly one entry, `I2OSP32(nullifier)`
   with quantity 1 (an extra entry of any quantity, including a burn, is refused);
   the receipt goes to the exact receipt address: the policy's script credential
   with no stake credential;
2. `(pkU, pkV)` = the parameterised issuer key;
3. `epoch` = `policyEpoch`, with `0 < policyEpoch < r`;
4. `eligible = 1`;
5. an output whose payment credential is a key hash `h`, `|h| = 28`,
   `integer(h) = recipient`, carrying at least `payout` lovelace;
6. the Groth16 proof verifies.

Before signing the payout, the faucet refuses a nullifier that is already in
its paid-nullifier record (`airdrop-paid-nullifiers.json`) or whose receipt
unit was ever minted, wherever it went (Yaci Store's `assets/{unit}/history`;
if that lookup fails, the claim is refused). It then records the nullifier,
atomically and owner-only (temp file, fsync, rename, fsync of the directory).
The record survives restarts. It is released only if nothing was submitted
(build or signing failed), or if the node gave a definitive validation
rejection and the transaction is not on-chain. A transport error, a duplicate
or mempool answer, or any other outcome keeps it, so a holder whose claim
ended in an unknown state cannot claim again without operator action.

## 4. API

Base URL (default): `http://localhost:8086` (Docker: `8083`).

The demo server holds every holder's wallet, so this API is the **operator's
view**: privacy holds against chain and mempool observers, not against the
demo server. Even so, `/status` and `/history` return no names next to
nullifiers and no bits of any `personhoodId`.

### GET `/api/airdrop/status`

```json
{
  "users": [ { "name": "Alice", "alreadyClaimedThisRound": true }, … ],
  "issuerPkU": "0x…",
  "issuerPkV": "0x…",
  "round": 1,
  "policyEpoch": "0x…",
  "adaPerClaim": 2,
  "totalClaims": 1,
  "policyId": "c6c019a9…",
  "faucetAdmin": "addr_test1…"
}
```

### POST `/api/airdrop/claim`

```
{ "name": "Alice", "recipient": "addr_test1…" (optional) }
```

`name` selects a holder in the custodial demo wallet. The recipient must be a
key-credential address; if it is omitted, the payout goes to the faucet
admin's own address. Generates the ZK proof and submits the claim. Returns
the tx hash, nullifier and proving time. HTTP 409 if the nullifier was
already paid; HTTP 400 for a script or otherwise unusable recipient.

### GET `/api/airdrop/history`

Claims made through this server since it started: nullifier, tx hash, round,
amount, recipient and proving time. No holder names.

## 5. Running

```
# Prereqs: Java 25, yaci-devkit on localhost
cd zeroj-usecases/personhood-airdrop
./gradlew bootRun
```

The circuit has 10,467 constraints and uses a power-14 development SRS.
First-boot setup time is machine-dependent. Later boots load a setup whose
filename is keyed by SHA-256 of the complete serialized R1CS.

Upgrading from an earlier version: the issuer key, the policy parameters and
the policy id all change, so start fresh (`./demo.sh airdrop --clean-cache`).

On a network other than DevKit, set `DEMO_TOPUP_ENABLED=false` and fund the
faucet admin address that the demo logs at startup.

### Minimal demo script

```bash
# 1. Alice claims 2 ADA (to the faucet admin address, the demo default)
curl -X POST -H 'Content-Type: application/json' \
  http://localhost:8086/api/airdrop/claim \
  -d '{"name": "Alice"}'

# 2. Alice attempts a double claim (409 — same nullifier, already paid)
curl -X POST -H 'Content-Type: application/json' \
  http://localhost:8086/api/airdrop/claim \
  -d '{"name": "Alice"}'

# 3. Bob claims (different nullifier — succeeds)
curl -X POST -H 'Content-Type: application/json' \
  http://localhost:8086/api/airdrop/claim \
  -d '{"name": "Bob"}'
```

Or open <http://localhost:8086> for the UI and click through.

### Tests

```bash
./gradlew test                         # unit + Plutus VM tests
ZEROJ_YACI_E2E=true ./gradlew test     # also the DevKit end-to-end test
```

`FaucetMintingPolicyVmTest` refuses a payout to another key, a script
credential carrying the recipient's hash, a payout below `payout`, epoch 0,
an epoch ≥ r and a credential signed with the old published seed.
`AirdropDevKitE2ETest` also shows that a replay spending a faucet input
without the admin's signature is refused by the ledger, and that a replay
with the claimant's own funds can mint a second receipt but takes no faucet
payout.

## 6. Nullifier anatomy

`nullifier = Poseidon(personhoodId, policyEpoch)` — 32 bytes. It is secret in
`personhoodId` and public in `policyEpoch`. Only the holder knows
`personhoodId`; the issuer saw only `Poseidon(personhoodId, 0)`. What is
public is "this nullifier has been used", that is, "someone holding some
credential has claimed in this round".

Each round (and each deployment) has its own `policyEpoch`, so the same
credential gets an unrelated nullifier next round.

## 7. Limitations

- **The one-human check is out of band.** The issuer is trusted to issue one
  credential per human. The demo stands in for that check with the person's
  name; real systems use biometric or social-graph checks.
- **A lost credential cannot be re-issued.** The issuer refuses a second
  issuance for a person, which is what stops one person from claiming twice
  with two holder-chosen identifiers. A holder that loses `personhoodId` or the
  signature cannot claim again.
- **Receipt uniqueness on-chain is deferred.** The policy keeps no "minted
  once" state. The faucet pays each nullifier at most once (its durable record
  plus the receipt check), and only the faucet admin's key can spend the
  faucet's ADA. A replay with the claimant's own funds can mint a second
  receipt for the same nullifier, but takes nothing from the faucet.
- **Front-running.** A mempool observer can copy a pending claim's proof into
  its own transaction. The policy still requires the payout to the proved
  recipient, so the copier can only pay the recipient from its own funds.
- **The demo is custodial.** The server holds every holder's wallet, so it
  knows each `personhoodId` (the issuer component does not). The API is the
  operator's view; a real holder keeps `personhoodId` on its own device.
- **Stolen credentials.** Whoever holds `personhoodId` and the signature can
  claim once per round. Revocation is not demonstrated.
- **Static round.** `faucet.round` is read from `application.yml`, not from
  the chain. Changing it deploys a new policy id.
- **Issuer signing scope.** The issuer signs with ZeroJ's compatibility/offline
  profile and is an in-process component. Do not expose it as a
  network-reachable issuance endpoint.
- **Devnet keys.** The issuer and faucet admin keys are random but stored
  unencrypted in the demo data directory. A production faucet keeps them in a
  KMS or HSM.

## 8. Where to go next

- Enforce receipt uniqueness on-chain (a sorted nullifier list, as in the NFT
  gate).
- Wallet integration via CIP-30: the holder keeps `personhoodId` and proves
  locally, rather than the server holding it.
- Wire W3C VC issuance so the credential can be presented to non-Cardano
  services as well.
