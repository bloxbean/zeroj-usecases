# Private Voting Demo — Encrypted Ballots and a Homomorphic Tally on Cardano

Cast votes in a DAO election **without revealing who you are or how you voted**. Each ballot is
an encryption of 0 or 1 under a key that a set of trustees share. Ballots are added up while
still encrypted, and only the final total is decrypted, once, after voting closes. Zero-knowledge
proofs (Groth16 on BLS12-381) are verified on-chain with Plutus V3. A sorted linked list of
nullifiers prevents double voting.

Built with [ZeroJ](https://github.com/bloxbean/zeroj), a pure Java ZK toolkit for Cardano.
Design: [ADR-0005](../docs/adr/0005-private-ballot-homomorphic-tally.md), which fixes
[issue #7](https://github.com/bloxbean/zeroj-usecases/issues/7).

## What This Demo Does

1. **Creates an election** with 5 test voters and **3 trustees**. Each trustee generates a share
   of the election key and proves it knows the secret behind it. The election key is the sum of
   the shares.
2. **Builds a voter eligibility Merkle tree.** Its root, the election id, the election key and the
   voting deadline become parameters of the on-chain scripts.
3. **Voters cast YES or NO.** The vote is encrypted with exponential ElGamal on the Jubjub curve:
   `A = [k]·G`, `B = [vote]·G + [k]·PK`. A ZK proof shows that the voter is eligible, that the
   nullifier is theirs, and that the ballot encrypts a 0 or a 1, without revealing which.
4. **On-chain verification.** The ballot policy verifies the proof, with every public input taken
   from its parameters or from the ledger. The vote list stores the ballot under the voter's
   nullifier, so each voter can vote once.
5. **Tally after the deadline.** Anyone can add up the encrypted ballots. Each trustee decrypts
   its share of the sum and proves it did so correctly. The shares together reveal the number of
   YES votes. The result re-verifies from chain data and the election manifest.

**What stays private.**
- **Public observers** see encrypted ballots, nullifiers and the final totals. They cannot open a
  ballot, nor link a nullifier to a voter.
- **Trustees** cannot decrypt a single ballot unless all of them collude. Decrypting the running
  total early would let anyone compare two totals and learn one vote, so the tally is decrypted
  exactly once, after the deadline.
- **The vote list is public:** anyone can see how many ballots were cast and when.

**Demo shortcuts.** The server holds every voter's and every trustee's secret and proves on their
behalf, so in this demo the server knows every vote. The protocol separates these roles; the demo
does not. The trusted setup is single-party and for development only. See
[Important Notes](#important-notes).

## Prerequisites

| Requirement | Version | How to install |
|-------------|---------|----------------|
| Java (GraalVM) | 25 | `sdk install java 25.0.2-graal` |
| Yaci DevKit | Latest | [yaci-devkit](https://github.com/bloxbean/yaci-devkit) |

## Quick Start

```bash
# 1. Start Yaci DevKit
yaci-cli devkit start

# 2. Set Java 25
sdk use java 25.0.2-graal

# 3. Build
cd private-voting
./gradlew clean bootJar

# 4. Top up admin wallet
curl -X POST http://localhost:10000/local-cluster/api/addresses/topup \
  -H "Content-Type: application/json" \
  -d '{"address":"addr_test1qryvgass5dsrf2kxl3vgfz76uhp83kv5lagzcp29tcana68ca5aqa6swlq6llfamln09tal7n5kvt4275ckwedpt4v7q48uhex","adaAmount":10000}'

# 5. Run
java --enable-native-access=ALL-UNNAMED \
  -Dzeroj.allowInsecureTrustedSetup=true \
  -jar build/libs/private-voting-*.jar
```

Startup takes about 2 minutes the first time (circuit compilation and the dev setup for both circuits); the keys are then cached under `data/`, and later starts are faster.

### 6. Open UI: **http://localhost:8086**

## Demo Flow via curl

```bash
# Election is auto-created with 5 voters at startup
# Check election status
curl http://localhost:8086/api/election/status | python3 -m json.tool

# voter1 votes YES
curl -X POST http://localhost:8086/api/vote \
  -H "Content-Type: application/json" \
  -d '{"voterLabel":"voter1","vote":1}'

# voter2 votes NO
curl -X POST http://localhost:8086/api/vote \
  -H "Content-Type: application/json" \
  -d '{"voterLabel":"voter2","vote":0}'

# voter3 votes YES
curl -X POST http://localhost:8086/api/vote \
  -H "Content-Type: application/json" \
  -d '{"voterLabel":"voter3","vote":1}'

# Double vote — rejected!
curl -X POST http://localhost:8086/api/vote \
  -H "Content-Type: application/json" \
  -d '{"voterLabel":"voter1","vote":0}'

# Tally: before the deadline only the encrypted sum; after it the decrypted totals,
# the trustee shares with their proofs, and the verification checks
curl http://localhost:8086/api/results | python3 -m json.tool
# → {phase: "decrypted", yes: 2, no: 1, total: 3, verified: true, checks: [...]}

# The election manifest: everything needed to re-check the scripts and the tally
curl http://localhost:8086/api/election/manifest | python3 -m json.tool
```

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/election/status` | Election info (voters, root, finalized) |
| POST | `/api/election/create` | Create new election (`name`) |
| POST | `/api/election/register` | Register voter (`label`, `secretKey`) |
| POST | `/api/election/finalize` | Build voter Merkle tree |
| POST | `/api/vote` | Cast vote (`voterLabel`, `vote`: 0=NO, 1=YES) |
| GET | `/api/election/manifest` | Election manifest (keys, key proofs, script hashes, seed) |
| GET | `/api/results` | Tally: encrypted sum while open; totals, shares and checks after the deadline |
| GET | `/api/status` | System status (circuit, election, votes) |

## How It Works

Each vote:
1. Encrypts the vote under the election key with fresh randomness `k`.
2. Generates a ZK proof of the ballot relation (`PrivateBallotProof`), about 9.5k constraints at
   depth 10.
3. Submits a Cardano transaction, valid only until the voting deadline, in which:
   - **VoteZkMintingPolicy** mints the nullifier token. It verifies the Groth16 proof against the
     election id, voter root and election key fixed in its parameters, and against the ballot
     read from the new list node's datum.
   - **VoteListValidator** inserts a node keyed by the nullifier into the sorted list. The list
     admits each nullifier once, an insert can touch only its anchor, and the root can be
     created only once.
4. The nullifier is `Poseidon(secretKey, electionId)`: the same voter and the same election always
   give the same nullifier.

The tally (`TallyService`):
1. Walks the vote list from its root. It fails closed if the list is broken, if any list token
   lies outside the walk, or if any node is malformed.
2. After the deadline (plus a settling margin), adds up the ballots and asks each trustee for its
   decryption share. Each share carries a proof that it used the same secret as the trustee's
   published key (`TrusteeShareProof`).
3. Recovers the YES count from `ΣB − Σ shares = [YES]·G`, publishes it with a digest of the ballot
   set, and re-verifies everything from public data.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Spring Boot 3.5.0-M3 |
| Java | GraalVM 25 |
| ZK Proofs | ZeroJ (Groth16, BLS12-381, pure Java) |
| On-chain | Julc (Java to Plutus V3) |
| Cardano client | cardano-client-lib 0.8.0 |
| Frontend | Svelte 5 + Vite |
| Local devnet | Yaci DevKit |

## Project Structure

```
private-voting/
├── build.gradle
├── src/main/java/.../voting/
│   ├── PrivateVotingApplication.java
│   ├── circuit/PrivateBallotProof.java      # Ballot relation (eligibility + ElGamal)
│   ├── circuit/TrusteeShareProof.java       # Trustee key / decryption-share relation
│   ├── circuit/JubjubElGamalGadget.java     # In-circuit ElGamal and DLEQ
│   ├── crypto/JubjubElGamal.java            # Host-side ElGamal and tally
│   ├── config/CardanoConfig.java            # Network config
│   ├── controller/
│   │   ├── ElectionController.java          # Election management API
│   │   └── VoteController.java              # Voting + results API
│   ├── service/
│   │   ├── VoteCircuitService.java          # Circuit compile + prove
│   │   ├── ElectionService.java             # Voter registration + Merkle tree
│   │   ├── AccountSetupService.java         # Test account creation
│   │   ├── OnChainVoteService.java          # On-chain tx building
│   │   ├── KeyedCircuit.java               # Circuit + dev keys + JSON verification
│   │   └── TallyService.java               # Homomorphic tally and verification
│   └── onchain/
│       ├── VoteZkMintingPolicy.java         # Groth16 verifier (Plutus V3)
│       ├── VoteListValidator.java           # Sorted linked list (Plutus V3)
│       └── VoteListLib.java                 # List validation logic
├── src/main/resources/
│   ├── application.yml
│   └── static/                              # Built frontend
└── frontend/                                # Svelte 5 + Vite source
```

## Important Notes

- **Dev trusted setup.** The setup is single-party. Whoever holds its toxic waste can forge
  ballots and trustee proofs. Production needs an MPC ceremony for both circuits.
- **Trust in the trustees.** They decrypt n-of-n: all must take part (liveness), and all must
  collude to open a single ballot (privacy). Threshold sharing with distributed key generation is
  future work.
- **Not provided:** receipt-freeness and coercion resistance. A voter can reveal `k` to prove
  their vote. A small or unanimous result also reveals how everyone voted.
- **Linkability.** On a real network, voters submitting their own transactions would link their
  nullifier to their wallet through fees and timing. A relayer is needed. The demo submits every
  ballot from one admin wallet.
- **Finality.** On a public network the tally must wait for the deadline plus a finality margin;
  configure `election.tally-settle-seconds`.
- **Locked ADA.** Each on-chain vote node locks about 2 ADA.
- **Test voters.** 5 test voters are auto-created at startup with deterministic secret keys.

## Configuration

| Property | Default | Meaning |
|---|---|---|
| `zk.tree-depth` | 10 | Eligibility tree depth (up to 1024 voters) |
| `election.trustee-count` | 3 | Trustees holding shares of the election key |
| `election.voting-window-seconds` | 600 | Ballots are accepted until this long after startup |
| `election.tally-settle-seconds` | 20 | Wait after the deadline before decrypting |

## Tests

```bash
./gradlew test                          # circuits, host ElGamal, Plutus VM mutation tests
ZEROJ_YACI_E2E=true ./gradlew test      # + a full election on a running Yaci DevKit
```

`JubjubElGamalTest` checks the Java implementation against an independent Python reference
(`src/test/resources/elgamal-reference/`), which re-implements Jubjub and the tally from the curve
definition.
