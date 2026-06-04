# ZeroJ Use Case Demos

A collection of runnable, end-to-end examples that show how to build **zero-knowledge (ZK) applications on Cardano in pure Java** — no circom, no snarkjs, no native toolchains.

Every demo is built with **[ZeroJ](https://github.com/bloxbean/zeroj)** — a pure-Java zero-knowledge toolkit for Cardano (Groth16 proofs over the BLS12-381 curve, Poseidon hashing, a circuit DSL, and on-chain verifiers compiled to Plutus V3 via [Julc](https://github.com/bloxbean/zeroj)).

> **New to zero-knowledge proofs?** Jump to [What is a zero-knowledge proof?](#what-is-a-zero-knowledge-proof) and [Glossary](#glossary-plain-english) first, then come back to [Quick Start](#quick-start).

---

## Table of Contents

- [What is a zero-knowledge proof?](#what-is-a-zero-knowledge-proof)
- [The examples at a glance](#the-examples-at-a-glance)
- [Prerequisites](#prerequisites)
- [One-time setup](#one-time-setup)
- [Quick Start](#quick-start)
- [Two kinds of demo](#two-kinds-of-demo)
- [The examples in detail](#the-examples-in-detail)
- [Building everything at once](#building-everything-at-once)
- [Glossary (plain English)](#glossary-plain-english)
- [Troubleshooting](#troubleshooting)
- [Learn more](#learn-more)

---

## What is a zero-knowledge proof?

A zero-knowledge proof lets you **prove a statement is true without revealing why it is true**.

Classic examples you'll see in this repo:

- "I am over 18 and from an approved country" — *without revealing your age or country* ([identity-kyc](#1-identity-kyc--privacy-preserving-kyc)).
- "I own an NFT from this collection" — *without revealing which wallet or which NFT* ([nft-ownership](#2-nft-ownership--private-token-gated-access)).
- "Our exchange holds enough reserves to cover all customer balances" — *without revealing any individual balance* ([proof-of-reserves](#4-proof-of-reserves--zk-solvency)).

On Cardano, the proof is verified **on-chain** by a Plutus V3 script using the built-in BLS12-381 pairing operations, so a smart contract can gate funds or mint tokens based only on "the proof is valid."

ZeroJ does all of this in Java: you write the circuit (the statement to prove) as Java code, generate the proof on a plain JVM, and the matching on-chain verifier is generated for you.

---

## The examples at a glance

There are **12 examples**, in two styles.

### Full-stack demos (Spring Boot backend + Svelte UI + real on-chain transactions)

These run against a local Cardano devnet (Yaci DevKit), build and submit real transactions, and ship with a browser UI.

| # | Demo | What you prove | Port | On-chain pattern |
|---|------|----------------|------|------------------|
| 1 | [identity-kyc](#1-identity-kyc--privacy-preserving-kyc) | Age ≥ 18 AND country approved, without revealing them | 8087 | Spending validator (reusable proof) |
| 2 | [nft-ownership](#2-nft-ownership--private-token-gated-access) | I own an NFT, without revealing my wallet | 8085 | Nullifier in a sorted linked list (one-time) |
| 3 | [private-voting](#3-private-voting--anonymous-dao-governance) | I'm an eligible voter, without revealing identity/vote | 8086 | Nullifier list + vote commitments |
| 4 | [proof-of-reserves](#4-proof-of-reserves--zk-solvency) | Reserves ≥ liabilities, without revealing balances | 8089 | Merkle Sum Tree + attestation UTXO |
| 5 | [digital-product-passport](#5-digital-product-passport--eu-dpp-compliance) | Product is compliant (carbon, recycled %, origin) | 8088 | Poseidon MPF trie + spending validator |
| 6 | [personhood-airdrop](#6-personhood-airdrop--sybil-resistant-faucet) | I'm a unique human, claim once per epoch | 8086 | Nullifier as NFT asset name (sybil resistance) |
| 7 | [selective-disclosure](#7-selective-disclosure--one-credential-many-proofs) | Many predicates from one signed credential | 8085 | Two predicate-gated validators |

> Ports 8085/8086 are reused across demos — run **one demo at a time**, or change the port in that demo's `src/main/resources/application.yml`.

### Annotation-style circuit demos (command-line, no devnet needed)

These are smaller, focused examples of ZeroJ's **annotation-based circuit DSL** — you describe the circuit with Java annotations (`@ZkBool`, `@ZkUInt`, `@FixedSize`, …) and a companion circuit class is generated. They run with `./gradlew run` and print results to the console; great for understanding circuits in isolation.

| # | Demo | What it teaches |
|---|------|-----------------|
| 8 | [annotated-private-voting](#8-annotated-private-voting) | Voting circuit via symbolic annotations (registry root, vote commitment, nullifier) |
| 9 | [annotated-compliance-credential](#9-annotated-compliance-credential) | Selective-disclosure credential gate with `ZkUInt`/`ZkBool` constraints |
| 10 | [annotated-proof-of-reserves](#10-annotated-proof-of-reserves) | Parameterized fixed-depth Merkle circuit with `@CircuitParam`/`@FixedSize` |
| 11 | [annotated-batch-threshold-matrix](#11-annotated-batch-threshold-matrix) | Nested `ZkArray<ZkArray<…>>` matrix, row-major flattening |
| 12 | [zk-mpf-private-registry](#12-zk-mpf-private-registry) | Private membership in a Poseidon MPF trie (witness-level demo) |

---

## Prerequisites

| Requirement | Version | How to get it |
|-------------|---------|---------------|
| Java (GraalVM) | 25 | `sdk install java 25.0.2-graal` then `sdk use java 25.0.2-graal` (via [SDKMAN](https://sdkman.io/)) |
| Yaci DevKit | Latest | [github.com/bloxbean/yaci-devkit](https://github.com/bloxbean/yaci-devkit) — *only needed for the full-stack demos (1–7)* |
| Node.js | 18+ | Optional — only if you want to rebuild a Svelte frontend yourself |
| ZeroJ | `0.1.0-pre3` | Pulled from Maven; see [note on local ZeroJ](#using-a-local-zeroj-build) below |

You do **not** need Node.js to run the demos — each ships with a pre-built frontend bundled in the JAR.

---

## One-time setup

These steps apply to the full-stack demos (1–7). The annotation demos (8–12) need only Java.

**1. Start a local Cardano devnet (Yaci DevKit):**

```bash
yaci-cli devkit start
```

This gives you a local Cardano network at `http://localhost:8080` with an admin API at `http://localhost:10000`.

**2. Select Java 25:**

```bash
sdk use java 25.0.2-graal
```

**3. Fund the demo's admin wallet** (the demos share one hardcoded test address):

```bash
curl -X POST http://localhost:10000/local-cluster/api/addresses/topup \
  -H "Content-Type: application/json" \
  -d '{"address":"addr_test1qryvgass5dsrf2kxl3vgfz76uhp83kv5lagzcp29tcana68ca5aqa6swlq6llfamln09tal7n5kvt4275ckwedpt4v7q48uhex","adaAmount":10000}'
```

> The mnemonic and address are **for local testing only** — never use them on a real network.

---

## Quick Start

Run your first full-stack demo (identity-kyc) end to end:

```bash
# Prerequisites: yaci-devkit running, Java 25 selected, admin wallet funded (see above)

cd identity-kyc

# Build (skip tests for speed)
./gradlew clean build -x test

# Run
java --enable-native-access=ALL-UNNAMED -jar build/libs/identity-kyc-0.1.0-SNAPSHOT.jar
```

First startup takes ~30–60s (it compiles the ZK circuit and runs a dev trusted setup). When you see `Started …Application`, open:

### http://localhost:8087

Click through the UI, or drive it from the command line:

```bash
# Verify Alice (eligible: age 25, USA) — generates a real ZK proof
curl -X POST http://localhost:8087/api/credential/verify \
  -H "Content-Type: application/json" -d '{"name":"Alice"}'

# Verify Charlie (not eligible: under 18)
curl -X POST http://localhost:8087/api/credential/verify \
  -H "Content-Type: application/json" -d '{"name":"Charlie"}'
```

The proof reveals **only** `eligible: YES/NO` — never the age or country.

For your first command-line (annotation) demo, no devnet is needed:

```bash
cd annotated-compliance-credential
./gradlew run
```

---

## Two kinds of demo

| | Full-stack (1–7) | Annotation circuits (8–12) |
|---|------------------|----------------------------|
| Needs Yaci DevKit | ✅ Yes | ❌ No |
| How to run | Build a JAR, then `java -jar …` | `./gradlew run` |
| UI | Browser (Svelte) | Console output |
| Submits Cardano txs | ✅ Yes | ❌ No (witness/circuit only) |
| Good for | Seeing the full ZK + on-chain flow | Learning the circuit DSL |

**Why `java -jar` instead of `./gradlew bootRun` for the full-stack demos?**
ZeroJ uses the native BLST library for BLS12-381, which needs the `--enable-native-access=ALL-UNNAMED` JVM flag. Running the built JAR is the reliable way to pass it. (`./gradlew bootRun` also works for some demos but the JAR form is recommended.)

---

## The examples in detail

Each demo has its own README/tutorial with full API references and architecture notes — linked below. What follows is a beginner-oriented summary and the minimal run steps.

### 1. identity-kyc — Privacy-preserving KYC

📄 [Full README](identity-kyc/README.md) · 🔑 [EdDSA/Jubjub tutorial](identity-kyc/EDDSA_JUBJUB_TUTORIAL.md)

Prove you meet KYC requirements (**age ≥ 18 AND country in an approved list**) without revealing your age, country, or identity. A KYC provider issues a Poseidon-signed credential; you generate a proof; ADA locked at a Plutus V3 script is unlockable only with a valid proof. The proof is **reusable** (no nullifier) — appropriate for ongoing DeFi access. Ships with 5 test users (some eligible, some not).

```bash
cd identity-kyc
./gradlew clean build -x test
java --enable-native-access=ALL-UNNAMED -jar build/libs/identity-kyc-0.1.0-SNAPSHOT.jar
# → http://localhost:8087
```

### 2. nft-ownership — Private token-gated access

📄 [Full README](nft-ownership/README.md) · 📐 [Design notes](nft-ownership/DESIGN.md)

Prove you **own an NFT from a collection without revealing your wallet address or which NFT**. The app mints NFTs on the devnet, builds a Merkle snapshot of holders, and you prove membership. Access is **one-time**: a nullifier is inserted into an on-chain **sorted linked list** so the same proof can't be used twice.

```bash
cd nft-ownership
./gradlew clean build -x test
java --enable-native-access=ALL-UNNAMED -jar build/libs/nft-ownership-0.1.0-SNAPSHOT.jar
# → http://localhost:8085
```

### 3. private-voting — Anonymous DAO governance

📄 [Full README](private-voting/README.md)

Cast a YES/NO vote in a DAO election **without revealing who you are or how you voted**. Eligibility is proven against a voter Merkle tree; a nullifier (`Poseidon(secret, electionId)`) prevents double-voting; vote commitments on-chain are decoded at tally time. Auto-creates 5 funded test voters at startup.

```bash
cd private-voting
./gradlew clean build -x test
java --enable-native-access=ALL-UNNAMED -jar build/libs/private-voting-0.1.0-SNAPSHOT.jar
# → http://localhost:8086
```

### 4. proof-of-reserves — ZK solvency

📄 [Full README](proof-of-reserves/README.md)

Prove an exchange holds **reserves ≥ total customer liabilities** without revealing any individual balance. Customer balances form a **Merkle Sum Tree** (each leaf `Poseidon(accountId, balance)`, each node carries a running sum); the circuit proves all balances are non-negative, the root matches, the sum equals declared liabilities, and reserves cover them. An attestation UTXO records the result on-chain.

```bash
cd proof-of-reserves
./gradlew clean build -x test
java --enable-native-access=ALL-UNNAMED -jar build/libs/proof-of-reserves-0.1.0-SNAPSHOT.jar
# → http://localhost:8089
```

### 5. digital-product-passport — EU DPP compliance

📄 [Full README](digital-product-passport/README.md)

Prove a product complies with EU ESPR rules (**carbon footprint, recycled content, manufacturing origin, inspections passed**) without revealing sensitive supply-chain data. Products are stored in a **Poseidon Merkle Patricia Forestry (MPF)** trie (persistent RocksDB storage, ZK-verifiable root). Two scenarios — EV Battery (per-product) and Textile (per-batch) — including non-compliant negative cases.

```bash
cd digital-product-passport
./gradlew clean build -x test
java --enable-native-access=ALL-UNNAMED -jar build/libs/digital-product-passport-0.1.0-SNAPSHOT.jar
# → http://localhost:8088
```

### 6. personhood-airdrop — Sybil-resistant faucet

📄 [Full tutorial](personhood-airdrop/SYBIL_AIRDROP_TUTORIAL.md)

A **one-claim-per-human** faucet. You prove possession of an issuer-signed **personhood credential** (EdDSA over Jubjub, verified in-circuit) and publish a deterministic nullifier `Poseidon(personhoodId, epoch)`. The faucet mints one NFT per claim whose asset name is the nullifier — a second claim in the same epoch reproduces the same nullifier and the mint fails. This is the building block behind Semaphore / Worldcoin / Tornado-style sybil resistance.

```bash
cd personhood-airdrop
./gradlew bootRun
# → http://localhost:8086
```

> First boot runs Powers of Tau (~3 min) + Phase-2 setup (~4 min) for the ~20k-constraint circuit, then caches to `./data/` for sub-second subsequent boots.

### 7. selective-disclosure — One credential, many proofs

📄 [Full tutorial](selective-disclosure/SELECTIVE_DISCLOSURE_TUTORIAL.md)

One issuer-signed rich credential (`dobYear, country, roleId, salaryBracket, nameHash`) proves **different predicates to different DApps** with no linkability between them. Example: prove *"adult resident"* to a Library gate and *"senior doctor"* to a Healthcare gate, from the same signature. Each predicate is an independent Groth16 proof against its own Plutus V3 validator. This is the shape of W3C Verifiable Credential selective disclosure.

```bash
cd selective-disclosure
./gradlew bootRun
# → http://localhost:8085
```

### 8. annotated-private-voting

📄 [README](annotated-private-voting/README.md)

The voting circuit written purely with **ZeroJ symbolic annotations**. The voter proves `voteChoice` is boolean (`ZkBool`), the voter secret is in a BLS12-381 Poseidon registry Merkle root, and the public vote commitment / nullifier were correctly derived. The generated `PrivateVoteProofCircuit` exposes `build`, `schema`, `inputs`, `publicInputs`, `calculateWitness`.

```bash
cd annotated-private-voting
./gradlew test    # run the circuit tests
./gradlew run     # run the demo
```

### 9. annotated-compliance-credential

📄 [README](annotated-compliance-credential/README.md)

A selective-disclosure credential gate via annotations. Proves age ≥ public minimum, country equals required code, sanctions flag is true, and a Poseidon commitment binds the attributes + salt. Shows how `ZkUInt` range constraints and `ZkBool` boolean constraints are injected by the symbolic type factories while the source still reads like plain domain code.

```bash
cd annotated-compliance-credential
./gradlew test && ./gradlew run
```

### 10. annotated-proof-of-reserves

📄 [README](annotated-proof-of-reserves/README.md)

A proof-of-reserves slice using `@CircuitParam` and `@FixedSize(param = "depth")`, so the **same Java source builds Merkle circuits of different depths**. Proves a private liability leaf is in the public liabilities root, assets ≥ claimed liabilities, and the account balance is covered. Uses explicit BLS12-381 Poseidon parameters aligned with the Cardano Groth16 path.

```bash
cd annotated-proof-of-reserves
./gradlew test && ./gradlew run
```

### 11. annotated-batch-threshold-matrix

📄 [README](annotated-batch-threshold-matrix/README.md)

A grouped compliance check over a **nested symbolic array** — a private `ZkArray<ZkArray<ZkUInt>>` matrix of measurements proven to be ≤ a public per-column maximum. Demonstrates how nested arrays flatten row-major into witness names (`measurement_0_0`, `measurement_0_1`, …).

```bash
cd annotated-batch-threshold-matrix
./gradlew test && ./gradlew run
```

### 12. zk-mpf-private-registry

📄 [README](zk-mpf-private-registry/README.md)

A private-membership circuit over a **Cardano Client Lib MPF registry** using a Poseidon hash profile (so the root is ZK-verifiable, unlike the default Blake2b MPF). It's a **witness-level demo**: it builds the registry, derives MPF witness arrays, and evaluates the BLS12-381 circuit. The public verifier sees only `registryRoot` and `keyPathNullifier`. A full Groth16/Yaci flow is deferred until MPF circuit cost is reduced.

```bash
cd zk-mpf-private-registry
./gradlew test && ./gradlew run
```

---

## Building everything at once

From the repository root, a Gradle aggregator wires up every example:

```bash
# Build all examples (with tests)
./gradlew buildAllUsecases

# Build all, skipping tests (faster)
./gradlew buildAllUsecasesNoTests

# Test all / clean all
./gradlew testAllUsecases
./gradlew cleanAllUsecases
```

There's also a convenience script that builds a subset sequentially:

```bash
./build-all.sh                 # default: build
./build-all.sh build -x test   # pass any gradle args through
```

### Using a local ZeroJ build

The examples depend on ZeroJ `0.1.0-pre3` from Maven. To test against a ZeroJ build from source, publish it to your local Maven repository and pass the version through:

```bash
# In the zeroj checkout
cd ../zeroj
./gradlew publishToMavenLocal

# Then build a usecase with that version
cd ../zeroj-usecases
./gradlew buildAllUsecasesNoTests -PzerojVersion=0.1.0-pre3
```

Each module reads `zerojVersion` (a Gradle property / env var with a sensible default), so `-PzerojVersion=…` is forwarded to every example.

---

## Glossary (plain English)

| Term | What it means here |
|------|--------------------|
| **Zero-knowledge proof (ZKP)** | A proof that a statement is true that reveals nothing else. |
| **Groth16** | A specific, compact, fast-to-verify ZKP scheme. Proofs are tiny and verification is constant-time (3 pairings). |
| **BLS12-381** | The elliptic curve the proofs use. Cardano (Plutus V3) has built-in operations for it, so proofs can be checked on-chain. |
| **Circuit** | The statement to prove, expressed as arithmetic constraints. In ZeroJ you write it in Java. |
| **Constraint count** | Roughly the "size" of a circuit; bigger = slower proving. These demos range from ~1,000 to ~20,000 constraints. |
| **Trusted setup / Powers of Tau** | A one-time ceremony producing parameters for proving/verifying. These demos use a **dev-only single-party** setup — production needs a multi-party ceremony. |
| **Poseidon** | A hash function designed to be cheap inside ZK circuits (unlike SHA/Blake2b). Used for commitments, Merkle trees, and nullifiers. |
| **Nullifier** | A deterministic, one-way tag (e.g. `Poseidon(secret, context)`) published with a proof. It reveals nothing about the secret but lets the chain reject reuse ("already voted / already claimed"). |
| **Merkle tree / root** | A tree of hashes whose single root commits to a whole set. A proof can show "X is in the set" against just the root. |
| **Merkle Sum Tree** | A Merkle tree where each node also carries a sum — used to prove a total (e.g. total liabilities). |
| **MPF (Merkle Patricia Forestry)** | A persistent key/value trie with a verifiable root. The DPP and registry demos use a **Poseidon** MPF so the root works inside a circuit. |
| **Plutus V3** | Cardano's current smart-contract language version; includes the BLS12-381 builtins that verify these proofs on-chain. |
| **Julc** | The ZeroJ tool that compiles on-chain verifier logic written in Java to Plutus V3. |
| **Yaci DevKit** | A one-command local Cardano devnet for development and testing. |
| **EdDSA over Jubjub** | A signature scheme that can be verified efficiently *inside* a BLS12-381 circuit — used to check issuer-signed credentials in zero knowledge. |

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `UnsatisfiedLinkError` / BLST native errors | Run the JAR with `--enable-native-access=ALL-UNNAMED` and make sure you're on **Java 25 GraalVM** (`sdk use java 25.0.2-graal`). |
| Transaction / topup fails, "address has no funds" | Make sure `yaci-cli devkit start` is running and you ran the [admin top-up](#one-time-setup) curl. |
| Port already in use (8085/8086 collisions) | Run only one demo at a time, or change `server.port` in that demo's `src/main/resources/application.yml`. |
| Startup takes a long time | Expected — circuit compilation + dev trusted setup runs on first boot (30s–8min depending on circuit size). Setups are cached to `./data/` for later boots. |
| `Could not resolve com.bloxbean.cardano:zeroj-*` | Publish ZeroJ locally (`./gradlew publishToMavenLocal` in the zeroj repo) and/or pass `-PzerojVersion=…`. See [Using a local ZeroJ build](#using-a-local-zeroj-build). |

---

## Learn more

- **ZeroJ** — the pure-Java ZK toolkit powering these demos: https://github.com/bloxbean/zeroj
- **Yaci DevKit** — local Cardano devnet: https://github.com/bloxbean/yaci-devkit
- **cardano-client-lib** — the Java Cardano client used to build transactions: https://github.com/bloxbean/cardano-client-lib
- **Background docs in this repo:**
  - [docs/JUBJUB_ON_CARDANO.md](docs/JUBJUB_ON_CARDANO.md) — verifying Jubjub/EdDSA signatures inside a BLS12-381 circuit
  - [docs/PRESENTATION.md](docs/PRESENTATION.md) — overview presentation

---

*Project conventions and the shared tech-stack/NFR matrix live in [CLAUDE.md](CLAUDE.md).*
