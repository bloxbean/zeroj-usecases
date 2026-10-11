# Design: Private NFT Ownership on Cardano

How this demo works — from the ZK circuit to on-chain verification — after the ADR-0009 D2
hardening ([ADR](../docs/adr/0009-privacy-and-binding-hardening-of-the-original-demos.md)).

## Table of Contents

- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [Threat Model and Trust](#threat-model-and-trust)
- [System Architecture](#system-architecture)
- [ZK Circuit (Version 2)](#zk-circuit-version-2)
  - [What the Circuit Proves](#what-the-circuit-proves)
  - [Signals](#signals)
  - [Circuit Logic Step by Step](#circuit-logic-step-by-step)
  - [Encodings](#encodings)
  - [Merkle Tree](#merkle-tree)
  - [Nullifier](#nullifier)
- [Registration (the Indexer)](#registration-the-indexer)
- [Proof Generation (Off-Chain)](#proof-generation-off-chain)
- [On-Chain Verification](#on-chain-verification)
  - [One Event, Two Scripts](#one-event-two-scripts)
  - [ZkProofMintingPolicy](#zkproofmintingpolicy)
  - [NullifierListValidator](#nullifierlistvalidator)
- [Sorted Linked List (On-Chain Nullifier Storage)](#sorted-linked-list-on-chain-nullifier-storage)
- [Transaction Flow](#transaction-flow)
- [What Each Party Sees](#what-each-party-sees)
- [Security Properties and Limitations](#security-properties-and-limitations)
- [Keys and Roles](#keys-and-roles)
- [Cost Analysis](#cost-analysis)

---

## The Problem

On Cardano, proving you own an NFT usually means revealing your wallet address, and with it every
other token you hold, your history and your balance. That is a privacy problem for token-gated
events, anonymous DAO voting and airdrops.

## The Solution

The holder proves, in zero knowledge, that one leaf of a published snapshot of holders is theirs,
and publishes a nullifier that is the same for every use of that leaf in one event. The proof is
verified on-chain with Plutus V3's BLS12-381 builtins, and the nullifier is admitted once by an
on-chain sorted list.

The nullifier is `Poseidon(Poseidon(s, t), contextId)`, where `s` is the holder's 252-bit secret
and `t` the token. It does not reveal which NFT was used. Version 1 of the circuit published
`Poseidon(t, contextId)`, which anyone could compute for every token of the collection: it showed
which NFT, and so which wallet, was used.

## Threat Model and Trust

Privacy claims are against a **chain observer** (reads every datum, token name, redeemer and
public input) and a **mempool observer** (can copy a pending transaction's redeemer and submit its
own transaction first).

| Party | May try | Prevented by |
|-------|---------|--------------|
| Holder | use one holding twice | one registration per token, each from an authenticated holding (indexer) + one list entry per nullifier (list script) |
| Holder | re-insert a nullifier, or remove a node | list: nodes are never spent outside an insert, never burned |
| Holder | register one token under two keys | the indexer refuses a second registration for a token |
| Anyone | register a token it does not hold | the indexer requires a CIP-8 signature by the payment key of the token's on-chain holder |
| Observer | link the nullifier to a token | the nullifier absorbs the holder's 252-bit secret |
| Anyone | reuse a proof for another event or snapshot | root and context are parameters of the event's ZK policy |
| Mempool observer | spend a holder's proof first | **not prevented** (deferred, see limitations) |

**Trusted:** the indexer (here, `SnapshotService` in the demo server) builds the event's snapshot
with one registration per token, from authenticated holders. It cannot check which token a leaf
commits to (the leaf hides `t`), so what it guarantees is at most one leaf per authenticated
holding. The demo server also holds the custody
wallet and the holder secrets (operator view, ADR-0009 D10), so privacy does not hold against it.

## System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  USER (Browser or curl) — the demo operator's view            │
│  1. Mint NFTs into custody   2. Register (server draws s)      │
│  3. Build snapshot            4. Prove   5. Access             │
└────────────────────┬─────────────────────────────────────────┘
                     │ REST API (http://localhost:8085)
                     ▼
┌──────────────────────────────────────────────────────────────┐
│  SPRING BOOT BACKEND                                          │
│  CustodyWallet           — random persisted key; holds NFTs,  │
│                            signs CIP-8 registrations          │
│  SnapshotService         — the indexer: checks registrations, │
│                            one registration per token, tree   │
│  ProverService           — circuit v2, dev setup, proofs      │
│  OnChainNullifierService — per-event scripts, list inserts    │
│  MintService             — mints NFTs into custody            │
└────────────────────┬─────────────────────────────────────────┘
                     │ Cardano transactions / indexer queries
                     ▼
┌──────────────────────────────────────────────────────────────┐
│  CARDANO (Yaci DevKit)                                        │
│  ZkProofMintingPolicy(root, context, VK) — Groth16 check      │
│  NullifierListValidator(zkPolicy, seed)  — sorted list        │
│    ROOT → node(n_A) → node(n_B) → ∅                           │
└──────────────────────────────────────────────────────────────┘
```

## ZK Circuit (Version 2)

### What the Circuit Proves

> "I know a secret `s` and a token `t` such that `Poseidon(Poseidon(s, 0), t)` is a leaf of the
> tree with root `snapshotRoot`, and `nullifier = Poseidon(Poseidon(s, t), contextId)`."

### Signals

```
PUBLIC (in this order):
  snapshotRoot — the event's snapshot root (a ZK policy parameter)
  contextId    — the event (a ZK policy parameter)
  isOwner      — must be 1
  nullifier    — Poseidon(Poseidon(s, t), contextId)

SECRET:
  secretKey    — the holder secret s (252 bits, SecureRandom)
  tokenName    — t, the NFT's asset name as a field element
  sibling_i    — Merkle path siblings
  pathBit_i    — Merkle path directions (boolean)
```

### Circuit Logic Step by Step

```
Step 1: ownerHash  = Poseidon(secretKey, 0)
Step 2: leaf       = Poseidon(ownerHash, tokenName)          (unchanged from version 1)
Step 3: Merkle path from leaf to snapshotRoot                 (asserted)
Step 4: holderTok  = Poseidon(secretKey, tokenName)
        nullifier' = Poseidon(holderTok, contextId)
Step 5: assert isOwner ∧ (nullifier' == nullifier)
```

All hashes are Poseidon over the BLS12-381 scalar field (ZeroJ `PoseidonParamsBLS12_381T3`).

### Encodings

- `t`: the asset name's bytes as a big-endian integer; 1–31 bytes and no leading zero byte, so
  each name has exactly one field value.
- `contextId`: the event label (`zk.default-context`, e.g. `nft-demo-v1`) encoded the same way.
- `s`: 252 random bits from `SecureRandom`, redrawn if shorter than 240 bits. The API refuses a
  secret below 2^240 (a typed-in number such as `42`) or wider than 252 bits.
- The ZK token name is the nullifier's canonical 32-byte big-endian encoding (`0 ≤ n < r`); the
  list key is `slice(1, 31, name)`.

### Merkle Tree

A depth-10 Poseidon tree (1,024 leaves); empty leaves are 0. A leaf is
`Poseidon(Poseidon(s, 0), t)`; an internal node is `Poseidon(left, right)`.

### Nullifier

```
Holder of ZeroJTicket_1 with secret s, event "nft-demo-v1":
  n = Poseidon(Poseidon(s, t_1), ctx)

Same holder, same event:   same n  → the list refuses the second insert
Same holder, other event:  other n → allowed
Observer: knows every t and ctx, but not s → cannot compute n for any token
```

**The use count now rests on the snapshot.** In version 1 the nullifier depended only on the
token, so the circuit itself gave one nullifier per NFT. In version 2 each leaf gives one
nullifier per event, and a holder who registered two leaves for one NFT would get two. The indexer
prevents that by admitting one registration per token, each signed by the token's on-chain
holder, so the snapshot has at most one leaf per authenticated holding (I4).

The indexer cannot check that a leaf registered under token A commits to A: the leaf hides `t`.
A holder of A could register a leaf over another token B; if B's holder also registers, two
leaves prove "B". The count is unchanged — at most one use per authenticated registration — but
the guarantee is one use per registered holding, not one use per specific NFT.

## Registration (the Indexer)

`SnapshotService.registerHolder(policyId, assetName, leaf, signature)`:

1. Refuses when the snapshot is built (registration is frozen) or the collection differs from the
   event's.
2. Refuses a second leaf for a token already registered.
3. Checks the CIP-8 `COSE_Sign1` signature (CCL's CIP-30 `signData` format):
   - the payload is exactly `"zeroj.demo.nft.register.v2" ‖ I2OSP32(contextId) ‖ I2OSP32(t) ‖ I2OSP32(leaf)`;
   - the Ed25519 signature verifies;
   - the address in the protected header is a base or enterprise address whose payment credential
     is the key hash of the signing key (not a script, not a reward address);
   - the chain indexer shows that this address holds exactly one unit of the token.
4. Any failure, including the indexer being unavailable, refuses the registration.

`buildSnapshot()` builds the tree once and freezes registration. A new event is a new run.

## Proof Generation (Off-Chain)

Groth16 over BLS12-381, in pure Java. The setup is a **dev-only single-party setup** generated at
startup; its verification key is baked into the ZK policy. Production needs an MPC ceremony.

## On-Chain Verification

### One Event, Two Scripts

Building the snapshot deploys the event:

```
ZkProofMintingPolicy(snapshotRoot, contextId, VK)    → zkPolicyId
NullifierListValidator(rootKey, prefix, 1, zkPolicyId, seedRef)  → list policy = list address
InitList: consumes the seed output, mints the root token into the root node
```

Both scripts run in every access transaction.

### ZkProofMintingPolicy

A `@MintingValidator`. Parameters: `snapshotRoot`, `contextId`, the VK. Redeemer:
`(piA, piB, piC, nullifier)`.

1. `snapshotRoot` and `contextId` are canonical field elements.
2. The mint map under this policy is exactly `{n: 1}`, `|n| = 32`.
3. `0 ≤ nullifier < r` and `n = I2OSP32(nullifier)`.
4. Groth16 verifies against `[snapshotRoot, contextId, 1, nullifier]`.

A proof for another snapshot or event fails step 4, because those inputs come from the
parameters, not the redeemer. The policy does not itself limit how often a valid proof mints:
access is a list node, and the list admits each nullifier once. A ZK token outside the list grants
nothing.

### NullifierListValidator

A `@MultiValidator`. Parameters: `rootKey`, `prefix`, `prefixLen`, `zkPolicyId`, `seedRef`.

**MINT, `InitList`:**
- the transaction consumes the seed output (so the root exists once);
- it spends no input at the list address;
- the mint map under the list policy is exactly `{rootKey: 1}`;
- the root token is in the root output, at the list address, holding only lovelace and the
  root token, with datum `ListElement((), "")`.

**MINT, `InsertNode`:**
- exactly one input at the list's payment credential: the anchor, found by its token;
- the mint map under the list policy is exactly one entry, `{prefix ‖ key: 1}` (no burns);
- the mint map under `zkPolicyId` is exactly `{n: 1}`, `|n| = 32`, and `key = slice(1, 31, n)`;
- the new node holds exactly lovelace, its list token and the ZK token, at the list address,
  with datum `ListElement((), anchor.oldNext)`;
- the continuing anchor holds exactly the anchor's tokens, at the list address, with datum
  `ListElement(anchor.userData, key)`;
- `anchorKey < key < anchor.oldNext` (with the root and the end as open bounds).

**SPEND:** the list policy mints exactly one token, quantity 1, in the same transaction. The seed
makes every later list mint an insert, and an insert allows exactly one list input, its anchor. So
a node can be spent only as an insert's anchor, its tokens move into the continuing anchor, and
nodes are never removed.

## Sorted Linked List (On-Chain Nullifier Storage)

Each nullifier is its own UTxO, linked in sorted order:

```
ROOT → node(0x3A…) → node(0x5C…) → ∅
```

Inserting `0x4B…` spends `node(0x3A…)` and produces the updated anchor (`next = 0x4B…`) and the
new node (`next = 0x5C…`). If no anchor with `anchorKey < key < next` exists, the key is already
in the list. Different inserts usually touch different anchors, so they can proceed in parallel.

Two nullifiers that share their low 31 bytes get the same key; the second insert fails closed.

## Transaction Flow

### Init: Deploy Root Sentinel (when the snapshot is built)

```
Inputs:  the seed output (operator wallet)
Mint:    {listPolicy: {"NROOT": 1}}
Output:  list address, 2 ADA + NROOT, datum ListElement((), "")
Checks:  NullifierListValidator MINT (InitList)
```

### Insert: Record a Nullifier On-Chain

```
Inputs:
  anchor node (the only list input)
  operator wallet (fees, collateral, ADA for the new node)

Mint:
  listPolicy: {"N" ‖ slice(1, 31, n): 1}
  zkPolicy:   {n: 1}                       n = I2OSP32(nullifier)

Outputs:
  continuing anchor: anchor's value, datum ListElement(userData, key)
  new node:          2 ADA + list token + ZK token, datum ListElement((), anchor.oldNext)

Scripts:
  ZkProofMintingPolicy (MINT): Groth16 over [root, context, 1, nullifier]
  NullifierListValidator (MINT, InsertNode): the rules above
  NullifierListValidator (SPEND): one list mint in this transaction
```

## What Each Party Sees

| Data | Holder | Demo server (operator) | Chain / mempool observer |
|------|--------|------------------------|--------------------------|
| Which NFT was used | Yes | Yes | **No** |
| Which wallet holds it | Yes | Yes (custody) | **No** (from the gate) |
| Holder secret `s` | Yes | Yes (drew it) | **No** |
| Snapshot root, event context | Yes | Yes | Yes |
| Nullifier, proof | Yes | Yes | Yes |
| "Some snapshot holder used the gate" | Yes | Yes | Yes |

## Security Properties and Limitations

| Property | How it is achieved |
|----------|--------------------|
| Soundness of a gate entry | Groth16 verified on-chain against the event's root and context (parameters) |
| One entry per proof, never removed | list: key = proved nullifier, one list input, exact mint, no burns, one-shot root |
| At most one use per registered holding per event | one authenticated registration per token (indexer) + one entry per nullifier (list) |
| Nullifier hides the token | it absorbs the holder's 252-bit secret |
| Holder authentication | CIP-8 signature by the payment key of the on-chain holder |

Limitations (stated, not prevented):
- **The indexer decides the snapshot.** It is trusted to admit one registration per token from
  authenticated holders.
- **Per holding, not per NFT.** The indexer cannot see which token a leaf commits to, so a proof
  may name a token other than the one it was registered under; uses stay at most one per
  authenticated registration.
- **Front-running.** A mempool observer can submit a holder's proof first and spend its
  nullifier; the access then goes to that transaction. The fix — a fresh one-time beneficiary key
  hash as a public input, with the gate's output paid to it — is deferred to keep circuit
  version 2 minimal.
- **Using the gate shows that some snapshot holder acted.**
- **The holder lookup** checks that the signing address holds exactly one unit of the token. It
  relies on the collection minting each name once (here, the demo server's per-run policy key).
- **Operator view.** The demo server holds the custody wallet and draws the holder secrets
  (D10). Privacy holds against chain and mempool observers only.
- **Dev setup and no external review.**

## Keys and Roles

| Role | Key | Lifecycle |
|------|-----|-----------|
| NFT custody wallet (holds NFTs, signs registrations) | random 24-word key (`CustodyWallet`) | written atomically, owner-only, in `demo.data-dir`, next to the deployment state with its address; loaded on restart; removed with the state by `./demo.sh nft --clean-cache`; a missing, corrupt or mismatched key with existing state stops startup |
| List operator (fees, collateral, seed, inserts) | DevKit's well-known mnemonic | public devnet role; gates no privacy claim; replace in a real deployment |
| Collection policy | random per run, in memory | mints the demo NFTs |

## Cost Analysis

| Operation | Cost | Frequency |
|-----------|------|-----------|
| Event deployment (root sentinel) | ~2 ADA locked + fee | once per event |
| ZK proof generation | off-chain computation | per access |
| Nullifier insertion | ~2 ADA locked per node + fee | per access |

Each nullifier node locks ~2 ADA. Nodes are never removed, so the ADA stays locked; reclaiming it
would need a reviewed post-event removal design.
