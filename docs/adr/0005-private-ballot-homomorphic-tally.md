# ADR-0005: Private ballots with a homomorphic tally (private-voting)

- **Status:** Proposed. Implementation is on `feat/pedersen-private-ballot-and-demos`.
- **Date:** 2026-10-04 (r2: amended after the design review; r3: after the implementation review)
- **Fixes:** [zeroj-usecases#7](https://github.com/bloxbean/zeroj-usecases/issues/7)
- **Related:** ZeroJ ADR-0051 (Pedersen commitment profiles; finding F7, scope item D8),
  ZeroJ ADR-0037/0038 (Jubjub gadget hardening), [ADR-0006](0006-pedersen-commitment-demos.md).
- **Risk:** R2. This is a protocol integration with on-chain binding. It uses
  only primitives ZeroJ already implements and tests: Jubjub arithmetic, Poseidon, Groth16, and
  the Plutus V3 Groth16 verifier. No new primitive is implemented. The ballot and decryption relations are new
  to this repository, though, so they are specified exactly here and reviewed like R3 relations.

## Context

The demo claims that "the proof reveals nothing about which voter cast the vote or how they
voted". Issue #7 shows the claim is false for the vote. The ballot is `Poseidon(vote, nullifier)`
and the nullifier is public. Since `vote ∈ {0, 1}`, anyone can hash both candidates and compare.
`TallyService` does exactly this to count votes.

Re-reading the on-chain path while designing the fix found four more gaps. Each one breaks the
tally's integrity, and each would also break a homomorphic tally:

| # | Gap | Consequence |
|---|---|---|
| G1 | `VoteZkMintingPolicy` takes `electionId`, `voterRoot` and `commitment` from the redeemer and checks them against nothing. | A proof against an attacker's own voter tree is accepted. Eligibility is not enforced, and one person can cast any number of ballots. |
| G2 | The list node's key, and the ballot stored in its datum, are not tied to the proved nullifier and commitment. | A voter can mint the nullifier token again and insert it under a fresh list key, and so vote twice. The stored ballot need not be the proved one. |
| G3 | The list spend validator only requires the list policy to run. An insert checks the anchor, but not other spent list nodes. | An insert transaction can also spend other voters' nodes, then drop or rewrite their ballots. |
| G4 | No voting deadline. | Ballots can be added at any time. With a decryptable tally, decrypting before and after a ballot reveals that ballot. |
| G5 | `InitList` is not one-shot. | A second root starts a parallel list in which the same nullifier can be inserted again. |

## Threat model and trust assumptions

**Adversaries.**

| Adversary | Goal | Capabilities |
|---|---|---|
| Malicious voter | Vote twice; cast an invalid ballot (a value other than 0 or 1, or a different key); replace or remove other ballots; learn other voters' votes. | Builds arbitrary transactions; mints its own nullifier token outside the list; sends junk to the list address. |
| Outsider | Same goals, without being eligible. | — |
| Public observer | Learn individual votes from chain data. | — |
| Up to n − 1 colluding trustees | Decrypt individual ballots; publish a wrong total. | — |
| Chain reorganisation | Change the ballot set after the tally. | — |

**Trusted.**
- At least one trustee is honest and available.
- The Groth16 setups of both circuits are honest. With the dev setup this demo uses, whoever
  holds the toxic waste can forge every proof, including a proof of possession for a rogue key.
- The election administrator publishes the manifest (below) and deploys scripts that match it.
  Anyone can check this.
- Plutus V3 and the ledger enforce validity intervals and minting as specified.

**Not trusted.** Redeemer contents, every output that a validator has not checked, and every
UTxO at the list address that does not satisfy the node rules below.

## Decision

Replace the ballot with **exponential ElGamal over the Jubjub prime-order subgroup** under an
election key that is **additively shared by n trustees**. Ballots are proved well-formed with
Groth16 and verified on-chain. Their sum is decrypted **once, after an on-chain deadline and
finality**. Each trustee proves its decryption share, and anyone can check the tally from chain
data and the election manifest. This is the Cramer–Gennaro–Schoenmakers construction [CGS97]
with n-of-n sharing in place of threshold sharing.

The ballot's second component, `B = [v]·G + [k]·PK`, is a Pedersen commitment to the vote whose
blinding base is the election key. Nobody can open a single ballot. The trustees can jointly
remove the blinding from the *sum*, because they hold the key behind that base.

### Notation

- `𝔾` is the Jubjub prime-order subgroup, of order `l`. `G` is `JubjubPoint.SUBGROUP_GENERATOR`,
  the value base of `pedersen-jubjub-v1`. `p` is the BLS12-381 scalar field.
- Random scalars are 64 bytes reduced mod `l` (`PedersenCommitment.randomBlinding`, as in ZeroJ
  ADR-0051 D2).
- `I2OSP32(x)` is the 32-byte big-endian encoding.

### Election key

Each trustee `j ∈ {1..n}` (the demo uses `n = 3`):

1. samples `sk_j ∈ [1, l)` and publishes `PK_j = [sk_j]·G`;
2. publishes a **key proof** `π_key_j`, a Groth16 proof of `R_dleq` (below) with `X = G` and
   `D = P = PK_j`. This proves knowledge of `sk_j` (proof of possession). The verifier always
   sets `X = G` itself, so a decryption-share proof cannot pass as a key proof.

The election key is `PK = Σ_j PK_j`. It is accepted only if every `π_key_j` verifies, the
`PK_j` are pairwise distinct, and neither any `PK_j` nor `PK` is the identity. Proof of
possession blocks the rogue-key attack: a trustee who publishes `PK_n = [x]·G − Σ_{j<n} PK_j`
cannot prove knowledge of its discrete log [RY07]. That holds only under an honest setup (see
the threat model). Key proofs are not bound to `(electionId, j)`. A trustee could reuse its key
across elections; that is the trustee's own choice and does not affect the other trustees.

`PK` is a sum of points proved to be multiples of `G`, so it lies in `𝔾`. On-chain, `PK` is a
**script parameter**, never a value the prover supplies. That is why its subgroup membership can
be discharged once, off-chain, by anyone who checks the manifest. A general on-chain consumer of
a public point cannot rely on that; this case can, and only because the point is fixed by the
script (cf. ZeroJ `ZkPedersenCommitment.fromVerifierCheckedPublic`).

### Election manifest

The administrator publishes the manifest. The demo serves it at `/api/election/manifest`. It
contains:
- `electionId`, `voterRoot` and `votingDeadline`;
- every `PK_j` with `π_key_j`;
- `PK`;
- the full ballot and DLEQ verification keys;
- the two parameter-applied scripts (CBOR);
- the seed output reference;
- the two script hashes.

A verifier:
1. checks every key proof and recomputes `PK = Σ PK_j`;
2. hashes the published scripts, and checks their parameters against the manifest's values;
3. checks on-chain that the list root token was **minted exactly once, with quantity 1, by the
   transaction that spent the seed**, using the token's mint history and that transaction's
   inputs;
4. reads ballots only from the list whose policy has that hash.

A second list built with the same ballot policy, but a different seed, is not the official list
and is ignored. The demo's own verification performs steps 1–3 against its deployment.

### Ballot

A voter has an eligibility secret `s` (leaf `Poseidon(s, 0)` in the voter tree), a vote
`v ∈ {0, 1}` and fresh randomness `k`. The voter computes

```
N = Poseidon(s, electionId)        nullifier
A = [k]·G                          decryption handle
B = [v]·G + [k]·PK                 vote, blinded by the election key
```

**Relation `R_ballot`.**
- Public, in this order: `electionId, voterRoot, PK.u, PK.v, N, A.u, A.v, B.u, B.v`.
- Secret: `s`, Merkle path, `v`, `k`.

It proves:

1. `v` is boolean (`ZkBool`).
2. `k` is decomposed once, to 252 bits. **The same decomposition** drives `A = [k]·G` (fixed
   base) and `[k]·PK` (variable base). If `A` and `B` used different scalars, a voter could add
   an arbitrary offset to the decrypted sum. Both bases are in `𝔾`, so only `k mod l` matters,
   and `k ≥ l` is harmless.
3. `[v]·G` is a selection between `G` and the identity. Then `B = [v]·G + [k]·PK`.
4. `PK` is bound with the curve equation (`witnessAffine`) and is not the identity.
5. `Poseidon(s, 0)` is a member of `voterRoot` (depth-d Merkle path), and
   `N = Poseidon(s, electionId)`.
6. `A` and `B` equal the public affine coordinates. Both are computed in-circuit from subgroup
   bases, so both are in `𝔾`.

`k`, and the trustee secret `x` in `R_dleq`, are guarded as hiding scalars
(`requireNotPublicOrConstant`, `requireHidingRange(252)`). A narrow `k` would let anyone
brute-force `B`.

### Tally

**Ballot set `𝔅`.** The set is defined by the list structure, not by what happens to sit at the
address.

1. Walk from the root token's node, following `nextKey`. Each step must reach exactly one UTxO
   holding the list token `prefix ‖ key`.
2. For every node, check that:
   - it holds exactly one list token and exactly one nullifier token `N`;
   - `key = last31(I2OSP32(N))`;
   - its datum parses as a ballot with `A, B ∈ 𝔾` and canonical coordinates.
3. The walk must visit **every** UTxO at the list address that holds a list token.
4. If any check fails, the tally is refused, never computed over a subset. UTxOs without a list
   token (junk) are ignored. All pages of the address are read.

**When.** Ballots are added up only once the chain tip is past `votingDeadline` **plus a
finality margin**:
- on DevKit, a few seconds;
- on a public network, at least the confirmation depth the operator accepts as final. The ledger's
  stability window is about 12 hours on mainnet.

Votes cannot land after the deadline, because the ballot policy enforces the validity range.

**Decryption.** Anyone computes `ΣA = Σ A_i` and `ΣB = Σ B_i`. Each trustee computes
`D_j = [sk_j]·ΣA` and publishes `π_dec_j`, a Groth16 proof of `R_dleq` with `X = ΣA`,
`P = PK_j` and `D = D_j`. Then

```
M = ΣB − Σ_j D_j = [T]·G,     T = the unique t ∈ [0, |𝔅|] with [t]·G = M
```

`T` is found by linear search. YES is `T` and NO is `|𝔅| − T`. If no `t` matches, the tally is
refused. The published result carries a **ballot-set digest**, so anyone can confirm it was
computed over the set they see:

```
blake2b_256("zeroj.private-voting.ballot-set.v1" ‖ I2OSP32(electionId) ‖ listPolicyId ‖ entries)
```

Each entry is `I2OSP32(N) ‖ I2OSP32(A.u) ‖ I2OSP32(A.v) ‖ I2OSP32(B.u) ‖ I2OSP32(B.v)`, and the
entries are sorted by `N`. The chain tip time is read before the ballots, so the set read is final.

**Relation `R_dleq`.**
- Public, in this order: `X.u, X.v, P.u, P.v, D.u, D.v`.
- Secret: `x`, 252 bits.

It proves `P = [x]·G` (fixed base) and `D = [x]·X` (variable base, the same decomposition), with
`X` bound by the curve equation. `X` is chosen by the verifier: `G` for key proofs, and the
recomputed `ΣA` for decryption. Each `A_i` is proved to be `[k_i]·G`, so `X ∈ 𝔾`. `X = O` is
harmless, since `D` must then be `O`.

**Single decryption.** Trustees decrypt exactly once per election, over the final ballot set. The
result is stored and re-served. A second decryption over a different set is refused (V7). In
this demo the trustees run inside the backend, which enforces the rule. The trustee secrets live
in memory only, so a restart cannot decrypt again either.

The demo's HTTP endpoints are unauthenticated:
- a `GET /api/results` after the deadline triggers the one decryption;
- `POST /api/election/create` is refused once an election is finalized, because replacing it would
  discard the trustees' shares.

A real deployment authenticates trustees and the administrator.

### On-chain (Plutus V3 via Julc)

**`VoteZkMintingPolicy`.**
- Parameters: `electionId`, `voterRoot`, `pkU`, `pkV` (integers), `votingDeadline` (POSIX ms),
  and the verification key.
- Redeemer: the proof `(piA, piB, piC)` and nothing else.

Every public input comes from the parameters or the ledger.

1. The policy's mint entry is exactly one token, with quantity 1 and a 32-byte name.
   `N = OS2IP(name)` must be `< p`.
2. The validity range has a **finite** upper bound `≤ votingDeadline`.
   - An infinite bound is rejected.
   - Whether the bound is open or closed is ignored. The ledger's TTL produces an open bound,
     and comparing its time with the deadline is correct either way.
3. **Exactly one unit** of `(policy, N)` exists across all transaction outputs. Its output's
   inline datum is `ListElement(Ballot(Au, Av, Bu, Bv), next)`, and each coordinate is `< p`.
   - Without this rule, a voter could pre-mint a copy of `N`, place that copy with the proved
     datum earlier in the outputs, and put an unproved ballot in the list node.
   - The rule also makes the copy unspendable in a vote transaction: the copy plus the new mint
     would make two units.
4. Groth16 verification passes with `[electionId, voterRoot, pkU, pkV, N, Au, Av, Bu, Bv]`.

**`VoteListValidator`.**
- Parameters: `rootKey`, `prefix`, `prefixLen`, `zkPolicyId`, and `seedRef = txId ‖ I2OSP2(index)`.

5. `InitList` must consume the seed output. The policy's mint entry must be exactly the root
   token (G5). The root output is exact: lovelace plus the root token, with datum
   `Constr 0 [Constr 0 [], B ""]`.
6. `InsertNode` spends **exactly one** input at the list script's payment credential, the anchor
   (G3).
7. `InsertNode` requires:
   - the list policy's mint entry is exactly one new token;
   - exactly one token is minted under `zkPolicyId`, with quantity 1 and a 32-byte name;
   - the new key equals the **low 31 bytes of that name** (G2).
8. **Values and datums are exact.**
   - The continuing anchor's datum is exactly `ListElement(old userData, B newKey)`. An extra
     field would be accepted by a field-by-field read on-chain but rejected by the off-chain walk,
     which would make the election untallyable. Anyone who copies a ballot transaction from the
     mempool could do that.
   - The new node holds lovelace, one new list token and one unit of `N`, and nothing else.
   - The continuing anchor holds lovelace plus exactly the anchor's tokens: its list token and,
     unless it is the root, its own nullifier token.
   - Without this rule, an inserter could attach dust or foreign nullifier tokens and make nodes
     ambiguous or too large to spend.

The existing anchor continuity, ordering and script-address checks stay. The sorted list admits
each key once. The new key is derived from `N`, so each eligible voter can insert one ballot
(G1 and G2 together).

### What is private, and from whom

- **Public observers** see ballots `(A_i, B_i)`, nullifiers and `T`. ElGamal is IND-CPA under DDH
  in `𝔾`, and Groth16 is zero-knowledge, so they learn `T` and nothing more about any vote.
- **Non-malleability.** Groth16 proofs can be re-randomised, but a re-randomised proof keeps its
  statement, which includes `N`, and the list rejects a duplicate `N`. Proving the same `(A, B)`
  under another nullifier needs knowledge of `k`, because `R_ballot` is a proof of knowledge. So
  a ballot cannot be copied or mauled into another voter's slot. On-chain rule 3 is what makes
  "the stored ballot is the proved ballot" true.
- **Up to n − 1 colluding trustees** learn the same as the public, because `sk = Σ sk_j` is
  shared n-of-n. This assumes an honest setup.
- **All n trustees together** can decrypt any single ballot. The trust assumption is therefore
  that at least one trustee is honest. n-of-n also means one absent trustee blocks the tally.
  Threshold sharing with distributed key generation [Ped91, GJKR07] is future work.
- **Dev setup.** Whoever holds the toxic waste of the ballot circuit can forge ballots. Whoever
  holds the toxic waste of the DLEQ circuit can forge a proof of possession for a rogue key and
  so decrypt every ballot alone. This demo's setup is single-party; see the production gates.
- **Voter identity.** The nullifier cannot be linked to a voter without `s`. If voters submit
  their own transactions, though, the fee payer, collateral and timing link `N` to a wallet. A
  real deployment needs a relayer or a submission service. In the demo the backend submits every
  ballot from one admin wallet.
- **Not provided:**
  - Receipt-freeness and coercion resistance: a voter can reveal `k` to prove how they voted.
  - Small electorates: a small or unanimous `T` is itself revealing.
- **Demo only:** the backend holds every voter's and every trustee's secret and proves on their
  behalf, so the server knows every vote. The design separates these roles. The demo does not.

### Encodings (consensus-critical)

- `Ballot = Constr 0 [I Au, I Av, I Bu, I Bv]`.
- `ListElement = Constr 0 [userData, B nextKey]`. For a vote node, `userData` is the `Ballot`.
  The root's `userData` is `Constr 0 []`.
- The nullifier token name is `I2OSP32(N)`. The list token name is `prefix ‖ last31(I2OSP32(N))`,
  with prefix `"V"`. The root token is `"VROOT"`.
- Public-input orders are as listed for `R_ballot` and `R_dleq`.

## Invariants

| ID | Invariant | Enforced by |
|---|---|---|
| V1 | Eligibility: a ballot is accepted only with a proof against the script-fixed `voterRoot` and `electionId`. | ZK policy parameters (1, 4) |
| V2 | One ballot per eligible voter. | `N` is the token name and the list key; the sorted list; one-shot root (5, 7) |
| V3 | The stored ballot is the proved ballot. | `(A, B)` read from the only output holding `N` (3) |
| V4 | Each ballot encrypts 0 or 1 under the election key. | `R_ballot` 1–4 |
| V5 | Existing ballots are immutable, and nodes are unambiguous. | One list input per insert; anchor `userData` preserved; exact values (6, 8) |
| V6 | No ballot after the deadline. | Validity-range check (2) |
| V7 | One decryption, over the final set, after the deadline and finality. | Trustee service |
| V8 | The decryption is correct. | `π_dec_j` per trustee; unique `T ∈ [0, |𝔅|]` |
| V9 | The key setup is sound. | Proof of possession per `PK_j`; distinct keys; `PK ≠ O` |
| V10 | On-chain integers are canonical. | Every public input and token-derived scalar is checked `< p` |
| V11 | The ballot set is the whole list. | Root walk, full coverage, per-node checks, fail closed, published digest |
| V12 | The scripts are the published election. | Manifest with full keys and scripts; hashes recomputed; root minted once by the seed's spender |

## Alternatives considered

1. **A hiding commitment per ballot**, either `Poseidon(v, N, r)` or Pedersen `[v]·G + [r]·H`.
   This hides each vote, but then nobody can tally (issue #7).
2. **Pedersen commitments with the openings encrypted to an authority.** The authority sees every
   vote.
3. **Twisted ElGamal**, `C = [v]·G + [k]·H` with `D = [k]·PK`. `C` is exactly a
   `pedersen-jubjub-v1` commitment, which is attractive. Decryption needs `sk⁻¹`, though, which
   does not split additively across trustees, so one key holder could decrypt every ballot.
4. **A Chaum–Pedersen Σ-protocol for `R_dleq`.** It is smaller and needs no setup. It does need a
   pinned Fiat–Shamir transcript, which this stack does not yet have (ZeroJ ADR-0051 D7 is
   blocked on one). Groth16 reuses reviewed machinery and adds no transcript. Revisit once a
   transcript is pinned.
5. **Verifying the tally on-chain.** Jubjub aggregation on-chain is cheap field arithmetic, but
   verifying n decryption proofs in one transaction exceeds the per-transaction budget. The
   tally is verified off-chain from chain data. Per-trustee share transactions are future work.

## Milestones

| Milestone | Scope |
|---|---|
| B0 | This ADR. |
| B1 | Ballot and DLEQ circuits, host ElGamal and tally, and circuit negatives. |
| B2 | On-chain policy and list changes, and Plutus VM mutation tests for V1–V6 and V10. |
| B3 | Services, manifest, ballot-set walk, API, UI and README; DevKit end-to-end run. |

## Verification

- **Host:** encryption round trips, homomorphic sums and discrete-log search.
- **Independent reference:** a standalone Python reimplementation of Jubjub ElGamal and tally,
  from the curve definition, produces fixed vectors that the Java code must match.
- **Circuit negatives:**
  - `v = 2`;
  - `A` and `B` built from different `k`;
  - `B` under another key;
  - an identity key;
  - a wrong nullifier;
  - a non-member leaf;
  - a public input changed after proving;
  - a DLEQ statement with the wrong share, the wrong key or the wrong base.
- **Plutus VM mutations:**
  - root, election id and key not from the parameters (G1);
  - list key not equal to the nullifier (G2);
  - a second list input (G3);
  - after the deadline, or no upper bound (G4);
  - an `InitList` without the seed (G5);
  - a datum ballot that differs from the proved one;
  - **a pre-minted copy of `N` in another output**;
  - stray tokens in the new node or the continuing anchor;
  - extra list or nullifier mint entries;
  - non-canonical coordinates.
- **DevKit:** cast ballots; on-ledger script rejections of a swapped ballot, a double vote
  forced past the client, and a ballot valid past the deadline; close; walk the list; tally;
  verify every share, the manifest and the seed binding.
- **Mutation checks:** removing the one-unit rule or the exact anchor datum makes a VM test fail.

## Production gates (not met by this demo)

- An MPC trusted-setup ceremony for both circuits.
- Threshold distributed key generation and independent trustee custody.
- Voters holding their own keys and proving client-side, with a relayer for submission.
- A finality policy for the tally on public networks.
- External review of the relations and the validators.

## References

- [CGS97] R. Cramer, R. Gennaro, B. Schoenmakers. *A Secure and Optimally Efficient
  Multi-Authority Election Scheme.* EUROCRYPT 1997.
- [RY07] T. Ristenpart, S. Yilek. *The Power of Proofs-of-Possession.* EUROCRYPT 2007.
- [Ped91] T. P. Pedersen. *A Threshold Cryptosystem without a Trusted Party.* EUROCRYPT 1991.
- [GJKR07] R. Gennaro, S. Jarecki, H. Krawczyk, T. Rabin. *Secure Distributed Key Generation for
  Discrete-Log Based Cryptosystems.* J. Cryptology 2007.
- ZeroJ `docs/specs/pedersen-jubjub-v1.md` (bases and scalar sampling) and ADR-0051.
