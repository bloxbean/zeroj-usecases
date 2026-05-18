# Jubjub + BLS12-381 Poseidon on Cardano — What Becomes Possible

> Status: Exploratory writeup, 2026-04-18. Scope: what the ADR-0015 Poseidon
> work already unlocked, what the upcoming ADR-0016 Jubjub work will unlock,
> and how each zeroj usecase can exploit them.

## 1. Why this matters for Cardano

Cardano onchain supports exactly one ZK-friendly pairing-friendly curve
natively: **BLS12-381**. Any circuit whose Groth16 / PlonK proof is verified
by a Plutus V3 script must be built over BLS12-381. That constrains every
other cryptographic primitive used inside the circuit — field arithmetic,
hash functions, signatures, commitments — to be **defined over the
BLS12-381 scalar field** (or derivatively composable with it).

Before ADR-0015 (shipped), zeroj circuits used `Poseidon` built from BN254
circomlib constants operating over the BLS12-381 scalar prime — a
non-standard hybrid that worked internally but was incompatible with every
published reference implementation. Third parties could not reproduce a
hash, verify a commitment, or re-derive a nullifier from chain data.

After ADR-0015 → ADR-0016 (planned):

- **Poseidon over BLS12-381 scalar field**, paper-canonical (✅ shipped;
  paper-spec Sage cross-checked; byte-reproducible from chain data by any
  conforming implementation).
- **Jubjub** — a twisted-Edwards elliptic curve whose base field *is* the
  BLS12-381 scalar field, so its operations are cheap to prove inside a
  BLS12-381 SNARK (🔜 ADR-0016).

Together these two primitives complete the minimum cryptographic alphabet
for privacy-preserving applications on Cardano.

## 2. Terminology: Jubjub vs BabyJubJub

| Name | Host curve (scalar field) | Use |
|---|---|---|
| **BabyJubJub** | BN254 (alt_bn128) | Ethereum, circom ecosystem |
| **Jubjub** | BLS12-381 | Zcash, Filecoin, Cardano ZK |

Both are twisted Edwards curves with identical structural design, different
parameters. **Cardano wants Jubjub, not BabyJubJub.** The onchain validator
can only verify Groth16 proofs over BLS12-381, so all in-circuit
elliptic-curve operations must be native to that scalar field.

The zeroj codebase (and ADR-0015) uses "Jubjub" to mean the Zcash/zkcrypto
variant pinned at those curve parameters.

## 3. Primitives the stack enables

### Shipped in ADR-0015

| Primitive | Building block | Evidence |
|---|---|---|
| Poseidon hash (2-to-1, N-to-1) | `PoseidonHash`, `Poseidon` gadget | Circomlibjs BN254 match + Sage paper-spec match |
| Poseidon Merkle trees | `SignalMerkle` + `SignalPoseidon` | End-to-end DPP on yaci-devkit (tx `80c28182…`) |
| MPF (Merkle Patricia Forest) with Poseidon leaves | DPP `PoseidonHashFunction` → CCL | DPP demo persistence |
| Nullifier derivation | Poseidon(secret, context) | private-voting, nft-ownership |
| Commitment schemes | Poseidon(secret, value) | identity-kyc credential hash |

### Unlocked by ADR-0016 (upcoming)

| Primitive | Building block | Why it matters on Cardano |
|---|---|---|
| **Jubjub point arithmetic in-circuit** | add, double, scalar-mul | Foundation for every later item |
| **Pedersen commitment** | `g^v · h^r` on Jubjub | Hiding + binding + homomorphic; enables confidential amounts without range-proof cost of Poseidon commitment |
| **EdDSA signature verification in-circuit** | Ed25519-like over Jubjub | Asymmetric-signed credentials (W3C VC, DID, Atala PRISM interop); bank/issuer signs, holder proves knowledge |
| **Schnorr signatures in-circuit** | Jubjub-Schnorr | Anonymous wallet signatures; threshold schemes |
| **Jubjub Merkle trees** | Using Pedersen or Poseidon leaves | Alternative to Poseidon Merkle — better for very large trees due to homomorphic parent derivation |
| **Group signatures / anonymous credentials** | Jubjub + Pedersen | BBS+-style or similar |
| **Deterministic vote encryption** | ElGamal on Jubjub | Homomorphic tallying; threshold decryption |

All of these produce a Groth16 / PlonK proof that ZeroJ's existing Plutus V3
verifier (`zeroj-onchain-julc/Groth16BLS12381Verifier`) accepts on-chain.
**No new Plutus builtins or onchain changes needed** — the full complexity
is internalized in the SNARK.

## 4. Impact on each existing zeroj usecase

### 4.1 identity-kyc — **highest-impact target** for Jubjub

**Today (Poseidon-signed, symmetric):**
- Credential = `Poseidon(issuerSecret, Poseidon(age, country))`.
- Holder and issuer share `issuerSecret`. Either party can forge new
  credentials. Key must be secretly transmitted to every holder — not a
  real VC model.
- No interop with W3C VC / DID wallets / Atala PRISM.

**With Jubjub EdDSA (ADR-0016 M5):**
- Issuer signs credential with `sign(issuer_sk, Poseidon(age, country))` —
  asymmetric.
- Holder proves in ZK: "I know a credential + signature verifying under
  the issuer's public key, such that age ≥ 18 and country ∈ EU", without
  revealing claim values or the signature.
- **Interoperable with W3C VC** (EdDSA-Ed25519 is RFC 8032; the Jubjub
  variant is the natural in-SNARK analog).
- Issuer rotation, revocation, multi-issuer all become tractable.
- Direct path to Atala PRISM / CIP-30 credential presentation.

**ADR-0014 explicitly flagged this as the motivation for re-adding EC
operations to circuit-lib.** ADR-0016 is its Cardano-native realization.

### 4.2 private-voting

**Today:**
- Eligible voter set = Poseidon Merkle tree of public keys (where each
  key = `Poseidon(secret, 0)`).
- Nullifier = `Poseidon(secret, electionId)`.
- Commitment = `Poseidon(vote, nullifier)`.

**With Jubjub:**
- **Voter keys become Jubjub keypairs.** Voter public key = `[sk]·G` where
  G is the Jubjub generator — a standard EdDSA public key. Voters can
  derive and prove membership using the same key they'd use for wallet
  signing.
- **Vote commitment via Pedersen** = `[vote]·G + [r]·H` — homomorphic.
  Allows **additive tallying** (sum the on-chain commitments → encrypted
  total → threshold-decrypt off-chain by vote authority). No need for
  the tallier to see individual votes.
- **Sybil-resistant registration**: voter proves ownership of a Cardano
  wallet via Jubjub-Schnorr tied to an on-chain stake key commitment.
- **Weighted voting by stake**: same proof, but the tally weights each
  vote by a stake amount committed via Pedersen.

Cardano onchain: the minting policy already exists; only the witness-set
contents change.

### 4.3 proof-of-reserves

**Today:**
- Merkle Sum Tree of `Poseidon(accountId, balance)` leaves.
- Proves sum of all balances ≤ declared reserves.

**With Jubjub:**
- **Pedersen-committed balances** (hiding + binding). The Merkle Sum Tree
  holds Pedersen commitments instead of cleartext `(accountId, balance)`
  hashes. The exchange doesn't reveal even the hash of the pair — only
  a commitment. Aggregate sum is a **homomorphic** sum of Pedersen
  commitments (opened to reveal only the total, not individuals).
- Users can prove inclusion of their own balance (by opening one leaf's
  Pedersen commitment to themselves) without the exchange revealing it
  to anyone else.
- **Optional: EdDSA-signed balance attestations** from the exchange —
  each leaf's Pedersen commitment is signed by the exchange, binding
  them to not re-issue it under a different account.

Result: significantly stronger confidentiality than the current scheme
(which hashes `(id, balance)` but still leaks balance to anyone who can
enumerate ID space).

### 4.4 nft-ownership

**Today:**
- `ownerHash = Poseidon(secretKey, 0)`; leaf = `Poseidon(ownerHash, tokenName)`.
- Proves membership in a Merkle snapshot of holders.
- Nullifier = `Poseidon(tokenName, contextId)`.

**With Jubjub:**
- **Proper wallet-derived ownership**: replace `secretKey` with a Jubjub
  (or Cardano stake-key-derived) signature over `(tokenName, contextId)`.
  Owner proves "I hold the Cardano key that last received this NFT" —
  stronger binding than `Poseidon(secret, 0)`.
- **Pedersen-hidden token names**: snapshots commit to Pedersen
  commitments of token IDs, not cleartext hashes. Prevents a third
  party from enumerating "which NFTs exist" from the snapshot.
- **Batched airdrop claims** with one proof covering multiple holdings
  (Pedersen commitment sum = total).

### 4.5 digital-product-passport (DPP)

**Today:**
- Three ZK circuits (carbon threshold, recycled threshold, country
  membership) under Poseidon.
- On-chain Plutus policy mints an NFT if proof valid.

**With Jubjub:**
- **Inspector signatures** (currently a Poseidon key in the circuit)
  become Jubjub EdDSA. Inspectors hold standard Ed25519-equivalent keys
  that they can also use off-chain for other purposes.
- **Supply-chain chain-of-custody** — each leg of the supply chain signs
  a Pedersen-committed product state. The DPP minting circuit proves
  "an unbroken chain of valid signatures from raw-material supplier to
  retailer exists", without revealing intermediate parties or timestamps.
- **Confidential batch sizes**: manufacturers commit to batch sizes via
  Pedersen; downstream proofs reason about bounds without revealing exact
  production volume.

### 4.6 Not-yet-existing usecases the stack unlocks

- **Private Cardano-native payment proofs** — prove "I sent ≥ X ADA in
  the last epoch" via Pedersen-committed transfer amounts, without
  revealing exact amounts or counterparties.
- **Anonymous governance voting** on CIP-1694 governance actions — eligible
  stake-weighted voting where individual ADA-holder votes are Pedersen-
  committed and homomorphically summed.
- **Reusable identity attestations for dApps** — DID holder proves
  "my identity credential from issuer X includes country Y" directly
  to any dApp, via a single proof reusing a signed credential. Revoke
  revocation list via Merkle membership on Jubjub.
- **Privacy-preserving loyalty programs** — users prove "I bought ≥ N
  products from retailer X in the last year" without retailer seeing
  purchase history.
- **Confidential sealed-bid auctions** — Pedersen-committed bids, proved
  valid and in range via Jubjub-backed range proofs, revealed only on
  auction close.
- **KYC-gated DeFi** — DeFi protocol requires ZK proof "I hold an
  issuer-signed KYC credential" before allowing withdrawal; issuer
  signatures are Jubjub EdDSA.

## 5. Why these primitives specifically (and not BLS12-381 group ops)

BLS12-381 itself has G1 + G2 + pairings natively. So why add a second curve
(Jubjub) inside the SNARK?

Because **BLS12-381 scalar multiplication inside a BLS12-381 SNARK is
prohibitively expensive**. Each EC op on the host curve requires emulating
base-field arithmetic inside scalar-field arithmetic — tens of thousands
of constraints per scalar-mul.

Jubjub operates natively in the scalar field of BLS12-381, so a Jubjub
scalar-mul is a few hundred constraints — cheap enough for real-time ZK
proofs. That's the entire point of having an "embedded" curve: the curve
arithmetic and the SNARK arithmetic share the same field.

The trade-off: Jubjub operations stay *inside* the proof. You cannot use a
Jubjub public key as a Cardano wallet signing key — those are Ed25519, a
different curve. But the two can be linked via a one-time derivation
commitment proved in-circuit.

## 6. Security note on BabyJubJub vs Jubjub

ADR-0014 (WIP) mentions the earlier zeroj BabyJubJub code was removed
because of missing subgroup checks and EdDSA malleability. **These
concerns apply equally to Jubjub and must be handled by the ADR-0016
implementation.** The current ADR-0016 plan:

- `JubjubPoint.isInSubgroup()` method; every input from untrusted source
  must pass this check before being used in scalar-mul.
- EdDSA verification pins the canonical encoding of S < l (no S + l
  malleability).
- Cofactor handling: all primitives use cofactor-cleared points.

## 7. Milestone summary (ADR-0016)

| Milestone | Deliverable | Status |
|---|---|---|
| M1 | Off-circuit `JubjubPoint` + ops + subgroup check | 🔜 |
| M2 | In-circuit point add + fixed-base scalar-mul | 🔜 |
| M3 | Variable-base scalar-mul | 🔜 |
| M4 | Pedersen commitment + `BLS12_381_T5` Poseidon preset + Jubjub Merkle | 🔜 |
| M5 | EdDSA-Jubjub verification in-circuit | 🔜 |
| M6 | External cross-verification (zkcrypto/jubjub test vectors) | 🔜 |
| Usecase | Migrate identity-kyc to EdDSA-Jubjub-signed credentials | 🔜 |

End-to-end yaci-devkit verification required at the end.
