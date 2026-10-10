# ADR-0008: Sealed-bid auction with enforced bid disclosure to the auctioneer

- **Status:** Proposed. Implementation is on `feat/confidential-notes-m3`.
- **Date:** 2026-10-10 (r2, 2026-10-10: amended after the design review; see "Revision history")
- **Related:**
  - [ADR-0007](0007-confidential-notes-in-pedersen-demos.md): its `AuditorRegistry`,
    `KeyPossessionProof` and key admission (N1, N5, N7) are reused here, through an auctioneer
    registry instance of its own.
  - ZeroJ `elgamal-jubjub-v1` (§6.1 decryption, §8 public inputs, §9.1 `R_enc`, §10.1
    admission) and ADR-0052.
  - [ADR-0006](0006-pedersen-commitment-demos.md), whose "Alternatives considered" deferred this
    auction as larger than a demo.
- **Risk:** R2. This is a new application protocol and a new circuit composition (the
  settlement relation, D4) over the accepted `elgamal-jubjub-v1` relation. No primitive is
  implemented. **D4's decryption argument is this repository's own and needs review.** See
  "Escalation".

## Context

A commit–reveal sealed-bid auction has a known weakness: a bidder who sees it is losing, or who
regrets its bid, simply does not reveal. ADR-0006 deferred an auction because a complete one
needs either an auctioneer who sees every bid or an on-chain state machine.

`elgamal-jubjub-v1` gives a third way. Each bid is encrypted to the auctioneer's key, and the
bid transaction's Groth16 proof shows that the ciphertext encrypts the very amount the bid is
checked against. Disclosure to the auctioneer is therefore **enforced at bid time**, and there is
no reveal phase to abandon. At settlement, the auctioneer proves who won and at what price
without publishing the losing bids.

## Threat model and trust assumptions

| Party | Trusted for | May try |
|---|---|---|
| Bidder | Nothing | Bid above its deposit; bid below the reserve; copy another bidder's ciphertext or proof; bid after the deadline; bid twice; withdraw its bid; fill every bid slot with sybil keys |
| Seller | Nothing beyond listing its own item | Bid on its own lot (directly, or through other keys); take the item back after a sale |
| Auctioneer | **Confidentiality of bids**: it sees every bid and is honest-but-curious. It could leak bids to a colluding bidder during bidding; this ADR does not prevent that. | Name a wrong winner or price; omit or reorder bids; settle early; never settle; bid itself |
| Anyone | — | Pay a fake lot to the address; settle or refund a lot at the wrong time; steal deposits; make one output satisfy two lots' payouts |

**Secret:** each bid amount (from everyone except the bidder and the auctioneer), each bid's
encryption randomness, and the auctioneer's ElGamal secret.

**Public by design:** the bidders, the bid count, the common deposit, the reserve, the
deadlines, the winner and the winning price. Payment is in ADA, so the price is public anyway.

## Decision

### D1 — The lot: one state UTxO (`SealedBidAuction`)

A Julc multi-validator whose hash is both the lot-token policy and the lot address.

**Parameters:**
- `registryPolicy`, `registryToken`: the **auctioneer's** registry instance (ADR-0007 N1). It is
  separate from any note ledger's auditor registry.
- `minWindow`: the minimum `settleBy − biddingEnds`, in milliseconds;
- `minLotAda`: the minimum ADA a lot output carries, in lovelace;
- the verification keys: one for the bid relation (D3), and one each for settlement with 1, 2
  and 3 bids (D4).

**Datum:** `Lot(seller: B28, auctioneer: B28, itemPolicy: B28, itemName: B, lotAda: I,
deposit: I, reserve: I, biddingEnds: I, settleBy: I, pkU: I, pkV: I, generation: I,
bids: [Bid(bidder: B28, A.u: I, A.v: I, B.u: I, B.v: I)])`.
- `deposit` and `reserve` are whole ADA, with `2 ≤ reserve ≤ deposit < 2^32`. `lotAda` is in
  lovelace, `lotAda ≥ minLotAda`.
- `biddingEnds` and `settleBy` are POSIX milliseconds, with `settleBy − biddingEnds ≥ minWindow`.
- `(pkU, pkV, generation)` is the auctioneer's key and registry generation, copied from the
  registry at Open and fixed for the lot's lifetime.
- `bids` holds at most **3** bids. That fixes the settlement circuits and the budget.

**An authentic lot** is an output at the script's exact enterprise address whose value is
exactly:
- lovelace;
- one unit of `itemPolicy.itemName`;
- exactly one token under the script's policy, the **lot token** `T`, with quantity 1.

Wallets and the auctioneer consider only authentic lots. Every spending action requires the
spent input to be authentic, and every action burns or carries forward that same `T`.

**Payout outputs.** Every payout goes to the recipient's **exact enterprise address**,
`(PubKeyCredential(pkh), no stake)`. It carries the inline datum `Payout(T)`. `T` is unique to
one lot (below), so one output can never satisfy two lots' payouts, even across differently
parameterized auction scripts in one transaction. Within one lot the recipients are distinct
(seller, auctioneer and bidders, below).

**Time.** A rule "ends at or before t" requires a **finite** upper bound `≤ t`, and "starts at or
after t" a **finite** lower bound `≥ t`. An infinite bound fails.

| Action | Purpose | Conditions |
|---|---|---|
| **Open** | mint | <ul><li>No input under the script's payment credential.</li><li>The mint entry under the policy is exactly `{T: 1}`, where `T = blake2b_256(refBytes(i))` for some input `i` the transaction spends. So `T` is one-shot and globally unique.</li><li>Exactly one output under the script's credential. It is an authentic lot holding `T`, with exactly `lotAda` lovelace and `bids = []`.</li><li>`seller` signs. `seller`, `auctioneer` and `itemPolicy` are 28 bytes; `itemPolicy` is not the script's policy; `itemName` is at most 32 bytes.</li><li>The parameter ranges above hold.</li><li>The transaction ends at or before `biddingEnds`.</li><li>Exactly one registry reference input (ADR-0007 N3's rule). Its entry's `auditor`, `pkU`, `pkV` and `generation` equal the datum's `auctioneer`, `pkU`, `pkV` and `generation`.</li></ul> |
| **Bid** | spend | <ul><li>The spent input is an authentic lot, and the only input under the script's credential.</li><li>No mint under the policy.</li><li>The transaction ends at or before `biddingEnds`.</li><li>The appended bid's `bidder` signs. It is 28 bytes and differs from `seller`, `auctioneer` and every earlier bidder.</li><li>Fewer than 3 bids before this one.</li><li>Exactly one output under the script's credential: an authentic lot with the same `T`, the same item, and lovelace exactly `deposit · 10^6` more.</li><li>Its datum equals the old datum with exactly this `Bid` appended. It is rebuilt and compared.</li><li>Coordinates are canonical, `A.u ≠ 0`, and `A` differs from every earlier bid's `A`.</li><li>`BidProof` verifies over `[OS2IP(bidder), deposit, reserve, pkU, pkV, A.u, A.v, B.u, B.v]` (D3).</li></ul> |
| **Settle** | spend + burn | <ul><li>The spent input is an authentic lot, and the only script input.</li><li>The mint entry is exactly `{T: −1}`, and there is no output under the script's credential.</li><li>The transaction starts at or after `biddingEnds` and ends at or before `settleBy`.</li><li>`n = len(bids) ≥ 1`, with `w` and `p` from the redeemer, `1 ≤ w ≤ n` and `reserve ≤ p ≤ deposit`.</li><li>`SettleProof(n)` verifies over `[w, p, pkU, pkV, A_1, B_1, …, A_n, B_n]` from the datum (D4).</li><li>Payouts, each tagged `Payout(T)`: to `bids[w].bidder` the item and at least `lotAda + (deposit − p) · 10^6` lovelace; to `seller` at least `p · 10^6`; to every other bidder at least `deposit · 10^6`.</li></ul> |
| **NoBids** | spend + burn | <ul><li>The spent input is authentic and the only script input.</li><li>The mint entry is `{T: −1}`, and there is no script output.</li><li>The transaction starts at or after `biddingEnds`, and `bids = []`.</li><li>`seller` signs.</li><li>A payout to `seller` with the item and at least `lotAda`.</li></ul> |
| **Refund** | spend + burn | <ul><li>The spent input is authentic and the only script input.</li><li>The mint entry is `{T: −1}`, and there is no script output.</li><li>The transaction starts at or after `settleBy`.</li><li>A payout to `seller` with the item and at least `lotAda`.</li><li>A payout to every bidder of at least `deposit · 10^6`.</li><li>Anyone may submit it.</li></ul> |

**Why the payouts are sound:**
- `T` is unique, and every payout output carries `Payout(T)` at an exact address.
- The lot's recipients are distinct.
- So each required payout is a different output, and none is shared with another lot.
- The payouts sum to the lot's value: `lotAda + n · deposit` against
  `(lotAda + deposit − p) + p + (n − 1) · deposit`. The transaction fee comes from the
  submitter's own inputs.
- `lotAda` travels with the item, so the output holding the item always has enough ADA.

### D2 — Notation and encodings

- Bids are `elgamal-jubjub-v1` ciphertexts at width 32 under `PK = (pkU, pkV)`.
- `OS2IP(bidder)` is the 28-byte key hash as an integer, below `2^224 < p`. It is computed on-chain
  with `byteStringToInteger` (big-endian).
- All coordinates are canonical (`< p`). The validator checks this before any proof.

### D3 — Bid relation (`BidProof`)

- **Public, in order:** `bidderInt, deposit, reserve, PK.u, PK.v, A.u, A.v, B.u, B.v`. The
  application's inputs come first, then the key group and the ciphertext group in
  `elgamal-jubjub-v1` §8 order.
- **Witness:** `bid` (32 bits) and `k` (252 bits).
- **Constraints:**
  - `ZkElGamal.encrypt(bid, k, fromVerifierFixedPublic(PK))` equals `(A, B)` (`R_enc(32)`);
  - `reserve ≤ bid ≤ deposit`;
  - `bidderInt² = sq`, with `sq` a witness.

  The last constraint puts `bidderInt` into a constraint so that the proof is bound to it. A
  public input that appears in no constraint does not affect Groth16 verification, and ZeroJ's
  native setup refuses such a wire. Without the binding, another bidder could copy a ciphertext
  together with its proof.
- **Verifier obligations** (spec §9.3):
  - `PK ∈ 𝔾`: the auctioneer registry verifies the key's possession proof on-chain (ADR-0007 N1),
    and Open takes the key from the registry;
  - every coordinate is canonical.
- **What it guarantees:**
  - `A = [k]·G`, so `A ∈ 𝔾`. With `A.u ≠ 0`, `A` is not the identity: a bid with `k ≡ 0` would
    otherwise make the lot unsettleable, because D4's key rule needs `u ≠ 0`.
  - The auctioneer can decrypt every accepted bid, and the bid lies in `[reserve, deposit]`.

### D4 — Settlement relation (`SettleProof(n)`, `n ∈ {1, 2, 3}`)

- **Public, in order:** `w, p, PK.u, PK.v`, then for each bid `i = 1 … n` in datum order:
  `A_i.u, A_i.v, B_i.u, B_i.v`. That is `4 + 4n` inputs. These are a key group and `n`
  ciphertext groups (spec §8), not `R_enc` statements.
- **Witness:** `sk` (252 bits) and `m_1 … m_n` (32 bits each).
- **Constraints:**
  1. **Decryption.** For each `i`, `ZkElGamal.encrypt(m_i, sk, fromVerifierFixedPublic(A_i))`
     is asserted equal to `(PK, B_i)`. The `ZkUInt` decomposition of `sk` is minted once and
     cached, so one decomposition drives every multiplication. By `R_enc`'s definition (spec
     §9.1, with key `A_i` and randomness `sk`) this states exactly:
     - `[sk]·G = PK`, so `sk` is the auctioneer's secret mod `l`. `sk ≥ l` is harmless, because
       `A_i ∈ 𝔾`;
     - `[m_i]·G + [sk]·A_i = B_i`, that is, `B_i − [sk]·A_i = [m_i]·G`;
     - `m_i < 2^32`.

     That is ElGamal decryption (spec §6.1, `M = B − [sk]·A`) of bid `i` to `m_i`. `m_i` is
     unique given `(A_i, B_i)`, because `G` has prime order `l > 2^32`.
  2. **Winner.** `w ∈ {1, …, n}`, as a one-hot selection, and `m_w = p`.
  3. **First price, earliest bid wins ties.** `m_i < p` for `i < w`, and `m_i ≤ p` for `i > w`.
- **Verifier obligations:**
  - each `A_i ∈ 𝔾 ∖ {𝒪}`, from D3 and the Bid check;
  - `PK ∈ 𝔾`, from the registry;
  - canonical coordinates.
- **What it guarantees:**
  - the winner holds the highest bid, and the earliest one on a tie;
  - `p` is that bid.
  - The proof itself discloses only `w` and `p`. The order rule implies `m_i < p` for earlier
    bids and `m_i ≤ p` for later ones.
- **Cost estimate.** Each bid needs one `R_enc` instance, about 6.6k–6.9k rows, so about 22k
  constraints at `n = 3`. On-chain, 16 public inputs at `n = 3`; the cost is measured in M6.

### D5 — Wallets and the auctioneer (host side)

- **Authentication first.** Wallets and the auctioneer read only authentic lots (D1). Anything
  else at the address, such as a token-less "lot" with chosen ciphertexts, is never decrypted or
  settled. `ElGamal.admit(…, s -> true)` (delegated admission, spec §10.1) is legitimate only for
  the bids of an authentic lot: the validator verified each bid's proof when the bid was
  appended.
- **Seller and bidders.**
  - They admit the auctioneer's registry entry exactly as ADR-0007 N5 does. They require the
    lot's `(auctioneer, pkU, pkV, generation)` to equal the current entry's.
  - If the auctioneer has rotated since Open, wallets refuse to bid: they fail closed.
  - **Operational rule:** the auctioneer does not rotate while it has open lots.
- **Bidder.** Encrypts its bid with `ElGamal.encryptWithOpening(context, bid, 32, rng)`. It never
  uses the variable-time `scalarMul`.
- **Auctioneer.**
  - Keeps the secret for every generation, and uses the one the lot records.
  - For each bid it runs `admit`, then `decryptWithSecret` with `maxPlaintext = 2^32 − 1` and one
    reusable `JubjubDiscreteLog` table. An admitted width-32 ciphertext carries that bound, and
    `ElGamal` refuses any smaller one. It then checks `reserve ≤ m ≤ deposit`.
  - It computes the winner and the price, and proves D4.

## Invariants

| ID | Invariant |
|---|---|
| A-I1 | Each lot is one authentic UTxO with a one-shot, globally unique token `T`, at the exact enterprise address, from Open until `T` is burned. |
| A-I2 | A bid is accepted only before `biddingEnds`, signed by a new bidder (not the seller or the auctioneer), with exactly `deposit` ADA added and the datum extended by exactly that bid. |
| A-I3 | Every accepted bid encrypts, under the lot's key, an amount in `[reserve, deposit]`, bound to its bidder (D3). |
| A-I4 | Settlement happens only in `[biddingEnds, settleBy]`, covers **every** bid in the datum, names the earliest highest bid and its amount, and pays the seller, the winner and every loser through outputs tagged with `T`. |
| A-I5 | If there is no settlement by `settleBy`, anyone can return every deposit and the item. |
| A-I6 | No transaction discloses a losing bid amount; settlement discloses only `w` and `p`. The bid ciphertexts are permanent: whoever holds the lot's auctioneer secret, now or later, can read every bid. There is no forward secrecy. |
| A-I7 | One lot per transaction; payouts are tagged with the lot's unique token; within a lot, recipients are distinct. |

## Limitations (stated, not prevented)

- **Auctioneer trust.** It sees all bids during bidding and could leak them. Removing that trust
  needs threshold decryption (ZeroJ ADR-0053) or a timed release, which is out of scope. Together
  with the seller, it has a free option not to settle: bidders then wait until `settleBy` for
  Refund.
- **Bid capacity and sybils.** The first three distinct keys fill a lot. One party with three keys
  can occupy every slot at the reserve, and a seller or auctioneer can bid through keys other
  than its own. Real use would need an allowlist or a bid bond. The demo states this.
- **Rotation freezes open lots** for compliant wallets (D5).

## Escalation (external review)

- **D4 composes `R_enc`'s gadget with the auctioneer's secret as the randomness and a bid handle
  as the key.** This is algebraically the decryption relation, and both design reviewers verified
  that the gadget supports it: the key path, the shared cached decomposition, and the `u ≠ 0`
  rule. ZeroJ's specs define no named decryption relation (ADR-0052 D8 put on-chain decryption
  shares out of scope). The argument is this repository's own and needs external review.

## Alternatives considered

- **Commit–reveal with forfeited deposits.** A bidder can still refuse to reveal, at the cost of
  its deposit, and the auction then ends with a wrong price.
- **Bids as Pedersen commitments with D5 deliveries.** Deliveries cannot be enforced (ADR-0055
  D3 is deferred), so a bidder could post an unreadable bid.
- **Publishing decryption shares at settlement.** Simple, but it reveals every losing bid.
- **A Vickrey (second-price) auction.** It needs `p = ` the second-highest bid. That is a small
  change to D4, deferred to keep the demo small.
- **Payouts matched by payment credential only.** Rejected (review C1, F14): the submitter could
  pick the stake credential, and one output could satisfy two lots.

## Revision history

- **r1** (2026-10-10): initial proposal.
- **r2** (2026-10-10; design review by an adversarial Claude reviewer, F1–F17, and Codex,
  C1–C10; no P0; both verified D4):
  - C1, F14: payouts are tagged with `Payout(T)` and paid to exact enterprise addresses.
  - C2, F9: lot authentication and the per-action rules are written out.
  - C3: Open spends no script input.
  - C4, F4: decryption uses the `2^32 − 1` bound.
  - C5, F3: `lotAda`, computed from the serialized output, replaces the fixed 2 ADA.
  - C8, F6: the generation is pinned; the operational rule against rotation is added.
  - C9, F11: finite bounds and `minWindow`.
  - C10, F13: the auctioneer is refused as a bidder; sybil capacity is listed under limitations.
  - F12: on-chain range checks for `w` and `p`.
  - F15: A-I6 reworded.
  - F16: the auctioneer has its own registry instance.
  - F1: the registry key is verified on-chain (ADR-0007 r2).

## Verification

- **Circuits:**
  - bid: a bid above the deposit or below the reserve; a ciphertext of another amount; another
    key; a proof for one bidder checked against another (the binding test);
  - settle: a wrong winner, a wrong price, a later equal bid named as winner (the tie order), a
    wrong `sk`, a bid omitted.
- **Plutus VM mutations:**
  - Open: no consumed input matching `T`, a script input spent, two tokens, a wrong item, too
    little `lotAda`, the key or generation not from the registry, the auctioneer not the entry's,
    `minWindow` not met, the transaction after `biddingEnds`, bad ranges;
  - Bid: late; an infinite upper bound; unsigned; by the seller; by the auctioneer; a repeated
    bidder; a fourth bid; the deposit off by one lovelace; the datum not appended exactly (a
    reordered or modified earlier bid); a copied handle; `A` the identity; a stake-variant
    output; a token-less input; an extra asset;
  - Settle: early; late; a missing, underpaid or untagged payout; a payout at a stake address; the
    token not burned; `w` or `p` out of range; a proof over a subset of the bids; two lots in one
    transaction;
  - Refund: early, or underpaid; NoBids with bids present, or unsigned.
- **DevKit end to end:** open, three bids, settle (with the winner and price checked, and the
  losers refunded); the refund path; a bid over the deposit refused (no proof); a late bid
  refused.
- **UI** through the Playwright MCP.
- **Measurements**, filled in at M6: constraints, prover time, and the Julc VM cost of Bid and of
  Settle (`n = 1, 2, 3`) against the 80% gate.
