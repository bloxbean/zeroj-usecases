# ADR-0007: Confidential notes in the Pedersen demos — on-chain opening delivery, enforced auditor amounts, proof-enforced payroll

- **Status:** Proposed. Implementation is on `feat/confidential-notes-m3`, stacked on
  `feat/pedersen-private-ballot-and-demos` (PR #8).
- **Date:** 2026-10-10 (r2, 2026-10-10: amended after the design review; see "Revision history")
- **Related:**
  - ZeroJ ADR-0055 (`confidential-note-jubjub-v1`). Its design is accepted, and milestones M0–M2,
    M4 and M5a are merged (bloxbean/zeroj#82, `1e78c6f`). **This ADR is its milestone M3**, the
    usecase migration.
  - ZeroJ specs `confidential-note-jubjub-v1`, `elgamal-jubjub-v1` and `pedersen-jubjub-v1`, at
    `1e78c6f`.
  - [ADR-0006](0006-pedersen-commitment-demos.md): demos A (points) and C (solvency), which this
    ADR changes.
  - [ADR-0005](0005-private-ballot-homomorphic-tally.md): the DLEQ possession proof pattern.
  - [ADR-0008](0008-sealed-bid-auction-enforced-disclosure.md): the sealed-bid auction, which
    reuses this ADR's registry and wallet pieces.
- **Risk:** R2. These are application protocols, validators and circuit compositions over
  profiles ZeroJ has already accepted and implemented. No primitive is implemented here. Every
  secret operation goes through ZeroJ's public API.

## Context

ADR-0006 hides amounts as `pedersen-jubjub-v1` commitments, but its openings never leave the
process that made them. A recipient or auditor cannot recover a note from chain data, and the web
demo's server keeps every wallet's openings. ZeroJ ADR-0055 closes that gap with **notes**: the
commitment plus its opening encrypted on-chain to each reader (Zcash Sapling's KA, KDF and
ChaCha20-Poly1305). Its D3a additionally gives an auditor the **amount** of every note that a
proof-enforced transition creates. It does this with `elgamal-jubjub-v1` limb ciphertexts that
the transition's Groth16 proof binds to the commitment.

ADR-0055's M3 exit criteria, which this ADR must meet:
1. On Yaci DevKit: issue, transfer and redeem, with recovery from chain data by the owner and by
   the auditor.
2. Validator mutation tests: a missing auditor delivery, wrong lengths, extra deliveries.
3. A garbage delivery is reported as unopenable.
4. **(a)** The demo defines and enforces its address policy: how continuing outputs are matched
   (payment credential and stake credential) and how notes are authenticated. The mutations
   include an extra output under the script's payment credential with another stake credential.
5. **(b)** The wallet's prover encrypts limbs with `ElGamal.encryptWithOpening`, under a key
   context built from a possession-verified registry key. It never uses the reference test's
   variable-time fixture.
6. ADR-0055 note 8: the gate check runs on the application's **complete** transaction (spending
   plus minting purposes), at most 80% of the per-transaction step and memory limits.

This ADR also adds two uses of the same pieces, as the maintainer asked:
- **solvency** (demo C) with on-chain delivery of each customer's entry, which ADR-0055 lists as
  optional;
- a new **confidential payroll** demo, whose issuance is proof-enforced (ADR-0055 Q9 (b)).

## Threat model and trust assumptions

ADR-0006's model stands. This ADR adds the following.

| Party | Trusted for | Not trusted for | May try |
|---|---|---|---|
| Sender of a note (transfer, redeem) | Nothing | The owner's delivery, the auditor's limbs, randomness | Garbage or wrong deliveries; limbs of another amount; limbs under a retired or foreign key; reused limb randomness; an extra note at a stake-variant address |
| Points issuer | Supply (ADR-0006), **and** the audit data of issued notes (Q9 (a)) | Anything else | Issuing notes whose limbs understate the amount. This succeeds, and the auditor labels it as issuer-trusted. |
| Payroll employer (issuer) | Supply only | The audit data of issued notes (Q9 (b)) | Paying a salary while under-reporting it to the tax authority. This is refused, because no proof exists. |
| Auditor or tax authority | Its own registry entry; honest-but-curious | — | Reads every amount, which is the point. It never receives spending authority. It can stop auditing (by losing its keys), but it cannot freeze notes: a registered ElGamal key is checked on-chain to be a valid subgroup key (N1), so every spend circuit stays satisfiable. |
| Registry operator (the auditor) | Which keys it registers | — | Registering a key it does not hold, such as someone else's published key with that key's published proofs. Possession proofs are bound to the registrant, the registry and the key type (N7), so a copied proof does not verify. |
| Demo server | Everything (demo custody) | — | It holds every wallet's viewing key and scans on their behalf. **This is demo-only** and contradicts ADR-0055 D9, under which scanning runs in the user's own wallet process. The UI says so. |

**Secret:** the viewing keys, the auditor's ElGamal secret, every opening `(v, r)`, the limb
values and their randomness `k`.

**Untrusted inputs:** every datum, every delivery, every registry entry until its possession
proofs verify, and every reference input.

**Assumptions:** ADR-0055's A1–A3, which are unproved and gated on external review. The demos
make no claim beyond them.

## Decision

### N1 — Auditor registry (`AuditorRegistry`)

Each audited application has one registry instance: a Julc multi-validator whose hash is both
the registry token's policy and the registry's address. This follows spec §8.1's first option,
a **singleton** registry token that the registry's own script moves forward on rotation.

- **Init (mint).** The parameter is a seed, `txId ‖ I2OSP2(index)`, as in `VoteListLib`. The
  policy mints exactly one `REG` token, and only in a transaction that spends the seed. The token
  goes into exactly one output, at the registry's exact enterprise address, with a well-formed
  entry with `generation = 0`. The auditor named in the entry signs, and `pkProof` verifies
  on-chain (below). No input under the registry's own payment credential is spent. The seed can
  be spent once, so the token is unique forever.
- **Entry datum.** `Entry(auditor: B28, generation: I, pkU: I, pkV: I, pkEnc: B32, viewKey: B32,
  pkProof: B192, viewProof: B192)`:
  - `pkU`, `pkV`: the auditor's `elgamal-jubjub-v1` key `PK_a` as canonical affine coordinates,
    which validators read;
  - `pkEnc`: the same key's 32-byte encoding (spec §7.3), which wallets decode strictly;
  - `viewKey`: the auditor's `confidential-note-jubjub-v1` reader key, encoded;
  - `pkProof`, `viewProof`: compressed Groth16 possession proofs (`piA ‖ piB ‖ piC`) for the two
    keys, under the demo's `KeyPossessionProof` circuit (N7). Each proof is bound to its key type,
    to this registry's policy id and to the entry's `auditor`.
- **Rotate (spend).** All of these must hold:
  - exactly one input under the registry's payment credential;
  - the old entry's auditor signs, and so does the new entry's;
  - exactly one output holds the token;
  - that output is at the exact enterprise address, with value exactly lovelace plus the token;
  - its datum has the exact shape, canonical coordinates, lengths 28/32/32/192/192,
    `pkEnc ≠ viewKey`, and `generation = old + 1`;
  - the new entry's `pkProof` verifies on-chain;
  - no mint under the registry policy;
  - the spent input holds the registry token (so a token-less output at the address cannot be
    "rotated").

  The token is never burned or duplicated, so no older entry stays unspent. That is what makes
  the current generation enforceable (ADR-0055 Q7, implementation note 11).
- **Possession (Q6).**
  - **The ElGamal key is checked on-chain** at Init and Rotate. The registry verifies `pkProof`
    (one Groth16 verification, 7 public inputs, about 3.5e9 steps; rotation is rare) over
    `[ctx(0x01), G.u, G.v, pkU, pkV, pkU, pkV]`. This discharges `R_enc`'s `PK ∈ 𝔾` obligation
    on-chain (spec §9.3). It also means an auditor cannot register an identity, off-curve or
    out-of-subgroup key, which would make every spend circuit unsatisfiable and freeze every note.
  - **The viewing key is checked off-chain** by every sender before delivering to it (N5). A bad
    viewing key costs the auditor its own D5 deliveries, nothing else.
  - **Binding.** The context `ctx(type)` (N7) is computed on-chain from the key type, the
    registry's own policy id and the entry's `auditor`. A proof copied from another registry, from
    another registrant or from the other key type does not verify. Together with the registrant's
    own signature on Init and Rotate, this binds each registration to its registrant, its registry
    and this profile (ADR-0055 D2, spec §2.2).
- **Pinning.** A ledger takes the registry's policy id and token name as parameters. Which
  auditor an application uses is therefore the operator's choice, fixed in the ledger's hash. The
  auditor checks that the ledger names its registry.

### N2 — The note ledger (`NoteLedger`, replacing `PointsLedger`)

`PointsLedger` (ADR-0006 A) becomes `NoteLedger`, which has two instances:

| Instance | Token | Issuance | Auditor |
|---|---|---|---|
| Confidential points | `PTS` | **Trusted** (ADR-0055 Q9 (a)) | Points auditor registry |
| Confidential payroll | `SAL` | **Proof-enforced** (Q9 (b)) | Tax-authority registry |

The parameters are:
- the issuer's pkh, the token name and the issuance mode;
- the registry policy and token;
- the verification keys: transfer, redeem, and proved issuance for one and for two notes.

**Datum:** `Note(owner: B28, u: I, v: I, generation: I, audit: [I × 8], deliveries: [B89 × 2])`.
- `audit` holds the two `elgamal-jubjub-v1` limb ciphertexts at width 32, `A.u, A.v, B.u, B.v`
  for limb 0 and then limb 1 (spec §8.1).
- `deliveries` holds the owner's delivery, then the auditor's (spec §3.2). The auditor's delivery
  goes to the registry entry's `viewKey`.
- `generation` is the registry generation the note was created under. Every path (Issue,
  ProvedIssue, Transfer, Redeem) requires every created note's `generation` to equal the current
  entry's (read from the registry reference input). The auditor uses it to pick the right
  generation's keys (N5).
- The output's value is exactly lovelace plus one note token (no other asset). Its lovelace is
  computed from the serialized output and the protocol's `coinsPerUTxOByte`, not hard-coded
  (ADR-0055 D8). The datum is about 0.6 KB, so a note needs about 3.5 ADA.

A validator checks the shape, the counts (8 and 2), the lengths (28, and 89 for each delivery)
and that every integer is canonical. It cannot check that a delivery decrypts (ADR-0055 D8).

**Address policy (M3 criterion (a)):**
- A **note output** is any output whose payment credential is the ledger's script.
- In every ledger transaction (issue, transfer, redeem), **every** such output must:
  - be at the ledger's **exact enterprise address**, with no stake credential;
  - hold exactly lovelace and one note token, and nothing else;
  - have a well-formed note datum of the current generation.

  Otherwise the transaction is refused.
- An output at a stake-variant address is therefore never silently ignored, unlike ZeroJ's
  reference validator (ADR-0055 implementation note 12). It makes the whole transaction fail.
- Script inputs are counted by payment credential, as in ADR-0006, so one note is spent per
  transaction under any stake variant.

**Note authentication.**
- The note token is minted only by Issue (by the issuer, or with a proof in payroll mode) and by
  Split (alongside a proved transfer).
- Every path places every token in a note at the exact address.
- A wallet therefore treats a UTxO as a note only if:
  - it is at the exact ledger address;
  - it holds exactly one note token of the ledger's policy;
  - its datum parses.

  Anything else paid to the address is ignored (ADR-0006 P6).

### N3 — Enforced auditor amount on transfer and redeem (ADR-0055 D3a)

Both circuits get a new version (`NoteTransferProof` and `NoteRedeemProof`, version 2). Each
created note `o` gets:
- two secret 32-bit limbs with `L_{o,0} + 2^32·L_{o,1} = amount_o`, where `amount_o` is the
  witness that opens `C_o`;
- for each limb, `ZkElGamal.encrypt(limb, k, key)` under
  `ZkElGamalPublicKey.fromVerifierFixedPublic(pkU, pkV)`, with `assertAffineEquals` against the
  public coordinates.

The public inputs, in spec §8.2 order after the application's own:
- **transfer:** `in.u, in.v, o1.u, o1.v, o2.u, o2.v, PK.u, PK.v`, then o1's 8 coordinates, then
  o2's. That is 24 inputs.
- **redeem:** `in.u, in.v, change.u, change.v, price, PK.u, PK.v`, then the change note's 8
  coordinates. That is 15 inputs.

The validator fixes every one of them:
- the commitments and coordinates from the datums;
- the price from the redeemer, as in ADR-0006;
- `PK` from **exactly one** reference input holding exactly one registry token. The datum must
  be an `Entry` of the exact shape; a second entry, another quantity or another shape is refused.

**Fresh randomness.** All limb handles `A` in the transaction must be pairwise distinct (spec
§8.1). This catches exact reuse, an honest wallet's accident. Related or cross-transaction reuse
cannot be detected; it rests on the prover's random generator.

**Layout gate.**
- The direct layout (spec §8.2) is used if and only if the complete transaction measures at most
  80% of both limits. The complete transaction is the spend plus the `Split` or `Receipt` mint.
  It is measured in the Julc VM (protocol version 11 cost model) and confirmed on DevKit from the
  evaluator's execution units.
- The reference validator measured 73.4% for the transfer spend alone. If the complete
  transaction exceeds 80%, that transaction uses the hash-compressed layout (spec §8.3) instead.
  Its public inputs are then the application's inputs, `PK.u, PK.v`, `digest_hi`, `digest_lo`
  (transfer: `in, o1, o2, PK, digest_hi, digest_lo`, 10 inputs).
- The measured table goes into "Measurements" below. Until it is filled in, this decision is
  open.

### N4 — Issuance

- **Trusted (points).** ADR-0006's `Issue` rules apply, plus N2's datum shape and address policy.
  The issuer supplies the limbs and deliveries, and the auditor relies on the issuer for them.
  The auditor's view labels such notes **issuer-trusted**, and flags it when the limb amount
  differs from the auditor's own D5 opening.
- **Both modes** require: the issuer's signature; no input under the ledger's payment
  credential (`ownInputs = 0`, which the auditor's origin label relies on); the mint entry exactly
  `{token: n}`; exactly `n` note outputs, each satisfying N2 (exact address, exact value, datum
  shape, current generation); and exactly one registry reference input (N3's rule).
- **Proved (payroll).** A `ProvedIssue(piA, piB, piC)` redeemer replaces `Issue`. In this mode
  `Issue` is refused, and in trusted mode `ProvedIssue` is refused. In addition:
  - `n ∈ {1, 2}`;
  - every limb handle of every issued note is pairwise distinct (spec §8.1);
  - `NoteIssueProof(n)` verifies over `u_1 … u_n`, `v_1 … v_n` (the issued commitments in
    output order), `PK.u, PK.v` **from the registry reference input**, and then each note's 8
    coordinates **from its datum**, in output order. That is `2n + 2 + 8n` inputs: 12 for one
    note, 22 for two. No public input comes from the redeemer.

  The circuit proves, for every issued note, the same limb relation as N3. So an employer that
  supplies a wrong audit ciphertext has no proof, and its transaction is refused. That is
  ADR-0055 M5a's Q9 (b) obligation. The same gate applies: a size `n` whose complete transaction
  exceeds 80% is not offered.

### N5 — Wallets, senders and auditors (host side)

All of this uses ZeroJ's public API only.

**Admitting a registry entry.** A sender or auditor admits an entry only if every check passes,
and fails closed otherwise:
1. `VerifiedKeyShare.verify(pkEnc, s -> s.kind() == POSSESSION && possession.verify(pkProof,
   s.publicInputs()))`. This decodes strictly: canonical, in the subgroup, not the identity.
2. `ElGamalPublicKey.aggregate(List.of(share))`, giving an `NOfNKeyContext` with one key.
3. The context's key equals the datum's `(pkU, pkV)`, which is what the validator feeds the
   proof.
4. `NoteReaderKey.verified(viewKey, …)` with `viewProof`.

**Limbs.**
- Only `ElGamal.encryptWithOpening(context, limb, 32, rng)` is used (M3 criterion (b)). It draws
  `k` and runs every secret multiplication on the blinded best-effort schedule, which is
  ADR-0039's compatibility/offline class.
- Main code never builds limbs with variable-time `scalarMul`.
- Deliveries come from `ConfidentialNotes.seal(opening, [ownerKey, auditorViewKey], rng)`, with
  `NoteOpening.random`.

**Wallet scan.**
- For each note UTxO (N2's authentication), the wallet builds `Candidate.of(deliveries[0], u, v,
  owner == myPkh)` and runs `NoteScanner.of(myViewingKey).scan(...)`. The result is the opened
  notes and the **unopenable owned** notes (ADR-0055 I9).
- A note counts as the wallet's, and is offered for spending, only if it **both** opened **and**
  names the wallet's own key hash as `owner`. Opening alone is not ownership: `Scan.opened()`
  also lists notes whose delivery opens but whose `owner` is someone else (spec §5, "the
  application's step"). Those are shown as "readable, not yours". An owned note that does not
  open is shown as value the user owns but cannot spend, which is evidence of a misbehaving
  sender.

**Auditor.** For each note:
- **keys:** the auditor keeps every generation's ElGamal secret and viewing key (ADR-0055 D2,
  "Rotation"), and uses the generation the note's datum records. That field is checked against
  the registry when the note is created (N2).
- **which notes:** only authenticated notes (N2: exact address, exactly one note token of this
  ledger). Anything else paid to the address is never admitted or decrypted.
- **amount:** `RawElGamalCiphertext.fromAffine` (strict), then `ElGamal.admit(raw, context, 32,
  s -> true)`, then `decryptWithSecret` with one reusable `JubjubDiscreteLog` table at
  `2^32 − 1`. The amount is `L0 + 2^32·L1`.
  - The delegated verifier `s -> true` is legitimate (spec §10.1) only because the ledger verified
    the transaction proof when an authenticated **proof-enforced** note was created.
  - For an **issuer-trusted** note no proof was verified. Its decrypted amount is reported as
    "issuer-claimed", never as enforced. This is a deliberate, labelled use of the admitted API
    outside its delegated-verifier premise.
- **origin:**
  - **proof-enforced** if the creating transaction spent a ledger input, or was a `ProvedIssue`
    (payroll);
  - **issuer-trusted** otherwise (points issuance).

  It is derived from chain data: the creating transaction's inputs, through Yaci Store.
- **cross-check:** the auditor also opens its D5 delivery. A delivery that does not open, or
  whose value differs from the limb amount, is shown as a sender fault. For an issuer-trusted
  note it is shown as "issuer data inconsistent".

**Keys.**
- Viewing keys and auditor secrets are generated with `NoteViewingKey.generate` and
  `ElGamalSecretKey.generate`, then kept in the server's demo custody.
- Possession proofs come from `NoteViewingKey.provePossession` and
  `ElGamalSecretKey.possessionStatement()`.

### N6 — Solvency entries carry deliveries (demo C)

- **Datum.** `Attestation([Entry(idHash: B32, u, v, delivery: B89)] × N, auditorDelivery: B89)`.
  - Each entry's `delivery` goes to the customer's viewing key. The customer gives that key to
    the exchange when opening an account; it encrypts to the customer, so it needs no possession
    proof.
  - `auditorDelivery` delivers the **aggregate** opening `(L, Σ r_i mod l)` of `Σ C_i` to the
    auditor's possession-verified viewing key. It needs `L < 2^64`, which the exchange checks
    before attesting.
- **Validator.** `SolvencyVault` additionally checks each delivery's length (89) and the datum's
  shape. The circuit, its verification key and its public inputs are unchanged, because
  deliveries are not public inputs.
- **Customer check.**
  1. The customer scans the period's live entries and opens the delivery of the entry under its
     `idHash`.
  2. It compares the opened balance with its own account record.
  3. The `idHash` "exactly once" rule (ADR-0006) is unchanged. The per-period salt still reaches
     the customer off-chain, with its account statement.

  An entry under its `idHash` that does not open is reported. The opening now comes from the
  chain, not from the exchange's say-so.
- **Auditor check.** The auditor computes `Σ C_i` from the chain and opens `auditorDelivery`
  against it, which gives `L` with no off-chain hand-over.
- **What the auditor learns.** One aggregate per **attestation**, not per period. With several
  attestations in a period the auditor learns each one's subtotal, and an attestation holding one
  real customer plus zero-padding would reveal that customer's balance. The demo therefore makes
  exactly one attestation per period, and the exchange must not split a period into sparse
  attestations.
- **The auditor's key.** The exchange admits the auditor's registry entry (N1, N5) and encrypts
  `auditorDelivery` to its `viewKey`. The vault does not read the registry. `L < 2^64` follows from
  `Σ b_i ≤ R < 2^64`.

### N7 — Key possession circuit (`KeyPossessionProof`)

This is `elgamal-jubjub-v1` §9.2 `R_dleq` (`ZkElGamal.assertDiscreteLogEquality`) with one
application input in front, as spec §8 allows ("application circuits may embed these groups among
their own inputs"):
- **Public, in order:** `ctx`, then `DleqStatement.publicInputs()` (`X.u, X.v, P.u, P.v, D.u,
  D.v`).
- `ctx(type) = OS2IP(blake2b_256(ASCII("zeroj.usecases.key-possession.v1") ‖ type ‖ registryPolicy
  ‖ auditor)[0..30])`, 31 bytes, so `ctx < 2^248 < p`. `type` is one byte: `0x01` for the
  `elgamal-jubjub-v1` key, `0x02` for the viewing key. `registryPolicy` is 28 bytes and `auditor`
  28 bytes.
- The circuit constrains `ctx² = sq` with `sq` a witness, so `ctx` enters a constraint and the
  proof is bound to it. A public input in no constraint would not affect Groth16 verification,
  and ZeroJ's native setup refuses unbound public wires.
- It is used for the possession statement `(X = G, P = D = key)` of both key types. The key
  types stay distinct (ADR-0055 I6): the statement's form is shared, but `type` makes a proof for
  one type useless for the other.
- A `DleqStatementVerifier` built on it verifies the proof over `[ctx] ‖ statement.publicInputs()`,
  with `ctx` computed by the verifier, never taken from the prover.

### N8 — Payroll demo

- The employer is the payroll `NoteLedger` issuer, and the tax authority is its registry auditor.
- **Employer's pay run:** one `ProvedIssue` transaction for one or two employees.
- **Employees:** read their payslips from the chain by scanning, and transfer or cash out ("redeem
  at the employer", which mints a receipt as in ADR-0006) through N3.
- **Tax authority:** reads every salary from chain data, every one proof-enforced, with totals per
  employee.
- **Cheats:**
  - under-report a salary to the tax authority: no proof exists;
  - a garbage payslip delivery: the employee sees an unopenable note, and the tax authority still
    reads the amount;
  - limbs encrypted to a retired key: refused, because only the current registry entry exists.

## Revision history

- **r1** (2026-10-10): initial proposal.
- **r2** (2026-10-10; design review by an adversarial Claude reviewer, F1–F17, and Codex,
  C1–C10; no P0):
  - F1: a registered ElGamal key could be the identity or off-curve, freezing every note → its
    possession proof is verified on-chain at Init and Rotate (N1).
  - F7, C7: possession proofs were replayable across registrants, registries and key types →
    `KeyPossessionProof` takes a bound context `ctx(type)` (N7).
  - F2: proved issuance did not pin `PK`'s source and lacked distinct handles and `ownInputs = 0`
    → N4 lists every rule.
  - C6: decryptability was treated as ownership → the wallet also requires `owner` = its key
    (N5, N-I7).
  - F6: the auditor ignored generations → notes record `generation`, checked against the
    registry; the auditor keeps every generation's keys (N2, N5).
  - F8: delegated admission obligations stated; issuer-trusted amounts are "issuer-claimed" (N5).
  - F5: the solvency auditor learns per-attestation subtotals → stated; one attestation per
    period in the demo (N6).
  - F17: notes hold exactly lovelace plus the token; min-ADA computed; per-path compressed
    inputs listed; the source-scan pattern scoped.
  - F10 (script size) stays a measurement at M3a.

## Invariants

| ID | Invariant | Enforced by |
|---|---|---|
| N-I1 | Every note output of every ledger transaction is at the exact ledger address, holding exactly lovelace and one note token, with the current registry generation, 8 canonical audit coordinates, and exactly 2 deliveries of 89 bytes. | `NoteLedger` (all paths) |
| N-I2 | No ledger transaction has an output under the ledger's payment credential with a stake credential. | `NoteLedger` |
| N-I3 | `PK_a` comes from exactly one registry reference input. The registry token is a singleton, and rotation increments the generation under both auditors' signatures. Every registered ElGamal key has an on-chain-verified possession proof bound to its registrant, registry and key type, so it is a valid subgroup key. | `NoteLedger`, `AuditorRegistry` |
| N-I4 | Transfer and redeem: the limbs of every created note encrypt, under `PK_a`, the amount that opens its commitment. Every public input comes from the ledger. Handles are pairwise distinct. | Circuit + `NoteLedger` |
| N-I5 | Payroll: no `SAL` is minted without a proof, over the registry's key and the datums' limbs, binding every issued note's limbs to its amount, with distinct handles. Points: no `PTS` is minted without the issuer's signature. | Circuit + `NoteLedger` |
| N-I6 | Senders encrypt limbs only with `encryptWithOpening`, and deliver only to keys of an admitted registry entry (N5). | Host code; a test checks that main code has no `scalarMul` call |
| N-I7 | A wallet counts a note as its own only after the profile's acceptance (spec §5 steps 1–7), N2's authentication **and** `owner` = its key hash. Owned notes that do not open are reported, not dropped. | `NoteScanner` + wallet |
| N-I8 | The auditor decrypts only authenticated notes, with the keys of the note's generation, and reports an amount as enforced only for proof-enforced notes. | Auditor view |
| N-I9 | Solvency entries and the attestation carry deliveries of the right length. Customers and the auditor recover from the chain. | `SolvencyVault` + host code |
| P1–P8, S1–S7 | ADR-0006's invariants, unchanged. | As in ADR-0006 |

## Alternatives considered

- **Possession proofs verified on-chain at registration.** Two Groth16 verifications would cost
  about 8e9 steps, and Q6 allows off-chain checking. Rejected for the demo; anyone can still
  verify the proofs, which are stored in the entry.
- **The issuer governs the registry.** The auditee would then control the auditor's key.
  Rejected: the auditor rotates its own entry, and the operator only pins which registry a
  ledger uses.
- **Notes identified by payment credential under any stake credential.** Wallets would have to
  scan an open set of addresses, and stake-variant outputs could carry unchecked notes (ADR-0055
  note 12). Rejected in favour of N2's exact-address rule.
- **The hash-compressed layout everywhere.** It costs about 3.5×10^5 constraints and tens of
  seconds per proof. It is used only where the direct layout fails the gate (N3).
- **Deliveries in transaction metadata.** Invisible to Plutus (ADR-0055 D8).
- **A separate payroll validator.** It would duplicate the ledger. A mode parameter on
  `NoteLedger` shows Q9 (a) against Q9 (b) side by side instead.

## Milestones

| ID | Scope |
|---|---|
| M0 | ZeroJ snapshot `0.1.0-pre13-1e78c6f-SNAPSHOT`; the existing tests stay green. |
| M1 | This ADR and ADR-0008. |
| M2 | `AuditorRegistry`, `KeyPossessionProof`, and the key, wallet and auditor helpers. |
| M3a | `NoteLedger`, the version 2 circuits, the points migration, and the layout gate. |
| M3b | The points service and UI. |
| M4 | Payroll: issuance circuits, proved issuance, service and UI. |
| M5 | Solvency deliveries: vault, service and UI. |
| M6 | The auction (ADR-0008). |
| M7 | README, `demo.sh`, final reviews. |

## Verification

- **Circuit invalid witnesses** (ADR-0055 I12), mirroring ZeroJ's reference test:
  - a wrong limb, or a limb at `2^32`;
  - limbs swapped, or swapped between notes;
  - another key;
  - limbs of another amount;
  - for proved issuance, an issued note with a wrong audit ciphertext.
- **Plutus VM mutations** (Julc testkit):
  - ADR-0006's P1–P8;
  - the audit data absent, wrong (either output), swapped between outputs, limbs swapped, not
    canonical, or 7 entries;
  - a delivery missing, short (88 bytes), or extra (3 deliveries);
  - the registry missing, another key, a second entry, quantity 2, an extra field, the wrong
    token;
  - reused handles (within a note and across notes);
  - **an extra output at a stake-variant script address** (criterion (a));
  - a tampered proof;
  - for the registry: a second mint, a mint without the seed, rotation without either signature,
    a generation not incremented, an extra token, a stake address, the wrong shape,
    `pkEnc = viewKey`, a `pkProof` for another key, another registrant, another registry or the
    other key type, and an identity or off-curve key;
  - a created note of a stale generation, an extra asset in a note, and for proved issuance:
    `PK` not from the registry, datum limbs other than the proved ones, reused handles, `n`
    different from the number of note outputs, and a ledger input spent.
- **Host:**
  - registry admission refuses a wrong possession proof, mismatched coordinates, a swapped proof,
    and a proof copied from another registrant or registry;
  - a source-scan test shows that main code calls no variable-time `JubjubPoint.scalarMul(`
    (the blinded `scalarMulSecretBlindedBestEffort` is not matched);
  - a note readable by the wallet but owned by someone else is not counted as the wallet's;
  - the owner, the auditor and the sender recover the same amount (a differential check).
- **DevKit end to end** (`ZEROJ_YACI_E2E=true`):
  - points: issue, transfer and redeem, with recovery by the owner and the auditor; a garbage
    delivery is unopenable; a key rotation, after which stale limbs are refused;
  - payroll: a pay run, payslips, the tax view, and the under-report refused;
  - solvency: customers and the auditor recover from the chain.
- **UI:** each tab is driven through the Playwright MCP, covering the honest flows and every
  cheat.

## Measurements

To be filled in at M3a and M4: constraints, prover time, and the Julc VM cost of the complete
transaction as a percentage of `maxTxExecutionUnits` (10e9 steps, 16.5e6 memory), for transfer,
redeem, and proved issuance with n = 1 and n = 2.

## Production gates (not met by this demo)

- ADR-0055's gates: external review of D2, D5–D7 and A1–A3, a scanning deployment model under
  ADR-0039, and the registry design.
- Scanning inside the user's own wallet process, not on a server (ADR-0055 D9).
- Keys from an MPC ceremony, not the single-party development setup.
- Registry governance beyond "the auditor signs": key escrow, recovery and revocation policy.
