# ADR-0009: Privacy and binding hardening of the original demos

- **Status:** Proposed. Design reviewed by two independent reviewers with no open P0–P2 (see "Revision history"); acceptance is the maintainer's. Implementation is on `fix/demo-privacy-hardening`, stacked on
  `feat/confidential-notes-m3`.
- **Date:** 2026-10-11 (r6, 2026-10-11: fifth review round; see "Revision history")
- **Related:**
  - [ADR-0005](0005-private-ballot-homomorphic-tally.md), which fixed the same class of flaw in
    private voting ([issue #7](https://github.com/bloxbean/zeroj-usecases/issues/7)).
  - [ADR-0006](0006-pedersen-commitment-demos.md) demo B (committed credential), whose
    holder-bound issuance record D1 adapts.
  - ZeroJ `pedersen-jubjub-v1` and `pedersen-jubjub-vector-v1` (ADR-0051), `docs/specs/` at
    ZeroJ `6a89f8a` (the `0.1.0-pre13-6a89f8a-SNAPSHOT` these demos build against).
- **Risk:** R2. Application circuits, validators and flows over accepted ZeroJ profiles. No
  primitive is implemented and no ZeroJ code changes.

## Context

Private voting published `Poseidon(vote, nullifier)`. Its nullifier is public and a vote is 0 or
1, so anyone could hash both values and read every vote. Every other demo was reviewed against
the same question: can a value published as a hash, commitment or ciphertext be recovered by
guessing, or does a deterministic value link a user? The review also covered on-chain binding.
Every item below was checked against the code at `11a6238`.

| ID | Demo | Finding | Sev |
|---|---|---|---|
| F1 | digital-product-passport | `auditorHash = Poseidon(auditorSecret, Poseidon(productId, m))`. `auditorSecret` is a **prover witness**, so every manufacturer that proves must hold it, and the demo hard-codes it (`777777`, `ComplianceService.java:22`). The carbon and recycled measurements are 16-bit and the mint datum publishes `[productId, threshold, auditorHash, isCompliant]` (`OnChainDppService.java:108`), so trying all 65,536 values recovers `m`. The country (≈250 codes) falls the same way. The minting policy pins neither the threshold nor `auditorHash`, so a manufacturer can commit to any value or choose its own threshold. The token name is not tied to `productId`, and the same name can be minted again in later transactions. | P1 |
| F2 | nft-ownership | The list insert checks only that the ZK policy minted something (`NullifierListLib.java:139`). The new list key is not bound to the proved nullifier. The root mint is not one-shot (`NullifierListLib.java:55-69`). A list spend only needs some list-policy mint in the transaction (`NullifierListValidator.java:72-77`), so nodes can be removed and their nullifiers re-inserted. The ZK policy has no uniqueness check of its own, so one proof gates any number of accesses. `snapshotRoot` and `contextId` come from the redeemer. The nullifier `Poseidon(tokenName, contextId)` has public inputs only, so it reveals which NFT (and so which wallet) was used, contrary to the README. | P1 |
| F3 | personhood-airdrop | The issuer chooses `personhoodId` and the nullifier is `Poseidon(pid, epoch)`, so the issuer can link every claim to a person in every epoch. Demo ids are a counter and `name.hashCode()`. The policy never checks that the payout goes to `recipient`. Issuance silently overwrites a person's previous credential (`PersonhoodIssuerService.java:69-79`). | P1 |
| F4 | proof-of-reserves | Leaves are `Poseidon(bytes(username), balance)` with no salt, so anyone holding a neighbour's leaf (a sibling on a path, or a published tree) can try balances. The custodian answers inclusion itself (`ReservesController.java:151-196`) rather than letting the customer check. The attestation datum is created by a plain lock: the proof is checked only when that UTxO is spent (`OnChainReserveService.java:81-100`), so a datum alone proves nothing. | P2 |
| F5 | private-voting | Test voter keys are `10000 + i`, so anyone can match each nullifier to a voter, and vote for voters who have not voted. | P2 |
| F6 | reusable-kyc, account-ownership | Both vouchers lock 10 ADA and enforce only "some output pays the recipient ≥ 2 ADA" (`BbsKycClaimValidator.java:86-91`, `OwnershipProofValidator.java:77`). Anyone who sees a claim of an unspent voucher can resubmit its redeemer and keep the remainder, less fees. One output can also satisfy two vouchers in one transaction. | P2 |
| F7 | pedersen-commitments (solvency) | Re-attesting after a release reuses every salt and blinding, and entries keep book order, so customers link across periods. | P3 |
| F8 | payroll, points | Redeeming a whole note publishes a price equal to its amount; a partial redemption bounds it. | P2 (docs) |
| F9 | auction, account-ownership, identity-kyc, selective-disclosure | Documentation precision only:<br>- losing bids are bounded to `[reserve, price]` (earlier bids strictly below);<br>- "the path stays private" holds against observers, not against an xpub holder;<br>- the identity and selective-disclosure gates are stateless, so a proof copied from chain can open any other UTxO at the same gate. The pages say so. | P3 |
| F10 | all demos | The demo HTTP APIs expose what only a user should see: unauthenticated voting by label, an NFT secret defaulting to `42`, airdrop history pairing names with nullifiers, DPP measurements, reserves balances and solvency identities. Compose publishes every port on all interfaces. | P2 |
| F11 | identity-kyc, selective-disclosure, personhood-airdrop | Each issuer's EdDSA-Jubjub signing key is derived from a seed published in the source (`IssuerService.java:47`, `RichCredentialIssuerService.java:49`, `PersonhoodIssuerService.java:35`). Anyone can sign credentials that the deployed validators accept. | P1 |

Only F1 is a case where the new primitives give a materially better design. The others are
fixed by salting, holder-chosen secrets, one-shot state and on-chain binding.

## Threat model

Common to all demos:
- a **chain observer** reads every datum, token name, redeemer and public input;
- a **mempool observer** can copy any pending transaction's redeemer and submit its own
  transaction first.

**Privacy claims in this ADR are against these two.** The demo server holds every user's keys
for convenience. Its API is the operator's view (D10), and the ADR doesn't claim privacy against
it.

| Demo | Parties and what they may try | Trusted for |
|---|---|---|
| DPP | **Another manufacturer:** replays a proof, or reuses a record for its own or another product. **The manufacturer:** mints twice, or proves against a value it chose. **Observer:** recovers measurements. | **Auditor:** measures honestly, keeps measurements confidential, and co-signs at most one passport per product. |
| NFT gate | **Holder:** uses one NFT twice, re-inserts a nullifier, or registers one token under two keys. **Observer:** links the nullifier to a token. **Mempool observer:** spends a holder's proof first. | **Indexer:** builds the event's snapshot with one leaf per token, from authenticated holders. |
| Airdrop | **Person:** claims twice per epoch, or obtains two credentials. **Issuer:** links claims to persons. **Observer:** redirects a payout. | **Issuer:** one credential per human, checked out of band. **Faucet:** pays only receipts it has checked. |
| Reserves | **Customer:** learns another customer's balance. **Anyone:** fakes or replays an attestation. | **Custodian:** reports balances honestly; the proof only checks the sum. |
| Vouchers (KYC, ownership) | **Mempool observer:** takes the remainder, or satisfies two vouchers with one output. | **Funder:** sets the voucher's terms. |
| Solvency | **Observer:** links customers across periods. | As ADR-0006 and ADR-0007. |

## Decision

### D1: Product passports are proved against auditor-issued Pedersen commitments (F1)

**Model.** The manufacturer is the prover and is not trusted for its measurements. The auditor
measures, commits and co-signs. The passport is a **public record, not a tradeable asset**. It
stays at its own script address with an immutable datum carrying every attested commitment, so
any claim can later be re-proved against another threshold, or opened to a regulator, without
asking the auditor again.

1. **Commitment.**
   - The auditor chooses a fresh 252-bit blinding `r` (`PedersenCommitment.randomBlinding` over
     `SecureRandom`).
   - It computes a `pedersen-jubjub-vector-v1` commitment `C = (u, v)` under the claim's schema.
   - It gives `(m, r)` to the manufacturer with its report. Hiding: `pedersen-jubjub-v1` §3.

2. **Passport transaction** (one transaction, no separate record UTxO).
   - The manufacturer builds it, and the auditor co-signs it after checking every commitment and
     `productId` against its report.
   - `DppPassport` is a Julc multi-validator. Its hash is both the passport policy and the
     passport address. Its parameters are `manufacturerPkh`, `auditorPkh`, the gated claim with
     its `σ` and `threshold`, and the VK.
   - It mints exactly one token, named `productId`, into an output **at its own script address
     (payment credential, no stake credential)** with inline datum
     `Passport(productId: B, manufacturerPkh: B28, claims: List<Claim(claim: I, σ: B32, u: I, v: I)>)`.
     `claims` lists every claim the auditor attests, at most 4.

   **Mint checks:**
   - **(a)** both signatures;
   - **(b)** the mint map under this policy is exactly `{productId: 1}`, and `productId` is 1–32
     bytes;
   - **(c)** exactly one output holds the token, it is at the passport address, and its inline
     datum has the exact shape, with:
     - `manufacturerPkh` equal to the parameter;
     - for every claim entry: canonical `u, v` and a 32-byte `σ`;
     - distinct claims;
     - the gated claim present with the parameter `σ`;
   - **(d)** the Groth16 proof verifies against `[σ, u, v, threshold]`, taken from the gated
     claim's entry. The redeemer carries only the proof.

   **Spend checks.** The only spend allowed is `Revoke`, which needs:
   - the auditor's signature;
   - a burn of exactly that passport's token, `{productId: −1}`.

   No transfer or datum change is ever possible, so a passport's datum is the one the mint
   transaction checked. The auditor can revoke without anyone else's cooperation. Readers
   accept only a passport token found at the passport address.

   **Uniqueness.** At most one passport per product is the auditor's commitment, because it
   co-signs once. A second token with the same name under the same policy is publicly visible.
   An on-chain "minted once" registry is an alternative (see Alternatives). Because a passport
   is minted together with its commitment, no record ever exists for a product that failed.

3. **Schemas** (`pedersen-jubjub-vector-v1`; labels and widths are normative here):

   | Claim | Schema id | Entries |
   |---|---|---|
   | carbon (≤) | `zeroj.demo.dpp.carbon`, v1 | `carbon_kg`/16 |
   | recycled content (≥) | `zeroj.demo.dpp.recycled`, v1 | `recycled_pct`/16 |
   | origin | `zeroj.demo.dpp.origin`, v1 | `country`/16 |
   | inspections | `zeroj.demo.dpp.inspections`, v1 | `inspector_0`/8, `time_0`/32, `inspector_1`/8, `time_1`/32, `inspector_2`/8, `time_2`/32 |

   The auditor commits only passed inspections, so there is no `passed` entry.

4. **Circuits** (annotation DSL). They replace `ComplianceThresholdCircuit`,
   `CountryMembershipCircuit` and `InspectionChainCircuit`. Each one:
   - binds its schema (`ZkPedersenVector.bindSchema`);
   - opens `C` in-circuit with the witness `(m…, r)`, where `commit` range-constrains every
     entry to its width;
   - proves its rule.

   | Circuit | Public, in order | Rule |
   |---|---|---|
   | `CarbonClaimProof` | `σ, u, v, threshold` | `carbon_kg ≤ threshold` |
   | `RecycledClaimProof` | `σ, u, v, threshold` | `recycled_pct ≥ threshold` |
   | `OriginClaimProof` | `σ, u, v, countryRoot` | `country` is a leaf of `countryRoot` |
   | `InspectionClaimProof` | `σ, u, v, inspectorRoot` | each `inspector_i` is a leaf of `inspectorRoot`, and `time_0 < time_1 < time_2` |

   - **Tree padding.** The approved-set trees pad with the sentinel `2^k` (k = the entry width),
     which no committed value can equal. Today they pad with 0, which would make 0 a member of
     every set.
   - **Repeats.** An inspector may appear in more than one checkpoint.
   - **No secret.** There is no `auditorSecret`, and no `isCompliant` output, because every rule
     is an assertion.
   - **Placement.** Only carbon is gated on-chain in the demo. Origin, recycled content and
     inspections are proved off-chain, against the commitments in the passport datum.
     `pedersen-jubjub-vector-v1` §6 requires an authenticated issuance record for a commitment
     accepted from someone else, and here that record is the auditor-co-signed passport. A
     verifier never accepts a commitment from the manufacturer's API.
   - **Verifier rules.**
     - An off-chain verifier takes each claim's expected `σ` from its own schema registry
       (vector spec §5), compares it with the datum, and never takes `σ` from the datum.
     - A reader refuses a `productId` for which the policy's mint history shows more than one
       passport, the same rule as D4's duplicate-period check.

5. **API and registry** (D10). The MPF registry stores `(productId, passport outref)`, not
   values. `/api/dpp/status` and `/products` return no measurements. The manufacturer's own
   values appear only in a panel labelled "manufacturer (private)".

6. **Deferred: delivering openings to a regulator.** `confidential-note-jubjub-v1` carries a
   scalar commitment's opening and recomputes a scalar commitment. A vector commitment uses
   different bases (vector spec §2), so delivering vector openings needs its own reviewed
   design.

The demo's unused `DppComplianceValidator` is removed.

### D2: NFT gate, with a sound nullifier list and a hidden token (F2)

1. **The list is a single list, and its nodes stay in it.**
   - The root is one-shot: the list policy is parameterised by a seed UTxO, which `InitList`
     must spend.
   - `NullifierListValidator` lets an input be spent only under `InsertNode`, as that
     transaction's anchor. The transaction may spend exactly one input at the list address.
   - The mint map under the list policy is exactly one entry, with quantity 1. Nothing is
     burned, so nodes are never removed.
   - Every minted list token lands in the output that carries its node datum, at the list
     address:
     - the root token, in `InitList`;
     - the new node's token, in an insert.
   - "Only as the anchor" is enforced by the anchor lookup (`findInputWithToken`) together with
     the single-list-input rule. The seed makes every later list mint an insert.
2. **The new key is the proved nullifier.** In the insert transaction:
   - the mint map under `zkPolicyId` is exactly `{n: 1}`, with `length(n) == 32`;
   - the new key equals `slice(1, 31, n)`, the encoding the list already uses for its 31-byte
     keys;
   - the ZK token sits in the new node's output, which later anchor spends already require.

   Values `≥ r` are already refused by the verifier's field check. Two nullifiers that share
   their low 31 bytes collide, and the second insert fails closed.
3. **The event is a script parameter.** `ZkProofMintingPolicy` takes `snapshotRoot` and
   `contextId` as parameters, so there is one policy instance per event, as voting does. The
   redeemer carries only the proof and the nullifier.
4. **The nullifier hides the token.** It becomes
   `Poseidon(Poseidon(secretKey, tokenName), contextId)` (circuit version 2). Holder secrets are
   252-bit values from `SecureRandom`, generated by the app. The API refuses shorter keys, and
   the UI's default of `42` goes.
5. **One use per NFT is now the indexer's job.** The version 1 circuit enforced it, because its
   nullifier depended only on the token. In version 2 it holds because the snapshot has one leaf
   per token. Registration:
   - refuses a second leaf for a token already in the snapshot;
   - requires a CIP-8 signature over `(contextId, tokenName, leaf)` from the payment key of the
     address
     that holds the token on-chain. The demo server signs with its custodial wallet (D10);
   - freezes when the snapshot is built.
6. **Deferred: front-running.** A mempool observer can submit a holder's proof first and spend
   its nullifier, and the access goes to that transaction. The fix would add a fresh one-time
   beneficiary key hash as a public input, with the gate's output paid to it. It is deferred to
   keep circuit version 2 minimal, and stated as a limitation.

### D3: Personhood airdrop, with the person choosing the identifier (F3)

1. The holder samples `personhoodId` (252 bits, `SecureRandom`) and sends only
   `m = Poseidon(pid, 0)`. The circuit is unchanged: it already proves knowledge of a `pid`
   whose `Poseidon(pid, 0)` the issuer signed. The issuer never learns `pid`, so it can't
   compute `Poseidon(pid, epoch)`.
2. **One credential per human.** The issuer keeps a durable record of each person it has issued
   to, and refuses a second issuance, so a lost credential can't be re-issued. Without this
   rule, holder-chosen identifiers would let a person obtain two credentials and claim twice.
   The rule replaces the identifier the issuer used to assign.
3. **The epoch is a domain tag.** It is
   `Poseidon2(Poseidon2(tag("zeroj.airdrop.epoch.v1"), deploymentId), n)`, fixed as
   `policyEpoch`, so two airdrops never share a nullifier. Here:
   - `Poseidon2` is ZeroJ's `PoseidonHash` over `PoseidonParamsBLS12_381T3`;
   - `tag(s)` is the integer of `blake2b_256(UTF-8(s))` with the top byte cleared;
   - `deploymentId` is the integer of `blake2b_256(txId ‖ I2OSP2(index))` of the faucet's seed
     `TxOutRef`, with the top byte cleared. This covers the whole outref, so sibling outputs of
     one transaction give different deployments;
   - `n` is the round number, `1 ≤ n < 2^32`.

   The script refuses `policyEpoch = 0` and any epoch `≥ r`.
4. **The payout goes to the proved recipient.** `FaucetMintingPolicy` requires an output whose
   payment credential is a key hash `h`, with `|h| = 28` and `integer(h) = recipient`, carrying
   at least `payout` lovelace (a new parameter). The controller accepts only key-credential
   addresses, with no fallback.
5. **The faucet pays each nullifier once.**
   - The faucet records paid nullifiers durably and atomically (the same storage rules as D11),
     before it signs a payout.
   - It refuses a nullifier that is already recorded, or already present as a receipt on-chain.
   - Its admin key is private (D11), so the payout can't be signed around the service.
6. `/status` and the claim history return neither names next to nullifiers nor identifier bits.
7. The issuer's signing key is random (D11).

### D4: Proof of reserves, with salted leaves and attestations proved at creation (F4)

1. **Salted leaves.** Each account gets a 252-bit salt per snapshot, and its leaf becomes
   `Poseidon(Poseidon(idTag, salt), balance)`.
   - `idTag = fold(Poseidon2, tag("zeroj.reserves.id.v1"), [len, c_0, …, c_k])`, where:
     - `len` is the UTF-8 byte length;
     - `c_i` are the UTF-8 bytes in 31-byte big-endian chunks, with the last chunk right-padded
       with zeros, so no id reduces mod p;
     - `fold(f, a, [x, …]) = f(…f(f(a, x_0), x_1)…)`.

     Test vectors cover the empty id, 31 and 32 bytes, and leading zero bytes.
   - The solvency circuit is **unchanged**: its `accountIds` witness is now the salted id, so
     the existing keys stay valid.
2. **An attestation is a minted, locked token.** `ReserveAttestation` is a Julc multi-validator,
   parameterised by the custodian's key hash and the VK.
   - **Mint.** It mints exactly `{I2OSP8(period): 1}` into an output at its own script address,
     with inline datum `Attestation(period, liabilitiesRoot, totalLiabilities, totalReserves)`,
     and needs the custodian's signature. The proof verifies against
     `[totalReserves, liabilitiesRoot, totalLiabilities, 1]`, taken from that datum, so only a
     solvent statement attests.
   - **Spend.** The only spend is a custodian-signed burn of that token after the period ends.
     The datum can't change while the token exists.
   - **Timing.**
     - The parameters `genesisMs` and `periodMs` (POSIX ms, `periodMs > 0`) map period `p` to
       `[genesisMs + p·periodMs, genesisMs + (p+1)·periodMs)`.
     - A burn needs a finite validity lower bound ≥ the period's end. An unbounded interval is
       refused, as in `SealedBidAuction`.
   - **Uniqueness.** One attestation per period is the custodian's word, but it is visible. The
     customer UI refuses a period whose token was minted more than once (from the policy's mint
     history in the chain indexer). Without this check, a custodian could split liabilities
     across several trees against the same reserves.
   - **Reserves.** `totalReserves` is declared by the custodian. The demo doesn't check it
     against on-chain holdings, and the page says so.

   A datum without the token proves nothing. `ReserveAttestationValidator`'s lock-then-verify
   flow is replaced.
3. **Customers check against the chain.**
   - `/verify/{id}` returns the customer's salt, balance, leaf index and path (the demo's
     custodian view; see D10).
   - The UI recomputes the root in the browser. It finds the attestation token for the current
     period under the known policy id through the chain indexer (Yaci Store), not the
     custodian's API, and compares the two.
   - The customer also compares the balance with their own records.

### D5: Voting keys from SecureRandom (F5)

`AccountSetupService` generates each test voter's secret with `SecureRandom` and persists it
under the demo data directory, so restarts keep the voters. Voting by label remains a
demo-operator action (D10).

### D6: Vouchers pay exactly what they owe, one voucher per transaction (F6)

This applies to both `BbsKycClaimValidator` and `OwnershipProofValidator`.
- The datum gains `funderPkh: B28` and `maxFee: I`.
- A spend requires the following:
  - **tagged payments.** Only outputs whose inline datum is exactly the spent voucher's
    `TxOutRef` count as its payments. A tag is unique per voucher, so no output can satisfy two
    vouchers whose validators enforce tags. That covers both voucher validators here, whatever
    the stake credential. This replaces counting inputs, which compared full addresses and could
    be dodged.

    The guarantee does not extend to a script that ignores tags, such as the old
    `OwnershipProofValidator`, which counts any paying output. Both voucher validators are
    replaced in the same change. Composing a voucher spend with a tag-unaware script is
    documented as unsafe;
  - the voucher's value is ADA-only;
  - tagged outputs to the recipient's key credential sum to at least `refundAmount`;
  - tagged outputs to the funder's key credential sum to at least
    `voucherLovelace − refundAmount − maxFee`;
  - if the funder and the recipient are the same key, the combined sum covers both
    obligations;
  - when the remainder is 0, no funder output is required.
- **Creation** (wallet side) refuses a remainder that is positive but below min-UTxO, which
  would make the voucher unspendable.
- **Fee slack.** Whoever submits the spend can keep `maxFee` minus the actual fee, so the funder
  should set `maxFee` close to the expected fee.
- The validators also check `refundAmount ≥ 0`, `maxFee ≥ 0`, and that
  `refundAmount + maxFee ≤ voucherLovelace`.
- **Limitation.** One KYC'd credential can satisfy many vouchers. BBS per-verifier pseudonyms
  are out of scope.

### D7: Solvency re-attestation is fresh (F7)

Every `attest()` regenerates salts and blindings, and shuffles the entry order independently
with `SecureRandom`. The proof's witness order and the sealed deliveries follow the shuffled
order. The circuit and its keys don't change.

### D8: Documentation (F8, F9)

- **Redemptions.** Redeeming a whole note publishes its amount, and the payroll and points pages
  say so.
- **Auction.** Losing bids are bounded to `[reserve, price]` (strictly below the price before
  the winner), and the auction page gains the demo custody note.
- **Account ownership.** "Path private" is restated as "private from observers", claimants are
  advised to use a fresh recipient, and the stale javadoc is fixed.
- **Identity and selective-disclosure gates.** These are classified as stateless, replayable
  demo gates: a real deployment binds the proof to the output it spends. Unsalted, non-holder-
  bound credentials are stated as limitations.

### D9: Withdrawn (merged into D6).

### D10: Demo APIs are operator views (F10)

Every demo README and page states the following:
- the server holds users' keys, and its API is the operator's view;
- privacy holds against chain and mempool observers, not against the demo server.

Compose publishes every demo port on `127.0.0.1` only. Authenticated operator access is out of
scope for single-user demos; the README states it as the first production change.

The concrete leaks are removed where they serve no demo purpose:
- the airdrop history pairs names with nullifiers;
- the NFT secret defaults to `42`;
- DPP measurements appear in public status responses;
- solvency identities appear on public endpoints.

### D11: Issuer keys are random and persisted (F11)

The identity-KYC, selective-disclosure and airdrop issuers generate their EdDSA-Jubjub keys with
`SecureRandom` on first start, and the published seeds are deleted. Each validator keeps pinning
the issuer's public key as a deploy parameter, so a fresh install gets a new key and new script
hashes.

**Key lifecycle.**
- **Storage.** The key is written atomically (temp file and rename, owner-only permissions) in
  the demo data directory, next to the demo's deployment state.
- **Restart.** A restart loads it.
- **Reset.** `./demo.sh <demo> --clean-cache` removes the key and the deployment state together,
  which amounts to a fresh deployment.
- **Fail closed.** If deployment state exists but the key file is missing, unreadable or doesn't
  match the deployed parameter, the demo stops with an error. It never silently creates a new
  key.

**Tests.**
- A credential signed with the old published seed is refused.
- The key survives a restart.
- A deleted or corrupted key with existing state fails closed.

**Scope.** This covers the three credential issuers and the signing roles that D1 and D4
introduce or rely on:
- the DPP manufacturer and auditor;
- the reserves custodian;
- the solvency exchange, whose signature makes an attestation the exchange's;
- the airdrop faucet admin, whose signature releases payouts;
- the NFT holder custody wallet, which holds the demo NFTs and signs D2's CIP-8
  registrations.

Each of these is a random wallet key with the same storage, reset and fail-closed lifecycle. It
is funded through DevKit's top-up, and its key hash is the validator parameter.

**Deliberately public roles.** The other roles keep wallets derived from DevKit's well-known
test mnemonic in `application.yml`:
- the voucher funders (KYC, account ownership);
- the NFT list operator;
- the vote-list operator;
- the funding wallets.

On a devnet, anyone can sign as these roles. That is acceptable only because:
- their signatures gate no claim the demo makes about privacy or attestation;
- they are devnet-only.

The README lists them, and real deployments must replace them.

## Invariants

| ID | Invariant | Decisions | Test |
|---|---|---|---|
| I1 | Against chain and mempool observers, no published datum, token name, redeemer field or public input is a deterministic function of a small-domain secret alone. Each such value also absorbs a ≥ 252-bit secret that the publisher keeps. | D1–D5, D7 | Per demo, an attacker routine given only chain data and the guessable domain recovers nothing. This is a regression check, not a proof of hiding; hiding rests on `pedersen-jubjub-v1` §3 and Poseidon. |
| I2 | A passport's threshold or root, schema, manufacturer and auditor are fixed by the script, never by the prover. | D1 | VM mutations |
| I3 | A passport for `p` exists only at the passport address, minted in a transaction the auditor signed, with a proof over the gated commitment in its own datum. Its mint map is exactly `{p: 1}`. Its datum never changes, and only the auditor can remove it. | D1 | VM mutations |
| I4 | One gate proof yields at most one list entry, whose key is the proved nullifier. Entries are never removed. With the indexer's one-leaf-per-token snapshot, each NFT is used at most once per event. | D2 | VM mutations, E2E |
| I5 | The gate's snapshot root and context are script parameters. | D2 | VM |
| I6 | The airdrop issuer never receives `pid` and issues one credential per person. A claim pays its proved key-hash recipient at least `payout`. | D3 | Unit, VM |
| I7 | A reserves attestation exists only as a locked token whose minting verified a solvent statement read from its own datum. A customer can check inclusion against it without the custodian's API, and refuses a period that has more than one attestation. | D4 | VM, E2E |
| I8 | Each voucher spend is paid only by outputs tagged with its own outref: the refund to the recipient, and the remainder, less at most `maxFee`, to the funder. The fee slack may go to any submitter. | D6 | VM |
| I9 | Each attestation draws fresh salts and blindings and an independently shuffled order. | D7 | Unit |
| I10 | No credential issuer key (identity KYC, selective disclosure, airdrop) and no role key that gates a payout or an attestation (DPP manufacturer and auditor, reserves custodian, solvency exchange, airdrop faucet admin, NFT custody wallet) is derivable from published data, and a demo never silently replaces one. The remaining devnet roles are listed as public. | D11 | Unit, VM |

## Alternatives considered

- **DPP with an auditor EdDSA signature over `Poseidon(productId, claim, m, salt)`,** verified
  in-circuit. Rejected: it hides `m` but leaves no public commitment to re-prove against, sum or
  open. It also costs more constraints than the vector commitment.
- **DPP with a separate on-chain attestation record** that the passport references. This was r1.
  Rejected: records need a lifecycle (spent, revoked, superseded), and a record without a
  passport hints that the product failed.
- **DPP uniqueness enforced on-chain** with a sorted "minted products" list, as in the nullifier
  list. Deferred: the auditor's co-signature already gates issuance in this model.
- **DPP with the auditor as the prover.** Rejected: the manufacturer, not the auditor, must be
  able to mint on its own schedule.
- **NFT nullifier `Poseidon(leaf, contextId)`.** Rejected: published snapshot leaves would let
  anyone recompute it.
- **NFT snapshot as a reference-input UTxO.** This was r1. Rejected: it needs an
  event-to-snapshot binding and a lifecycle. Script parameters per event are simpler and match
  voting.
- **On-chain uniqueness for airdrop receipts.** Deferred. The faucet's payout is admin-signed
  and checked off-chain, and this is stated.
- **Pedersen-committed reserves leaves.** Not needed: the hidden-liability solvency demo already
  covers a hidden total.

## Compatibility

- **New circuit versions and dev setups:** D1 (four claims) and D2 (`nft-ownership` v2).
- **New issuer keys:** D11, with new validator parameters.
- **Unchanged:** the D3 and D4 circuits; D4's keys stay valid.
- **New script hashes:** every changed script.
- **Migration.** Demo state doesn't survive the upgrade, so each changed demo starts fresh:
  - the DPP product database and MPF registry, with their minted references;
  - the reserves and NFT in-memory state;
  - the solvency book.

  The README says to clear the demo data directory or volume (`./demo.sh <demo> --clean-cache`).
- Committed `demo-cache` entries for changed circuits are regenerated.

## Milestones

| ID | Scope | Exit |
|---|---|---|
| M2 | D5, D6, D7, D11 | **Vouchers** (VM): the remainder kept by a third party; two vouchers (same or different validators, different stake parts) sharing outputs; untagged payouts; funder = recipient with only one obligation paid; a non-ADA voucher — all refused. Correct tagged payouts and a zero remainder are accepted. **Issuers:** a credential signed with the old published seed is refused by every validator. The key survives a restart, and a deleted or corrupted key with existing state fails closed. **Voting:** keys have 252-bit entropy and survive a restart. **Solvency:** two attestations differ in every `idHash` and `C`. Existing E2E green, including KYC with `-Dkyc.e2e=true`. |
| M3 | D3 | **VM:** payout to another key, a script-credential payout, a payout below `payout`, epoch 0 and an epoch ≥ r are refused. **Unit:** sibling seed outputs `(T, 0)` and `(T, 1)` give different deployment IDs. A second claim with the same nullifier is refused, also after a restart. **E2E:** a direct replay that spends another faucet-owned input without the admin's signature is refused by the ledger. A replay that re-mints a receipt with the claimant's own funds is possible (receipt uniqueness is deferred), but it takes no faucet payout. **Unit:** the issuer API never receives `pid`, and a second issuance for the same person is refused. E2E. |
| M4 | D4 | **VM:** an attestation token minted with a bad proof, with an insolvent statement (`isSolvent = 0`), with two tokens, with a wrong datum or outside the script address is refused; a spend without a burn, with a lower bound of `end − 1`, or with an unbounded validity interval is refused; an otherwise valid burn with a lower bound of exactly `end` is accepted. **UI:** the customer check refuses a period with two separately valid mints, and a burn followed by a re-mint. History is read across pages. Unavailable or incomplete history fails closed. **UI and unit:** the customer check passes for a correct path and fails for a tampered path, a fake attestation and a stale period. **Brute force:** guessing the neighbour's balance fails without the salt. E2E. |
| M5 | D2 | **VM:** a second root; spending a node outside an insert; two list inputs; a burn; an insert with a fresh key, with key ≠ the minted nullifier, with a 31-byte ZK name, with two ZK tokens, or with the ZK token or the list token outside the new node; a root token outside its datum output — all refused. **Circuit:** negatives for the new nullifier. **Unit:** a duplicate token registration, a short secret, and a registration signed with the public DevKit operator key are refused. E2E. |
| M6 | D1 | **Circuits:** over or under the threshold, a wrong blinding, a wrong schema digest, an unlisted country, value 0 against the padded tree, an unlisted inspector, equal or decreasing times — all refused. **VM:** no auditor signature, another manufacturer's policy replaying a proof, a datum for another product, a mint map with an extra entry or quantity 2, a token name ≠ productId, a wrong threshold, a non-canonical coordinate, a passport outside its address, a duplicate claim, any spend other than an auditor-signed burn (including a datum change and a transfer), and a Revoke without the auditor — all refused. An auditor-only Revoke is accepted. **Brute force:** regression test as in I1. Budget table. E2E and UI. |
| M7 | READMEs, DESIGN docs, PRESENTATION (+ PDF), demo.sh; full test and E2E runs; final reviews | No open P0–P2 from Codex or a Claude review |

## Verification

- `./gradlew -p <demo> test`, and `ZEROJ_YACI_E2E=true ./gradlew -p <demo> test` on Yaci
  DevKit. Reusable KYC also needs `-Dkyc.e2e=true`.
- Brute-force regression tests take only chain data (datums, token names, redeemers), as the
  attacker would, and must fail to recover the secret.
- Expected values in circuit tests come from the ZeroJ host API (`PedersenCommitment`,
  `PedersenVectorSchema`, `PoseidonHash`), not from the circuit under test.

## Limitations (stated, not prevented)

- **DPP.**
  - The auditor sees every measurement, could collude with a manufacturer, and alone ensures
    one passport per product.
  - A passport reveals which product has which claim, but not its value.
  - A very small approved set (one country) reveals the value.
- **NFT.**
  - The indexer decides the snapshot.
  - Using the gate shows that some snapshot holder acted.
  - A mempool observer can spend a holder's proof first (deferred fix in D2).
- **Airdrop.** The one-human check is out of band, and a lost credential can't be re-issued.
- **Reserves.**
  - The proof checks the sum, not that the balances are true.
  - `totalReserves` is declared by the custodian.
- **Vouchers.** One KYC'd credential can satisfy many vouchers.
- **Gates.** The identity and selective-disclosure gates are replayable.
- **All demos.** The demo servers hold users' keys, and their APIs are operator views (D10).
- **External review.** None of these demos is externally reviewed. The ZeroJ profiles they use
  keep their own offline-secret restrictions and audit gates (`pedersen-jubjub-v1` §9).

## Revision history

- **r1** (2026-10-11): initial.
- **r2** (2026-10-11), responding to the Codex review (F-R1–F-R15) and a Claude adversarial
  review (F-C1–F-C14) of r1 at `7ebc935`:
  - **D1 rebuilt.** Passports are minted in an auditor-co-signed transaction with an exact mint
    map, a datum bound to the manufacturer, and a revoke path. The separate record and its
    lifecycle are gone. Tree padding uses a sentinel. Delivery to a regulator is deferred.
    (F-R1, F-R2, F-R3, F-C5, F-C6, F-C7, F-C8, F-C9)
  - **D2.** The list root is one-shot, with exact spend and mint rules. Key encoding is
    `slice(1, 31, n)` with a 32-byte length check. The event is a script parameter. Secrets
    have ≥ 252 bits. The trust shift to the indexer and the front-running limitation are
    stated. (F-C1, F-C2, F-C3, F-C4, F-R4, F-R5, F-R6)
  - **D3.** One credential per person; the epoch is a domain tag; the recipient is a
    canonical key hash. (F-C10, F-R7)
  - **D4.** Attestations are tokens minted with the proof; the customer checks against an
    independent indexer; the id encoding is specified. (F-R8, F-C11)
  - **D6.** Extended to account ownership. One voucher per transaction, aggregate sums and
    ADA-only vouchers. (F-R9, F-R10, F-C12)
  - **D7.** "Independently shuffled", aligned with the proof and deliveries. (F-R12, F-C13)
  - **D8.** Precision fixes; replayable gates classified. (F-R10, F-R15)
  - **D10 (new).** Demo APIs are operator views, and the concrete leaks are removed. (F-R11)
  - **Elsewhere.** The threat model is per demo (F-C14, F-R14). Invariants are scoped to
    observers and given tests (F-R13). Migration is stated (F-R14). The hiding citation is
    corrected to §3 (F-C13).
- **r3** (2026-10-11), responding to round 2 of both reviews of r2:
  - **D1.** The passport becomes a locked public record at its own multi-validator address,
    with an immutable datum, an auditor-only Revoke burn, and every attested claim's commitment
    in the datum. (F-C15, F-R18, F-C16, F-R21, F-R2)
  - **D2.**
    - Token and datum colocation, and how the anchor rule is enforced. (F-R22, F-C1 note)
    - CIP-8 holder authentication at registration. (F-R6)
    - Front-running is reworded as deferred, with its fix. (F-C19)
  - **D3.** The epoch encoding is specified (F-C20, F-R23), and the issuer key is random (D11,
    F-R19).
  - **D4.**
    - The attestation is locked and proves `[reserves, root, liabilities, 1]` from its own
      datum, one per period, checked by the UI.
    - Declared reserves are stated.
    - The id encoding is specified, with vectors.

    (F-R17, F-C17, F-R23)
  - **D6.** Payments are tagged with the voucher's outref instead of counting inputs. This
    closes cross-validator and stake-credential double satisfaction. A zero remainder and
    min-UTxO cases are covered. (F-R16, F-C18, F-R9, F-R13)
  - **D10.** Ports bind to `127.0.0.1`. Authenticated operator access stays out of scope for
    single-user demos and is listed as the first production change; F-R20 is partly disputed,
    because the demos are custodial by design.
  - **D11 (new).** Random, persisted issuer keys, with an old-seed refusal test. (F-R19)
- **r4** (2026-10-11), responding to round 3 of both reviews of r3. The Claude review approved r3
  with P3s F-C21–F-C25; Codex raised F-R24–F-R29.
  - **D3.** `deploymentId` hashes the whole seed `TxOutRef`, and round numbers are bounded.
    (F-R24)
  - **D4.** Period timing is given by parameters, a burn needs a bounded validity interval,
    and the UI duplicate check is tested across pages and fails closed. (F-R25, F-C23, F-R29)
  - **D11.** The key lifecycle is defined (atomic storage, reset together with state, fail
    closed on loss or mismatch), and the scope is the three credential issuers, with the devnet
    wallets named as exceptions. I10 is narrowed to match. (F-R26, F-R28)
  - **D6.**
    - The tag guarantee is limited to tag-enforcing validators.
    - Composing with tag-unaware scripts is documented as unsafe.
    - The fee slack is stated in I8.

    (F-R27, F-C24)
  - **D1.** Per-entry `u, v, σ` checks; off-chain verifiers take `σ` from their own registry;
    readers refuse duplicate passports. (F-C21, F-C22)
  - **D2.** The CIP-8 payload includes `contextId`. (F-C25)
- **r5** (2026-10-11), responding to round 4 of the Codex review of r4:
  - **M4.** The boundary test is corrected: a lower bound of exactly the period end is
    accepted, `end − 1` and unbounded are refused. (F-R30)
  - **D11.** The DPP manufacturer and auditor, the reserves custodian and the solvency exchange
    get random persisted keys. The remaining DevKit-mnemonic roles are listed as deliberately public devnet roles,
    and the "authorizes nothing" assurance is withdrawn. I10 is widened to match. (F-R31)
- **r6** (2026-10-11), responding to round 5 of the Codex review of r5:
  - **D3 and D11.** The airdrop faucet admin key is private, and paid nullifiers are recorded
    durably and atomically, with replay and restart tests. (F-R32)
  - **D2 and D11.** The NFT holder custody wallet gets a private persisted key, with a
    public-key registration negative test. (F-R33)
  - Approved by Codex at r6 (F-R34, a P3, folded in: the M3 replay test is made precise) and
    by the Claude review at r3. P3s F-C21–F-C25 were folded in at r4.
