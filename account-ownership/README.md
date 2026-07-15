# Account-Ownership Recovery

Prove you are the real owner of a Cardano address **in zero knowledge** — so a compromised wallet
can be refunded to the genuine owner without ever exposing the recovery phrase, and without an
attacker or a front-runner stealing the refund.

Built on [ZeroJ](https://github.com/bloxbean/zeroj) (Groth16 over BLS12-381, pure Java).

---

## The problem

A wallet or custodial account gets compromised. An attacker obtains the **leaf signing keys** — the
day-to-day keys that sign transactions — and drains the funds. This happens through phishing, a
leaked hot-wallet key, malware, a bad browser extension, and so on.

The genuine owner still holds the **master seed** (the 24-word recovery phrase) that the whole wallet
is derived from. The attacker, by assumption, does **not** — they only grabbed the leaf keys.

A service provider — say an exchange or wallet operator (call them **the operator**) — decides to
**refund the affected users**. That immediately raises hard questions:

- **Who is the real owner?** The attacker can show up and claim too. Signing with a leaf key proves
  nothing — the attacker can do that.
- **The owner can't just hand over their seed** to prove ownership. Revealing a recovery phrase to
  anyone is catastrophic; it would defeat the whole point.
- **A refund can be stolen in transit.** If the owner submits a proof on-chain, anyone watching the
  mempool could copy it and redirect the money to themselves.
- **Nobody should be able to claim twice.**

So the operator needs a way for the true owner — and *only* the true owner — to prove ownership
**without revealing the seed**, and to make sure the refund goes **only** to the address the owner
chose.

---

## The solution (with ZeroJ)

The owner produces a **zero-knowledge proof** that says, in effect:

> "I know the master seed that this address is derived from, and I want the refund sent to *this*
> address" — while revealing **nothing** about the seed.

How it works, in plain terms:

1. **Derivation, in a circuit.** Every Cardano address comes from the master seed through a standard
   derivation path (CIP-1852). ZeroJ runs that whole derivation *inside a zero-knowledge circuit* and
   checks it lands on the address's payment key hash. Because it starts from the **root seed**, only
   someone who has the seed can produce a valid proof. An attacker with just the leaf keys **cannot**.
2. **Nothing leaks.** The proof reveals only what's already public — the address and the chosen
   recipient. The seed and the derivation path stay secret (that's the "zero-knowledge" part).
3. **The refund is bound to a recipient.** The proof is tied to the payout address the owner picked,
   so a copied proof **can't be redirected** — a front-runner gets nothing.
4. **Verify anywhere.** The proof can be checked **off-chain** in a fraction of a second, or
   **on-chain** by a small Cardano (Plutus) validator that runs the verifier *and* enforces that the
   payout actually goes to the bound recipient. A per-account refund voucher (a UTxO that can be spent
   only once) prevents double-claims.

The result: the operator refunds the genuine owner, the owner never exposes their seed, the attacker
can't claim, and the money can't be hijacked on the way.

---

## Two ways to use it

| | For whom | What it does |
|---|---|---|
| **Desktop app** (`ui/`) | end users | A simple point-and-click app: set up keys, enter your recovery phrase (hidden — it never leaves your machine) and the address to receive the refund, generate a proof, and verify it off-chain or on-chain. |
| **Command-line tool** (`cli/`) | developers, operators, scripting | The same flow from the terminal — `setup` → `prove` → `verify` — plus key-bundle management and the on-chain demo. Ships as a Java zip. |

Both are pure Java and run the same underlying flow; nothing about your seed is ever stored or sent.

---

## Documentation

- **[CLI — getting started](cli/README.md)** — install, the five commands, distributions, measured
  performance.
- **[CLI — full usage reference](cli/USAGE.md)** — every command and option, key-bundle setup,
  Docker, on-chain verification.
- **[Verification & on-chain validator flow](docs/verification-and-validator-flow.md)** — the
  technical reference: the circuit's public interface, how a proof is produced and verified off-chain
  and on-chain, the validator's checks, and the on-chain cost.
- **[On-chain verification: options & decision record](docs/account-ownership-onchain-verification-options.md)**
  — the design analysis (replay protection, recipient binding, nullifiers) behind the chosen approach.

---

## A note on trust

- **Your seed never leaves your machine** — it's read from a hidden prompt, used to build the proof
  in memory, and discarded. It is never written to disk or sent over the network.
- **The proof discloses only** the address's payment key hash and the recipient — both of which are
  already public on-chain.
- **Keys come from a trusted setup.** For trying it out, generate a **local, development-only** key
  bundle. For production, the setup is run as a multi-party ceremony (see the CLI docs). A production
  refund program should also confirm the recipient through its own authenticated channel.
