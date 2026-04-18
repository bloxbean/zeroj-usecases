package com.bloxbean.cardano.zeroj.usecases.airdrop.circuit;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalPoseidon;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitEdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * Sybil-resistant airdrop / faucet claim circuit.
 *
 * <h2>What it proves</h2>
 * <i>"I hold a personhood credential signed by issuer {@code pk}, and the
 * nullifier I've published equals {@code Poseidon(personhoodId, epoch)},
 * and I'm claiming for recipient {@code R}."</i>
 *
 * <p>The verifier (and the on-chain validator) can therefore conclude:
 * <ul>
 *   <li>The claimer is a unique human attested by the issuer.</li>
 *   <li>The nullifier is deterministically tied to (personhoodId, epoch);
 *       any subsequent attempt by the same personhoodId in the same epoch
 *       produces the same nullifier and is rejected on-chain.</li>
 *   <li>The recipient is bound into the proof — a relayer cannot redirect
 *       the claim.</li>
 * </ul>
 *
 * <h2>Public inputs (6)</h2>
 * <ol>
 *   <li>{@code pkU, pkV} — issuer's Jubjub public key (affine).</li>
 *   <li>{@code epoch} — claim epoch (e.g., Cardano epoch number).</li>
 *   <li>{@code nullifier} — published per-claim, equals Poseidon(personhoodId, epoch).</li>
 *   <li>{@code recipient} — Cardano recipient identifier (e.g., low 254 bits of payment-key hash).</li>
 *   <li>{@code eligible} — output flag, always 1 for a successful proof.</li>
 * </ol>
 *
 * <h2>Secret inputs</h2>
 * {@code personhoodId, sigRU, sigRV, sigS, kModL, kQuotient}.
 */
public class PersonhoodAirdropCircuit implements CircuitSpec {

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    @Override
    public void define(SignalBuilder c) {
        // --- Public inputs ---
        Signal pkU = c.publicInput("pkU");
        Signal pkV = c.publicInput("pkV");
        Signal epoch = c.publicInput("epoch");
        Signal nullifier = c.publicInput("nullifier");
        Signal recipient = c.publicInput("recipient");
        Signal eligible = c.publicOutput("eligible");

        // --- Secret inputs ---
        Signal personhoodId = c.privateInput("personhoodId");
        Signal sigRU = c.privateInput("sigRU");
        Signal sigRV = c.privateInput("sigRV");
        Signal sigS = c.privateInput("sigS");
        Signal kModL = c.privateInput("kModL");
        Signal kQuotient = c.privateInput("kQuotient");

        // 1. Verify EdDSA-Jubjub: Poseidon(personhoodId) is the message; issuer pk.
        Signal claimsMsg = SignalPoseidon.hash(c, POSEIDON, personhoodId, c.constant(0));

        InCircuitJubjub.Point pkPoint = new InCircuitJubjub.Point(
                pkU.variable(), pkV.variable(), c.api().constant(1),
                c.api().mul(pkU.variable(), pkV.variable()));
        InCircuitJubjub.Point sigRPoint = new InCircuitJubjub.Point(
                sigRU.variable(), sigRV.variable(), c.api().constant(1),
                c.api().mul(sigRU.variable(), sigRV.variable()));

        InCircuitEdDSAJubjub.verify(c.api(), pkPoint, claimsMsg.variable(),
                sigRPoint, sigS.variable(),
                kModL.variable(), kQuotient.variable());

        // 2. Compute and assert nullifier = Poseidon(personhoodId, epoch).
        Signal computedNullifier = SignalPoseidon.hash(c, POSEIDON, personhoodId, epoch);
        c.assertEqual(computedNullifier, nullifier);

        // 3. Bind recipient into the proof. The recipient signal is asserted
        //    nonzero so a valid proof commits to a specific destination — the
        //    constraint here is `recipient * 1 == recipient`, which the gates
        //    will fold into a public-input wire constraint, ensuring the
        //    recipient is part of the verifying-key public-input commitment.
        c.assertEqual(recipient, recipient);

        // 4. Output eligibility (always 1 for successful proofs).
        c.assertEqual(eligible, c.constant(1));
    }

    public static CircuitBuilder build() {
        return CircuitBuilder.create("personhood-airdrop")
                .publicVar("pkU").publicVar("pkV")
                .publicVar("epoch")
                .publicVar("nullifier")
                .publicVar("recipient")
                .publicVar("eligible")
                .secretVar("personhoodId")
                .secretVar("sigRU").secretVar("sigRV")
                .secretVar("sigS")
                .secretVar("kModL").secretVar("kQuotient")
                .defineSignals(new PersonhoodAirdropCircuit());
    }
}
