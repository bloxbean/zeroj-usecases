package com.bloxbean.cardano.zeroj.usecases.identity.circuit;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalComparators;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMerkle;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalPoseidon;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitEdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * ZK circuit for privacy-preserving KYC credential verification, now backed
 * by <b>EdDSA-Jubjub signatures</b> (ADR-0016). See
 * {@code JUBJUB_ON_CARDANO.md} for the why.
 *
 * <h2>Proof statement</h2>
 * Proves: <i>"I hold an issuer-signed credential stating (age, country),
 * and age ≥ minAge, and country is in the approved-countries Merkle set"</i>
 * — without revealing age, country, or the signature itself.
 *
 * <h2>Difference from the old Poseidon-MAC version</h2>
 * Previously the "credential" was {@code Poseidon(issuerSecret, Poseidon(age, country))} —
 * a shared-secret scheme. Issuer and holder both knew {@code issuerSecret};
 * either could forge credentials; the secret had to be transmitted securely
 * at issuance. Incompatible with W3C VC / DID / Atala PRISM.
 *
 * <p>The new scheme uses asymmetric EdDSA-Jubjub signatures:
 * <ul>
 *   <li>Issuer holds a secret scalar {@code sk}; publishes
 *       {@code pk = [sk]·G_jubjub}.</li>
 *   <li>Credential = {@code sign(sk, Poseidon(age, country)) = (R, S)}.</li>
 *   <li>Holder holds {@code (age, country, R, S)}; the secret never leaves
 *       the issuer, the signature never leaves the holder.</li>
 *   <li>This circuit proves {@code verify(pk, Poseidon(age, country), (R, S))}
 *       plus the claim predicates.</li>
 * </ul>
 *
 * <h2>Public vs secret signals</h2>
 * Public (known to verifier): {@code pkU, pkV, minAge, countryRoot, eligible}.
 * Secret (witness): {@code age, country, sigRU, sigRV, sigS, kModL, kQuotient,
 * Merkle siblings, path bits}.
 *
 * @param countryTreeDepth depth of approved countries Merkle tree (4 = 16 countries)
 */
public class CredentialCircuit implements CircuitSpec {

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    private final int countryTreeDepth;

    public CredentialCircuit(int countryTreeDepth) {
        this.countryTreeDepth = countryTreeDepth;
    }

    @Override
    public void define(SignalBuilder c) {
        // --- Public: issuer's public key (affine coords) + policy params ---
        Signal pkU = c.publicInput("pkU");
        Signal pkV = c.publicInput("pkV");
        Signal minAge = c.publicInput("minAge");
        Signal countryRoot = c.publicInput("countryRoot");
        Signal eligible = c.publicOutput("eligible");

        // --- Secret: credential claims + signature + Merkle proof ---
        Signal age = c.privateInput("age");
        Signal country = c.privateInput("country");
        Signal sigRU = c.privateInput("sigRU");
        Signal sigRV = c.privateInput("sigRV");
        Signal sigS = c.privateInput("sigS");
        Signal kModL = c.privateInput("kModL");
        Signal kQuotient = c.privateInput("kQuotient");
        Signal[] siblings = new Signal[countryTreeDepth];
        Signal[] pathBits = new Signal[countryTreeDepth];
        for (int i = 0; i < countryTreeDepth; i++) {
            siblings[i] = c.privateInput("sibling_" + i);
            pathBits[i] = c.privateInput("pathBit_" + i);
        }

        // 1. Verify issuer signature on (age, country) via in-circuit EdDSA-Jubjub.
        //    claimsMsg = Poseidon(age, country).
        Signal claimsMsg = SignalPoseidon.hash(c, POSEIDON, age, country);
        InCircuitJubjub.Point pkPoint = new InCircuitJubjub.Point(
                pkU.variable(), pkV.variable(),
                c.api().constant(1),
                c.api().mul(pkU.variable(), pkV.variable()));
        InCircuitJubjub.Point sigRPoint = new InCircuitJubjub.Point(
                sigRU.variable(), sigRV.variable(),
                c.api().constant(1),
                c.api().mul(sigRU.variable(), sigRV.variable()));
        InCircuitEdDSAJubjub.verify(c.api(), pkPoint, claimsMsg.variable(),
                sigRPoint, sigS.variable(),
                kModL.variable(), kQuotient.variable());

        // 2. Age check: age >= minAge (8-bit comparison — ages 0-255)
        Signal ageOk = SignalComparators.greaterOrEqual(c, age, c.signal("minAge"), 8);

        // 3. Country membership: verify Merkle proof against countryRoot
        SignalMerkle.verifyProof(c, country, c.signal("countryRoot"),
                siblings, pathBits, (sb, a, b) -> SignalPoseidon.hash(sb, POSEIDON, a, b));

        // 4. Eligibility output: ageOk (country check is an assert, not a conditional)
        c.assertEqual(eligible, ageOk);
    }

    public static CircuitBuilder build(int countryTreeDepth) {
        var builder = CircuitBuilder.create("credential-verify-eddsa")
                .publicVar("pkU").publicVar("pkV")
                .publicVar("minAge")
                .publicVar("countryRoot")
                .publicVar("eligible")
                .secretVar("age")
                .secretVar("country")
                .secretVar("sigRU").secretVar("sigRV")
                .secretVar("sigS")
                .secretVar("kModL").secretVar("kQuotient");

        for (int i = 0; i < countryTreeDepth; i++) {
            builder = builder.secretVar("sibling_" + i).secretVar("pathBit_" + i);
        }

        return builder.defineSignals(new CredentialCircuit(countryTreeDepth));
    }
}
