package com.bloxbean.cardano.zeroj.usecases.identity.circuit;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalComparators;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMerkle;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalPoseidon;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * ZK circuit for privacy-preserving KYC credential verification.
 *
 * <p>Proves: "I have a valid credential issued by a trusted provider AND
 * my age meets the minimum AND my country is in the approved list"
 * without revealing age, country, or any personal data.</p>
 *
 * <p>Uses Poseidon-signed credentials:
 * {@code credentialHash = Poseidon(issuerSecret, Poseidon(age, country))}</p>
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
        // Secret inputs — only the credential holder knows these
        Signal credentialSecret = c.privateInput("credentialSecret");
        Signal age = c.privateInput("age");
        Signal country = c.privateInput("country");

        // Country Merkle proof (secret)
        Signal[] siblings = new Signal[countryTreeDepth];
        Signal[] pathBits = new Signal[countryTreeDepth];
        for (int i = 0; i < countryTreeDepth; i++) {
            siblings[i] = c.privateInput("sibling_" + i);
            pathBits[i] = c.privateInput("pathBit_" + i);
        }

        // Public inputs
        Signal credentialHash = c.publicInput("credentialHash");
        Signal minAge = c.publicInput("minAge");
        Signal countryRoot = c.publicInput("countryRoot");

        // Public output
        Signal eligible = c.publicOutput("eligible");

        // 1. Verify credential: Poseidon(credentialSecret, Poseidon(age, country)) == credentialHash
        Signal claimsHash = SignalPoseidon.hash(c, POSEIDON, age, country);
        c.assertEqual(SignalPoseidon.hash(c, POSEIDON, credentialSecret, claimsHash), c.signal("credentialHash"));

        // 2. Age check: age >= minAge (8-bit comparison — ages 0-255)
        Signal ageOk = SignalComparators.greaterOrEqual(c, age, c.signal("minAge"), 8);

        // 3. Country check: country is in the approved countries Merkle tree
        SignalMerkle.verifyProof(c, country, c.signal("countryRoot"),
                siblings, pathBits, (sb, a, b) -> SignalPoseidon.hash(sb, POSEIDON, a, b));

        // 4. Output eligibility
        c.assertEqual(eligible, ageOk);
    }

    public static CircuitBuilder build(int countryTreeDepth) {
        var builder = CircuitBuilder.create("credential-verify")
                .publicVar("credentialHash")
                .publicVar("minAge")
                .publicVar("countryRoot")
                .publicVar("eligible")
                .secretVar("credentialSecret")
                .secretVar("age")
                .secretVar("country");

        for (int i = 0; i < countryTreeDepth; i++) {
            builder = builder.secretVar("sibling_" + i).secretVar("pathBit_" + i);
        }

        return builder.defineSignals(new CredentialCircuit(countryTreeDepth));
    }
}
