package com.bloxbean.cardano.zeroj.usecases.dpp.circuit;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMerkle;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalPoseidon;

/**
 * Proves a country is in an approved set (Merkle membership).
 * <p>
 * Used for: "Made in EU", "conflict-free minerals" (country NOT in conflict set).
 * For non-membership, maintain a separate "approved" set and prove membership in it.
 *
 * @param treeDepth Merkle tree depth (4 = 16 countries)
 */
public class CountryMembershipCircuit implements CircuitSpec {

    private final int treeDepth;

    public CountryMembershipCircuit(int treeDepth) {
        this.treeDepth = treeDepth;
    }

    @Override
    public void define(SignalBuilder c) {
        // Secret: the actual country + Merkle proof
        Signal country = c.privateInput("country");
        Signal[] siblings = new Signal[treeDepth];
        Signal[] pathBits = new Signal[treeDepth];
        for (int i = 0; i < treeDepth; i++) {
            siblings[i] = c.privateInput("sibling_" + i);
            pathBits[i] = c.privateInput("pathBit_" + i);
        }

        // Public
        Signal productId = c.publicInput("productId");
        Signal countryRoot = c.publicInput("countryRoot");

        // Output
        Signal isMember = c.publicOutput("isMember");

        // Verify country is in the approved set
        SignalMerkle.verifyProof(c, country, c.signal("countryRoot"),
                siblings, pathBits, SignalPoseidon::hash);

        c.assertEqual(isMember, c.constant(1));
    }

    public static CircuitBuilder build(int treeDepth) {
        var builder = CircuitBuilder.create("country-membership")
                .publicVar("productId")
                .publicVar("countryRoot")
                .publicVar("isMember")
                .secretVar("country");

        for (int i = 0; i < treeDepth; i++) {
            builder = builder.secretVar("sibling_" + i).secretVar("pathBit_" + i);
        }

        return builder.defineSignals(new CountryMembershipCircuit(treeDepth));
    }
}
