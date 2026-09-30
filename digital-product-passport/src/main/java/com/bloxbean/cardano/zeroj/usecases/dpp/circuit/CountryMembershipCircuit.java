package com.bloxbean.cardano.zeroj.usecases.dpp.circuit;

import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.CircuitSpec;
import org.zeroj.circuit.Signal;
import org.zeroj.circuit.SignalBuilder;
import org.zeroj.circuit.lib.SignalMerkle;
import org.zeroj.circuit.lib.SignalPoseidon;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * Proves a product's auditor-attested origin country is in an approved set (Merkle membership).
 * <p>
 * The auditor publishes {@code auditorHash = Poseidon(auditorSecret, Poseidon(productId, country))}
 * for the product, as for the compliance-threshold claims. The circuit proves that the committed
 * country for {@code productId} is in the set, so the proof is about this product and cannot be
 * produced for another product or another country.
 * <p>
 * Used for: "Made in EU", "conflict-free minerals" (country NOT in conflict set).
 * For non-membership, maintain a separate "approved" set and prove membership in it.
 *
 * @param treeDepth Merkle tree depth (4 = 16 countries)
 */
public class CountryMembershipCircuit implements CircuitSpec {

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    private final int treeDepth;

    public CountryMembershipCircuit(int treeDepth) {
        this.treeDepth = treeDepth;
    }

    @Override
    public void define(SignalBuilder c) {
        // Secret: the actual country, the auditor's secret, and the country's Merkle proof
        Signal country = c.privateInput("country");
        Signal auditorSecret = c.privateInput("auditorSecret");
        Signal[] siblings = new Signal[treeDepth];
        Signal[] pathBits = new Signal[treeDepth];
        for (int i = 0; i < treeDepth; i++) {
            siblings[i] = c.privateInput("sibling_" + i);
            pathBits[i] = c.privateInput("pathBit_" + i);
        }

        // Public
        Signal productId = c.publicInput("productId");
        Signal countryRoot = c.publicInput("countryRoot");
        Signal auditorHash = c.publicInput("auditorHash");

        // Output
        Signal isMember = c.publicOutput("isMember");

        // 1. The auditor attested this product's origin:
        //    auditorHash == Poseidon(auditorSecret, Poseidon(productId, country))
        Signal claimsHash = SignalPoseidon.hash(c, POSEIDON, c.signal("productId"), country);
        c.assertEqual(SignalPoseidon.hash(c, POSEIDON, auditorSecret, claimsHash), c.signal("auditorHash"));

        // 2. That country is in the approved set
        SignalMerkle.verifyProof(c, country, c.signal("countryRoot"),
                siblings, pathBits, (sb, a, b) -> SignalPoseidon.hash(sb, POSEIDON, a, b));

        c.assertEqual(isMember, c.constant(1));
    }

    public static CircuitBuilder build(int treeDepth) {
        var builder = CircuitBuilder.create("country-membership")
                .publicVar("productId")
                .publicVar("countryRoot")
                .publicVar("auditorHash")
                .publicVar("isMember")
                .secretVar("country")
                .secretVar("auditorSecret");

        for (int i = 0; i < treeDepth; i++) {
            builder = builder.secretVar("sibling_" + i).secretVar("pathBit_" + i);
        }

        return builder.defineSignals(new CountryMembershipCircuit(treeDepth));
    }
}
