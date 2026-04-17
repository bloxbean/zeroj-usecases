package com.bloxbean.cardano.zeroj.usecases.dpp.circuit;

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
 * Proves N quality inspections passed in chronological order.
 * <p>
 * Each inspection: an approved inspector verified the product at a specific time.
 * The circuit proves all passed, in order, by approved inspectors — without
 * revealing inspector identities, timestamps, or inspection details.
 *
 * @param numCheckpoints number of required inspections (e.g., 3)
 * @param inspectorTreeDepth Merkle tree depth for approved inspectors
 */
public class InspectionChainCircuit implements CircuitSpec {

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    private final int numCheckpoints;
    private final int inspectorTreeDepth;

    public InspectionChainCircuit(int numCheckpoints, int inspectorTreeDepth) {
        this.numCheckpoints = numCheckpoints;
        this.inspectorTreeDepth = inspectorTreeDepth;
    }

    @Override
    public void define(SignalBuilder c) {
        // Public inputs
        Signal productId = c.publicInput("productId");
        Signal inspectorRoot = c.publicInput("inspectorRoot");

        // Public output
        Signal allPassed = c.publicOutput("allPassed");

        Signal prevTimestamp = c.constant(0);

        for (int i = 0; i < numCheckpoints; i++) {
            // Secret: each inspection's data
            Signal passed = c.privateInput("passed_" + i);
            Signal timestamp = c.privateInput("timestamp_" + i);
            Signal inspectorKey = c.privateInput("inspectorKey_" + i);

            // Inspector Merkle proof
            Signal[] siblings = new Signal[inspectorTreeDepth];
            Signal[] pathBits = new Signal[inspectorTreeDepth];
            for (int j = 0; j < inspectorTreeDepth; j++) {
                siblings[j] = c.privateInput("insp_sibling_" + i + "_" + j);
                pathBits[j] = c.privateInput("insp_pathBit_" + i + "_" + j);
            }

            // 1. Inspection must pass
            c.assertEqual(passed, c.constant(1));

            // 2. Timestamps must be in chronological order
            if (i > 0) {
                Signal orderOk = SignalComparators.greaterThan(c, timestamp, prevTimestamp, 32);
                c.assertEqual(orderOk, c.constant(1));
            }
            prevTimestamp = timestamp;

            // 3. Inspector must be in approved set
            Signal inspectorHash = SignalPoseidon.hash(c, POSEIDON, inspectorKey, c.constant(0));
            SignalMerkle.verifyProof(c, inspectorHash, c.signal("inspectorRoot"),
                    siblings, pathBits, (sb, a, b) -> SignalPoseidon.hash(sb, POSEIDON, a, b));
        }

        c.assertEqual(allPassed, c.constant(1));
    }

    public static CircuitBuilder build(int numCheckpoints, int inspectorTreeDepth) {
        var builder = CircuitBuilder.create("inspection-chain")
                .publicVar("productId")
                .publicVar("inspectorRoot")
                .publicVar("allPassed");

        for (int i = 0; i < numCheckpoints; i++) {
            builder = builder
                    .secretVar("passed_" + i)
                    .secretVar("timestamp_" + i)
                    .secretVar("inspectorKey_" + i);
            for (int j = 0; j < inspectorTreeDepth; j++) {
                builder = builder
                        .secretVar("insp_sibling_" + i + "_" + j)
                        .secretVar("insp_pathBit_" + i + "_" + j);
            }
        }

        return builder.defineSignals(new InspectionChainCircuit(numCheckpoints, inspectorTreeDepth));
    }
}
