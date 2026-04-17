package com.bloxbean.cardano.zeroj.usecases.dpp.circuit;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalComparators;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalPoseidon;

/**
 * Generic compliance threshold circuit for DPP claims.
 * <p>
 * Proves: "the auditor-certified measurement meets the threshold"
 * without revealing the actual measurement value.
 * <p>
 * Used for: carbon footprint < X kg, recycled content >= Y%, battery retention >= Z%.
 *
 * @param comparisonMode 0 = measurement >= threshold (recycled content), 1 = measurement <= threshold (carbon)
 */
public class ComplianceThresholdCircuit implements CircuitSpec {

    private final int comparisonMode;

    public ComplianceThresholdCircuit(int comparisonMode) {
        this.comparisonMode = comparisonMode;
    }

    @Override
    public void define(SignalBuilder c) {
        // Secret inputs — commercially sensitive
        Signal measurement = c.privateInput("measurement");
        Signal auditorSecret = c.privateInput("auditorSecret");

        // Public inputs
        Signal productId = c.publicInput("productId");
        Signal threshold = c.publicInput("threshold");
        Signal auditorHash = c.publicInput("auditorHash");

        // Public output
        Signal isCompliant = c.publicOutput("isCompliant");

        // 1. Verify auditor signed the measurement
        //    auditorHash == Poseidon(auditorSecret, Poseidon(productId, measurement))
        Signal claimsHash = SignalPoseidon.hash(c, c.signal("productId"), measurement);
        c.assertEqual(SignalPoseidon.hash(c, auditorSecret, claimsHash), c.signal("auditorHash"));

        // 2. Check threshold (16-bit comparison — measurements 0-65535)
        Signal passes;
        if (comparisonMode == 0) {
            // measurement >= threshold (e.g., recycled content >= 30%)
            passes = SignalComparators.greaterOrEqual(c, measurement, c.signal("threshold"), 16);
        } else {
            // measurement <= threshold (e.g., carbon < 50kg — use threshold >= measurement)
            passes = SignalComparators.greaterOrEqual(c, c.signal("threshold"), measurement, 16);
        }

        c.assertEqual(isCompliant, passes);
    }

    /**
     * Build a "greater or equal" threshold circuit (measurement >= threshold).
     * Use for: recycled content, battery retention.
     */
    public static CircuitBuilder buildGte() {
        return CircuitBuilder.create("compliance-gte")
                .publicVar("productId")
                .publicVar("threshold")
                .publicVar("auditorHash")
                .publicVar("isCompliant")
                .secretVar("measurement")
                .secretVar("auditorSecret")
                .defineSignals(new ComplianceThresholdCircuit(0));
    }

    /**
     * Build a "less or equal" threshold circuit (measurement <= threshold).
     * Use for: carbon footprint.
     */
    public static CircuitBuilder buildLte() {
        return CircuitBuilder.create("compliance-lte")
                .publicVar("productId")
                .publicVar("threshold")
                .publicVar("auditorHash")
                .publicVar("isCompliant")
                .secretVar("measurement")
                .secretVar("auditorSecret")
                .defineSignals(new ComplianceThresholdCircuit(1));
    }
}
