package com.bloxbean.cardano.zeroj.usecases.recovery.circuit;

import com.bloxbean.cardano.zeroj.api.CurveId;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Compiles the v4 circuit and reports its dimensions + fingerprint (recipient added + account secret,
 * public inputs packed to 2 scalars). Heavy (~19M-constraint compile, several GB); gated behind
 * {@code -Dcircuit.measure=true}.
 */
class CircuitV3MeasureTest {

    @Test
    @EnabledIfSystemProperty(named = "circuit.measure", matches = "true")
    void measure() {
        var r1cs = OwnershipProofCircuit.build().compileR1CS(CurveId.BLS12_381);
        int nc = r1cs.numConstraints(), nw = r1cs.numWires(), np = r1cs.numPublicInputs();
        System.out.println("[circuit v4] constraints=" + nc + "  wires=" + nw + "  public=" + np);
        System.out.println("[circuit v4] fingerprint=c" + nc + "-w" + nw + "-p" + np);
        assertEquals(2, np, "packed pkh + packed recipient (2 public inputs)");
    }
}
