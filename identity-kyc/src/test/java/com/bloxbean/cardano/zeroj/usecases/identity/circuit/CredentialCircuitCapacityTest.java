package com.bloxbean.cardano.zeroj.usecases.identity.circuit;

import org.zeroj.api.CurveId;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialCircuitCapacityTest {

    private static final int DEV_POT_POWER = 14;
    private static final int DEV_POT_CAPACITY = 1 << DEV_POT_POWER;

    @Test
    void credentialCircuitFitsConfiguredDevelopmentSrs() {
        var r1cs = CredentialProofCircuit.build(4).compileR1CS(CurveId.BLS12_381);

        assertTrue(r1cs.numConstraints() <= DEV_POT_CAPACITY,
                () -> "credential circuit needs " + r1cs.numConstraints()
                        + " rows, exceeding the power-" + DEV_POT_POWER + " dev SRS");
    }
}
