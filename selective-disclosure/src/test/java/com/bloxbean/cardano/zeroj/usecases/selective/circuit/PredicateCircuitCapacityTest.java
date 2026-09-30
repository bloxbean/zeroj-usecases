package com.bloxbean.cardano.zeroj.usecases.selective.circuit;

import org.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.usecases.selective.service.RichCredentialIssuerService;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class PredicateCircuitCapacityTest {

    private static final int DEV_POT_POWER = 14;
    private static final int DEV_POT_CAPACITY = 1 << DEV_POT_POWER;

    @Test
    void bothPredicatesFitConfiguredDevelopmentSrs() {
        var adult = AdultResidentProofCircuit
                .build(RichCredentialIssuerService.COUNTRY_TREE_DEPTH)
                .compileR1CS(CurveId.BLS12_381);
        var doctor = SeniorDoctorProofCircuit.build().compileR1CS(CurveId.BLS12_381);

        assertTrue(adult.numConstraints() <= DEV_POT_CAPACITY,
                () -> "adult-resident needs " + adult.numConstraints()
                        + " rows, exceeding the power-" + DEV_POT_POWER + " dev SRS");
        assertTrue(doctor.numConstraints() <= DEV_POT_CAPACITY,
                () -> "senior-doctor needs " + doctor.numConstraints()
                        + " rows, exceeding the power-" + DEV_POT_POWER + " dev SRS");
    }
}
