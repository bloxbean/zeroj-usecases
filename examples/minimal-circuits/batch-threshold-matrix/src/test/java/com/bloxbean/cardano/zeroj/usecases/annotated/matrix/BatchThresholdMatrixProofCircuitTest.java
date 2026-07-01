package com.bloxbean.cardano.zeroj.usecases.annotated.matrix;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.usecases.annotated.matrix.circuit.BatchThresholdMatrixProofCircuit;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BatchThresholdMatrixProofCircuitTest {

    @Test
    void validMatrixWitnessPassesOnBls12381() {
        int rows = 2;
        int cols = 3;
        var circuit = BatchThresholdMatrixProofCircuit.build(rows, cols);
        var schema = BatchThresholdMatrixProofCircuit.schema(rows, cols);

        assertEquals(List.of("columnMaximum_0", "columnMaximum_1", "columnMaximum_2"),
                schema.publicInputs().names());
        assertEquals(List.of(
                        "measurement_0_0", "measurement_0_1", "measurement_0_2",
                        "measurement_1_0", "measurement_1_1", "measurement_1_2"),
                schema.secretInputs().names());
        assertEquals(List.of(rows, cols), schema.input("measurement").dimensions());

        var inputs = BatchThresholdMatrixProofCircuit.inputs(rows, cols)
                .columnMaximums(List.of(
                        BigInteger.valueOf(10),
                        BigInteger.valueOf(20),
                        BigInteger.valueOf(30)))
                .measurements(List.of(
                        List.of(BigInteger.valueOf(8), BigInteger.valueOf(19), BigInteger.valueOf(30)),
                        List.of(BigInteger.valueOf(10), BigInteger.valueOf(20), BigInteger.valueOf(29))));

        assertEquals(List.of(BigInteger.valueOf(10), BigInteger.valueOf(20), BigInteger.valueOf(30)),
                inputs.publicValues());
        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381));
    }

    @Test
    void measurementAboveColumnMaximumFails() {
        int rows = 2;
        int cols = 3;
        var circuit = BatchThresholdMatrixProofCircuit.build(rows, cols);
        var inputs = BatchThresholdMatrixProofCircuit.inputs(rows, cols)
                .columnMaximums(List.of(
                        BigInteger.valueOf(10),
                        BigInteger.valueOf(20),
                        BigInteger.valueOf(30)))
                .measurements(List.of(
                        List.of(BigInteger.valueOf(8), BigInteger.valueOf(21), BigInteger.valueOf(30)),
                        List.of(BigInteger.valueOf(10), BigInteger.valueOf(20), BigInteger.valueOf(29))));

        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381));
    }

    @Test
    void raggedMatrixInputFailsBeforeWitnessCalculation() {
        assertThrows(IllegalArgumentException.class,
                () -> BatchThresholdMatrixProofCircuit.inputs(2, 3)
                        .measurements(List.of(
                                List.of(BigInteger.ONE),
                                List.of(BigInteger.TWO, BigInteger.valueOf(3), BigInteger.valueOf(4)))));
    }
}
