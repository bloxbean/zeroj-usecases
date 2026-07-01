package com.bloxbean.cardano.zeroj.usecases.plonk.reserves;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.usecases.plonk.reserves.circuit.ReserveSolvencyProofCircuit;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ReserveSolvencyProofCircuitTest {
    @Test
    void validSolvencyWitnessPasses() {
        var fixture = SampleReserveStatement.solventFixture();
        var circuit = ReserveSolvencyProofCircuit.build(SampleReserveStatement.ACCOUNT_COUNT);

        assertDoesNotThrow(() -> ReserveSolvencyProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BLS12_381));
        assertEquals(
                List.of(fixture.liabilityBatchCommitment(), fixture.assetValue(), fixture.claimedLiabilities()),
                ReserveSolvencyProofCircuit.publicInputs(fixture.inputs()));
    }

    @Test
    void invalidSurplusWitnessFails() {
        var fixture = fixture(BigInteger.valueOf(100), BigInteger.valueOf(175), BigInteger.valueOf(25));
        var circuit = ReserveSolvencyProofCircuit.build(SampleReserveStatement.ACCOUNT_COUNT);

        assertThrows(ArithmeticException.class,
                () -> ReserveSolvencyProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BLS12_381));
    }

    private static SampleReserveStatement.Fixture fixture(
            BigInteger assetValue,
            BigInteger claimedLiabilities,
            BigInteger surplus) {
        var liabilities = new BigInteger[]{
                BigInteger.valueOf(50),
                BigInteger.valueOf(40),
                BigInteger.valueOf(35),
                BigInteger.valueOf(50)
        };
        var liabilityBatchCommitment = SampleReserveStatement.liabilityBatchCommitment(liabilities);

        var inputs = ReserveSolvencyProofCircuit.inputs(SampleReserveStatement.ACCOUNT_COUNT)
                .liabilityBatchCommitment(liabilityBatchCommitment)
                .assetValue(assetValue)
                .claimedLiabilities(claimedLiabilities)
                .surplus(surplus)
                .privateLiabilities(Arrays.asList(liabilities));
        return new SampleReserveStatement.Fixture(
                inputs,
                liabilityBatchCommitment,
                assetValue,
                claimedLiabilities,
                surplus,
                liabilities);
    }
}
