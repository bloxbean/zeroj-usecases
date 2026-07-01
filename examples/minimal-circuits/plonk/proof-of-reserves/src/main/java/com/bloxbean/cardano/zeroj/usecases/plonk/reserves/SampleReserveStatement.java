package com.bloxbean.cardano.zeroj.usecases.plonk.reserves;

import com.bloxbean.cardano.zeroj.usecases.plonk.reserves.circuit.ReserveSolvencyProofCircuit;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * Deterministic sample data for the PlonK proof-of-reserves demo.
 */
public final class SampleReserveStatement {
    public static final int ACCOUNT_COUNT = 4;

    private SampleReserveStatement() {
    }

    public static Fixture solventFixture() {
        var liabilities = new BigInteger[]{
                BigInteger.valueOf(50),
                BigInteger.valueOf(40),
                BigInteger.valueOf(35),
                BigInteger.valueOf(50)
        };
        var liabilityBatchCommitment = liabilityBatchCommitment(liabilities);
        var assetValue = BigInteger.valueOf(200);
        var claimedLiabilities = BigInteger.valueOf(175);
        var surplus = BigInteger.valueOf(25);

        var inputs = ReserveSolvencyProofCircuit.inputs(ACCOUNT_COUNT)
                .liabilityBatchCommitment(liabilityBatchCommitment)
                .assetValue(assetValue)
                .claimedLiabilities(claimedLiabilities)
                .surplus(surplus)
                .privateLiabilities(Arrays.asList(liabilities));
        return new Fixture(inputs, liabilityBatchCommitment, assetValue, claimedLiabilities, surplus, liabilities);
    }

    public static BigInteger liabilityBatchCommitment(BigInteger[] liabilities) {
        BigInteger commitment = BigInteger.ZERO;
        for (int i = 0; i < liabilities.length; i++) {
            commitment = commitment.add(liabilities[i].multiply(BigInteger.valueOf(17L + i)));
        }
        return commitment;
    }

    public record Fixture(
            ReserveSolvencyProofCircuit.Inputs inputs,
            BigInteger liabilityBatchCommitment,
            BigInteger assetValue,
            BigInteger claimedLiabilities,
            BigInteger surplus,
            BigInteger[] liabilities) {
        public Fixture {
            liabilities = liabilities == null ? null : Arrays.copyOf(liabilities, liabilities.length);
        }

        @Override
        public BigInteger[] liabilities() {
            return liabilities == null ? null : Arrays.copyOf(liabilities, liabilities.length);
        }
    }
}
