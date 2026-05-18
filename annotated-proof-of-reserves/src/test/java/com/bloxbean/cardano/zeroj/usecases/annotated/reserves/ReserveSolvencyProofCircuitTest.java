package com.bloxbean.cardano.zeroj.usecases.annotated.reserves;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.usecases.annotated.reserves.circuit.ReserveSolvencyProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.annotated.reserves.support.BinaryMerkle;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ReserveSolvencyProofCircuitTest {
    @Test
    void validSolvencyWitnessPasses() {
        var fixture = fixture(BigInteger.valueOf(2_000_000), BigInteger.valueOf(1_750_000));
        var circuit = ReserveSolvencyProofCircuit.build(2);

        assertDoesNotThrow(() -> ReserveSolvencyProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BLS12_381));
        assertEquals(
                List.of(fixture.liabilitiesRoot(), fixture.assetValue(), fixture.claimedLiabilities()),
                ReserveSolvencyProofCircuit.publicInputs(fixture.inputs()));
    }

    @Test
    void bn254CompilationFailsBecauseCircuitUsesBlsPoseidon() {
        var fixture = fixture(BigInteger.valueOf(2_000_000), BigInteger.valueOf(1_750_000));
        var circuit = ReserveSolvencyProofCircuit.build(2);

        assertThrows(IllegalStateException.class,
                () -> ReserveSolvencyProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BN254));
    }

    @Test
    void insolventPublicValuesFail() {
        var fixture = fixture(BigInteger.valueOf(1_000_000), BigInteger.valueOf(1_750_000));
        var circuit = ReserveSolvencyProofCircuit.build(2);

        assertThrows(ArithmeticException.class,
                () -> ReserveSolvencyProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BLS12_381));
    }

    private static Fixture fixture(BigInteger assetValue, BigInteger claimedLiabilities) {
        var accountId = BigInteger.valueOf(424242);
        var accountBalance = BigInteger.valueOf(1500);
        var accountSalt = BigInteger.valueOf(987654321);
        var liabilityLeaf = PoseidonHash.hashN(
                PoseidonParamsBLS12_381T3.INSTANCE,
                accountId,
                accountBalance,
                accountSalt);
        var siblings = List.of(BigInteger.valueOf(1100), BigInteger.valueOf(2200));
        var pathBits = List.of(BigInteger.ONE, BigInteger.ZERO);
        var liabilitiesRoot = BinaryMerkle.root(liabilityLeaf, siblings, pathBits);

        var inputs = ReserveSolvencyProofCircuit.inputs(2)
                .accountId(accountId)
                .accountBalance(accountBalance)
                .accountSalt(accountSalt)
                .liabilitiesRoot(liabilitiesRoot)
                .assetValue(assetValue)
                .claimedLiabilities(claimedLiabilities)
                .liabilitySiblings(siblings)
                .liabilityPathBits(pathBits);
        return new Fixture(inputs, liabilitiesRoot, assetValue, claimedLiabilities);
    }

    private record Fixture(
            ReserveSolvencyProofCircuit.Inputs inputs,
            BigInteger liabilitiesRoot,
            BigInteger assetValue,
            BigInteger claimedLiabilities) {
    }
}
