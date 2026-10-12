package com.bloxbean.cardano.zeroj.usecases.pedersen.points;

import com.bloxbean.cardano.zeroj.usecases.pedersen.points.ConfidentialPoints.Note;
import com.bloxbean.cardano.zeroj.usecases.pedersen.points.circuit.PointsRedeemProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.points.circuit.PointsTransferProofCircuit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Demo A's relations: honest transfers and redemptions prove; unbalanced or overflowing ones do not. */
class PointsCircuitTest {

    static final byte[] ALICE = filled((byte) 0xa1);
    static final byte[] BOB = filled((byte) 0xb0);
    private static ConfidentialPoints points;

    @BeforeAll
    static void setup() {
        points = new ConfidentialPoints();
    }

    @Test
    @DisplayName("Transfer: balanced split proves and verifies; any changed commitment is rejected")
    void transferProves() {
        Note in = Note.of(ALICE, 1_000), out1 = Note.of(BOB, 700), out2 = Note.of(ALICE, 300);
        var inputs = ConfidentialPoints.transferInputs(in, out1, out2);
        var proof = points.proveTransfer(in, out1, out2);
        List<BigInteger> pub = PointsTransferProofCircuit.publicInputs(inputs);
        assertTrue(points.transferCircuit().verify(proof, pub));
        for (int i = 0; i < pub.size(); i++) {
            List<BigInteger> changed = new ArrayList<>(pub);
            changed.set(i, changed.get(i).add(BigInteger.ONE));
            assertFalse(points.transferCircuit().verify(proof, changed), "public input " + i);
        }
        System.out.println("[points-transfer] constraints: " + points.transferCircuit().numConstraints());
    }

    @Test
    @DisplayName("Transfer: no witness for an unbalanced split, a wrong commitment or a wrapped amount")
    void transferRejects() {
        var circuit = points.transferCircuit().circuit();
        Note in = Note.of(ALICE, 1_000);
        assertThrows(RuntimeException.class, () -> circuit.calculateWitness(
                ConfidentialPoints.transferInputs(in, Note.of(BOB, 701), Note.of(ALICE, 300)).toWitnessMap(), CurveId.BLS12_381));
        var wrongCommitment = ConfidentialPoints.transferInputs(in, Note.of(BOB, 700), Note.of(ALICE, 300));
        var other = PedersenCommitment.commit(BigInteger.valueOf(700), PedersenCommitment.randomBlinding(new SecureRandom())).normalized();
        wrongCommitment.out1U(other.affineU()).out1V(other.affineV());
        assertThrows(RuntimeException.class, () -> circuit.calculateWitness(wrongCommitment.toWitnessMap(), CurveId.BLS12_381));
        // Wraparound: l − 1 = (l − 6) + 5 balances mod l, but l − 1 is not a 64-bit amount.
        BigInteger lMinusOne = JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.ONE);
        BigInteger r = PedersenCommitment.randomBlinding(new SecureRandom());
        var huge = PedersenCommitment.commit(lMinusOne, r).normalized();
        var wrapped = ConfidentialPoints.transferInputs(in, Note.of(BOB, 5), Note.of(ALICE, 0))
                .inAmount(lMinusOne).inBlinding(r).inU(huge.affineU()).inV(huge.affineV());
        assertThrows(RuntimeException.class, () -> circuit.calculateWitness(wrapped.toWitnessMap(), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("Redeem: in = change + price proves; a different price or an oversized price is rejected")
    void redeemProvesAndRejects() {
        Note in = Note.of(ALICE, 500), change = Note.of(ALICE, 380);
        var inputs = ConfidentialPoints.redeemInputs(in, change, 120);
        var proof = points.proveRedeem(in, change, 120);
        List<BigInteger> pub = PointsRedeemProofCircuit.publicInputs(inputs);
        assertTrue(points.redeemCircuit().verify(proof, pub));
        List<BigInteger> cheaper = new ArrayList<>(pub);
        cheaper.set(4, BigInteger.valueOf(119));
        assertFalse(points.redeemCircuit().verify(proof, cheaper), "a proof for 120 must not pay 119");

        var circuit = points.redeemCircuit().circuit();
        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381));
        assertThrows(RuntimeException.class, () -> circuit.calculateWitness(
                ConfidentialPoints.redeemInputs(in, change, 121).toWitnessMap(), CurveId.BLS12_381));
        // Isolate the price's 32-bit range: in = change + 2^32 balances, but the price is too wide.
        Note big = Note.of(ALICE, (1L << 32) + 380);
        assertThrows(RuntimeException.class, () -> circuit.calculateWitness(
                ConfidentialPoints.redeemInputs(big, change, 0).price(BigInteger.ONE.shiftLeft(32)).toWitnessMap(),
                CurveId.BLS12_381));
        System.out.println("[points-redeem] constraints: " + points.redeemCircuit().numConstraints());
    }

    static byte[] filled(byte b) {
        byte[] out = new byte[28];
        Arrays.fill(out, b);
        return out;
    }
}
