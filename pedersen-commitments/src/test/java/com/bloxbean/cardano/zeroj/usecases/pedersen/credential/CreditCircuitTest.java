package com.bloxbean.cardano.zeroj.usecases.pedersen.credential;

import com.bloxbean.cardano.zeroj.usecases.pedersen.credential.CreditGate.Profile;
import com.bloxbean.cardano.zeroj.usecases.pedersen.credential.circuit.CreditProfileProof;
import com.bloxbean.cardano.zeroj.usecases.pedersen.credential.circuit.CreditProfileProofCircuit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.lib.jubjub.PedersenVectorCommitment;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema.Entry;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Demo B's relation: predicates over a committed profile, bound to its schema. */
class CreditCircuitTest {

    static final long MIN_INCOME = 50_000;
    static final int MIN_SCORE = 650;
    private static CreditGate gate;

    @BeforeAll
    static void setup() {
        gate = new CreditGate();
    }

    @Test
    @DisplayName("A qualifying profile proves; the proof is bound to σ, the commitment and both thresholds")
    void qualifyingProfileProves() {
        Profile p = Profile.of(85_000, 720, 1990, 356);
        var proof = gate.prove(p, MIN_INCOME, MIN_SCORE);
        List<BigInteger> pub = CreditProfileProofCircuit.publicInputs(CreditGate.inputs(p, MIN_INCOME, MIN_SCORE));
        assertTrue(gate.circuit().verify(proof, pub));
        for (int i = 0; i < pub.size(); i++) {
            List<BigInteger> changed = new ArrayList<>(pub);
            changed.set(i, changed.get(i).add(BigInteger.ONE));
            assertFalse(gate.circuit().verify(proof, changed), "public input " + i + " not bound");
        }
        System.out.println("[credit-profile-check] constraints: " + gate.circuit().numConstraints());
    }

    @Test
    @DisplayName("Thresholds are inclusive; one below either threshold has no witness")
    void thresholds() {
        var circuit = gate.circuit().circuit();
        assertDoesNotThrow(() -> circuit.calculateWitness(
                CreditGate.inputs(Profile.of(MIN_INCOME, MIN_SCORE, 2000, 1), MIN_INCOME, MIN_SCORE).toWitnessMap(),
                CurveId.BLS12_381));
        assertThrows(RuntimeException.class, () -> circuit.calculateWitness(
                CreditGate.inputs(Profile.of(MIN_INCOME - 1, 800, 2000, 1), MIN_INCOME, MIN_SCORE).toWitnessMap(),
                CurveId.BLS12_381));
        assertThrows(RuntimeException.class, () -> circuit.calculateWitness(
                CreditGate.inputs(Profile.of(900_000, MIN_SCORE - 1, 2000, 1), MIN_INCOME, MIN_SCORE).toWitnessMap(),
                CurveId.BLS12_381));
    }

    @Test
    @DisplayName("Schema binding: another schema's digest, or a commitment made under another schema, has no witness")
    void schemaBinding() {
        var circuit = gate.circuit().circuit();
        Profile p = Profile.of(85_000, 720, 1990, 356);
        // Same shape, different meaning: "score" first. Its digest is not this circuit's σ.
        PedersenVectorSchema other = PedersenVectorSchema.of("zeroj.demo.credit-profile", 2, List.of(
                new Entry("income", 64), new Entry("credit_score", 16), new Entry("birth_year", 16), new Entry("country", 16)));
        assertThrows(RuntimeException.class, () -> circuit.calculateWitness(
                CreditGate.inputs(p, MIN_INCOME, MIN_SCORE).schemaDigest(other.digest()).toWitnessMap(), CurveId.BLS12_381));
        // The commitment of other attribute values: the opening does not match (u, v).
        var c = PedersenVectorCommitment.commit(CreditProfileProof.SCHEMA,
                List.of(BigInteger.valueOf(85_000), BigInteger.valueOf(720), BigInteger.valueOf(1991), BigInteger.valueOf(356)),
                p.blinding()).point().normalized();
        assertThrows(RuntimeException.class, () -> circuit.calculateWitness(
                CreditGate.inputs(p, MIN_INCOME, MIN_SCORE).u(c.affineU()).v(c.affineV()).toWitnessMap(), CurveId.BLS12_381));
    }
}
