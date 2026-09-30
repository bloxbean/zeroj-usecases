package com.bloxbean.cardano.zeroj.usecases.airdrop.circuit;

import org.zeroj.api.CurveId;
import org.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import org.zeroj.circuit.lib.jubjub.InCircuitEdDSAJubjub;
import org.zeroj.circuit.lib.jubjub.JubjubMessage;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PersonhoodAirdropCircuitTest {

    private static final int DEV_POT_CAPACITY = 1 << 14;

    @Test
    void compatibilitySignatureSatisfiesRegisteredKeyCircuit() {
        var keypair = EdDSAJubjub.keypairFromSecret(BigInteger.valueOf(42));
        BigInteger personhoodId = BigInteger.valueOf(0x100).shiftLeft(160)
                .or(BigInteger.valueOf("Alice".hashCode() & 0xffffffffL));
        BigInteger epoch = BigInteger.ONE;
        BigInteger recipient = BigInteger.valueOf(99);

        BigInteger message = PoseidonHash.hash(
                PoseidonParamsBLS12_381T3.INSTANCE, personhoodId, BigInteger.ZERO);
        var signature = EdDSAJubjub.signCompatibilityOffline(
                keypair, canonicalMessage(message));
        var reduction = InCircuitEdDSAJubjub.witnessComputeKReduction(
                signature.r(), keypair.pk(), message);
        BigInteger nullifier = PoseidonHash.hash(
                PoseidonParamsBLS12_381T3.INSTANCE, personhoodId, epoch);

        var circuit = PersonhoodAirdropProofCircuit.build();
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        assertTrue(r1cs.numConstraints() <= DEV_POT_CAPACITY,
                () -> "personhood circuit needs " + r1cs.numConstraints()
                        + " rows, exceeding the power-14 dev SRS");
        Map<String, List<BigInteger>> inputs = new HashMap<>();
        inputs.put("pkU", List.of(keypair.pk().affineU()));
        inputs.put("pkV", List.of(keypair.pk().affineV()));
        inputs.put("epoch", List.of(epoch));
        inputs.put("nullifier", List.of(nullifier));
        inputs.put("recipient", List.of(recipient));
        inputs.put("eligible", List.of(BigInteger.ONE));
        inputs.put("personhoodId", List.of(personhoodId));
        inputs.put("sigRU", List.of(signature.r().affineU()));
        inputs.put("sigRV", List.of(signature.r().affineV()));
        inputs.put("sigS", List.of(signature.s()));
        inputs.put("kModL", List.of(reduction.kModL()));
        inputs.put("kQuotient", List.of(reduction.kQuotient()));

        BigInteger[] witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);
        assertArrayEquals(new BigInteger[]{
                        keypair.pk().affineU(), keypair.pk().affineV(), epoch,
                        nullifier, recipient, BigInteger.ONE
                },
                java.util.Arrays.copyOfRange(witness, 1, 7),
                "public witness order must match the on-chain verifier");
        assertAllConstraintsSatisfied(r1cs, witness);

        BigInteger[] changedRecipient = witness.clone();
        changedRecipient[5] = recipient.add(BigInteger.ONE);
        assertFalse(allConstraintsSatisfied(r1cs, changedRecipient),
                "a proof witness must be bound to its public recipient");
    }

    private static void assertAllConstraintsSatisfied(
            org.zeroj.circuit.r1cs.R1CSConstraintSystem r1cs,
            BigInteger[] witness) {
        for (int i = 0; i < r1cs.numConstraints(); i++) {
            var constraint = r1cs.constraints().get(i);
            BigInteger a = evaluate(constraint.a(), witness, r1cs.prime());
            BigInteger b = evaluate(constraint.b(), witness, r1cs.prime());
            BigInteger c = evaluate(constraint.c(), witness, r1cs.prime());
            assertEquals(c, a.multiply(b).mod(r1cs.prime()),
                    "unsatisfied BLS12-381 constraint " + i);
        }
    }

    private static boolean allConstraintsSatisfied(
            org.zeroj.circuit.r1cs.R1CSConstraintSystem r1cs,
            BigInteger[] witness) {
        for (var constraint : r1cs.constraints()) {
            BigInteger a = evaluate(constraint.a(), witness, r1cs.prime());
            BigInteger b = evaluate(constraint.b(), witness, r1cs.prime());
            BigInteger c = evaluate(constraint.c(), witness, r1cs.prime());
            if (!c.equals(a.multiply(b).mod(r1cs.prime()))) {
                return false;
            }
        }
        return true;
    }

    private static JubjubMessage canonicalMessage(BigInteger fieldElement) {
        byte[] raw = fieldElement.toByteArray();
        int sourceOffset = raw.length == JubjubMessage.CANONICAL_BYTES + 1
                && raw[0] == 0 ? 1 : 0;
        int length = raw.length - sourceOffset;
        byte[] canonical = new byte[JubjubMessage.CANONICAL_BYTES];
        System.arraycopy(raw, sourceOffset, canonical, canonical.length - length, length);
        return JubjubMessage.fromCanonicalFieldBytes(canonical);
    }

    private static BigInteger evaluate(
            Map<Integer, BigInteger> expression,
            BigInteger[] witness,
            BigInteger prime) {
        BigInteger value = BigInteger.ZERO;
        for (var term : expression.entrySet()) {
            value = value.add(term.getValue().multiply(witness[term.getKey()]));
        }
        return value.mod(prime);
    }
}
