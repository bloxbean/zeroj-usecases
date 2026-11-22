package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import com.bloxbean.cardano.zeroj.usecases.pedersen.common.KeyedCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.ProofBytes;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.circuit.KeyPossessionProofCircuit;
import org.zeroj.circuit.lib.jubjub.DleqStatement;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Fields;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Proofs of possession for registry keys (ADR-0007 N7): Groth16 over {@code R_dleq} for a
 * library-built {@link DleqStatement}, bound to a context {@link #ctx}, stored as 192 compressed
 * bytes.
 */
public final class KeyPossession {

    /** The key types a registry entry holds. */
    public enum KeyType {
        ELGAMAL((byte) 0x01), VIEWING((byte) 0x02);

        final byte tag;

        KeyType(byte tag) {
            this.tag = tag;
        }
    }

    private static final byte[] DOMAIN = "zeroj.usecases.key-possession.v1".getBytes(StandardCharsets.US_ASCII);

    private final KeyedCircuit circuit;

    public KeyPossession() {
        circuit = KeyedCircuit.compile("key-possession", KeyPossessionProofCircuit.build());
    }

    /** {@code DOMAIN ‖ type}: the prefix the registry hashes with its policy and the auditor. */
    public static byte[] ctxPrefix(KeyType type) {
        return Fields.concat(DOMAIN, new byte[]{type.tag});
    }

    /**
     * {@code ctx(type) = OS2IP(blake2b_256(DOMAIN ‖ type ‖ registryPolicy ‖ auditor)[0..30])}, 31
     * bytes, so below {@code p}. The registry validator computes the same value on-chain.
     */
    public static BigInteger ctx(KeyType type, byte[] registryPolicy, byte[] auditor) {
        if (registryPolicy.length != 28 || auditor.length != 28) {
            throw new IllegalArgumentException("policy and auditor are 28-byte hashes");
        }
        byte[] digest = Blake2bUtil.blake2bHash256(Fields.concat(ctxPrefix(type), registryPolicy, auditor));
        return new BigInteger(1, Arrays.copyOf(digest, 31));
    }

    /** The proof's public inputs: {@code ctx} then the statement's six, in order. */
    public static List<BigInteger> publicInputs(BigInteger ctx, DleqStatement statement) {
        List<BigInteger> out = new ArrayList<>(7);
        out.add(ctx);
        out.addAll(statement.publicInputs());
        return out;
    }

    /** Proves {@code statement} with its secret under {@code ctx}; the statement's inputs are used verbatim. */
    public byte[] prove(BigInteger ctx, DleqStatement statement, BigInteger secret) {
        List<BigInteger> pub = statement.publicInputs();
        var inputs = KeyPossessionProofCircuit.inputs()
                .ctx(ctx).ctxSquared(ctx.multiply(ctx).mod(Fields.FR))
                .baseU(pub.get(0)).baseV(pub.get(1))
                .keyU(pub.get(2)).keyV(pub.get(3))
                .shareU(pub.get(4)).shareV(pub.get(5))
                .secret(secret);
        return ProofBytes.encode(circuit.prove(inputs.toWitnessMap()));
    }

    /**
     * Verifies a stored proof for exactly the possession statement the library built, under the
     * verifier's own {@code ctx}. A malformed proof is a failed verification, never an exception.
     */
    public boolean verifyPossession(BigInteger ctx, DleqStatement statement, byte[] proof) {
        if (statement == null || statement.kind() != DleqStatement.Kind.POSSESSION) return false;
        try {
            return circuit.verify(ProofBytes.decode(proof), publicInputs(ctx, statement));
        } catch (RuntimeException e) {
            return false;
        }
    }

    public KeyedCircuit circuit() {
        return circuit;
    }
}
