package com.bloxbean.cardano.zeroj.usecases.nft;

import com.bloxbean.cardano.zeroj.usecases.nft.circuit.NFTOwnershipProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.nft.service.NftScheme;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.api.R1CSConstraint;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.FieldConfig;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The NFT ownership circuit, version 2 (ADR-0009 D2): the nullifier is
 * {@code Poseidon(Poseidon(s, t), contextId)}. Expected values come from ZeroJ's
 * {@link PoseidonHash}; the negatives show that a nullifier for another secret, token or context,
 * or the version 1 nullifier, is not accepted for a valid membership.
 */
class CircuitTest {

    private static final BigInteger PRIME = FieldConfig.BLS12_381.prime();
    /** Wire layout: [1, snapshotRoot, contextId, isOwner, nullifier, ...]. */
    private static final int NULLIFIER_WIRE = 4;

    private static NftFixture fx;
    private static CircuitBuilder circuit;
    private static R1CSConstraintSystem r1cs;

    @BeforeAll
    static void setup() {
        fx = NftFixture.get();
        circuit = NFTOwnershipProofCircuit.build(NftFixture.DEPTH);
        r1cs = circuit.compileR1CS(CurveId.BLS12_381);
    }

    @Test
    void circuit_compiles() {
        assertTrue(r1cs.numConstraints() > 0, "Should have constraints");
        assertEquals(4, r1cs.numPublicInputs(), "4 public: snapshotRoot, contextId, isOwner, nullifier");
        assertEquals(2, NFTOwnershipProofCircuit.CIRCUIT_VERSION);
        assertEquals(NftScheme.CIRCUIT_VERSION, NFTOwnershipProofCircuit.CIRCUIT_VERSION);
        System.out.println("NFT ownership circuit v2 (depth=" + NftFixture.DEPTH + "): "
                + r1cs.numConstraints() + " constraints");
    }

    @Test
    @DisplayName("The host nullifier is Poseidon(Poseidon(s, t), contextId), not the version 1 Poseidon(t, contextId)")
    void hostNullifierFormula() {
        BigInteger s = NftFixture.SECRETS.get(0);
        BigInteger t = NftFixture.token(0);
        BigInteger inner = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, s, t);
        BigInteger expected = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, inner, NftFixture.CONTEXT);
        assertEquals(expected, NftScheme.nullifier(s, t, NftFixture.CONTEXT));
        assertNotEquals(PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, t, NftFixture.CONTEXT), expected);
        // The leaf is unchanged from version 1.
        BigInteger owner = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, s, BigInteger.ZERO);
        assertEquals(PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, owner, t), NftScheme.leaf(s, t));
    }

    @Test
    @DisplayName("An honest proof verifies, and its public inputs are [root, context, 1, nullifier]")
    void honestProofVerifies() {
        var result = fx.prove(1);
        BigInteger expected = NftScheme.nullifier(NftFixture.SECRETS.get(1), NftFixture.token(1), NftFixture.CONTEXT);
        assertEquals(expected, result.nullifier());
        assertEquals(fx.root(), result.witness()[1]);
        assertEquals(NftFixture.CONTEXT, result.witness()[2]);
        assertEquals(BigInteger.ONE, result.witness()[3]);
        assertEquals(expected, result.witness()[NULLIFIER_WIRE]);
        assertTrue(satisfied(result.witness()), "the honest witness satisfies the R1CS");
        assertTrue(fx.prover.verifyOffChain(result.proof(), fx.root(), NftFixture.CONTEXT, expected));

        // The same proof does not verify for another context, nullifier or root.
        assertFalse(fx.prover.verifyOffChain(result.proof(), fx.root(), NftFixture.CONTEXT.add(BigInteger.ONE), expected));
        assertFalse(fx.prover.verifyOffChain(result.proof(), fx.root(), NftFixture.CONTEXT, expected.add(BigInteger.ONE)));
        assertFalse(fx.prover.verifyOffChain(result.proof(), fx.root().add(BigInteger.ONE), NftFixture.CONTEXT, expected));
    }

    enum NullifierMutation { WRONG_SECRET, WRONG_TOKEN, WRONG_CONTEXT, VERSION_1 }

    @Test
    @DisplayName("For a valid membership, a nullifier for a wrong secret, token or context, or the v1 nullifier, is refused")
    void wrongNullifierRefused() {
        int index = 0;
        BigInteger s = NftFixture.SECRETS.get(index);
        BigInteger t = NftFixture.token(index);
        assertDoesNotThrow(() -> circuit.calculateWitness(
                inputs(index, NftScheme.nullifier(s, t, NftFixture.CONTEXT)), CurveId.BLS12_381));

        for (NullifierMutation m : NullifierMutation.values()) {
            BigInteger wrong = switch (m) {
                case WRONG_SECRET -> NftScheme.nullifier(NftFixture.SECRETS.get(1), t, NftFixture.CONTEXT);
                case WRONG_TOKEN -> NftScheme.nullifier(s, NftFixture.token(1), NftFixture.CONTEXT);
                case WRONG_CONTEXT -> NftScheme.nullifier(s, t, NftScheme.contextId("another-event"));
                case VERSION_1 -> NftScheme.poseidon(t, NftFixture.CONTEXT);
            };
            assertThrows(RuntimeException.class,
                    () -> circuit.calculateWitness(inputs(index, wrong), CurveId.BLS12_381),
                    "witness accepted nullifier mutation " + m);
        }
    }

    @Test
    @DisplayName("A forged nullifier wire in an otherwise honest witness does not satisfy the R1CS")
    void forgedNullifierWireUnsatisfied() {
        BigInteger[] witness = fx.prove(2).witness().clone();
        witness[NULLIFIER_WIRE] = NftScheme.nullifier(NftFixture.SECRETS.get(2), NftFixture.token(2),
                NftScheme.contextId("another-event"));
        assertFalse(satisfied(witness));
    }

    @Test
    @DisplayName("A holder of a token in the snapshot cannot prove with another holder's token")
    void otherTokenRefused() {
        // Holder 0's secret with holder 1's token: no such leaf in the tree.
        var p = NftFixture.path(fx.tree, 1);
        assertThrows(RuntimeException.class, () -> fx.prover.prove(NftFixture.SECRETS.get(0), NftFixture.token(1),
                fx.root(), NftFixture.CONTEXT, p[0], p[1]));
    }

    private Map<String, List<BigInteger>> inputs(int index, BigInteger nullifier) {
        var p = NftFixture.path(fx.tree, index);
        Map<String, List<BigInteger>> in = new HashMap<>();
        in.put("secretKey", List.of(NftFixture.SECRETS.get(index)));
        in.put("tokenName", List.of(NftFixture.token(index)));
        in.put("snapshotRoot", List.of(fx.root()));
        in.put("contextId", List.of(NftFixture.CONTEXT));
        in.put("isOwner", List.of(BigInteger.ONE));
        in.put("nullifier", List.of(nullifier));
        for (int i = 0; i < NftFixture.DEPTH; i++) {
            in.put("sibling_" + i, List.of(p[0][i]));
            in.put("pathBit_" + i, List.of(p[1][i]));
        }
        return in;
    }

    private static boolean satisfied(BigInteger[] w) {
        for (R1CSConstraint c : r1cs.constraints()) {
            BigInteger a = dot(c.a(), w), b = dot(c.b(), w), cc = dot(c.c(), w);
            if (!a.multiply(b).mod(PRIME).equals(cc)) return false;
        }
        return true;
    }

    private static BigInteger dot(Map<Integer, BigInteger> lc, BigInteger[] w) {
        BigInteger sum = BigInteger.ZERO;
        for (var e : lc.entrySet()) sum = sum.add(e.getValue().multiply(w[e.getKey()]));
        return sum.mod(PRIME);
    }
}
