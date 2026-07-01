package com.bloxbean.cardano.zeroj.usecases.nft;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.usecases.nft.circuit.NFTOwnershipProofCircuit;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the NFT ownership ZK circuit.
 * Verifies: circuit compilation, witness generation, proof generation, pairing verification.
 */
class CircuitTest {

    private static final BigInteger PRIME = FieldConfig.BLS12_381.prime();

    @Test
    void circuit_compiles() {
        var circuit = NFTOwnershipProofCircuit.build(3);
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);

        assertTrue(r1cs.numConstraints() > 0, "Should have constraints");
        assertEquals(4, r1cs.numPublicInputs(), "4 public: snapshotRoot, contextId, isOwner, nullifier");
        System.out.println("NFT ownership circuit (depth=3): " + r1cs.numConstraints() + " constraints");
    }

    @Test
    void circuit_proveAndVerify_depth3() {
        int depth = 3;
        var circuit = NFTOwnershipProofCircuit.build(depth);
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);

        var constraints = r1cs.constraints();

        // Simulate: holder with secretKey=42, tokenName=100
        BigInteger secretKey = BigInteger.valueOf(42);
        BigInteger tokenName = BigInteger.valueOf(100);
        BigInteger contextId = BigInteger.valueOf(999);

        // Compute owner hash and leaf
        BigInteger ownerHash = poseidon(secretKey, BigInteger.ZERO);
        BigInteger leaf = poseidon(ownerHash, tokenName);

        // Build a minimal Merkle tree (depth=3 = 8 leaves)
        // Place our leaf at index 0, fill rest with dummy leaves
        BigInteger[] leaves = new BigInteger[8];
        leaves[0] = leaf;
        for (int i = 1; i < 8; i++) {
            leaves[i] = poseidon(BigInteger.valueOf(i + 1000), BigInteger.valueOf(i + 2000));
        }

        // Build tree bottom-up
        BigInteger[][] tree = new BigInteger[depth + 1][];
        tree[0] = leaves;
        for (int level = 1; level <= depth; level++) {
            int size = tree[level - 1].length / 2;
            tree[level] = new BigInteger[size];
            for (int i = 0; i < size; i++) {
                tree[level][i] = poseidon(tree[level - 1][2 * i], tree[level - 1][2 * i + 1]);
            }
        }
        BigInteger root = tree[depth][0];

        // Extract siblings and path for leaf at index 0
        BigInteger[] siblings = new BigInteger[depth];
        BigInteger[] pathBits = new BigInteger[depth];
        int index = 0;
        for (int i = 0; i < depth; i++) {
            int siblingIdx = (index % 2 == 0) ? index + 1 : index - 1;
            siblings[i] = tree[i][siblingIdx];
            pathBits[i] = BigInteger.valueOf(index % 2);
            index /= 2;
        }

        // Compute expected nullifier
        BigInteger nullifier = poseidon(tokenName, contextId);

        // Build witness
        Map<String, List<BigInteger>> inputs = new HashMap<>();
        inputs.put("secretKey", List.of(secretKey));
        inputs.put("tokenName", List.of(tokenName));
        inputs.put("snapshotRoot", List.of(root));
        inputs.put("contextId", List.of(contextId));
        inputs.put("isOwner", List.of(BigInteger.ONE));
        inputs.put("nullifier", List.of(nullifier));
        for (int i = 0; i < depth; i++) {
            inputs.put("sibling_" + i, List.of(siblings[i]));
            inputs.put("pathBit_" + i, List.of(pathBits[i]));
        }

        BigInteger[] witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);
        assertNotNull(witness);

        // Setup + prove
        var srs = PowersOfTauBLS381.generate(13);
        var setup = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                r1cs.numPublicInputs(), srs.tauScalar());

        var proof = Groth16ProverBLS381.prove(setup.provingKey(), witness,
                constraints, r1cs.numWires());

        assertTrue(proof.a().isOnCurve());
        assertTrue(proof.b().isOnCurve());
        assertTrue(proof.c().isOnCurve());

        // Verify off-chain via pairing
        var pk = setup.provingKey();
        var ic = setup.ic();
        BigInteger[] pubInputs = {root, contextId, BigInteger.ONE, nullifier};

        G1Point vkX = toG1(ic[0]);
        for (int i = 0; i < pubInputs.length; i++) {
            vkX = vkX.add(toG1(ic[i + 1]).scalarMul(pubInputs[i]));
        }

        boolean verified = BLS12381Pairing.pairingCheck(
                new G1Point[]{toG1(proof.a()), toG1(pk.alphaG1()).negate(),
                              vkX.negate(), toG1(proof.c()).negate()},
                new G2Point[]{toG2(proof.b()), toG2(pk.betaG2()),
                              toG2(setup.gammaG2()), toG2(pk.deltaG2())});

        assertTrue(verified, "NFT ownership ZK proof must verify via BLS12-381 pairing");
        System.out.println("NFT ownership proof: VERIFIED (depth=" + depth + ")");
    }

    // --- Poseidon helper (BLS12-381 Fr, standards-compatible per ADR-0015) ---

    private BigInteger poseidon(BigInteger a, BigInteger b) {
        return com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash.hash(
                com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3.INSTANCE,
                a, b);
    }

    private static G1Point toG1(com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1 p) {
        if (p.isInfinity()) return G1Point.INFINITY;
        return new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    private static G2Point toG2(com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2 p) {
        if (p.isInfinity()) return G2Point.INFINITY;
        return new G2Point(
                Fp2.of(Fp.of(p.x().reBigInt()), Fp.of(p.x().imBigInt())),
                Fp2.of(Fp.of(p.y().reBigInt()), Fp.of(p.y().imBigInt())));
    }
}
