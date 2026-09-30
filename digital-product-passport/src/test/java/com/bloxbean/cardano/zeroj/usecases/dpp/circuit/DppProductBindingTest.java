package com.bloxbean.cardano.zeroj.usecases.dpp.circuit;

import com.bloxbean.cardano.zeroj.usecases.dpp.mpf.PoseidonCompute;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;
import org.zeroj.bls12381.pairing.BLS12381Pairing;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.crypto.groth16.Groth16ProverBLS381;
import org.zeroj.crypto.setup.Groth16SetupBLS381;
import org.zeroj.crypto.setup.PowersOfTauBLS381;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The country-membership and inspection-chain proofs are bound to their product: the auditor's
 * commitment ties the secret country / inspection log to {@code productId}. Without that binding
 * ZeroJ's setup refuses the circuits (ADR-0045: {@code productId} unconstrained, IC[1] at infinity,
 * so one proof would verify for any product).
 */
class DppProductBindingTest {

    private static final BigInteger AUDITOR_SECRET = BigInteger.valueOf(777777);
    private static final BigInteger PRODUCT = new BigInteger(1, "BAT-SN001".getBytes());
    private static final BigInteger OTHER_PRODUCT = new BigInteger(1, "BAT-SN002".getBytes());

    // Small trees in the ProductService layout: Poseidon(left, right) parents, pathBit = index % 2
    private static final int COUNTRY_DEPTH = 2;
    private static final List<BigInteger> EU = List.of(BigInteger.valueOf(276), BigInteger.valueOf(250),
            BigInteger.valueOf(380), BigInteger.valueOf(724)); // DE, FR, IT, ES
    private static final BigInteger FR = BigInteger.valueOf(250);
    private static final BigInteger US = BigInteger.valueOf(840);

    private static final int CHECKPOINTS = 2;
    private static final int INSPECTOR_DEPTH = 2;
    private static final List<BigInteger> INSPECTOR_KEYS = List.of(BigInteger.valueOf(1001),
            BigInteger.valueOf(1002), BigInteger.valueOf(1003), BigInteger.valueOf(1004));

    private static BigInteger[][] countryTree;
    private static BigInteger[][] inspectorTree;

    @BeforeAll
    static void trees() {
        countryTree = merkleTree(EU.toArray(BigInteger[]::new), COUNTRY_DEPTH);
        BigInteger[] inspectorLeaves = INSPECTOR_KEYS.stream()
                .map(k -> PoseidonCompute.poseidon(k, BigInteger.ZERO)).toArray(BigInteger[]::new);
        inspectorTree = merkleTree(inspectorLeaves, INSPECTOR_DEPTH);
    }

    // ---------------------------------------------------------------- country membership

    @Test
    void countryProofVerifiesForItsProductAndNotForAnother() {
        CircuitBuilder circuit = CountryMembershipCircuit.build(COUNTRY_DEPTH);
        var inputs = countryInputs(FR, PRODUCT, auditorHash(PRODUCT, FR), 1);

        Proven proven = setupAndProve(circuit, inputs);
        assertEquals(4, proven.publicInputs().length, "productId, countryRoot, auditorHash, isMember");
        assertTrue(verify(proven, proven.publicInputs()), "the proof verifies for its own product");

        BigInteger[] otherProduct = proven.publicInputs().clone();
        otherProduct[0] = OTHER_PRODUCT;
        assertFalse(verify(proven, otherProduct), "the same proof must not verify for another product");
    }

    @Test
    void countryCommittedForAnotherProductIsRejected() {
        var inputs = countryInputs(FR, PRODUCT, auditorHash(OTHER_PRODUCT, FR), 1);
        assertThrows(ArithmeticException.class, () -> witness(CountryMembershipCircuit.build(COUNTRY_DEPTH), inputs));
    }

    @Test
    void provenCountryMustBeTheCommittedOne() {
        // the auditor committed DE for this product; the prover tries FR (also in the EU set)
        var inputs = countryInputs(FR, PRODUCT, auditorHash(PRODUCT, BigInteger.valueOf(276)), 1);
        assertThrows(ArithmeticException.class, () -> witness(CountryMembershipCircuit.build(COUNTRY_DEPTH), inputs));
    }

    @Test
    void countryOutsideTheSetIsRejectedEvenWhenCommitted() {
        // committed US, but US is not in the EU tree: borrow FR's Merkle path
        var inputs = countryInputs(FR, PRODUCT, auditorHash(PRODUCT, US), 1);
        inputs.put("country", List.of(US));
        assertThrows(ArithmeticException.class, () -> witness(CountryMembershipCircuit.build(COUNTRY_DEPTH), inputs));
    }

    // ---------------------------------------------------------------- inspection chain

    @Test
    void inspectionProofVerifiesForItsProductAndNotForAnother() {
        CircuitBuilder circuit = InspectionChainCircuit.build(CHECKPOINTS, INSPECTOR_DEPTH);
        List<BigInteger> keys = List.of(INSPECTOR_KEYS.get(0), INSPECTOR_KEYS.get(2));
        List<BigInteger> times = List.of(BigInteger.valueOf(1000), BigInteger.valueOf(1100));
        var inputs = inspectionInputs(PRODUCT, keys, times, logHash(PRODUCT, keys, times));

        Proven proven = setupAndProve(circuit, inputs);
        assertEquals(4, proven.publicInputs().length, "productId, inspectorRoot, auditorHash, allPassed");
        assertTrue(verify(proven, proven.publicInputs()), "the proof verifies for its own product");

        BigInteger[] otherProduct = proven.publicInputs().clone();
        otherProduct[0] = OTHER_PRODUCT;
        assertFalse(verify(proven, otherProduct), "the same proof must not verify for another product");
    }

    @Test
    void inspectionLogCommittedForAnotherProductIsRejected() {
        List<BigInteger> keys = List.of(INSPECTOR_KEYS.get(0), INSPECTOR_KEYS.get(2));
        List<BigInteger> times = List.of(BigInteger.valueOf(1000), BigInteger.valueOf(1100));
        var inputs = inspectionInputs(PRODUCT, keys, times, logHash(OTHER_PRODUCT, keys, times));
        assertThrows(ArithmeticException.class,
                () -> witness(InspectionChainCircuit.build(CHECKPOINTS, INSPECTOR_DEPTH), inputs));
    }

    @Test
    void inspectionsMustBeTheCommittedOnes() {
        // the auditor committed inspector 0 then 2; the prover swaps in inspector 1 (also approved)
        List<BigInteger> committedKeys = List.of(INSPECTOR_KEYS.get(0), INSPECTOR_KEYS.get(2));
        List<BigInteger> provenKeys = List.of(INSPECTOR_KEYS.get(0), INSPECTOR_KEYS.get(1));
        List<BigInteger> times = List.of(BigInteger.valueOf(1000), BigInteger.valueOf(1100));
        var inputs = inspectionInputs(PRODUCT, provenKeys, times, logHash(PRODUCT, committedKeys, times));
        assertThrows(ArithmeticException.class,
                () -> witness(InspectionChainCircuit.build(CHECKPOINTS, INSPECTOR_DEPTH), inputs));
    }

    @Test
    void outOfOrderInspectionsAreRejectedEvenWhenCommitted() {
        List<BigInteger> keys = List.of(INSPECTOR_KEYS.get(0), INSPECTOR_KEYS.get(2));
        List<BigInteger> times = List.of(BigInteger.valueOf(1100), BigInteger.valueOf(1000));
        var inputs = inspectionInputs(PRODUCT, keys, times, logHash(PRODUCT, keys, times));
        assertThrows(ArithmeticException.class,
                () -> witness(InspectionChainCircuit.build(CHECKPOINTS, INSPECTOR_DEPTH), inputs));
    }

    // ---------------------------------------------------------------- helpers

    private record Proven(Groth16SetupBLS381.SetupResult setup, Groth16ProofBLS381 proof, BigInteger[] publicInputs) {}

    private static BigInteger auditorHash(BigInteger productId, BigInteger country) {
        return PoseidonCompute.poseidon(AUDITOR_SECRET, PoseidonCompute.poseidon(productId, country));
    }

    private static BigInteger logHash(BigInteger productId, List<BigInteger> keys, List<BigInteger> times) {
        BigInteger log = BigInteger.ZERO;
        for (int i = 0; i < keys.size(); i++) {
            BigInteger inspectorHash = PoseidonCompute.poseidon(keys.get(i), BigInteger.ZERO);
            log = PoseidonCompute.poseidon(log, PoseidonCompute.poseidon(inspectorHash, times.get(i)));
        }
        return PoseidonCompute.poseidon(AUDITOR_SECRET, PoseidonCompute.poseidon(productId, log));
    }

    private static Map<String, List<BigInteger>> countryInputs(BigInteger country, BigInteger productId,
                                                               BigInteger auditorHash, int isMember) {
        var inputs = new HashMap<String, List<BigInteger>>();
        inputs.put("country", List.of(country));
        inputs.put("auditorSecret", List.of(AUDITOR_SECRET));
        inputs.put("productId", List.of(productId));
        inputs.put("countryRoot", List.of(countryTree[COUNTRY_DEPTH][0]));
        inputs.put("auditorHash", List.of(auditorHash));
        inputs.put("isMember", List.of(BigInteger.valueOf(isMember)));
        int index = EU.indexOf(country);
        BigInteger[][] path = path(countryTree, COUNTRY_DEPTH, index);
        for (int i = 0; i < COUNTRY_DEPTH; i++) {
            inputs.put("sibling_" + i, List.of(path[0][i]));
            inputs.put("pathBit_" + i, List.of(path[1][i]));
        }
        return inputs;
    }

    private static Map<String, List<BigInteger>> inspectionInputs(BigInteger productId, List<BigInteger> keys,
                                                                  List<BigInteger> times, BigInteger auditorHash) {
        var inputs = new HashMap<String, List<BigInteger>>();
        inputs.put("productId", List.of(productId));
        inputs.put("inspectorRoot", List.of(inspectorTree[INSPECTOR_DEPTH][0]));
        inputs.put("auditorSecret", List.of(AUDITOR_SECRET));
        inputs.put("auditorHash", List.of(auditorHash));
        inputs.put("allPassed", List.of(BigInteger.ONE));
        for (int i = 0; i < keys.size(); i++) {
            inputs.put("passed_" + i, List.of(BigInteger.ONE));
            inputs.put("timestamp_" + i, List.of(times.get(i)));
            inputs.put("inspectorKey_" + i, List.of(keys.get(i)));
            BigInteger[][] path = path(inspectorTree, INSPECTOR_DEPTH, INSPECTOR_KEYS.indexOf(keys.get(i)));
            for (int j = 0; j < INSPECTOR_DEPTH; j++) {
                inputs.put("insp_sibling_" + i + "_" + j, List.of(path[0][j]));
                inputs.put("insp_pathBit_" + i + "_" + j, List.of(path[1][j]));
            }
        }
        return inputs;
    }

    private static BigInteger[] witness(CircuitBuilder circuit, Map<String, List<BigInteger>> inputs) {
        return circuit.calculateWitness(inputs, CurveId.BLS12_381);
    }

    private static Proven setupAndProve(CircuitBuilder circuit, Map<String, List<BigInteger>> inputs) {
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        BigInteger tau = PowersOfTauBLS381.generate(4).tauScalar();
        var setup = Groth16SetupBLS381.setup(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(), tau);
        BigInteger[] witness = witness(circuit, inputs);
        var proof = Groth16ProverBLS381.prove(setup.provingKey(), witness, r1cs.constraints(), r1cs.numWires());
        return new Proven(setup, proof, Arrays.copyOfRange(witness, 1, 1 + r1cs.numPublicInputs()));
    }

    /** The Groth16 equation e(A,B) = e(alpha,beta) e(vkX,gamma) e(C,delta). */
    private static boolean verify(Proven proven, BigInteger[] publicInputs) {
        var pk = proven.setup().provingKey();
        AffineG1[] ic = proven.setup().ic();
        G1Point vkX = g1(ic[0]);
        for (int i = 0; i < publicInputs.length; i++) {
            vkX = vkX.add(g1(ic[i + 1]).scalarMul(publicInputs[i]));
        }
        var proof = proven.proof();
        return BLS12381Pairing.pairingCheck(
                new G1Point[]{g1(proof.a()), g1(pk.alphaG1()).negate(), vkX.negate(), g1(proof.c()).negate()},
                new G2Point[]{g2(proof.b()), g2(pk.betaG2()), g2(proven.setup().gammaG2()), g2(pk.deltaG2())});
    }

    private static BigInteger[][] merkleTree(BigInteger[] leaves, int depth) {
        var tree = new BigInteger[depth + 1][];
        tree[0] = new BigInteger[1 << depth];
        for (int i = 0; i < tree[0].length; i++) {
            tree[0][i] = i < leaves.length ? leaves[i] : BigInteger.ZERO;
        }
        for (int level = 1; level <= depth; level++) {
            tree[level] = new BigInteger[tree[level - 1].length / 2];
            for (int i = 0; i < tree[level].length; i++) {
                tree[level][i] = PoseidonCompute.poseidon(tree[level - 1][2 * i], tree[level - 1][2 * i + 1]);
            }
        }
        return tree;
    }

    /** Returns {siblings, pathBits}, as ProductService builds them. */
    private static BigInteger[][] path(BigInteger[][] tree, int depth, int index) {
        var siblings = new ArrayList<BigInteger>();
        var bits = new ArrayList<BigInteger>();
        for (int i = 0; i < depth; i++) {
            int sibling = (index % 2 == 0) ? index + 1 : index - 1;
            siblings.add(tree[i][sibling]);
            bits.add(BigInteger.valueOf(index % 2));
            index /= 2;
        }
        return new BigInteger[][]{siblings.toArray(BigInteger[]::new), bits.toArray(BigInteger[]::new)};
    }

    private static G1Point g1(AffineG1 p) {
        return p.isInfinity() ? G1Point.INFINITY : new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    private static G2Point g2(AffineG2 p) {
        return p.isInfinity() ? G2Point.INFINITY
                : new G2Point(Fp2.of(Fp.of(p.x().reBigInt()), Fp.of(p.x().imBigInt())),
                              Fp2.of(Fp.of(p.y().reBigInt()), Fp.of(p.y().imBigInt())));
    }
}
