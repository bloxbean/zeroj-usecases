package com.bloxbean.cardano.zeroj.usecases.nft.service;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.usecases.nft.circuit.NFTOwnershipCircuit;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * ZK proof generation and verification for NFT ownership.
 *
 * <p>Compiles the circuit once at startup, performs trusted setup (dev),
 * and provides prove/verify methods for the REST API.</p>
 */
@Service
public class ProverService {

    private static final Logger log = LoggerFactory.getLogger(ProverService.class);

    @Value("${zk.tree-depth}")
    private int treeDepth;

    @Value("${zk.pot-power}")
    private int potPower;

    private CircuitBuilder circuit;
    private R1CSConstraintSystem r1cs;
    private List<R1CSConstraint> constraints;
    private Groth16SetupBLS381.SetupResult setupResult;

    @PostConstruct
    public void init() {
        log.info("Compiling NFT ownership circuit (treeDepth={})...", treeDepth);

        circuit = NFTOwnershipCircuit.build(treeDepth);
        r1cs = circuit.compileR1CS(CurveId.BLS12_381);

        log.info("Circuit compiled: {} constraints, {} wires, {} public inputs",
                r1cs.numConstraints(), r1cs.numWires(), r1cs.numPublicInputs());

        constraints = r1cs.constraints();

        // Dev/test trusted setup (single-party — NOT for production)
        log.info("Running dev trusted setup (power={})...", potPower);
        var srs = PowersOfTauBLS381.generate(potPower);
        setupResult = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                r1cs.numPublicInputs(), srs.tauScalar());

        log.info("Trusted setup complete. Ready to generate proofs.");
    }

    /**
     * Generate a ZK proof of NFT ownership.
     *
     * @param secretKey    holder's secret key (identifies the wallet)
     * @param tokenName    NFT asset name (identifies which NFT)
     * @param snapshotRoot current Merkle root from on-chain snapshot
     * @param contextId    context for nullifier (event ID, airdrop ID, etc.)
     * @param siblings     Merkle proof siblings (one per tree level)
     * @param pathBits     Merkle path direction bits (0=left, 1=right)
     * @return the generated proof
     */
    public ProofResult prove(BigInteger secretKey, BigInteger tokenName,
                              BigInteger snapshotRoot, BigInteger contextId,
                              BigInteger[] siblings, BigInteger[] pathBits) {

        if (siblings.length != treeDepth || pathBits.length != treeDepth) {
            throw new IllegalArgumentException("siblings and pathBits must have length " + treeDepth);
        }

        // Compute expected nullifier (for return value)
        BigInteger nullifier = computeNullifier(tokenName, contextId);

        // Build witness inputs
        Map<String, List<BigInteger>> inputs = new HashMap<>();
        inputs.put("secretKey", List.of(secretKey));
        inputs.put("tokenName", List.of(tokenName));
        inputs.put("snapshotRoot", List.of(snapshotRoot));
        inputs.put("contextId", List.of(contextId));
        inputs.put("isOwner", List.of(BigInteger.ONE));
        inputs.put("nullifier", List.of(nullifier));

        for (int i = 0; i < treeDepth; i++) {
            inputs.put("sibling_" + i, List.of(siblings[i]));
            inputs.put("pathBit_" + i, List.of(pathBits[i]));
        }

        // Calculate witness
        BigInteger[] witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);

        // Generate Groth16 proof (pure Java BLS12-381)
        var proof = Groth16ProverBLS381.prove(setupResult.provingKey(), witness,
                constraints, r1cs.numWires());

        return new ProofResult(proof, nullifier, witness);
    }

    /**
     * Verify a ZK proof off-chain via BLS12-381 pairing check.
     */
    public boolean verifyOffChain(Groth16ProofBLS381 proof, BigInteger snapshotRoot,
                                    BigInteger contextId, BigInteger nullifier) {
        var pk = setupResult.provingKey();
        var ic = setupResult.ic();

        // Public inputs: [snapshotRoot, contextId, isOwner, nullifier]
        BigInteger[] pubInputs = {snapshotRoot, contextId, BigInteger.ONE, nullifier};

        G1Point vkX = toG1(ic[0]);
        for (int i = 0; i < pubInputs.length; i++) {
            vkX = vkX.add(toG1(ic[i + 1]).scalarMul(pubInputs[i]));
        }

        return BLS12381Pairing.pairingCheck(
                new G1Point[]{toG1(proof.a()), toG1(pk.alphaG1()).negate(),
                              vkX.negate(), toG1(proof.c()).negate()},
                new G2Point[]{toG2(proof.b()), toG2(pk.betaG2()),
                              toG2(setupResult.gammaG2()), toG2(pk.deltaG2())});
    }

    /**
     * Compute the nullifier for a given token + context.
     */
    public BigInteger computeNullifier(BigInteger tokenName, BigInteger contextId) {
        // Poseidon(tokenName, contextId) — must match the circuit
        return computePoseidon(tokenName, contextId);
    }

    /**
     * Compute the owner hash from a secret key.
     */
    public BigInteger computeOwnerHash(BigInteger secretKey) {
        return computePoseidon(secretKey, BigInteger.ZERO);
    }

    /**
     * Compute a leaf hash: Poseidon(ownerHash, tokenName).
     */
    public BigInteger computeLeafHash(BigInteger ownerHash, BigInteger tokenName) {
        return computePoseidon(ownerHash, tokenName);
    }

    public Groth16SetupBLS381.SetupResult getSetupResult() {
        return setupResult;
    }

    public int getTreeDepth() {
        return treeDepth;
    }

    // --- Helpers ---

    private final java.util.concurrent.ConcurrentHashMap<String, BigInteger> poseidonCache =
            new java.util.concurrent.ConcurrentHashMap<>();

    /**
     * Compute Poseidon(a, b) over BLS12-381 using the standards-compatible preset.
     * Results are cached for performance. After ADR-0015, this delegates to
     * {@link com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash} —
     * no more reflection into {@code PoseidonConstants}.
     */
    private BigInteger computePoseidon(BigInteger a, BigInteger b) {
        String key = a.toString(16) + ":" + b.toString(16);
        return poseidonCache.computeIfAbsent(key, k ->
                com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash.hash(
                        com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3.INSTANCE,
                        a, b));
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

    /**
     * Result of ZK proof generation.
     */
    public record ProofResult(
            Groth16ProofBLS381 proof,
            BigInteger nullifier,
            BigInteger[] witness
    ) {}
}
