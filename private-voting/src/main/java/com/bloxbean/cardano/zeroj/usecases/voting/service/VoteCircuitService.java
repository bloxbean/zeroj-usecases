package com.bloxbean.cardano.zeroj.usecases.voting.service;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupCache;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.usecases.voting.circuit.PrivateVoteProofCircuit;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class VoteCircuitService {

    private static final Logger log = LoggerFactory.getLogger(VoteCircuitService.class);
    private static final BigInteger PRIME = FieldConfig.BLS12_381.prime();
    private static final String CACHE_DIR = "./data";

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
        log.info("Compiling private vote circuit (treeDepth={})...", treeDepth);

        circuit = PrivateVoteProofCircuit.build(treeDepth);
        r1cs = circuit.compileR1CS(CurveId.BLS12_381);

        log.info("Circuit compiled: {} constraints, {} wires, {} public inputs",
                r1cs.numConstraints(), r1cs.numWires(), r1cs.numPublicInputs());

        constraints = r1cs.constraints();

        setupResult = loadOrRunSetup();

        log.info("Trusted setup complete. Ready to generate vote proofs.");
    }

    private Groth16SetupBLS381.SetupResult loadOrRunSetup() {
        Path cacheDir = Path.of(CACHE_DIR);
        Path setupCache = cacheDir.resolve("setup-voting.bin");
        try {
            Files.createDirectories(cacheDir);
            if (Files.exists(setupCache)) {
                long start = System.currentTimeMillis();
                var cached = Groth16SetupCache.loadBls12381Setup(setupCache);
                if (matchesCurrentCircuit(cached)) {
                    log.info("Setup loaded from cache in {}ms", System.currentTimeMillis() - start);
                    return cached;
                }
                log.warn("Setup cache shape does not match current circuit; regenerating");
            }
        } catch (Exception e) {
            log.warn("Setup cache load failed: {}", e.getMessage());
        }

        log.info("Running dev trusted setup (power={})...", potPower);
        var srs = PowersOfTauBLS381.generate(potPower);
        var setup = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                r1cs.numPublicInputs(), srs.tauScalar());
        try {
            Groth16SetupCache.saveBls12381Setup(setup, setupCache);
            log.info("Setup cached to {}", setupCache);
        } catch (Exception e) {
            log.warn("Setup cache save failed: {}", e.getMessage());
        }
        return setup;
    }

    private boolean matchesCurrentCircuit(Groth16SetupBLS381.SetupResult setup) {
        var pk = setup.provingKey();
        return pk.numPublic() == r1cs.numPublicInputs()
                && pk.pointsA().length == r1cs.numWires();
    }

    /**
     * Generate a ZK proof of a valid vote.
     */
    public ProofResult prove(BigInteger vote, BigInteger secretKey,
                              BigInteger electionId, BigInteger voterRoot,
                              BigInteger[] siblings, BigInteger[] pathBits) {

        if (siblings.length != treeDepth || pathBits.length != treeDepth) {
            throw new IllegalArgumentException("siblings and pathBits must have length " + treeDepth);
        }

        BigInteger nullifier = computeNullifier(secretKey, electionId);
        BigInteger commitment = computeCommitment(vote, nullifier);

        Map<String, List<BigInteger>> inputs = new HashMap<>();
        inputs.put("vote", List.of(vote));
        inputs.put("secretKey", List.of(secretKey));
        inputs.put("electionId", List.of(electionId));
        inputs.put("voterRoot", List.of(voterRoot));
        inputs.put("nullifier", List.of(nullifier));
        inputs.put("commitment", List.of(commitment));

        for (int i = 0; i < treeDepth; i++) {
            inputs.put("sibling_" + i, List.of(siblings[i]));
            inputs.put("pathBit_" + i, List.of(pathBits[i]));
        }

        BigInteger[] witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);

        var proof = Groth16ProverBLS381.prove(setupResult.provingKey(), witness,
                constraints, r1cs.numWires());

        return new ProofResult(proof, nullifier, commitment, witness);
    }

    public BigInteger computeNullifier(BigInteger secretKey, BigInteger electionId) {
        return computePoseidon(secretKey, electionId);
    }

    public BigInteger computeCommitment(BigInteger vote, BigInteger nullifier) {
        return computePoseidon(vote, nullifier);
    }

    public BigInteger computePublicKey(BigInteger secretKey) {
        return computePoseidon(secretKey, BigInteger.ZERO);
    }

    public Groth16SetupBLS381.SetupResult getSetupResult() {
        return setupResult;
    }

    public int getTreeDepth() {
        return treeDepth;
    }

    // --- Poseidon computation (standards-compatible BLS12-381, per ADR-0015) ---

    private final ConcurrentHashMap<String, BigInteger> poseidonCache = new ConcurrentHashMap<>();

    private BigInteger computePoseidon(BigInteger a, BigInteger b) {
        String key = a.toString(16) + ":" + b.toString(16);
        return poseidonCache.computeIfAbsent(key, k ->
                com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash.hash(
                        com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3.INSTANCE,
                        a, b));
    }

    public record ProofResult(
            Groth16ProofBLS381 proof,
            BigInteger nullifier,
            BigInteger commitment,
            BigInteger[] witness
    ) {}
}
