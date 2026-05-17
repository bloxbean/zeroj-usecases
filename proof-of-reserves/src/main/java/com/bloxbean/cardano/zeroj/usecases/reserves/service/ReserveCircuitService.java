package com.bloxbean.cardano.zeroj.usecases.reserves.service;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PtauImporterBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.SetupCache;
import com.bloxbean.cardano.zeroj.usecases.reserves.circuit.SolvencyCircuit;
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

@Service
public class ReserveCircuitService {

    private static final Logger log = LoggerFactory.getLogger(ReserveCircuitService.class);
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
        PtauImporterBLS381.SRS srs = loadOrGenerateSrs();

        log.info("Compiling solvency circuit (treeDepth={}, {} accounts)...", treeDepth, 1 << treeDepth);

        circuit = SolvencyCircuit.build(treeDepth);
        r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        log.info("Circuit compiled: {} constraints, {} wires, {} public",
                r1cs.numConstraints(), r1cs.numWires(), r1cs.numPublicInputs());

        constraints = r1cs.constraints();

        // Setup with cache
        Path setupCache = Path.of(CACHE_DIR, "setup-solvency.bin");
        try {
            if (Files.exists(setupCache)) {
                long start = System.currentTimeMillis();
                setupResult = SetupCache.loadSetup(setupCache);
                log.info("Setup loaded from cache in {}ms", System.currentTimeMillis() - start);
            }
        } catch (Exception e) {
            log.warn("Cache load failed: {}", e.getMessage());
        }

        if (setupResult == null) {
            log.info("Running Groth16 phase 2 setup...");
            setupResult = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                    r1cs.numPublicInputs(), srs.tauScalar());
            try {
                SetupCache.saveSetup(setupResult, setupCache);
                log.info("Setup cached to {}", setupCache);
            } catch (Exception e) {
                log.warn("Cache save failed: {}", e.getMessage());
            }
        }

        log.info("Reserve circuit ready.");
    }

    private PtauImporterBLS381.SRS loadOrGenerateSrs() {
        Path srsCache = Path.of(CACHE_DIR, "srs.bin");
        try {
            if (Files.exists(srsCache)) {
                log.info("Loading SRS from cache...");
                long start = System.currentTimeMillis();
                var srs = SetupCache.loadSrs(srsCache);
                log.info("SRS loaded in {}ms", System.currentTimeMillis() - start);
                return srs;
            }
        } catch (Exception e) {
            log.warn("SRS cache load failed: {}", e.getMessage());
        }

        log.info("Generating SRS (power={})...", potPower);
        var srs = PowersOfTauBLS381.generate(potPower);
        try {
            Files.createDirectories(srsCache.getParent());
            SetupCache.saveSrs(srs, srsCache);
            log.info("SRS cached to {}", srsCache);
        } catch (Exception e) {
            log.warn("SRS cache save failed: {}", e.getMessage());
        }
        return srs;
    }

    /**
     * Prove solvency: reserves >= liabilities, all balances >= 0, tree is correct.
     */
    public ProofResult prove(BigInteger totalReserves, BigInteger liabilitiesRoot,
                              BigInteger totalLiabilities, BigInteger[] accountIds,
                              BigInteger[] balances) {
        int numLeaves = 1 << treeDepth;
        if (accountIds.length > numLeaves || balances.length > numLeaves) {
            throw new IllegalArgumentException("Too many accounts for tree depth " + treeDepth);
        }

        boolean solvent = totalReserves.compareTo(totalLiabilities) >= 0;

        Map<String, List<BigInteger>> inputs = new HashMap<>();
        inputs.put("totalReserves", List.of(totalReserves));
        inputs.put("liabilitiesRoot", List.of(liabilitiesRoot));
        inputs.put("totalLiabilities", List.of(totalLiabilities));
        inputs.put("isSolvent", List.of(solvent ? BigInteger.ONE : BigInteger.ZERO));

        for (int i = 0; i < numLeaves; i++) {
            inputs.put("accountId_" + i, List.of(i < accountIds.length ? accountIds[i] : BigInteger.ZERO));
            inputs.put("balance_" + i, List.of(i < balances.length ? balances[i] : BigInteger.ZERO));
        }

        BigInteger[] witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);
        var proof = Groth16ProverBLS381.prove(setupResult.provingKey(), witness, constraints, r1cs.numWires());

        return new ProofResult(proof, solvent, witness);
    }

    public Groth16SetupBLS381.SetupResult getSetupResult() { return setupResult; }
    public int getTreeDepth() { return treeDepth; }

    public record ProofResult(Groth16ProofBLS381 proof, boolean solvent, BigInteger[] witness) {}
}
