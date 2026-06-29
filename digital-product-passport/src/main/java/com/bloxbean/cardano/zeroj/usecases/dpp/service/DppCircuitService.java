package com.bloxbean.cardano.zeroj.usecases.dpp.service;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupCache;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PtauImporterBLS381;
import com.bloxbean.cardano.zeroj.usecases.dpp.circuit.ComplianceThresholdCircuit;
import com.bloxbean.cardano.zeroj.usecases.dpp.circuit.CountryMembershipCircuit;
import com.bloxbean.cardano.zeroj.usecases.dpp.circuit.InspectionChainCircuit;
import com.bloxbean.cardano.zeroj.usecases.dpp.mpf.PoseidonCompute;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Manages all DPP ZK circuits: compilation, trusted setup, proof generation.
 * Three circuits: compliance threshold (GTE/LTE), inspection chain, country membership.
 */
@Service
public class DppCircuitService {

    private static final Logger log = LoggerFactory.getLogger(DppCircuitService.class);

    @Value("${zk.country-tree-depth}")
    private int countryTreeDepth;

    @Value("${zk.inspector-tree-depth}")
    private int inspectorTreeDepth;

    @Value("${zk.pot-power}")
    private int potPower;

    // Compiled circuits
    private CircuitSetup thresholdGte; // recycled >= X
    private CircuitSetup thresholdLte; // carbon <= X
    private CircuitSetup inspectionChain; // 3 inspections passed
    private CircuitSetup countryMembership; // country in set

    private static final String CACHE_DIR = "./data";

    @PostConstruct
    public void init() {
        // Wipe SRS / setup caches if Poseidon parameters changed since they were generated.
        // Without this check a cached R1CS carries stale Poseidon constants into the next
        // proof run — manifests as witness-evaluation errors on Merkle / hash constraints.
        boolean wiped = com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonCacheVersion
                .ensureFresh(java.nio.file.Path.of(CACHE_DIR),
                        java.util.List.of("srs.bin", "setup-*", "dpp-trie", "dpp-trie-minted"));
        if (wiped) {
            log.info("Poseidon parameters changed since last run — wiped stale SRS / R1CS / trie caches");
        }

        PtauImporterBLS381.SRS[] srsHolder = new PtauImporterBLS381.SRS[1];

        log.info("Compiling DPP circuits...");

        thresholdGte = compileWithCache("threshold-gte", ComplianceThresholdCircuit.buildGte(), srsHolder);
        thresholdLte = compileWithCache("threshold-lte", ComplianceThresholdCircuit.buildLte(), srsHolder);
        inspectionChain = compileWithCache("inspection-chain",
                InspectionChainCircuit.build(3, inspectorTreeDepth), srsHolder);
        countryMembership = compileWithCache("country-membership",
                CountryMembershipCircuit.build(countryTreeDepth), srsHolder);

        log.info("All DPP circuits compiled. Ready to generate proofs.");
    }

    private PtauImporterBLS381.SRS generateDevSrs() {
        log.info("Running in-memory dev Powers of Tau ceremony (power={})...", potPower);
        return PowersOfTauBLS381.generate(potPower);
    }

    private CircuitSetup compileWithCache(String name, CircuitBuilder circuit, PtauImporterBLS381.SRS[] srsHolder) {
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        log.info("  {} — {} constraints, {} wires, {} public",
                name, r1cs.numConstraints(), r1cs.numWires(), r1cs.numPublicInputs());

        var constraints = r1cs.constraints();

        // Try loading setup from cache
        Path setupCache = Path.of(CACHE_DIR, "setup-" + name + ".bin");
        Groth16SetupBLS381.SetupResult setup = null;
        try {
            if (Files.exists(setupCache)) {
                long start = System.currentTimeMillis();
                setup = Groth16SetupCache.loadBls12381Setup(setupCache);
                if (matchesCurrentCircuit(setup, r1cs)) {
                    log.info("  {} — loaded from cache in {}ms", name, System.currentTimeMillis() - start);
                } else {
                    log.warn("  {} — setup cache shape does not match current circuit; regenerating", name);
                    setup = null;
                }
            }
        } catch (Exception e) {
            log.warn("  {} — cache load failed: {}", name, e.getMessage());
        }

        if (setup == null) {
            if (srsHolder[0] == null) {
                srsHolder[0] = generateDevSrs();
            }
            setup = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                    r1cs.numPublicInputs(), srsHolder[0].tauScalar());
            try {
                Groth16SetupCache.saveBls12381Setup(setup, setupCache);
                log.info("  {} — cached to {}", name, setupCache);
            } catch (Exception e) {
                log.warn("  {} — cache save failed: {}", name, e.getMessage());
            }
        }

        return new CircuitSetup(circuit, r1cs, constraints, setup);
    }

    private static boolean matchesCurrentCircuit(Groth16SetupBLS381.SetupResult setup, R1CSConstraintSystem r1cs) {
        var pk = setup.provingKey();
        return pk.numPublic() == r1cs.numPublicInputs()
                && pk.pointsA().length == r1cs.numWires();
    }

    // --- Proof generation ---

    public ProofResult proveThresholdGte(BigInteger measurement, BigInteger auditorSecret,
                                          BigInteger productId, BigInteger threshold,
                                          BigInteger auditorHash) {
        return prove(thresholdGte, Map.of(
                "measurement", List.of(measurement),
                "auditorSecret", List.of(auditorSecret),
                "productId", List.of(productId),
                "threshold", List.of(threshold),
                "auditorHash", List.of(auditorHash),
                "isCompliant", List.of(measurement.compareTo(threshold) >= 0 ? BigInteger.ONE : BigInteger.ZERO)));
    }

    public ProofResult proveThresholdLte(BigInteger measurement, BigInteger auditorSecret,
                                          BigInteger productId, BigInteger threshold,
                                          BigInteger auditorHash) {
        return prove(thresholdLte, Map.of(
                "measurement", List.of(measurement),
                "auditorSecret", List.of(auditorSecret),
                "productId", List.of(productId),
                "threshold", List.of(threshold),
                "auditorHash", List.of(auditorHash),
                "isCompliant", List.of(measurement.compareTo(threshold) <= 0 ? BigInteger.ONE : BigInteger.ZERO)));
    }

    public ProofResult proveInspections(BigInteger productId, BigInteger inspectorRoot,
                                         Map<String, List<BigInteger>> inspectionInputs) {
        var inputs = new HashMap<>(inspectionInputs);
        inputs.put("productId", List.of(productId));
        inputs.put("inspectorRoot", List.of(inspectorRoot));
        inputs.put("allPassed", List.of(BigInteger.ONE));
        return prove(inspectionChain, inputs);
    }

    public ProofResult proveCountryMembership(BigInteger country, BigInteger productId,
                                                BigInteger countryRoot,
                                                BigInteger[] siblings, BigInteger[] pathBits) {
        var inputs = new HashMap<String, List<BigInteger>>();
        inputs.put("country", List.of(country));
        inputs.put("productId", List.of(productId));
        inputs.put("countryRoot", List.of(countryRoot));
        inputs.put("isMember", List.of(BigInteger.ONE));
        for (int i = 0; i < siblings.length; i++) {
            inputs.put("sibling_" + i, List.of(siblings[i]));
            inputs.put("pathBit_" + i, List.of(pathBits[i]));
        }
        return prove(countryMembership, inputs);
    }

    private ProofResult prove(CircuitSetup cs, Map<String, List<BigInteger>> inputs) {
        BigInteger[] witness = cs.circuit.calculateWitness(inputs, CurveId.BLS12_381);
        var proof = Groth16ProverBLS381.prove(cs.setup.provingKey(), witness,
                cs.constraints, cs.r1cs.numWires());
        return new ProofResult(proof, witness);
    }

    // --- Poseidon helpers ---

    public BigInteger computeAuditorHash(BigInteger auditorSecret, BigInteger productId, BigInteger measurement) {
        BigInteger claimsHash = PoseidonCompute.poseidon(productId, measurement);
        return PoseidonCompute.poseidon(auditorSecret, claimsHash);
    }

    public BigInteger poseidon(BigInteger a, BigInteger b) {
        return PoseidonCompute.poseidon(a, b);
    }

    // --- Getters ---

    public CircuitSetup getThresholdGte() { return thresholdGte; }
    public CircuitSetup getThresholdLte() { return thresholdLte; }
    public CircuitSetup getInspectionChain() { return inspectionChain; }
    public CircuitSetup getCountryMembership() { return countryMembership; }
    public int getCountryTreeDepth() { return countryTreeDepth; }
    public int getInspectorTreeDepth() { return inspectorTreeDepth; }

    // --- Records ---

    public record CircuitSetup(CircuitBuilder circuit, R1CSConstraintSystem r1cs,
                                List<R1CSConstraint> constraints,
                                Groth16SetupBLS381.SetupResult setup) {}

    public record ProofResult(Groth16ProofBLS381 proof, BigInteger[] witness) {}
}
