package com.bloxbean.cardano.zeroj.usecases.dpp.service;

import com.bloxbean.cardano.zeroj.usecases.dpp.mpf.PoseidonCompute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.*;

/**
 * Generates ZK compliance proofs for DPP claims.
 * <p>
 * Supports: carbon threshold (<=), recycled content (>=), country membership (EU),
 * and inspection chain (N checkpoints in order).
 */
@Service
public class ComplianceService {

    private static final Logger log = LoggerFactory.getLogger(ComplianceService.class);
    private static final BigInteger AUDITOR_SECRET = BigInteger.valueOf(777777);

    @Value("${dpp.carbon-threshold-kg}")
    private int carbonThreshold;

    @Value("${dpp.recycled-threshold-pct}")
    private int recycledThreshold;

    private final DppCircuitService circuitService;
    private final ProductService productService;

    public ComplianceService(DppCircuitService circuitService, ProductService productService) {
        this.circuitService = circuitService;
        this.productService = productService;
    }

    /**
     * Generate a ZK proof that carbon <= threshold.
     */
    public ClaimResult proveCarbonCompliance(String productId, int actualCarbon) {
        BigInteger measurement = BigInteger.valueOf(actualCarbon);
        BigInteger threshold = BigInteger.valueOf(carbonThreshold);
        BigInteger prodId = new BigInteger(1, productId.getBytes());
        BigInteger auditorHash = circuitService.computeAuditorHash(AUDITOR_SECRET, prodId, measurement);

        long start = System.currentTimeMillis();
        var result = circuitService.proveThresholdLte(measurement, AUDITOR_SECRET,
                prodId, threshold, auditorHash);
        long elapsed = System.currentTimeMillis() - start;

        boolean compliant = actualCarbon <= carbonThreshold;
        log.info("Carbon proof for {}: {} kg (threshold {} kg) → {} ({}ms)",
                productId, actualCarbon, carbonThreshold, compliant ? "COMPLIANT" : "NOT COMPLIANT", elapsed);

        return new ClaimResult("carbon", compliant, result.proof(), elapsed,
                Map.of("measurement", actualCarbon, "threshold", carbonThreshold));
    }

    /**
     * Generate a ZK proof that recycled content >= threshold.
     */
    public ClaimResult proveRecycledCompliance(String productId, int actualRecycled) {
        BigInteger measurement = BigInteger.valueOf(actualRecycled);
        BigInteger threshold = BigInteger.valueOf(recycledThreshold);
        BigInteger prodId = new BigInteger(1, productId.getBytes());
        BigInteger auditorHash = circuitService.computeAuditorHash(AUDITOR_SECRET, prodId, measurement);

        long start = System.currentTimeMillis();
        var result = circuitService.proveThresholdGte(measurement, AUDITOR_SECRET,
                prodId, threshold, auditorHash);
        long elapsed = System.currentTimeMillis() - start;

        boolean compliant = actualRecycled >= recycledThreshold;
        log.info("Recycled proof for {}: {}% (threshold {}%) → {} ({}ms)",
                productId, actualRecycled, recycledThreshold, compliant ? "COMPLIANT" : "NOT COMPLIANT", elapsed);

        return new ClaimResult("recycled_content", compliant, result.proof(), elapsed,
                Map.of("measurement", actualRecycled, "threshold", recycledThreshold));
    }

    /**
     * Generate a ZK proof that country is in the EU set.
     */
    public ClaimResult proveCountryCompliance(String productId, int countryCode) {
        var proof = productService.getCountryProof(countryCode);
        boolean inEu = proof != null;

        if (!inEu) {
            log.info("Country proof for {}: {} not in EU → NOT COMPLIANT", productId, countryCode);
            return new ClaimResult("made_in_eu", false, null, 0,
                    Map.of("country", countryCode, "inEU", false));
        }

        BigInteger country = BigInteger.valueOf(countryCode);
        BigInteger prodId = new BigInteger(1, productId.getBytes());
        BigInteger countryRoot = productService.getEuCountryRoot();

        long start = System.currentTimeMillis();
        var result = circuitService.proveCountryMembership(country, prodId, countryRoot,
                proof.siblings(), proof.pathBits());
        long elapsed = System.currentTimeMillis() - start;

        log.info("Country proof for {}: {} in EU → COMPLIANT ({}ms)", productId, countryCode, elapsed);
        return new ClaimResult("made_in_eu", true, result.proof(), elapsed,
                Map.of("country", countryCode, "inEU", true));
    }

    /**
     * Generate a ZK proof that all inspections passed in order.
     */
    public ClaimResult proveInspectionCompliance(String productId, int numInspections) {
        BigInteger prodId = new BigInteger(1, productId.getBytes());
        BigInteger inspRoot = productService.getInspectorRoot();
        var inspKeys = productService.getInspectorKeys();

        // Build inspection data
        Map<String, List<BigInteger>> inputs = new HashMap<>();
        for (int i = 0; i < numInspections; i++) {
            inputs.put("passed_" + i, List.of(BigInteger.ONE));
            inputs.put("timestamp_" + i, List.of(BigInteger.valueOf(1000 + i * 100)));
            inputs.put("inspectorKey_" + i, List.of(inspKeys.get(i % inspKeys.size())));

            var inspProof = productService.getInspectorProof(inspKeys.get(i % inspKeys.size()));
            for (int j = 0; j < inspProof.siblings().length; j++) {
                inputs.put("insp_sibling_" + i + "_" + j, List.of(inspProof.siblings()[j]));
                inputs.put("insp_pathBit_" + i + "_" + j, List.of(inspProof.pathBits()[j]));
            }
        }

        long start = System.currentTimeMillis();
        var result = circuitService.proveInspections(prodId, inspRoot, inputs);
        long elapsed = System.currentTimeMillis() - start;

        log.info("Inspection proof for {}: {}/{} passed → COMPLIANT ({}ms)",
                productId, numInspections, numInspections, elapsed);
        return new ClaimResult("inspections", true, result.proof(), elapsed,
                Map.of("passed", numInspections, "required", numInspections));
    }

    /**
     * Generate all applicable compliance proofs for a product.
     */
    public List<ClaimResult> proveAllClaims(String productId, Map<String, Integer> claims) {
        List<ClaimResult> results = new ArrayList<>();

        if (claims.containsKey("carbon_kg")) {
            results.add(proveCarbonCompliance(productId, claims.get("carbon_kg")));
        }
        if (claims.containsKey("carbon_per_unit_kg")) {
            results.add(proveCarbonCompliance(productId, claims.get("carbon_per_unit_kg")));
        }
        if (claims.containsKey("recycled_pct")) {
            results.add(proveRecycledCompliance(productId, claims.get("recycled_pct")));
        }
        if (claims.containsKey("country")) {
            results.add(proveCountryCompliance(productId, claims.get("country")));
        }
        if (claims.containsKey("inspection_count")) {
            results.add(proveInspectionCompliance(productId, claims.get("inspection_count")));
        }

        return results;
    }

    public int getCarbonThreshold() { return carbonThreshold; }
    public int getRecycledThreshold() { return recycledThreshold; }

    public record ClaimResult(
            String claimType,
            boolean compliant,
            com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381 proof,
            long provingTimeMs,
            Map<String, Object> details
    ) {}
}
