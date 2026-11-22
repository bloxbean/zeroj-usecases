package com.bloxbean.cardano.zeroj.usecases.dpp.service;

import com.bloxbean.cardano.zeroj.usecases.dpp.passport.ApprovedSets;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.Claim;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.ClaimOpening;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The manufacturer's prover (ADR-0009 D1): proves each claim from the auditor's opening, against
 * the public threshold or approved-set root. A claim the committed values do not satisfy has no
 * proof at all; there is no "not compliant" proof.
 *
 * <p>Proofs are kept per product: the carbon proof goes into the passport transaction, the other
 * three are the manufacturer's published off-chain proofs, which readers verify against the
 * commitments in the passport datum.
 */
@Service
public class ComplianceService {

    private static final Logger log = LoggerFactory.getLogger(ComplianceService.class);

    @Value("${dpp.carbon-threshold-kg}")
    private int carbonThreshold;

    @Value("${dpp.recycled-threshold-pct}")
    private int recycledThreshold;

    private final DppCircuitService circuitService;
    private final Map<String, Map<Claim, ClaimProof>> proofs = new ConcurrentHashMap<>();

    public ComplianceService(DppCircuitService circuitService) {
        this.circuitService = circuitService;
    }

    /** A proved claim: the statement's public parameter and the proof. */
    public record ClaimProof(Claim claim, BigInteger param, Groth16ProofBLS381 proof) {}

    /** The outcome of proving one claim; {@code proof} is null when the claim cannot be proved. */
    public record ClaimResult(Claim claim, boolean proved, long provingTimeMs, ClaimProof proof, String error) {}

    /** The public parameter of each claim's statement. */
    public BigInteger param(Claim claim) {
        return switch (claim) {
            case CARBON -> BigInteger.valueOf(carbonThreshold);
            case RECYCLED -> BigInteger.valueOf(recycledThreshold);
            case ORIGIN -> ApprovedSets.EU_COUNTRIES.root();
            case INSPECTIONS -> ApprovedSets.INSPECTORS.root();
        };
    }

    /** Proves every claim of a product from its openings, and keeps the proofs that exist. */
    public List<ClaimResult> proveAll(String serial, List<ClaimOpening> openings) {
        List<ClaimResult> results = new ArrayList<>();
        Map<Claim, ClaimProof> kept = proofs.computeIfAbsent(serial, s -> new ConcurrentHashMap<>());
        for (ClaimOpening o : openings) {
            long start = System.currentTimeMillis();
            BigInteger param = param(o.claim());
            try {
                var proof = circuitService.circuits().prove(o, param);
                long ms = System.currentTimeMillis() - start;
                ClaimProof cp = new ClaimProof(o.claim(), param, proof);
                kept.put(o.claim(), cp);
                results.add(new ClaimResult(o.claim(), true, ms, cp, null));
                log.info("{}: {} claim proved ({} ms)", serial, o.claim().label(), ms);
            } catch (RuntimeException e) {
                kept.remove(o.claim());
                results.add(new ClaimResult(o.claim(), false, System.currentTimeMillis() - start, null,
                        "the committed values do not satisfy the claim, so no proof exists"));
                log.info("{}: {} claim cannot be proved", serial, o.claim().label());
            }
        }
        return results;
    }

    /** The kept proof of a claim, if it was proved. */
    public ClaimProof proof(String serial, Claim claim) {
        Map<Claim, ClaimProof> kept = proofs.get(serial);
        return kept == null ? null : kept.get(claim);
    }

    /**
     * A carbon proof against a threshold the manufacturer chose instead of the policy's (the
     * "skip off-chain check" demonstration): it is a valid proof, of a different statement, and
     * the passport script refuses it.
     */
    public Groth16ProofBLS381 proveCarbonAgainst(ClaimOpening carbon, long chosenThreshold) {
        return circuitService.circuits().prove(carbon, BigInteger.valueOf(chosenThreshold));
    }

    public int carbonThreshold() { return carbonThreshold; }

    public int recycledThreshold() { return recycledThreshold; }
}
