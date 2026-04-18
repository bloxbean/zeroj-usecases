package com.bloxbean.cardano.zeroj.usecases.identity.controller;

import com.bloxbean.cardano.zeroj.usecases.identity.service.CredentialService;
import com.bloxbean.cardano.zeroj.usecases.identity.service.IssuerService;
import com.bloxbean.cardano.zeroj.usecases.identity.service.OnChainCredentialService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.Map;

@RestController
@RequestMapping("/api/credential")
@CrossOrigin(origins = "*")
public class CredentialController {

    private static final Logger log = LoggerFactory.getLogger(CredentialController.class);

    private final CredentialService credentialService;
    private final IssuerService issuerService;
    private final OnChainCredentialService onChainService;

    // Cache last proof for unlock
    private volatile CredentialService.ProofResult lastProofResult;
    private volatile IssuerService.UserCredential lastProofUser;

    public CredentialController(CredentialService credentialService, IssuerService issuerService,
                                 OnChainCredentialService onChainService) {
        this.credentialService = credentialService;
        this.issuerService = issuerService;
        this.onChainService = onChainService;
    }

    @GetMapping("/status")
    public ResponseEntity<?> status() {
        var users = issuerService.getUsers().stream()
                .map(u -> {
                    boolean countryOk = issuerService.isCountryApproved(u.countryCode());
                    boolean ageOk = u.age() >= issuerService.getMinAge();
                    return Map.of(
                            "name", u.name(),
                            "age", u.age(),
                            "countryCode", u.countryCode(),
                            "sigR", u.signature().r().affineU().toString(16).substring(0, 16) + "...",
                            "expectedEligible", ageOk && countryOk);
                }).toList();

        var issuerPk = issuerService.getIssuerPublicKey();
        return ResponseEntity.ok(Map.of(
                "users", users,
                "minAge", issuerService.getMinAge(),
                "issuerPkU", issuerPk.affineU().toString(16).substring(0, 16) + "...",
                "issuerPkV", issuerPk.affineV().toString(16).substring(0, 16) + "...",
                "countryRoot", issuerService.getCountryRoot().toString(16).substring(0, 16) + "...",
                "lockedUtxos", onChainService.getLockedUtxoCount(),
                "countryTreeDepth", credentialService.getCountryTreeDepth()));
    }

    /**
     * Generate a ZK proof of credential eligibility.
     * Request: { "name": "Alice" }
     */
    @PostMapping("/verify")
    public ResponseEntity<?> verify(@RequestBody Map<String, String> request) {
        try {
            String name = request.get("name");
            var user = issuerService.getUser(name);
            if (user == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Unknown user: " + name));
            }

            BigInteger minAge = BigInteger.valueOf(issuerService.getMinAge());
            BigInteger countryRoot = issuerService.getCountryRoot();

            // Get country Merkle proof
            var countryProof = issuerService.getCountryProof(user.countryCode());
            if (countryProof == null) {
                // Country not in approved list — generate proof with dummy Merkle path
                // The proof will show eligible=false
                return ResponseEntity.ok(Map.of(
                        "name", name,
                        "eligible", false,
                        "reason", "Country " + user.countryCode() + " is not in the approved list"));
            }

            log.info("Generating credential proof for {} (EdDSA-Jubjub)...", name);
            long start = System.currentTimeMillis();
            var result = credentialService.prove(
                    issuerService.getIssuerPublicKey(),
                    user.signature(),
                    BigInteger.valueOf(user.age()),
                    BigInteger.valueOf(user.countryCode()),
                    minAge,
                    countryRoot,
                    countryProof.siblings(),
                    countryProof.pathBits());
            long elapsed = System.currentTimeMillis() - start;
            log.info("Credential proof for {}: eligible={}, {}ms", name, result.eligible(), elapsed);

            // Cache for unlock
            lastProofResult = result;
            lastProofUser = user;

            return ResponseEntity.ok(Map.of(
                    "name", name,
                    "eligible", result.eligible(),
                    "provingTimeMs", elapsed,
                    "age", user.age(),
                    "countryCode", user.countryCode()));
        } catch (Exception e) {
            log.error("Verification failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Lock ADA at the credential-gated script address.
     * Request: { "adaAmount": 5 }
     */
    @PostMapping("/lock")
    public ResponseEntity<?> lock(@RequestBody Map<String, Object> request) {
        try {
            double ada = request.containsKey("adaAmount")
                    ? ((Number) request.get("adaAmount")).doubleValue() : 5.0;
            BigInteger lovelace = BigInteger.valueOf((long) (ada * 1_000_000));

            String txHash = onChainService.lockFunds(lovelace);

            return ResponseEntity.ok(Map.of(
                    "txHash", txHash,
                    "adaLocked", ada,
                    "scriptAddress", onChainService.getScriptAddress()));
        } catch (Exception e) {
            log.error("Lock failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Unlock ADA using the last generated credential proof.
     * Request: { "name": "Alice" }
     * If forceOnChain=true, submits even ineligible proofs to demonstrate on-chain rejection.
     */
    @PostMapping("/unlock")
    public ResponseEntity<?> unlock(@RequestBody Map<String, Object> request) {
        try {
            String name = (String) request.get("name");
            boolean forceOnChain = Boolean.TRUE.equals(request.get("forceOnChain"));

            if (lastProofResult == null || lastProofUser == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "No proof generated yet. Call /verify first."));
            }

            if (!lastProofUser.name().equalsIgnoreCase(name)) {
                return ResponseEntity.badRequest().body(Map.of("error",
                        "Last proof was for " + lastProofUser.name() + ", not " + name));
            }

            if (!lastProofResult.eligible() && !forceOnChain) {
                return ResponseEntity.status(403).body(Map.of(
                        "error", "Proof shows NOT eligible — cannot unlock (set forceOnChain=true to attempt on-chain anyway)",
                        "name", name,
                        "eligible", false));
            }

            // Submit to chain — if eligible=false, the on-chain validator will reject
            var issuerPk = issuerService.getIssuerPublicKey();
            String txHash = onChainService.unlockWithProof(
                    lastProofResult.proof(),
                    issuerPk.affineU(), issuerPk.affineV(),
                    BigInteger.valueOf(issuerService.getMinAge()),
                    issuerService.getCountryRoot(),
                    lastProofResult.eligible());

            return ResponseEntity.ok(Map.of(
                    "name", name,
                    "txHash", txHash,
                    "eligible", true,
                    "message", "Funds unlocked with ZK credential proof!"));
        } catch (Exception e) {
            log.error("Unlock failed", e);
            String errorMsg = e.getMessage();
            // Check if the on-chain validator rejected
            boolean onChainRejection = errorMsg != null &&
                    (errorMsg.contains("script") || errorMsg.contains("Plutus") || errorMsg.contains("evaluating"));
            return ResponseEntity.status(onChainRejection ? 403 : 400).body(Map.of(
                    "error", errorMsg,
                    "onChainRejection", onChainRejection,
                    "name", (String) request.get("name")));
        }
    }
}
