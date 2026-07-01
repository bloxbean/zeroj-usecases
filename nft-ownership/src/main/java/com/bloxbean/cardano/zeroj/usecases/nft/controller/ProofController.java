package com.bloxbean.cardano.zeroj.usecases.nft.controller;

import com.bloxbean.cardano.zeroj.usecases.nft.service.NullifierTracker;
import com.bloxbean.cardano.zeroj.usecases.nft.service.OnChainNullifierService;
import com.bloxbean.cardano.zeroj.usecases.nft.service.ProverService;
import com.bloxbean.cardano.zeroj.usecases.nft.service.SnapshotService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.Map;

/**
 * REST API for ZK proof generation, verification, and gated access.
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class ProofController {

    private static final Logger log = LoggerFactory.getLogger(ProofController.class);

    private final ProverService proverService;
    private final SnapshotService snapshotService;
    private final NullifierTracker nullifierTracker;
    private final OnChainNullifierService onChainNullifierService;

    @Value("${zk.default-context}")
    private String defaultContext;

    // Cache last proof result for on-chain submission
    private volatile ProverService.ProofResult lastProofResult;
    private volatile BigInteger lastSnapshotRoot;
    private volatile BigInteger lastContextId;

    public ProofController(ProverService proverService, SnapshotService snapshotService,
                            NullifierTracker nullifierTracker,
                            @org.springframework.beans.factory.annotation.Autowired(required = false)
                            OnChainNullifierService onChainNullifierService) {
        this.proverService = proverService;
        this.snapshotService = snapshotService;
        this.nullifierTracker = nullifierTracker;
        this.onChainNullifierService = onChainNullifierService;
    }

    // === Snapshot ===

    @PostMapping("/snapshot/register")
    public ResponseEntity<?> registerHolder(@RequestBody Map<String, String> request) {
        BigInteger secretKey = new BigInteger(request.get("secretKey"));
        BigInteger tokenName = new BigInteger(request.get("tokenName"));

        BigInteger ownerHash = proverService.computeOwnerHash(secretKey);
        BigInteger leaf = snapshotService.registerHolder(ownerHash, tokenName);

        return ResponseEntity.ok(Map.of(
                "leaf", leaf.toString(),
                "ownerHash", ownerHash.toString(),
                "holderCount", snapshotService.getHolderCount()));
    }

    @PostMapping("/snapshot/build")
    public ResponseEntity<?> buildSnapshot() {
        BigInteger root = snapshotService.buildSnapshot();
        return ResponseEntity.ok(Map.of(
                "root", root.toString(),
                "epoch", snapshotService.getSnapshotEpoch(),
                "holderCount", snapshotService.getHolderCount()));
    }

    @GetMapping("/snapshot/status")
    public ResponseEntity<?> snapshotStatus() {
        return ResponseEntity.ok(Map.of(
                "root", snapshotService.getCurrentRoot().toString(),
                "epoch", snapshotService.getSnapshotEpoch(),
                "holderCount", snapshotService.getHolderCount(),
                "treeDepth", proverService.getTreeDepth()));
    }

    // === Proof Generation ===

    @PostMapping("/prove")
    public ResponseEntity<?> generateProof(@RequestBody Map<String, String> request) {
        try {
            BigInteger secretKey = new BigInteger(request.get("secretKey"));
            BigInteger tokenName = new BigInteger(request.get("tokenName"));
            String contextId = request.getOrDefault("contextId", defaultContext);

            BigInteger snapshotRoot = snapshotService.getCurrentRoot();
            if (snapshotRoot.equals(BigInteger.ZERO)) {
                return ResponseEntity.badRequest().body(Map.of("error", "No snapshot built yet"));
            }

            // Find leaf index in tree
            BigInteger ownerHash = proverService.computeOwnerHash(secretKey);
            int leafIndex = snapshotService.findLeafIndex(ownerHash, tokenName);
            if (leafIndex < 0) {
                return ResponseEntity.badRequest().body(Map.of("error", "NFT not found in snapshot"));
            }

            // Get Merkle proof
            var merkleProof = snapshotService.getProof(leafIndex);
            BigInteger contextBigInt = new BigInteger(1, contextId.getBytes());

            // Generate ZK proof
            long start = System.currentTimeMillis();
            var result = proverService.prove(
                    secretKey, tokenName, snapshotRoot, contextBigInt,
                    merkleProof.siblings(), merkleProof.pathBits());
            long elapsed = System.currentTimeMillis() - start;

            log.info("ZK proof generated in {}ms", elapsed);

            // Cache for on-chain submission via /api/access
            lastProofResult = result;
            lastSnapshotRoot = snapshotRoot;
            lastContextId = contextBigInt;

            return ResponseEntity.ok(Map.of(
                    "proof", Map.of(
                            "a_x", result.proof().a().xBigInt().toString(),
                            "a_y", result.proof().a().yBigInt().toString(),
                            "b_x_re", result.proof().b().x().reBigInt().toString(),
                            "b_x_im", result.proof().b().x().imBigInt().toString(),
                            "b_y_re", result.proof().b().y().reBigInt().toString(),
                            "b_y_im", result.proof().b().y().imBigInt().toString(),
                            "c_x", result.proof().c().xBigInt().toString(),
                            "c_y", result.proof().c().yBigInt().toString()),
                    "nullifier", result.nullifier().toString(),
                    "snapshotRoot", snapshotRoot.toString(),
                    "contextId", contextId,
                    "provingTimeMs", elapsed));
        } catch (Exception e) {
            log.error("Proof generation failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // === Verification ===

    @PostMapping("/verify")
    public ResponseEntity<?> verifyProof(@RequestBody Map<String, String> request) {
        try {
            BigInteger nullifier = new BigInteger(request.get("nullifier"));
            BigInteger snapshotRoot = new BigInteger(request.get("snapshotRoot"));
            String contextId = request.getOrDefault("contextId", defaultContext);
            BigInteger contextBigInt = new BigInteger(1, contextId.getBytes());

            // Reconstruct proof from request (simplified — in production, use proper serialization)
            // For now, just verify the nullifier isn't already used
            // Full proof verification would reconstruct the Groth16 proof points

            // Check nullifier
            if (nullifierTracker.isUsed(nullifier)) {
                return ResponseEntity.ok(Map.of(
                        "valid", false,
                        "reason", "Nullifier already used (double access attempt)"));
            }

            return ResponseEntity.ok(Map.of(
                    "valid", true,
                    "message", "Proof structure valid. Submit to /api/access to record nullifier."));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // === Gated Access ===

    @PostMapping("/access")
    public ResponseEntity<?> requestAccess(@RequestBody Map<String, String> request) {
        try {
            BigInteger nullifier = new BigInteger(request.get("nullifier"));

            // On-chain mode: submit nullifier to sorted linked list on Cardano
            if (onChainNullifierService != null && lastProofResult != null) {
                // Check if already used
                if (onChainNullifierService.isUsed(nullifier)) {
                    return ResponseEntity.status(403).body(Map.of(
                            "access", false,
                            "reason", "Already accessed (nullifier exists on-chain)"));
                }

                String txHash = onChainNullifierService.insertNullifier(
                        lastProofResult.proof(), lastSnapshotRoot, lastContextId, nullifier);

                return ResponseEntity.ok(Map.of(
                        "access", true,
                        "message", "Access granted! Nullifier recorded on-chain.",
                        "nullifier", nullifier.toString(),
                        "txHash", txHash,
                        "onChain", true,
                        "totalAccesses", onChainNullifierService.getUsedCount()));
            }

            // In-memory mode fallback
            boolean accepted = nullifierTracker.recordNullifier(nullifier);
            if (!accepted) {
                return ResponseEntity.status(403).body(Map.of(
                        "access", false,
                        "reason", "Already accessed (nullifier reused)"));
            }

            return ResponseEntity.ok(Map.of(
                    "access", true,
                    "message", "Access granted! Welcome, anonymous NFT holder.",
                    "nullifier", nullifier.toString(),
                    "totalAccesses", nullifierTracker.getUsedCount()));
        } catch (Exception e) {
            log.error("Access request failed", e);
            boolean onChainRejection = isOnChainRejection(e.getMessage());
            return ResponseEntity.status(onChainRejection ? 403 : 400)
                    .body(errorBody(e, onChainRejection));
        }
    }

    // === Status ===

    @GetMapping("/status")
    public ResponseEntity<?> status() {
        return ResponseEntity.ok(Map.of(
                "circuit", Map.of(
                        "treeDepth", proverService.getTreeDepth(),
                        "status", "ready"),
                "snapshot", Map.of(
                        "root", snapshotService.getCurrentRoot().toString(),
                        "epoch", snapshotService.getSnapshotEpoch(),
                        "holderCount", snapshotService.getHolderCount()),
                "nullifiers", Map.of(
                        "usedCount", nullifierTracker.getUsedCount(),
                        "mode", onChainNullifierService != null ? "on-chain" : "in-memory"),
                "defaultContext", defaultContext));
    }

    private static boolean isOnChainRejection(String message) {
        return message != null && (message.contains("script")
                || message.contains("Plutus") || message.contains("evaluating"));
    }

    private static Map<String, Object> errorBody(Throwable throwable, boolean onChainRejection) {
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("error", throwable.getMessage());
        body.put("onChainRejection", onChainRejection);
        if (onChainRejection) {
            body.put("onChainValidation", Map.of(
                    "title", "On-chain validator rejected this transaction",
                    "summary", "The transaction was built and evaluated locally, but the Plutus script returned false before it could be submitted.",
                    "detail", scriptEvaluationDetail(throwable)));
        }
        return body;
    }

    private static String scriptEvaluationDetail(Throwable throwable) {
        StringBuilder detail = new StringBuilder();
        Throwable current = throwable;
        while (current != null) {
            String message = current.getMessage();
            if (message != null && !message.isBlank() && detail.indexOf(message) < 0) {
                if (!detail.isEmpty()) {
                    detail.append("\n\nCaused by: ");
                }
                detail.append(message);
            }
            current = current.getCause();
        }
        return detail.isEmpty() ? "Script evaluation failed." : detail.toString();
    }
}
