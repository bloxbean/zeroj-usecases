package com.bloxbean.cardano.zeroj.usecases.nft.controller;

import com.bloxbean.cardano.zeroj.usecases.nft.service.CustodyWallet;
import com.bloxbean.cardano.zeroj.usecases.nft.service.MintService;
import com.bloxbean.cardano.zeroj.usecases.nft.service.NftScheme;
import com.bloxbean.cardano.zeroj.usecases.nft.service.NullifierTracker;
import com.bloxbean.cardano.zeroj.usecases.nft.service.OnChainNullifierService;
import com.bloxbean.cardano.zeroj.usecases.nft.service.ProverService;
import com.bloxbean.cardano.zeroj.usecases.nft.service.SnapshotService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * REST API for registration, ZK proof generation and gated access (ADR-0009 D2).
 *
 * <p>This API is the demo operator's view (D10): the server holds the custody wallet that holds
 * the NFTs, generates holder secrets and proves for the holder. Privacy holds against chain and
 * mempool observers, not against this server.
 */
@RestController
@RequestMapping("/api")
public class ProofController {

    private static final Logger log = LoggerFactory.getLogger(ProofController.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final ProverService proverService;
    private final SnapshotService snapshotService;
    private final NullifierTracker nullifierTracker;
    private final OnChainNullifierService onChainNullifierService;
    private final MintService mintService;
    private final CustodyWallet custodyWallet;

    /**
     * The last proof, for submission via /api/access: only the proof and its nullifier. The
     * witness (holder secret, token, path) is not kept.
     */
    private volatile LastProof lastProof;

    private record LastProof(Groth16ProofBLS381 proof, BigInteger nullifier) {}

    public ProofController(ProverService proverService, SnapshotService snapshotService,
                            NullifierTracker nullifierTracker,
                            @Autowired(required = false) OnChainNullifierService onChainNullifierService,
                            MintService mintService, CustodyWallet custodyWallet) {
        this.proverService = proverService;
        this.snapshotService = snapshotService;
        this.nullifierTracker = nullifierTracker;
        this.onChainNullifierService = onChainNullifierService;
        this.mintService = mintService;
        this.custodyWallet = custodyWallet;
    }

    // === Snapshot ===

    /**
     * Registers an NFT held by the custody wallet. Without {@code secretKey} the server draws a
     * fresh 252-bit holder secret; a supplied one must be a 252-bit value. The custody wallet
     * signs the registration (CIP-8), and the snapshot checks that signature against the token's
     * on-chain holder.
     */
    @PostMapping("/snapshot/register")
    public ResponseEntity<?> registerHolder(@RequestBody Map<String, String> request) {
        try {
            if (!mintService.hasCollection()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Mint the NFT collection first"));
            }
            String tokenName = request.get("tokenName");
            if (tokenName == null || tokenName.isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("error", "tokenName is required"));
            }
            String secretText = request.get("secretKey");
            BigInteger secretKey = secretText == null || secretText.isBlank()
                    ? NftScheme.newSecret(RANDOM)
                    : NftScheme.parseSecret(secretText);

            byte[] assetName = tokenName.getBytes(StandardCharsets.UTF_8);
            BigInteger token = NftScheme.tokenField(assetName);
            BigInteger leaf = NftScheme.leaf(secretKey, token);
            var signature = custodyWallet.signRegistration(snapshotService.getContextId(), token, leaf);
            int holders = snapshotService.registerHolder(mintService.getPolicyId(), assetName, leaf, signature);

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("tokenName", tokenName);
            body.put("leaf", leaf.toString());
            body.put("secretKey", "0x" + secretKey.toString(16));
            body.put("holderAddress", custodyWallet.address());
            body.put("holderCount", holders);
            body.put("note", "Operator view: keep the secret to prove later; the server does not store it.");
            return ResponseEntity.ok(body);
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Builds the snapshot, which freezes registration, and deploys the event's scripts (ZK policy
     * over this root and context, nullifier list with a one-shot root).
     */
    @PostMapping("/snapshot/build")
    public ResponseEntity<?> buildSnapshot() {
        try {
            BigInteger root = snapshotService.buildSnapshot();
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("root", root.toString());
            body.put("holderCount", snapshotService.getHolderCount());
            body.put("registrationOpen", false);
            body.put("contextId", snapshotService.getContextLabel());
            if (onChainNullifierService != null) {
                var d = onChainNullifierService.deploy(root, snapshotService.getContextId());
                body.put("zkPolicyId", d.zkPolicyHex());
                body.put("listPolicyId", d.listPolicyHex());
                body.put("registryAddress", d.registryAddr());
            }
            return ResponseEntity.ok(body);
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Event deployment failed", e);
            return ResponseEntity.status(500).body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    @GetMapping("/snapshot/status")
    public ResponseEntity<?> snapshotStatus() {
        return ResponseEntity.ok(Map.of(
                "root", snapshotService.getCurrentRoot().toString(),
                "holderCount", snapshotService.getHolderCount(),
                "registrationOpen", !snapshotService.isFrozen(),
                "contextId", snapshotService.getContextLabel(),
                "treeDepth", proverService.getTreeDepth()));
    }

    // === Proof Generation ===

    @PostMapping("/prove")
    public ResponseEntity<?> generateProof(@RequestBody Map<String, String> request) {
        try {
            BigInteger secretKey = NftScheme.parseSecret(request.get("secretKey"));
            String tokenName = request.get("tokenName");
            if (tokenName == null || tokenName.isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("error", "tokenName is required"));
            }
            String contextId = request.getOrDefault("contextId", snapshotService.getContextLabel());
            if (!snapshotService.getContextLabel().equals(contextId)) {
                return ResponseEntity.badRequest().body(Map.of("error",
                        "this run's event is '" + snapshotService.getContextLabel() + "'"));
            }

            if (!snapshotService.isFrozen()) {
                return ResponseEntity.badRequest().body(Map.of("error", "No snapshot built yet"));
            }
            BigInteger snapshotRoot = snapshotService.getCurrentRoot();

            // Find leaf index in tree
            BigInteger token = NftScheme.tokenField(tokenName);
            int leafIndex = snapshotService.findLeafIndex(NftScheme.leaf(secretKey, token));
            if (leafIndex < 0) {
                return ResponseEntity.badRequest().body(Map.of("error", "NFT not found in snapshot"));
            }

            // Get Merkle proof
            var merkleProof = snapshotService.getProof(leafIndex);
            BigInteger contextBigInt = snapshotService.getContextId();

            // Generate ZK proof
            long start = System.currentTimeMillis();
            var result = proverService.prove(
                    secretKey, token, snapshotRoot, contextBigInt,
                    merkleProof.siblings(), merkleProof.pathBits());
            long elapsed = System.currentTimeMillis() - start;

            log.info("ZK proof generated in {}ms", elapsed);

            // Cache the proof and nullifier (not the witness) for submission via /api/access
            lastProof = new LastProof(result.proof(), result.nullifier());

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
            return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    // === Verification ===

    /** Reports whether a nullifier is already used. It does not verify a proof. */
    @PostMapping("/verify")
    public ResponseEntity<?> verifyProof(@RequestBody Map<String, String> request) {
        try {
            BigInteger nullifier = new BigInteger(request.get("nullifier"));
            if (nullifierTracker.isUsed(nullifier)) {
                return ResponseEntity.ok(Map.of(
                        "valid", false,
                        "reason", "Nullifier already used (double access attempt)"));
            }
            return ResponseEntity.ok(Map.of(
                    "valid", true,
                    "message", "Nullifier not used yet. Submit to /api/access; the proof is verified there."));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    // === Gated Access ===

    @PostMapping("/access")
    public ResponseEntity<?> requestAccess(@RequestBody Map<String, String> request) {
        try {
            BigInteger nullifier = new BigInteger(request.get("nullifier"));
            var proof = lastProof;

            // On-chain mode: submit nullifier to sorted linked list on Cardano
            if (onChainNullifierService != null) {
                if (proof == null || !proof.nullifier().equals(nullifier)) {
                    return ResponseEntity.badRequest().body(Map.of("error", "Generate a proof for this nullifier first"));
                }
                // The event's scripts (normally deployed when the snapshot is built)
                onChainNullifierService.deploy(snapshotService.getCurrentRoot(), snapshotService.getContextId());
                if (onChainNullifierService.isUsed(nullifier)) {
                    return ResponseEntity.status(403).body(Map.of(
                            "access", false,
                            "reason", "Already accessed (nullifier exists on-chain)"));
                }

                String txHash = onChainNullifierService.insertNullifier(proof.proof(), nullifier);

                return ResponseEntity.ok(Map.of(
                        "access", true,
                        "message", "Access granted! Nullifier recorded on-chain.",
                        "nullifier", nullifier.toString(),
                        "txHash", txHash,
                        "onChain", true,
                        "totalAccesses", onChainNullifierService.getUsedCount()));
            }

            // In-memory mode: the server verifies the proof itself before recording the nullifier
            if (proof == null || !proof.nullifier().equals(nullifier)
                    || !proverService.verifyOffChain(proof.proof(), snapshotService.getCurrentRoot(),
                            snapshotService.getContextId(), nullifier)) {
                return ResponseEntity.badRequest().body(Map.of("error", "No verified proof for this nullifier"));
            }
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
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("contextId", snapshotService.getContextLabel());
        event.put("circuitVersion", NftScheme.CIRCUIT_VERSION);
        var d = onChainNullifierService != null ? onChainNullifierService.deployment() : null;
        if (d != null) {
            event.put("zkPolicyId", d.zkPolicyHex());
            event.put("listPolicyId", d.listPolicyHex());
            event.put("registryAddress", d.registryAddr());
        }
        return ResponseEntity.ok(Map.of(
                "circuit", Map.of(
                        "treeDepth", proverService.getTreeDepth(),
                        "status", "ready"),
                "snapshot", Map.of(
                        "root", snapshotService.getCurrentRoot().toString(),
                        "registrationOpen", !snapshotService.isFrozen(),
                        "holderCount", snapshotService.getHolderCount()),
                "nullifiers", Map.of(
                        "usedCount", nullifierTracker.getUsedCount(),
                        "mode", onChainNullifierService != null ? "on-chain" : "in-memory"),
                "event", event,
                "custodyAddress", custodyWallet.address()));
    }

    private static boolean isOnChainRejection(String message) {
        return message != null && (message.contains("script")
                || message.contains("Plutus") || message.contains("evaluating"));
    }

    private static Map<String, Object> errorBody(Throwable throwable, boolean onChainRejection) {
        Map<String, Object> body = new LinkedHashMap<>();
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
