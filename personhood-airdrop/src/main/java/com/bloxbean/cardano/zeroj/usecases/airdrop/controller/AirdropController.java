package com.bloxbean.cardano.zeroj.usecases.airdrop.controller;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.zeroj.usecases.airdrop.service.AirdropProofService;
import com.bloxbean.cardano.zeroj.usecases.airdrop.service.OnChainAirdropService;
import com.bloxbean.cardano.zeroj.usecases.airdrop.service.PersonhoodIssuerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;

@RestController
@RequestMapping("/api/airdrop")
@CrossOrigin
public class AirdropController {

    private static final Logger log = LoggerFactory.getLogger(AirdropController.class);

    private final PersonhoodIssuerService issuerService;
    private final AirdropProofService proofService;
    private final OnChainAirdropService onChainService;
    private final Account adminAccount;

    @Value("${faucet.ada-per-claim}")
    private int adaPerClaim;

    @Value("${faucet.current-epoch}")
    private long currentEpoch;

    private final ConcurrentLinkedDeque<ClaimRecord> history = new ConcurrentLinkedDeque<>();

    public AirdropController(PersonhoodIssuerService issuerService,
                             AirdropProofService proofService,
                             OnChainAirdropService onChainService,
                             Account adminAccount) {
        this.issuerService = issuerService;
        this.proofService = proofService;
        this.onChainService = onChainService;
        this.adminAccount = adminAccount;
    }

    @GetMapping("/status")
    public ResponseEntity<?> status() {
        var users = issuerService.list().stream().map(c -> Map.of(
                "name", c.name(),
                "personhoodId", "0x" + c.personhoodId().toString(16).substring(0, 16) + "...",
                "alreadyClaimedThisEpoch", onChainService.alreadyClaimed(
                        com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash.hash(
                                com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3.INSTANCE,
                                c.personhoodId(), BigInteger.valueOf(currentEpoch))))).toList();
        var pk = issuerService.getIssuerPublicKey();
        return ResponseEntity.ok(Map.of(
                "users", users,
                "issuerPkU", "0x" + pk.affineU().toString(16).substring(0, 16) + "...",
                "issuerPkV", "0x" + pk.affineV().toString(16).substring(0, 16) + "...",
                "currentEpoch", currentEpoch,
                "adaPerClaim", adaPerClaim,
                "totalClaims", onChainService.totalClaims(),
                "policyId", safePolicyId()));
    }

    @GetMapping("/history")
    public ResponseEntity<?> history() {
        return ResponseEntity.ok(Map.of("claims", List.copyOf(history)));
    }

    /**
     * Claim airdrop. Body: { "name": "Alice", "recipient": "addr_test1..." (optional) }.
     * If recipient is omitted, defaults to the faucet admin (for demo).
     */
    @PostMapping("/claim")
    public ResponseEntity<?> claim(@RequestBody Map<String, String> request) {
        try {
            String name = request.get("name");
            var cred = issuerService.get(name);
            if (cred == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Unknown personhood: " + name));
            }
            String recipientAddr = request.getOrDefault("recipient", adminAccount.baseAddress());

            BigInteger recipientField = recipientToField(recipientAddr);
            BigInteger epoch = BigInteger.valueOf(currentEpoch);

            log.info("Generating airdrop proof for {} (epoch={})...", name, currentEpoch);
            long start = System.currentTimeMillis();
            var claimProof = proofService.prove(
                    issuerService.getIssuerPublicKey(),
                    cred.signature(),
                    cred.personhoodId(),
                    epoch,
                    recipientField);
            long provingMs = System.currentTimeMillis() - start;

            if (onChainService.alreadyClaimed(claimProof.nullifier())) {
                return ResponseEntity.status(409).body(Map.of(
                        "error", "Already claimed in epoch " + currentEpoch,
                        "name", name,
                        "nullifier", "0x" + claimProof.nullifier().toString(16).substring(0, 16) + "..."));
            }

            String txHash = onChainService.submitClaim(
                    claimProof.proof(),
                    issuerService.getIssuerPublicKey().affineU(),
                    issuerService.getIssuerPublicKey().affineV(),
                    epoch, claimProof.nullifier(), recipientField,
                    recipientAddr, (long) adaPerClaim * 1_000_000L);

            var rec = new ClaimRecord(name,
                    "0x" + claimProof.nullifier().toString(16).substring(0, 16) + "...",
                    txHash, currentEpoch, adaPerClaim, recipientAddr, provingMs);
            history.addFirst(rec);
            return ResponseEntity.ok(Map.of(
                    "name", name,
                    "txHash", txHash,
                    "nullifier", "0x" + claimProof.nullifier().toString(16).substring(0, 16) + "...",
                    "ada", adaPerClaim,
                    "recipient", recipientAddr,
                    "provingTimeMs", provingMs));
        } catch (Exception e) {
            log.error("Claim failed", e);
            String msg = e.getMessage();
            boolean onChainRejection = isOnChainRejection(msg);
            return ResponseEntity.status(onChainRejection ? 403 : 400)
                    .body(errorBody(e, onChainRejection));
        }
    }

    private String safePolicyId() {
        try { return onChainService.getPolicyId(); } catch (Exception e) { return "(uninitialized)"; }
    }

    private static BigInteger recipientToField(String addressBech32) {
        // Reduce the recipient's payment-key hash to a BLS12-381 scalar so it
        // fits as a public input. This commits the proof to the recipient.
        try {
            var addr = new Address(addressBech32);
            byte[] pkh = addr.getPaymentCredentialHash().orElse(new byte[28]);
            // Treat as positive big-endian, reduce mod field prime.
            BigInteger n = new BigInteger(1, pkh);
            return n.mod(com.bloxbean.cardano.zeroj.circuit.FieldConfig.BLS12_381.prime());
        } catch (Exception e) {
            // Fallback: hash the address string into the field (demo-only).
            return new BigInteger(1, addressBech32.getBytes())
                    .mod(com.bloxbean.cardano.zeroj.circuit.FieldConfig.BLS12_381.prime());
        }
    }

    public record ClaimRecord(String name, String nullifier, String txHash,
                              long epoch, int ada, String recipient, long provingMs) {}

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
