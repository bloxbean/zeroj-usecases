package com.bloxbean.cardano.zeroj.usecases.airdrop.controller;

import com.bloxbean.cardano.zeroj.usecases.airdrop.service.AirdropProofService;
import com.bloxbean.cardano.zeroj.usecases.airdrop.service.HolderWallet;
import com.bloxbean.cardano.zeroj.usecases.airdrop.service.OnChainAirdropService;
import com.bloxbean.cardano.zeroj.usecases.airdrop.service.PaidNullifierLedger;
import com.bloxbean.cardano.zeroj.usecases.airdrop.service.PersonhoodIssuer;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Demo API (ADR-0009 D3, D10). The server holds the demo holders' wallets (custodial), so this
 * API is the operator's view; privacy holds against chain and mempool observers, not against
 * the demo server. Even so, {@code /status} and {@code /history} return no names next to
 * nullifiers and no bits of any {@code personhoodId}. There is no CORS policy: the UI is
 * same-origin, and a permissive one would let any website the operator visits read this API.
 */
@RestController
@RequestMapping("/api/airdrop")
public class AirdropController {

    private static final Logger log = LoggerFactory.getLogger(AirdropController.class);
    private static final List<String> DEMO_HOLDERS = List.of("Alice", "Bob", "Charlie", "Diana", "Eve");

    private final PersonhoodIssuer issuer;
    private final HolderWallet wallet;
    private final AirdropProofService proofService;
    private final OnChainAirdropService onChainService;

    private final ConcurrentLinkedDeque<ClaimRecord> history = new ConcurrentLinkedDeque<>();

    public AirdropController(PersonhoodIssuer issuer,
                             HolderWallet wallet,
                             AirdropProofService proofService,
                             OnChainAirdropService onChainService) {
        this.issuer = issuer;
        this.wallet = wallet;
        this.proofService = proofService;
        this.onChainService = onChainService;
    }

    /**
     * Enrols the demo holders once. Each samples its own identifier; the issuer signs only
     * {@code Poseidon(personhoodId, 0)}. A holder whose credential was lost cannot be re-enrolled.
     */
    @PostConstruct
    public void enrollDemoHolders() {
        for (String name : DEMO_HOLDERS) {
            if (wallet.get(name) != null) continue;
            try {
                wallet.enroll(name);
            } catch (PersonhoodIssuer.AlreadyIssuedException e) {
                log.warn("{} was already issued a credential that the holder wallet no longer has;"
                        + " it cannot be re-issued", name);
            }
        }
    }

    @GetMapping("/status")
    public ResponseEntity<?> status() {
        BigInteger epoch = onChainService.getPolicyEpoch();
        List<Map<String, Object>> users = new ArrayList<>();
        for (String name : wallet.holders()) {
            var cred = wallet.get(name);
            boolean claimed = epoch != null && onChainService.alreadyClaimed(
                    HolderWallet.nullifier(cred.personhoodId(), epoch));
            users.add(Map.of("name", name, "alreadyClaimedThisRound", claimed));
        }
        var pk = issuer.publicKey();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("users", users);
        body.put("issuerPkU", "0x" + pk.affineU().toString(16).substring(0, 16) + "...");
        body.put("issuerPkV", "0x" + pk.affineV().toString(16).substring(0, 16) + "...");
        body.put("round", onChainService.getRound());
        body.put("policyEpoch", epoch == null ? "(not deployed)" : "0x" + epoch.toString(16).substring(0, 16) + "...");
        body.put("adaPerClaim", onChainService.getPayoutLovelace() / 1_000_000L);
        body.put("totalClaims", onChainService.totalClaims());
        body.put("policyId", safePolicyId());
        body.put("faucetAdmin", onChainService.getAdminAddress());
        return ResponseEntity.ok(body);
    }

    /** Claims made through this server since it started. No names: a claim is not linked to a holder. */
    @GetMapping("/history")
    public ResponseEntity<?> history() {
        return ResponseEntity.ok(Map.of("claims", List.copyOf(history)));
    }

    /**
     * Claim airdrop. Body: { "name": "Alice", "recipient": "addr_test1..." (optional) }.
     * {@code name} selects a holder in the custodial demo wallet. The recipient's payment
     * credential must be a key hash; script addresses are refused. If it is omitted, the payout
     * goes to the faucet admin's own address (demo default).
     */
    @PostMapping("/claim")
    public ResponseEntity<?> claim(@RequestBody Map<String, String> request) {
        try {
            String name = request.get("name");
            var cred = name == null ? null : wallet.get(name);
            if (cred == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "No credential in the holder wallet for: " + name));
            }
            String recipientAddr = request.getOrDefault("recipient", onChainService.getAdminAddress());
            byte[] recipientKeyHash;
            try {
                recipientKeyHash = OnChainAirdropService.recipientKeyHash(recipientAddr);
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
            }
            BigInteger recipientField = new BigInteger(1, recipientKeyHash);
            BigInteger epoch = onChainService.getPolicyEpoch();
            if (epoch == null) {
                return ResponseEntity.status(503).body(Map.of("error", "The faucet is not deployed yet"));
            }
            BigInteger nullifier = HolderWallet.nullifier(cred.personhoodId(), epoch);
            if (onChainService.alreadyClaimed(nullifier)) {
                return alreadyClaimed(nullifier);
            }

            log.info("Generating airdrop proof (round={})...", onChainService.getRound());
            long start = System.currentTimeMillis();
            var claimProof = proofService.prove(
                    issuer.publicKey(),
                    cred.signature(),
                    cred.personhoodId(),
                    epoch,
                    recipientField);
            long provingMs = System.currentTimeMillis() - start;

            String txHash = onChainService.submitClaim(claimProof.proof(), claimProof.nullifier(), recipientAddr);

            long ada = onChainService.getPayoutLovelace() / 1_000_000L;
            history.addFirst(new ClaimRecord(shortHex(claimProof.nullifier()), txHash,
                    onChainService.getRound(), ada, recipientAddr, provingMs));
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("txHash", txHash);
            body.put("nullifier", shortHex(claimProof.nullifier()));
            body.put("ada", ada);
            body.put("recipient", recipientAddr);
            body.put("provingTimeMs", provingMs);
            return ResponseEntity.ok(body);
        } catch (PaidNullifierLedger.AlreadyPaidException e) {
            return ResponseEntity.status(409).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Claim failed", e);
            String msg = e.getMessage();
            boolean onChainRejection = isOnChainRejection(msg);
            return ResponseEntity.status(onChainRejection ? 403 : 400)
                    .body(errorBody(e, onChainRejection));
        }
    }

    private ResponseEntity<?> alreadyClaimed(BigInteger nullifier) {
        return ResponseEntity.status(409).body(Map.of(
                "error", "Already claimed in round " + onChainService.getRound(),
                "nullifier", shortHex(nullifier)));
    }

    private String safePolicyId() {
        String id = onChainService.getPolicyId();
        return id == null ? "(not deployed)" : id;
    }

    private static String shortHex(BigInteger value) {
        return "0x" + String.format("%064x", value).substring(0, 16) + "...";
    }

    /** One claim, as the history shows it: no holder name. */
    public record ClaimRecord(String nullifier, String txHash, long round, long ada,
                              String recipient, long provingMs) {}

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
