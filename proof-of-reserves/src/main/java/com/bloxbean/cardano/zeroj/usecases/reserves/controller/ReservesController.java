package com.bloxbean.cardano.zeroj.usecases.reserves.controller;

import com.bloxbean.cardano.zeroj.usecases.reserves.service.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/reserves")
public class ReservesController {

    private static final Logger log = LoggerFactory.getLogger(ReservesController.class);

    private final AccountService accountService;
    private final MerkleSumTreeService treeService;
    private final ReserveCircuitService circuitService;
    private final OnChainReserveService onChainService;

    private final String customerIndexerUrl;

    public ReservesController(AccountService accountService, MerkleSumTreeService treeService,
                               ReserveCircuitService circuitService, OnChainReserveService onChainService,
                               @Value("${reserves.customer-indexer-url:http://localhost:8080/api/v1/}") String customerIndexerUrl) {
        this.accountService = accountService;
        this.treeService = treeService;
        this.circuitService = circuitService;
        this.onChainService = onChainService;
        this.customerIndexerUrl = customerIndexerUrl;
    }

    @GetMapping("/status")
    public ResponseEntity<?> status() {
        var snapshot = treeService.snapshot();
        return ResponseEntity.ok(Map.of(
                "accountCount", accountService.getAccountCount(),
                "totalLiabilitiesAda", accountService.getTotalBalanceAda(),
                "treeBuilt", snapshot != null,
                "treeRoot", snapshot != null ? snapshot.root().toString(16).substring(0, 16) + "..." : "not built",
                "treeDepth", circuitService.getTreeDepth(),
                "maxAccounts", 1 << circuitService.getTreeDepth()));
    }

    /**
     * The attestation policy and clock, and the indexer the customer page reads. A customer pins
     * these from a published source; the page warns when this server later reports different ones.
     */
    @GetMapping("/deployment")
    public ResponseEntity<?> deployment() {
        var d = onChainService.deployment();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("policyId", d.policyId());
        body.put("scriptAddress", onChainService.getScriptAddress());
        body.put("genesisMs", d.genesisMs());
        body.put("periodMs", d.periodMs());
        body.put("custodianPkh", d.custodianPkh());
        body.put("indexerUrl", customerIndexerUrl);
        return ResponseEntity.ok(body);
    }

    /** Paginated account list: the demo custodian's operator view (ADR-0009 D10). */
    @GetMapping("/accounts")
    public ResponseEntity<?> listAccounts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        var result = accountService.listAccounts(page, size);
        return ResponseEntity.ok(Map.of(
                "accounts", result.getContent().stream().map(a -> Map.of(
                        "accountId", a.getAccountId(), "name", a.getName(),
                        "balanceAda", a.getBalanceAda(),
                        "balanceLovelace", a.getBalanceLovelace())).toList(),
                "page", page, "size", size,
                "totalPages", result.getTotalPages(),
                "totalElements", result.getTotalElements()));
    }

    /** Add random accounts */
    @PostMapping("/accounts/add")
    public ResponseEntity<?> addAccounts(@RequestBody Map<String, Object> request) {
        int count = ((Number) request.getOrDefault("count", 5)).intValue();
        var ids = accountService.addRandomAccounts(count);
        return ResponseEntity.ok(Map.of(
                "added", ids.size(),
                "totalAccounts", accountService.getAccountCount(),
                "totalLiabilitiesAda", accountService.getTotalBalanceAda()));
    }

    /** Build a fresh salted tree from all accounts (new salts every time). */
    @PostMapping("/build-tree")
    public ResponseEntity<?> buildTree() {
        try {
            var result = treeService.buildTree();
            var response = new HashMap<String, Object>();
            response.put("root", result.root().toString(16));
            response.put("totalLiabilitiesLovelace", result.totalLiabilities().toString());
            response.put("totalLiabilitiesAda", result.totalLiabilities().doubleValue() / 1_000_000);
            response.put("accountCount", result.accountCount());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Prove solvency and mint the current period's attestation. POST { "reservesAda": 10000 }.
     * The reserves figure is the custodian's declaration: the proof checks it against the sum of
     * the balances, not against any holdings.
     */
    @PostMapping("/prove")
    public ResponseEntity<?> prove(@RequestBody Map<String, Object> request) {
        try {
            var snapshot = treeService.snapshot();
            if (snapshot == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Build tree first"));
            }

            double reservesAda = ((Number) request.get("reservesAda")).doubleValue();
            boolean forceOnChain = Boolean.TRUE.equals(request.get("forceOnChain"));
            BigInteger reserves = BigInteger.valueOf((long) (reservesAda * 1_000_000));
            BigInteger liabilities = snapshot.totalLiabilities();
            BigInteger root = snapshot.root();
            boolean solvent = reserves.compareTo(liabilities) >= 0;

            log.info("Generating solvency proof: reserves={} ADA, liabilities={} ADA, solvent={}",
                    reservesAda, liabilities.doubleValue() / 1_000_000, solvent);

            long start = System.currentTimeMillis();
            var result = circuitService.prove(reserves, root, liabilities,
                    snapshot.leafIds(), snapshot.leafBalances());
            long elapsed = System.currentTimeMillis() - start;

            log.info("Solvency proof generated in {}ms (solvent={})", elapsed, solvent);

            // Off-chain check
            if (!solvent && !forceOnChain) {
                return ResponseEntity.ok(Map.of(
                        "solvent", false,
                        "reservesAda", reservesAda,
                        "liabilitiesAda", liabilities.doubleValue() / 1_000_000,
                        "shortfallAda", (liabilities.doubleValue() - reserves.doubleValue()) / 1_000_000,
                        "provingTimeMs", elapsed,
                        "message", "INSOLVENT — reserves < liabilities. Enable 'Skip off-chain check' to test on-chain rejection."));
            }

            // On-chain attestation: the mint itself verifies the proof.
            long period = onChainService.periods().periodAt(onChainService.chainTimeMs());
            String txHash;
            try {
                txHash = onChainService.publishAttestation(result.proof(), period, reserves, root, liabilities);
                treeService.markAttested(snapshot, period);
            } catch (OnChainReserveService.AlreadyAttestedException e) {
                return ResponseEntity.status(409).body(Map.of("error", e.getMessage(), "onChainRejection", false));
            }

            return ResponseEntity.ok(Map.of(
                    "solvent", solvent,
                    "reservesAda", reservesAda,
                    "liabilitiesAda", liabilities.doubleValue() / 1_000_000,
                    "period", period,
                    "txHash", txHash,
                    "provingTimeMs", elapsed,
                    "message", solvent
                            ? "SOLVENT — attestation token minted; the minting policy verified the Groth16 proof."
                            : "INSOLVENT — on-chain validator REJECTED the proof."));
        } catch (Exception e) {
            log.error("Prove failed", e);
            boolean onChainRejection = isOnChainRejection(e.getMessage());
            return ResponseEntity.status(onChainRejection ? 403 : 400)
                    .body(errorBody(e, onChainRejection));
        }
    }

    /**
     * The customer's inclusion data in the last attested snapshot: salt, balance, leaf index and
     * sibling path. The customer's page recomputes the root and compares it with the on-chain
     * attestation itself.
     * <p>
     * This is the demo custodian's operator view (ADR-0009 D10): it answers anyone, and the salt
     * it returns is what keeps a leaf's balance from being guessed.
     */
    @GetMapping("/verify/{accountId}")
    public ResponseEntity<?> verifyInclusion(@PathVariable String accountId) {
        try {
            var snapshot = treeService.customerSnapshot();
            if (snapshot == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Build tree first"));
            }
            var account = accountService.getAccount(accountId);
            if (account == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Unknown account: " + accountId));
            }
            var proof = snapshot.inclusionProof(accountId);
            if (proof == null) {
                return ResponseEntity.ok(Map.of(
                        "accountId", accountId,
                        "included", false,
                        "message", "Account NOT in the attested snapshot — the custodian must rebuild the tree and attest again."));
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("accountId", accountId);
            body.put("name", account.getName());
            body.put("included", true);
            body.put("salt", proof.salt().toString());
            body.put("balanceLovelace", proof.balance().toString());
            body.put("balanceAda", proof.balance().doubleValue() / 1_000_000);
            body.put("leafIndex", proof.leafIndex());
            body.put("siblings", Arrays.stream(proof.siblings()).map(BigInteger::toString).toList());
            return ResponseEntity.ok(body);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
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
