package com.bloxbean.cardano.zeroj.usecases.reserves.controller;

import com.bloxbean.cardano.zeroj.usecases.reserves.service.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/reserves")
@CrossOrigin(origins = "*")
public class ReservesController {

    private static final Logger log = LoggerFactory.getLogger(ReservesController.class);

    private final AccountService accountService;
    private final MerkleSumTreeService treeService;
    private final ReserveCircuitService circuitService;
    private final OnChainReserveService onChainService;

    // Proof cache: reserves amount → proof result
    private final ConcurrentHashMap<String, ReserveCircuitService.ProofResult> proofCache = new ConcurrentHashMap<>();

    public ReservesController(AccountService accountService, MerkleSumTreeService treeService,
                               ReserveCircuitService circuitService, OnChainReserveService onChainService) {
        this.accountService = accountService;
        this.treeService = treeService;
        this.circuitService = circuitService;
        this.onChainService = onChainService;
    }

    @GetMapping("/status")
    public ResponseEntity<?> status() {
        return ResponseEntity.ok(Map.of(
                "accountCount", accountService.getAccountCount(),
                "totalLiabilitiesAda", accountService.getTotalBalanceAda(),
                "treeBuilt", treeService.isBuilt(),
                "treeRoot", treeService.isBuilt() ? treeService.getRoot().toString(16).substring(0, 16) + "..." : "not built",
                "treeDepth", circuitService.getTreeDepth(),
                "maxAccounts", 1 << circuitService.getTreeDepth()));
    }

    /** Paginated account list */
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

    /** Build Merkle Sum Tree from all accounts */
    @PostMapping("/build-tree")
    public ResponseEntity<?> buildTree() {
        try {
            var result = treeService.buildTree();
            var response = new java.util.HashMap<String, Object>();
            response.put("root", result.root().toString(16));
            response.put("totalLiabilitiesLovelace", result.totalLiabilities().toString());
            response.put("totalLiabilitiesAda", result.totalLiabilities().doubleValue() / 1_000_000);
            response.put("accountCount", result.accountCount());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /** Generate solvency proof. POST { "reservesAda": 10000 } */
    @PostMapping("/prove")
    public ResponseEntity<?> prove(@RequestBody Map<String, Object> request) {
        try {
            if (!treeService.isBuilt()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Build tree first"));
            }

            double reservesAda = ((Number) request.get("reservesAda")).doubleValue();
            boolean forceOnChain = Boolean.TRUE.equals(request.get("forceOnChain"));
            BigInteger reserves = BigInteger.valueOf((long) (reservesAda * 1_000_000));
            BigInteger liabilities = treeService.getTotalLiabilities();
            BigInteger root = treeService.getRoot();
            boolean solvent = reserves.compareTo(liabilities) >= 0;

            log.info("Generating solvency proof: reserves={} ADA, liabilities={} ADA, solvent={}",
                    reservesAda, liabilities.doubleValue() / 1_000_000, solvent);

            long start = System.currentTimeMillis();
            var result = circuitService.prove(reserves, root, liabilities,
                    treeService.getLeafIds(), treeService.getLeafBalances());
            long elapsed = System.currentTimeMillis() - start;

            String cacheKey = reservesAda + "_" + root.toString(16).substring(0, 8);
            proofCache.put(cacheKey, result);

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

            // On-chain attestation
            String txHash = onChainService.publishAttestation(result.proof(),
                    reserves, root, liabilities, solvent);

            return ResponseEntity.ok(Map.of(
                    "solvent", solvent,
                    "reservesAda", reservesAda,
                    "liabilitiesAda", liabilities.doubleValue() / 1_000_000,
                    "txHash", txHash,
                    "provingTimeMs", elapsed,
                    "message", solvent
                            ? "SOLVENT — Groth16 proof verified ON-CHAIN!"
                            : "INSOLVENT — on-chain validator REJECTED the proof."));
        } catch (Exception e) {
            log.error("Prove failed", e);
            boolean onChainRejection = isOnChainRejection(e.getMessage());
            return ResponseEntity.status(onChainRejection ? 403 : 400)
                    .body(errorBody(e, onChainRejection));
        }
    }

    /** Verify individual account inclusion */
    @GetMapping("/verify/{accountId}")
    public ResponseEntity<?> verifyInclusion(@PathVariable String accountId) {
        try {
            if (!treeService.isBuilt()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Build tree first"));
            }

            var account = accountService.getAccount(accountId);
            if (account == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Unknown account: " + accountId));
            }

            var proof = treeService.getInclusionProof(accountId);
            if (proof == null) {
                return ResponseEntity.ok(Map.of(
                        "accountId", accountId,
                        "included", false,
                        "message", "Account NOT in Merkle tree — exchange may be excluding your balance!"));
            }

            // Verify the proof off-chain
            BigInteger leafHash = PoseidonCompute.poseidon(
                    accountService.getAccountIdHash(accountId),
                    BigInteger.valueOf(account.getBalanceLovelace()));

            BigInteger computed = leafHash;
            for (int i = 0; i < proof.siblings().length; i++) {
                if (proof.pathBits()[i].equals(BigInteger.ZERO)) {
                    computed = PoseidonCompute.poseidon(computed, proof.siblings()[i]);
                } else {
                    computed = PoseidonCompute.poseidon(proof.siblings()[i], computed);
                }
            }

            boolean rootMatches = computed.equals(proof.root());

            return ResponseEntity.ok(Map.of(
                    "accountId", accountId,
                    "name", account.getName(),
                    "balanceAda", account.getBalanceAda(),
                    "included", true,
                    "rootMatches", rootMatches,
                    "leafIndex", proof.leafIndex(),
                    "message", rootMatches
                            ? "✅ Account verified — your balance is correctly included in the solvency proof."
                            : "❌ Root mismatch — the tree may have been tampered with!"));
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
