package com.bloxbean.cardano.zeroj.usecases.nft.controller;

import com.bloxbean.cardano.zeroj.usecases.nft.service.MintService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class MintController {

    private static final Logger log = LoggerFactory.getLogger(MintController.class);

    private final MintService mintService;

    public MintController(MintService mintService) {
        this.mintService = mintService;
    }

    @PostMapping("/mint")
    public ResponseEntity<?> mintNfts(@RequestBody Map<String, Object> request) {
        try {
            String collectionName = (String) request.getOrDefault("collectionName", "ZeroJTicket");
            int count = request.containsKey("count")
                    ? ((Number) request.get("count")).intValue()
                    : 3;

            log.info("Minting {} NFTs for collection '{}'", count, collectionName);
            var result = mintService.mintToCustody(collectionName, count);

            return ResponseEntity.ok(Map.of(
                    "policyId", result.policyId(),
                    "tokenNames", result.tokenNames(),
                    "mintTxHash", result.mintTxHash(),
                    "custodyAddress", mintService.getCustodyAddress()));
        } catch (Exception e) {
            log.error("Mint failed", e);
            boolean onChainRejection = isOnChainRejection(e.getMessage());
            return ResponseEntity.status(onChainRejection ? 403 : 400)
                    .body(errorBody(e, onChainRejection));
        }
    }

    @GetMapping("/mint/status")
    public ResponseEntity<?> mintStatus() {
        return ResponseEntity.ok(Map.of(
                "policyId", mintService.getPolicyId(),
                "mintedTokens", mintService.getMintedTokens(),
                "custodyAddress", mintService.getCustodyAddress(),
                "operatorAddress", mintService.getAdminAddress()));
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
