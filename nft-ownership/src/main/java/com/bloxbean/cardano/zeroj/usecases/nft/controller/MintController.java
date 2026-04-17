package com.bloxbean.cardano.zeroj.usecases.nft.controller;

import com.bloxbean.cardano.zeroj.usecases.nft.service.MintService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
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
            var result = mintService.mintToAdmin(collectionName, count);

            return ResponseEntity.ok(Map.of(
                    "policyId", result.policyId(),
                    "tokenNames", result.tokenNames(),
                    "mintTxHash", result.mintTxHash(),
                    "adminAddress", mintService.getAdminAddress()));
        } catch (Exception e) {
            log.error("Mint failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/mint/status")
    public ResponseEntity<?> mintStatus() {
        return ResponseEntity.ok(Map.of(
                "policyId", mintService.getPolicyId(),
                "mintedTokens", mintService.getMintedTokens(),
                "adminAddress", mintService.getAdminAddress()));
    }
}
