package com.bloxbean.cardano.zeroj.usecases.voting.controller;

import com.bloxbean.cardano.zeroj.usecases.voting.service.ElectionService;
import com.bloxbean.cardano.zeroj.usecases.voting.service.OnChainVoteService;
import com.bloxbean.cardano.zeroj.usecases.voting.service.TallyService;
import com.bloxbean.cardano.zeroj.usecases.voting.service.VoteCircuitService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class VoteController {

    private static final Logger log = LoggerFactory.getLogger(VoteController.class);

    private final VoteCircuitService circuitService;
    private final ElectionService electionService;
    private final OnChainVoteService onChainVoteService;
    private final TallyService tallyService;

    public VoteController(VoteCircuitService circuitService, ElectionService electionService,
                           OnChainVoteService onChainVoteService, TallyService tallyService) {
        this.circuitService = circuitService;
        this.electionService = electionService;
        this.onChainVoteService = onChainVoteService;
        this.tallyService = tallyService;
    }

    /**
     * Cast a vote. Generates ZK proof and submits on-chain.
     * Request: { "voterLabel": "voter1", "vote": 1 }   (0=NO, 1=YES)
     */
    @PostMapping("/vote")
    public ResponseEntity<?> castVote(@RequestBody Map<String, Object> request) {
        try {
            String voterLabel = (String) request.get("voterLabel");
            int vote = ((Number) request.get("vote")).intValue();

            if (vote != 0 && vote != 1) {
                return ResponseEntity.badRequest().body(Map.of("error", "Vote must be 0 (NO) or 1 (YES)"));
            }

            if (!electionService.isFinalized()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Election not finalized yet"));
            }

            BigInteger secretKey = electionService.getSecretKey(voterLabel);
            if (secretKey == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Unknown voter: " + voterLabel));
            }

            BigInteger electionId = electionService.getElectionId();
            BigInteger voterRoot = electionService.getVoterRoot();

            // Check for double vote
            BigInteger nullifier = circuitService.computeNullifier(secretKey, electionId);
            if (onChainVoteService.isNullifierUsed(nullifier)) {
                return ResponseEntity.status(403).body(Map.of(
                        "error", "Double vote — this voter already voted",
                        "voterLabel", voterLabel));
            }

            // Find voter in Merkle tree
            BigInteger publicKey = circuitService.computePublicKey(secretKey);
            int leafIndex = electionService.findVoterIndex(publicKey);
            if (leafIndex < 0) {
                return ResponseEntity.badRequest().body(Map.of("error", "Voter not in eligibility tree"));
            }

            var merkleProof = electionService.getProof(leafIndex);

            // Generate ZK proof
            log.info("Generating vote proof for {} (vote={})...", voterLabel, vote == 1 ? "YES" : "NO");
            long start = System.currentTimeMillis();
            var result = circuitService.prove(
                    BigInteger.valueOf(vote), secretKey, electionId, voterRoot,
                    merkleProof.siblings(), merkleProof.pathBits());
            long elapsed = System.currentTimeMillis() - start;
            log.info("Vote proof generated in {}ms", elapsed);

            // Submit on-chain
            String txHash = onChainVoteService.submitVote(
                    result.proof(), electionId, voterRoot,
                    result.nullifier(), result.commitment());

            return ResponseEntity.ok(Map.of(
                    "voterLabel", voterLabel,
                    "vote", vote == 1 ? "YES" : "NO",
                    "nullifier", result.nullifier().toString(),
                    "commitment", result.commitment().toString(),
                    "txHash", txHash,
                    "provingTimeMs", elapsed));
        } catch (Exception e) {
            log.error("Vote failed", e);
            boolean onChainRejection = isOnChainRejection(e.getMessage());
            return ResponseEntity.status(onChainRejection ? 403 : 400)
                    .body(errorBody(e, onChainRejection));
        }
    }

    @GetMapping("/results")
    public ResponseEntity<?> results() {
        try {
            var tally = tallyService.tally();
            return ResponseEntity.ok(Map.of(
                    "yes", tally.yes(),
                    "no", tally.no(),
                    "unknown", tally.unknown(),
                    "total", tally.total(),
                    "votes", tally.votes(),
                    "election", electionService.getElectionName()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/status")
    public ResponseEntity<?> status() {
        return ResponseEntity.ok(Map.of(
                "circuit", Map.of(
                        "treeDepth", circuitService.getTreeDepth(),
                        "status", "ready"),
                "election", Map.of(
                        "name", electionService.getElectionName() != null ? electionService.getElectionName() : "",
                        "voterCount", electionService.getVoterCount(),
                        "finalized", electionService.isFinalized()),
                "votes", Map.of(
                        "count", onChainVoteService.getVoteCount(),
                        "mode", "on-chain")));
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
