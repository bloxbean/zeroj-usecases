package com.bloxbean.cardano.zeroj.usecases.voting.controller;

import com.bloxbean.cardano.zeroj.usecases.voting.crypto.JubjubElGamal;
import com.bloxbean.cardano.zeroj.usecases.voting.service.ElectionService;
import com.bloxbean.cardano.zeroj.usecases.voting.service.OnChainVoteService;
import com.bloxbean.cardano.zeroj.usecases.voting.service.TallyService;
import com.bloxbean.cardano.zeroj.usecases.voting.service.VoteCircuitService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class VoteController {

    private static final Logger log = LoggerFactory.getLogger(VoteController.class);
    private static final SecureRandom RANDOM = new SecureRandom();

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
     * Cast a vote: encrypt it under the election key, prove the ballot, submit it on-chain.
     * Request: { "voterLabel": "voter1", "vote": 1 }   (0=NO, 1=YES)
     *
     * <p>The response deliberately does not echo the vote: everything returned here is public.
     */
    @PostMapping("/vote")
    public ResponseEntity<?> castVote(@RequestBody Map<String, Object> request) {
        try {
            String voterLabel = (String) request.get("voterLabel");
            int vote = ((Number) request.get("vote")).intValue();
            if (vote != 0 && vote != 1) {
                return ResponseEntity.badRequest().body(Map.of("error", "Vote must be 0 (NO) or 1 (YES)"));
            }
            var config = electionService.getConfig();
            if (config == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Election not finalized yet"));
            }
            if (onChainVoteService.chainTimeMillis() >= config.votingDeadlineMillis()) {
                return ResponseEntity.status(403).body(Map.of("error", "Voting has closed"));
            }
            BigInteger secretKey = electionService.getSecretKey(voterLabel);
            if (secretKey == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Unknown voter: " + voterLabel));
            }

            BigInteger nullifier = circuitService.computeNullifier(secretKey, config.electionId());
            if (onChainVoteService.isNullifierUsed(config, nullifier)) {
                return ResponseEntity.status(403).body(Map.of(
                        "error", "Double vote — this voter already voted",
                        "voterLabel", voterLabel));
            }
            int leafIndex = electionService.findVoterIndex(circuitService.computePublicKey(secretKey));
            if (leafIndex < 0) {
                return ResponseEntity.badRequest().body(Map.of("error", "Voter not in eligibility tree"));
            }
            var merkleProof = electionService.getProof(leafIndex);

            log.info("Proving a ballot for {}...", voterLabel);
            long start = System.currentTimeMillis();
            var ballot = circuitService.proveBallot(new VoteCircuitService.BallotWitness(
                    config.electionId(), config.voterRoot(), config.electionKey(),
                    secretKey, vote, JubjubElGamal.randomScalar(RANDOM),
                    merkleProof.siblings(), merkleProof.pathBits()));
            long elapsed = System.currentTimeMillis() - start;
            log.info("Ballot proof generated in {}ms", elapsed);

            String txHash = onChainVoteService.submitBallot(config, ballot);

            var c = ballot.ciphertext();
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("voterLabel", voterLabel);
            body.put("nullifier", ballot.nullifier().toString(16));
            body.put("ballot", Map.of("A", point(c.handle()), "B", point(c.ballot())));
            body.put("txHash", txHash);
            body.put("provingTimeMs", elapsed);
            return ResponseEntity.ok(body);
        } catch (Exception e) {
            log.error("Vote failed", e);
            boolean onChainRejection = isOnChainRejection(e.getMessage());
            return ResponseEntity.status(onChainRejection ? 403 : 400)
                    .body(errorBody(e, onChainRejection));
        }
    }

    /**
     * The tally. While voting is open: the ballot count and the encrypted running sum only.
     * After the deadline: the decrypted total, each trustee's share with its proof, and the
     * result of re-verifying everything from chain data.
     */
    @GetMapping("/results")
    public ResponseEntity<?> results() {
        try {
            var tally = tallyService.tally();
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("election", electionService.getElectionName());
            body.put("phase", tally.decrypted() ? "decrypted" : "voting-open");
            body.put("votingDeadline", tally.votingDeadlineMillis());
            body.put("ballots", tally.ballots());
            body.put("encryptedBallots", tally.ballotNodes().stream().map(n -> Map.of(
                    "nullifier", hexPrefix(n.nullifier()),
                    "A", point(n.ciphertext().handle()),
                    "B", point(n.ciphertext().ballot()))).toList());
            body.put("aggregate", Map.of("A", point(tally.aggregate().handle()), "B", point(tally.aggregate().ballot())));
            if (tally.decrypted()) {
                var verification = tallyService.verify(tally);
                body.put("yes", tally.yes());
                body.put("no", tally.no());
                body.put("total", tally.ballots());
                body.put("shares", tally.shares().stream().map(s -> Map.of(
                        "trustee", s.trustee(),
                        "publicKey", point(s.publicKey()),
                        "share", point(s.share()),
                        "proof", s.proofJson())).toList());
                body.put("verified", verification.valid());
                body.put("checks", verification.checks());
            }
            return ResponseEntity.ok(body);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    @GetMapping("/status")
    public ResponseEntity<?> status() {
        var config = electionService.getConfig();
        int ballots = 0;
        try {
            // Read-only: never deploys scripts as a side effect of a status request.
            if (config != null && onChainVoteService.isDeployed(config)) {
                ballots = onChainVoteService.getBallots(config).size();
            }
        } catch (Exception e) {
            log.debug("Ballot count unavailable: {}", e.getMessage());
        }
        return ResponseEntity.ok(Map.of(
                "circuit", Map.of(
                        "treeDepth", circuitService.getTreeDepth(),
                        "ballotConstraints", circuitService.ballotConstraints(),
                        "status", "ready"),
                "election", Map.of(
                        "name", electionService.getElectionName() != null ? electionService.getElectionName() : "",
                        "voterCount", electionService.getVoterCount(),
                        "finalized", electionService.isFinalized(),
                        "votingDeadline", config == null ? 0 : config.votingDeadlineMillis()),
                "votes", Map.of(
                        "count", ballots,
                        "mode", "on-chain, encrypted")));
    }

    static Map<String, String> point(JubjubPoint p) {
        JubjubPoint n = p.normalized();
        return Map.of("u", n.affineU().toString(16), "v", n.affineV().toString(16));
    }

    private static String hexPrefix(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, 8); i++) sb.append(String.format("%02x", bytes[i]));
        return sb.append("...").toString();
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
