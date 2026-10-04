package com.bloxbean.cardano.zeroj.usecases.voting.controller;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.voting.service.AccountSetupService;
import com.bloxbean.cardano.zeroj.usecases.voting.service.ElectionService;
import com.bloxbean.cardano.zeroj.usecases.voting.service.OnChainVoteService;
import com.bloxbean.cardano.zeroj.usecases.voting.service.VoteCircuitService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/election")
@CrossOrigin(origins = "*")
public class ElectionController {

    private final ElectionService electionService;
    private final AccountSetupService accountSetupService;
    private final VoteCircuitService circuitService;
    private final OnChainVoteService onChainVoteService;

    public ElectionController(ElectionService electionService,
                               AccountSetupService accountSetupService,
                               VoteCircuitService circuitService,
                               OnChainVoteService onChainVoteService) {
        this.electionService = electionService;
        this.accountSetupService = accountSetupService;
        this.circuitService = circuitService;
        this.onChainVoteService = onChainVoteService;
    }

    /**
     * The election manifest (ADR-0005): everything a third party needs to check the deployed
     * scripts and the tally. Recompute both script hashes from these parameters, check every key
     * proof (base G), and check that the election key is the sum of the trustee keys.
     */
    @GetMapping("/manifest")
    public ResponseEntity<?> manifest() {
        var config = electionService.getConfig();
        if (config == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Election not finalized yet"));
        }
        try {
            var binding = onChainVoteService.scriptBinding(config);
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("name", config.name());
            body.put("electionId", config.electionId().toString(16));
            body.put("voterRoot", config.voterRoot().toString(16));
            body.put("votingDeadline", config.votingDeadlineMillis());
            body.put("electionKey", VoteController.point(config.electionKey()));
            body.put("trustees", config.trustees().stream().map(t -> Map.of(
                    "label", t.label(),
                    "publicKey", VoteController.point(t.publicKey()),
                    "keyProof", t.keyProofJson())).toList());
            body.put("ballotVerificationKeyHash", blake2b(circuitService.ballotVerificationKeyJson()));
            body.put("dleqVerificationKey", circuitService.dleqVerificationKeyJson());
            body.put("seedRef", binding.seedRef());
            body.put("ballotPolicyId", binding.ballotPolicyId());
            body.put("listPolicyId", binding.listPolicyId());
            body.put("registryAddress", binding.registryAddress());
            return ResponseEntity.ok(body);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    private static String blake2b(String text) {
        return HexUtil.encodeHexString(Blake2bUtil.blake2bHash256(text.getBytes(StandardCharsets.UTF_8)));
    }

    @GetMapping("/status")
    public ResponseEntity<?> status() {
        var voters = accountSetupService.getVoters().stream()
                .map(v -> Map.of(
                        "label", v.label(),
                        "publicKey", v.publicKey().toString(16).substring(0, 16) + "...",
                        "address", v.address().substring(0, 30) + "..."))
                .toList();

        var config = electionService.getConfig();
        var key = electionService.getElectionKey();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", electionService.getElectionName() != null ? electionService.getElectionName() : "");
        body.put("electionId", electionService.getElectionId() != null ? electionService.getElectionId().toString(16) : "0");
        body.put("voterRoot", electionService.getVoterRoot().toString(16));
        body.put("voterCount", electionService.getVoterCount());
        body.put("finalized", electionService.isFinalized());
        body.put("treeDepth", circuitService.getTreeDepth());
        body.put("votingDeadline", config == null ? 0 : config.votingDeadlineMillis());
        body.put("electionKey", key == null ? Map.of() : VoteController.point(key));
        body.put("trustees", electionService.getTrusteeInfo().stream().map(t -> Map.of(
                "label", t.label(),
                "publicKey", VoteController.point(t.publicKey()),
                "keyProof", t.keyProofJson())).toList());
        body.put("voters", voters);
        return ResponseEntity.ok(body);
    }

    @PostMapping("/create")
    public ResponseEntity<?> create(@RequestBody Map<String, String> request) {
        String name = request.getOrDefault("name", "Proposal #1");
        electionService.createElection(name);
        return ResponseEntity.ok(Map.of(
                "name", name,
                "electionId", electionService.getElectionId().toString()));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> request) {
        String label = request.get("label");
        BigInteger secretKey = new BigInteger(request.get("secretKey"));
        BigInteger pubKey = electionService.registerVoter(label, secretKey);
        return ResponseEntity.ok(Map.of(
                "label", label,
                "publicKey", pubKey.toString(),
                "voterCount", electionService.getVoterCount()));
    }

    @PostMapping("/finalize")
    public ResponseEntity<?> finalizeElection() {
        var config = electionService.finalizeElection();
        return ResponseEntity.ok(Map.of(
                "voterRoot", config.voterRoot().toString(16),
                "voterCount", config.voterCount(),
                "votingDeadline", config.votingDeadlineMillis()));
    }
}
