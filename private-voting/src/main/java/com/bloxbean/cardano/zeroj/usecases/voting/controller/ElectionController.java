package com.bloxbean.cardano.zeroj.usecases.voting.controller;

import com.bloxbean.cardano.zeroj.usecases.voting.service.AccountSetupService;
import com.bloxbean.cardano.zeroj.usecases.voting.service.ElectionService;
import com.bloxbean.cardano.zeroj.usecases.voting.service.VoteCircuitService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.Map;

@RestController
@RequestMapping("/api/election")
@CrossOrigin(origins = "*")
public class ElectionController {

    private final ElectionService electionService;
    private final AccountSetupService accountSetupService;
    private final VoteCircuitService circuitService;

    public ElectionController(ElectionService electionService,
                               AccountSetupService accountSetupService,
                               VoteCircuitService circuitService) {
        this.electionService = electionService;
        this.accountSetupService = accountSetupService;
        this.circuitService = circuitService;
    }

    @GetMapping("/status")
    public ResponseEntity<?> status() {
        var voters = accountSetupService.getVoters().stream()
                .map(v -> Map.of(
                        "label", v.label(),
                        "publicKey", v.publicKey().toString(16).substring(0, 16) + "...",
                        "address", v.address().substring(0, 30) + "..."))
                .toList();

        return ResponseEntity.ok(Map.of(
                "name", electionService.getElectionName() != null ? electionService.getElectionName() : "",
                "electionId", electionService.getElectionId() != null ? electionService.getElectionId().toString() : "0",
                "voterRoot", electionService.getVoterRoot().toString(),
                "voterCount", electionService.getVoterCount(),
                "finalized", electionService.isFinalized(),
                "treeDepth", circuitService.getTreeDepth(),
                "voters", voters));
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
        BigInteger root = electionService.finalizeElection();
        return ResponseEntity.ok(Map.of(
                "voterRoot", root.toString(),
                "voterCount", electionService.getVoterCount()));
    }
}
