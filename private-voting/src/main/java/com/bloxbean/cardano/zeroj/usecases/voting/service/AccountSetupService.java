package com.bloxbean.cardano.zeroj.usecases.voting.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.*;

/**
 * Creates test voter accounts on Yaci DevKit and registers them in the election.
 *
 * <p>Each voter's secret key is random ({@link VoterKeyStore}, ADR-0009 D5) and persisted under
 * the demo data directory, so a restart registers the same voters in its new election. The server
 * holds these keys and votes by label on the voters' behalf: that is a demo-operator action, and
 * the server can link every nullifier to its voter.
 */
@Service
public class AccountSetupService {

    private static final Logger log = LoggerFactory.getLogger(AccountSetupService.class);

    @Value("${election.voter-count}")
    private int voterCount;

    @Value("${election.default-name}")
    private String defaultElectionName;

    @Value("${cardano.yaci.admin-url:}")
    private String yaciAdminUrl;

    @Value("${demo.topup.enabled:true}")
    private boolean topUpEnabled;

    @Value("${demo.data-dir:./data}")
    private String dataDir = "./data";

    private final ElectionService electionService;
    private final VoteCircuitService circuitService;
    private final BackendService backendService;

    private final List<VoterInfo> voters = new ArrayList<>();

    public AccountSetupService(ElectionService electionService, VoteCircuitService circuitService,
                                BackendService backendService) {
        this.electionService = electionService;
        this.circuitService = circuitService;
        this.backendService = backendService;
    }

    @PostConstruct
    public void setup() {
        log.info("Setting up election with {} test voters...", voterCount);

        // Load the voters' keys, or generate them on first start; a damaged key file stops the demo.
        Map<String, BigInteger> keys = VoterKeyStore.loadOrCreate(
                Path.of(dataDir).resolve(VoterKeyStore.FILE_NAME), voterCount, new SecureRandom());

        // Create election
        electionService.createElection(defaultElectionName);

        // Create voter accounts
        for (var entry : keys.entrySet()) {
            String label = entry.getKey();
            BigInteger secretKey = entry.getValue();
            BigInteger publicKey = circuitService.computePublicKey(secretKey);

            var account = new Account(Networks.testnet());
            if (topUpEnabled) {
                topUp(account.baseAddress(), 100);
            }

            electionService.registerVoter(label, secretKey);
            voters.add(new VoterInfo(label, secretKey, publicKey, account.baseAddress()));
            log.info("  {} — addr={}..., pubKey={}...", label,
                    account.baseAddress().substring(0, 25),
                    publicKey.toString(16).substring(0, 8));
        }

        // Finalize election (build Merkle tree)
        electionService.finalizeElection();
        log.info("Election ready: '{}' with {} voters, root={}...",
                electionService.getElectionName(),
                electionService.getVoterCount(),
                electionService.getVoterRoot().toString(16).substring(0, 8));
    }

    public List<VoterInfo> getVoters() {
        return Collections.unmodifiableList(voters);
    }

    private void topUp(String address, int adaAmount) {
        if (yaciAdminUrl == null || yaciAdminUrl.isBlank()) {
            log.info("Skipping top-up for {}; no Yaci admin URL configured", address.substring(0, 20));
            return;
        }
        try {
            var client = HttpClient.newHttpClient();
            var body = String.format("{\"address\":\"%s\",\"adaAmount\":%d}", address, adaAmount);
            var request = HttpRequest.newBuilder()
                    .uri(URI.create(yaciAdminUrl + "/local-cluster/api/addresses/topup"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            log.warn("Failed to top up {}: {}", address.substring(0, 20), e.getMessage());
        }
    }

    public record VoterInfo(String label, BigInteger secretKey, BigInteger publicKey, String address) {}
}
