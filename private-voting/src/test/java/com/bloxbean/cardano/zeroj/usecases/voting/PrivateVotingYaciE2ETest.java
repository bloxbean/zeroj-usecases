package com.bloxbean.cardano.zeroj.usecases.voting;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.usecases.voting.crypto.JubjubElGamal;
import com.bloxbean.cardano.zeroj.usecases.voting.service.ElectionService;
import com.bloxbean.cardano.zeroj.usecases.voting.service.OnChainVoteService;
import com.bloxbean.cardano.zeroj.usecases.voting.service.TallyService;
import com.bloxbean.cardano.zeroj.usecases.voting.service.VoteCircuitService;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * ADR-0005 on Yaci DevKit: a full private election.
 *
 * <ol>
 *   <li>Three trustees with proved keys; three voters; the scripts deployed with a one-shot
 *       root.</li>
 *   <li>Three encrypted ballots cast on-chain (YES, NO, YES).</li>
 *   <li>A second ballot by the same voter is refused; a valid proof submitted with a swapped
 *       ballot is rejected by the ballot policy.</li>
 *   <li>Before the deadline the tally reveals nothing but the ballot count.</li>
 *   <li>After the deadline the sum is decrypted once: 2 YES, 1 NO; the published tally
 *       re-verifies from chain data and the manifest.</li>
 * </ol>
 *
 * Runs only with {@code ZEROJ_YACI_E2E=true}; uses {@code ZEROJ_YACI_STORE_URL} /
 * {@code ZEROJ_YACI_ADMIN_URL} when DevKit uses non-default ports.
 */
class PrivateVotingYaciE2ETest {

    private static final String BASE_URL = env("ZEROJ_YACI_STORE_URL", "http://localhost:8080/api/v1/");
    private static final String ADMIN_URL = env("ZEROJ_YACI_ADMIN_URL", "http://localhost:10000");
    private static final long WINDOW_SECONDS = 150;

    @Test
    void privateElectionOnDevKit() throws Exception {
        assumeTrue(e2eEnabled(), "Set ZEROJ_YACI_E2E=true to run this Yaci DevKit E2E test");

        var circuits = new VoteCircuitService();
        ReflectionTestUtils.setField(circuits, "treeDepth", VotingFixture.DEPTH);
        circuits.init();
        var election = new ElectionService(circuits);
        ReflectionTestUtils.setField(election, "votingWindowSeconds", WINDOW_SECONDS);
        var admin = new Account(Networks.testnet());
        topUp(admin.baseAddress(), 1000);
        var backend = new BFBackendService(BASE_URL, "");
        var onChain = new OnChainVoteService(backend, admin, circuits);
        var tally = new TallyService(election, onChain, circuits);
        ReflectionTestUtils.setField(tally, "settleSeconds", 5L);

        election.createElection("E2E proposal");
        for (int i = 0; i < 4; i++) {
            election.registerVoter("voter" + i, BigInteger.valueOf(20001 + i));
        }
        var config = election.finalizeElection();
        onChain.deploy(config);

        // Three ballots: YES, NO, YES.
        int[] votes = {1, 0, 1};
        for (int i = 0; i < 3; i++) {
            String tx = onChain.submitBallot(config, prove(circuits, election, config, "voter" + i, votes[i]));
            System.out.println("Ballot " + i + " on DevKit: " + tx);
        }

        // A second ballot by voter0 (same nullifier) cannot be inserted.
        var again = prove(circuits, election, config, "voter0", 0);
        assertTrue(onChain.isNullifierUsed(config, again.nullifier()));
        assertThrows(IllegalStateException.class, () -> onChain.submitBallot(config, again));

        // A valid proof with a swapped (unproved) ballot in the datum: the ballot policy rejects it.
        var honest = prove(circuits, election, config, "voter3", 0);
        var swapped = new VoteCircuitService.BallotProof(honest.proof(), honest.nullifier(),
                JubjubElGamal.encrypt(1, JubjubElGamal.randomScalar(new SecureRandom()), config.electionKey()),
                honest.publicInputs());
        var rejected = assertThrows(RuntimeException.class, () -> onChain.submitBallot(config, swapped));
        System.out.println("Swapped ballot rejected: " + rejected.getMessage());
        assertTrue(String.valueOf(rejected.getMessage()).toLowerCase().contains("script")
                || String.valueOf(rejected.getMessage()).toLowerCase().contains("evaluat"),
                "rejection must come from script evaluation: " + rejected.getMessage());
        assertFalse(onChain.isNullifierUsed(config, honest.nullifier()), "the rejected ballot left no trace");

        // Before the deadline: no decryption, only the encrypted running sum.
        var open = tally.tally();
        assertFalse(open.decrypted());
        assertEquals(3, open.ballots());
        assertNull(open.yes());

        // Wait until the chain is past the deadline plus the settling margin.
        while (onChain.chainTimeMillis() < config.votingDeadlineMillis() + 6_000) {
            Thread.sleep(5_000);
        }
        var result = tally.tally();
        assertTrue(result.decrypted());
        assertEquals(2, result.yes());
        assertEquals(1, result.no());
        var verification = tally.verify(result);
        verification.checks().forEach(c -> System.out.println("  " + c));
        assertTrue(verification.valid(), "published tally must re-verify");
        assertTrue(tally.tally() == result, "the tally is decrypted once and re-served");

        // After the deadline no ballot can be cast (the transaction could not be valid in time).
        var late = prove(circuits, election, config, "voter2", 1);
        assertThrows(IllegalStateException.class, () -> onChain.submitBallot(config, late));
        System.out.println("Private election on DevKit: YES=" + result.yes() + " NO=" + result.no()
                + " digest=" + result.ballotSetDigest());
    }

    private static VoteCircuitService.BallotProof prove(VoteCircuitService circuits, ElectionService election,
                                                        ElectionService.ElectionConfig config, String voter, int vote) {
        BigInteger secret = election.getSecretKey(voter);
        int index = election.findVoterIndex(circuits.computePublicKey(secret));
        var path = election.getProof(index);
        return circuits.proveBallot(new VoteCircuitService.BallotWitness(config.electionId(), config.voterRoot(),
                config.electionKey(), secret, vote, JubjubElGamal.randomScalar(new SecureRandom()),
                path.siblings(), path.pathBits()));
    }

    private static boolean e2eEnabled() {
        return "true".equalsIgnoreCase(System.getenv("ZEROJ_YACI_E2E")) || Boolean.getBoolean("zeroj.yaci.e2e");
    }

    private static String env(String name, String fallback) {
        String v = System.getenv(name);
        return v == null || v.isBlank() ? fallback : v;
    }

    private static void topUp(String address, int ada) throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create(ADMIN_URL + "/local-cluster/api/addresses/topup"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"address\":\"" + address + "\",\"adaAmount\":" + ada + "}"))
                .build();
        HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        Thread.sleep(3_000);
    }
}
