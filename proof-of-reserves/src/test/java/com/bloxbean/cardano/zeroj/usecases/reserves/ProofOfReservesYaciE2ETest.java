package com.bloxbean.cardano.zeroj.usecases.reserves;

import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.usecases.reserves.config.CustodianKeyStore;
import com.bloxbean.cardano.zeroj.usecases.reserves.model.AccountEntity;
import com.bloxbean.cardano.zeroj.usecases.reserves.service.MerkleSumTreeService;
import com.bloxbean.cardano.zeroj.usecases.reserves.service.OnChainReserveService;
import com.bloxbean.cardano.zeroj.usecases.reserves.service.ReserveCircuitService;
import com.bloxbean.cardano.zeroj.usecases.reserves.verify.CustomerCheck;
import com.bloxbean.cardano.zeroj.usecases.reserves.verify.YaciStoreIndexer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * ADR-0009 D4 on Yaci DevKit: the custodian (a random, persisted key, topped up through DevKit)
 * mints the current period's attestation token with the solvency proof; a customer verifies
 * inclusion against the chain through Yaci Store; a second attestation for the period and an
 * insolvent statement are refused; after the period ends the custodian burns the token.
 */
class ProofOfReservesYaciE2ETest {
    private static final int TREE_DEPTH = 4;
    private static final long PERIOD_MS = 90_000L;
    private static final String YACI_ADMIN_URL = "http://localhost:10000";
    private static final String YACI_BASE_URL = "http://localhost:8080/api/v1/";

    @TempDir
    Path deploymentDir;

    @Test
    void attestsVerifiesAndReleasesOnYaciDevKit() throws Exception {
        assumeTrue(yaciE2eEnabled(), "Set ZEROJ_YACI_E2E=true to run this Yaci DevKit E2E test");

        var circuitService = new ReserveCircuitService();
        ReflectionTestUtils.setField(circuitService, "treeDepth", TREE_DEPTH);
        ReflectionTestUtils.setField(circuitService, "potPower", 13);
        circuitService.init();

        var custodian = CustodianKeyStore.loadOrCreate(deploymentDir, Networks.testnet(), new SecureRandom());
        var backend = new BFBackendService(YACI_BASE_URL, "");
        var onChain = new OnChainReserveService(backend, custodian, circuitService,
                deploymentDir.toString(), PERIOD_MS, YACI_BASE_URL, YACI_ADMIN_URL, true);
        onChain.initialize();

        var rng = new SecureRandom();
        var snapshot = MerkleSumTreeService.build(accounts(), TREE_DEPTH, rng);
        BigInteger liabilities = snapshot.totalLiabilities();
        BigInteger reserves = liabilities.add(BigInteger.valueOf(1_000_000_000L));
        var proof = circuitService.prove(reserves, snapshot.root(), liabilities,
                snapshot.leafIds(), snapshot.leafBalances());
        assertTrue(proof.solvent());

        // Start with at least 45 s of the period left, so the customer check sees the same period.
        long period = onChain.periods().periodAt(onChain.chainTimeMs());
        while (onChain.periods().end(period) - onChain.chainTimeMs() < 45_000) {
            Thread.sleep(2_000);
            period = onChain.periods().periodAt(onChain.chainTimeMs());
        }
        String txHash = onChain.publishAttestation(proof.proof(), period, reserves, snapshot.root(), liabilities);
        assertNotNull(txHash);

        // The customer checks against Yaci Store, not the custodian.
        var deployment = new CustomerCheck.Deployment(onChain.getPolicyId(),
                onChain.deployment().genesisMs(), onChain.deployment().periodMs());
        var alice = snapshot.inclusionProof("alice");
        var inclusion = new CustomerCheck.Inclusion("alice", alice.salt(), alice.balance(), alice.leafIndex(),
                Arrays.asList(alice.siblings()));
        var indexer = new YaciStoreIndexer(YACI_BASE_URL);
        CustomerCheck.Result result = null;
        for (int i = 0; i < 10; i++) {
            result = CustomerCheck.check(inclusion, deployment, indexer);
            if (result.verified()) break;
            Thread.sleep(2_000);
        }
        assertEquals(CustomerCheck.Outcome.VERIFIED, result.outcome(), result.detail());
        var tampered = new CustomerCheck.Inclusion("alice", alice.salt(), alice.balance().add(BigInteger.ONE),
                alice.leafIndex(), Arrays.asList(alice.siblings()));
        assertEquals(CustomerCheck.Outcome.ROOT_MISMATCH, CustomerCheck.check(tampered, deployment, indexer).outcome());

        // A second attestation for the period is refused before submission.
        final long attested = period;
        assertThrows(OnChainReserveService.AlreadyAttestedException.class,
                () -> onChain.publishAttestation(proof.proof(), attested, reserves, snapshot.root(), liabilities));

        // An insolvent statement fails the minting policy (the proof is for isSolvent = 0).
        BigInteger short1 = liabilities.subtract(BigInteger.ONE);
        var insolvent = circuitService.prove(short1, snapshot.root(), liabilities,
                snapshot.leafIds(), snapshot.leafBalances());
        assertThrows(Exception.class,
                () -> onChain.publishAttestation(insolvent.proof(), attested + 1, short1, snapshot.root(), liabilities));

        // After the period ends, the custodian burns the token and takes back its lovelace.
        assertNotNull(onChain.releaseAttestation(period));
    }

    private static List<AccountEntity> accounts() {
        return List.of(
                new AccountEntity("alice", "Alice", 500_000_000L),
                new AccountEntity("bob", "Bob", 1_200_000_000L),
                new AccountEntity("charlie", "Charlie", 300_000_000L),
                new AccountEntity("diana", "Diana", 2_500_000_000L),
                new AccountEntity("eve", "Eve", 800_000_000L),
                new AccountEntity("frank", "Frank", 150_000_000L),
                new AccountEntity("grace", "Grace", 3_000_000_000L),
                new AccountEntity("henry", "Henry", 50_000_000L));
    }

    private static boolean yaciE2eEnabled() {
        return "true".equalsIgnoreCase(System.getenv("ZEROJ_YACI_E2E"))
                || Boolean.getBoolean("zeroj.yaci.e2e");
    }
}
