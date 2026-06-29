package com.bloxbean.cardano.zeroj.usecases.reserves;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.usecases.reserves.service.OnChainReserveService;
import com.bloxbean.cardano.zeroj.usecases.reserves.service.PoseidonCompute;
import com.bloxbean.cardano.zeroj.usecases.reserves.service.ReserveCircuitService;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProofOfReservesYaciE2ETest {
    private static final int TREE_DEPTH = 4;
    private static final String YACI_ADMIN_URL = "http://localhost:10000";
    private static final String YACI_BASE_URL = "http://localhost:8080/api/v1/";
    private static final String YACI_MNEMONIC = "test test test test test test test test test test test test "
            + "test test test test test test test test test test test sauce";

    @Test
    void publishesSolvencyProofOnYaciDevKit() throws Exception {
        assumeTrue(yaciE2eEnabled(), "Set ZEROJ_YACI_E2E=true to run this Yaci DevKit E2E test");

        var circuitService = new ReserveCircuitService();
        ReflectionTestUtils.setField(circuitService, "treeDepth", TREE_DEPTH);
        ReflectionTestUtils.setField(circuitService, "potPower", 13);
        circuitService.init();

        var adminAccount = new Account(Networks.testnet(), YACI_MNEMONIC);
        topUp(adminAccount.baseAddress(), 1000);

        var tree = sampleTree();
        BigInteger reserves = tree.totalLiabilities().add(BigInteger.valueOf(1_000_000_000L));
        var proof = circuitService.prove(reserves, tree.root(), tree.totalLiabilities(),
                tree.leafIds(), tree.leafBalances());

        assertTrue(proof.solvent());

        var onChainReserveService = new OnChainReserveService(
                new BFBackendService(YACI_BASE_URL, ""), adminAccount, circuitService);
        String txHash = onChainReserveService.publishAttestation(proof.proof(), reserves,
                tree.root(), tree.totalLiabilities(), proof.solvent());

        assertNotNull(txHash);
    }

    private static boolean yaciE2eEnabled() {
        return "true".equalsIgnoreCase(System.getenv("ZEROJ_YACI_E2E"))
                || Boolean.getBoolean("zeroj.yaci.e2e");
    }

    private static Tree sampleTree() {
        int maxLeaves = 1 << TREE_DEPTH;
        BigInteger[] ids = new BigInteger[maxLeaves];
        BigInteger[] balances = new BigInteger[maxLeaves];
        Arrays.fill(ids, BigInteger.ZERO);
        Arrays.fill(balances, BigInteger.ZERO);

        putLeaf(ids, balances, 0, "alice", 500_000_000L);
        putLeaf(ids, balances, 1, "bob", 1_200_000_000L);
        putLeaf(ids, balances, 2, "charlie", 300_000_000L);
        putLeaf(ids, balances, 3, "diana", 2_500_000_000L);
        putLeaf(ids, balances, 4, "eve", 800_000_000L);
        putLeaf(ids, balances, 5, "frank", 150_000_000L);
        putLeaf(ids, balances, 6, "grace", 3_000_000_000L);
        putLeaf(ids, balances, 7, "henry", 50_000_000L);

        BigInteger liabilities = Arrays.stream(balances).reduce(BigInteger.ZERO, BigInteger::add);
        BigInteger[] level = new BigInteger[maxLeaves];
        for (int i = 0; i < maxLeaves; i++) {
            level[i] = PoseidonCompute.poseidon(ids[i], balances[i]);
        }
        for (int depth = 0; depth < TREE_DEPTH; depth++) {
            BigInteger[] next = new BigInteger[level.length / 2];
            for (int i = 0; i < next.length; i++) {
                next[i] = PoseidonCompute.poseidon(level[2 * i], level[2 * i + 1]);
            }
            level = next;
        }
        return new Tree(level[0], liabilities, ids, balances);
    }

    private static void putLeaf(BigInteger[] ids, BigInteger[] balances, int index, String accountId, long balance) {
        ids[index] = new BigInteger(1, accountId.getBytes(StandardCharsets.UTF_8));
        balances[index] = BigInteger.valueOf(balance);
    }

    private static void topUp(String address, int adaAmount) throws Exception {
        String body = "{\"address\":\"" + address + "\",\"adaAmount\":" + adaAmount + "}";
        HttpRequest request = HttpRequest.newBuilder(URI.create(YACI_ADMIN_URL + "/local-cluster/api/addresses/topup"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("Yaci top-up failed: HTTP "
                    + response.statusCode() + " " + response.body());
        }
    }

    private record Tree(BigInteger root, BigInteger totalLiabilities,
                        BigInteger[] leafIds, BigInteger[] leafBalances) {
    }
}
