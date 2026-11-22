package com.bloxbean.cardano.zeroj.usecases.nft.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.cip.cip30.CIP30DataSigner;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.util.HexUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * ADR-0009 D2 on Yaci DevKit: one NFT-gated event.
 *
 * <ol>
 *   <li>Two NFTs minted into a fresh custody wallet (random key, D11).</li>
 *   <li>Registration against the chain: the custody wallet's CIP-8 signatures are accepted; a
 *       second leaf for the same token and a registration signed with the DevKit key are
 *       refused; registration is frozen by the build.</li>
 *   <li>The event's scripts deployed with a one-shot root; holder 1 is admitted on-chain.</li>
 *   <li>Script rejections (evaluated locally with Julc, as the node would; never submitted): the
 *       same nullifier again, forced in after the node that points at it (list), and a valid
 *       proof made for another event (ZK policy).</li>
 *   <li>Holder 2 is admitted. Neither on-chain nullifier equals the version 1 nullifier
 *       {@code Poseidon(t, contextId)} of any minted token.</li>
 * </ol>
 *
 * Runs only with {@code ZEROJ_YACI_E2E=true}; uses {@code ZEROJ_YACI_STORE_URL} /
 * {@code ZEROJ_YACI_ADMIN_URL} when DevKit uses non-default ports.
 */
class NftOwnershipYaciE2ETest {

    private static final String BASE_URL = env("ZEROJ_YACI_STORE_URL", "http://localhost:8080/api/v1/");
    private static final String ADMIN_URL = env("ZEROJ_YACI_ADMIN_URL", "http://localhost:10000");
    private static final String DEVKIT_MNEMONIC = "test test test test test test test test test test test test "
            + "test test test test test test test test test test test sauce";
    private static final int DEPTH = 4;
    private static final SecureRandom RANDOM = new SecureRandom();

    @TempDir
    Path dataDir;

    @Test
    void nftGatedEventOnDevKit() throws Exception {
        assumeTrue(e2eEnabled(), "Set ZEROJ_YACI_E2E=true to run this Yaci DevKit E2E test");

        var prover = new ProverService();
        ReflectionTestUtils.setField(prover, "treeDepth", DEPTH);
        ReflectionTestUtils.setField(prover, "potPower", 12);
        prover.init();

        var operator = new Account(Networks.testnet());
        topUp(operator.baseAddress(), 1000);
        var backend = new BFBackendService(BASE_URL, "");
        var custody = new CustodyWallet(dataDir, Networks.testnet());
        var mint = new MintService(backend, operator, custody);
        var minted = mint.mintToCustody("E2ETicket" + Integer.toHexString(RANDOM.nextInt(0xffff)), 2);
        Thread.sleep(3_000);

        String label = "nft-e2e-" + Long.toHexString(RANDOM.nextLong());
        var snapshot = new SnapshotService(new BackendHolderLookup(backend), DEPTH, label);
        BigInteger context = snapshot.getContextId();
        List<String> tokens = minted.tokenNames();
        List<BigInteger> secrets = List.of(NftScheme.newSecret(RANDOM), NftScheme.newSecret(RANDOM));

        // Registration: the holder's signatures are accepted.
        for (int i = 0; i < 2; i++) {
            BigInteger t = NftScheme.tokenField(tokens.get(i));
            BigInteger leaf = NftScheme.leaf(secrets.get(i), t);
            snapshot.registerHolder(minted.policyId(), bytes(tokens.get(i)), leaf, custody.signRegistration(context, t, leaf));
        }
        // A second leaf for token 1, and the DevKit operator key, are refused.
        BigInteger t1 = NftScheme.tokenField(tokens.get(0));
        BigInteger second = NftScheme.leaf(NftScheme.newSecret(RANDOM), t1);
        assertThrows(IllegalArgumentException.class, () -> snapshot.registerHolder(minted.policyId(), bytes(tokens.get(0)),
                second, custody.signRegistration(context, t1, second)));
        var devkit = new Account(Networks.testnet(), DEVKIT_MNEMONIC);
        var devkitSig = CIP30DataSigner.INSTANCE.signData(new Address(custody.address()).getBytes(),
                NftScheme.registrationPayload(context, t1, second), devkit);
        assertThrows(IllegalArgumentException.class, () -> snapshot.registerHolder(minted.policyId(), bytes(tokens.get(0)),
                second, devkitSig));

        BigInteger root = snapshot.buildSnapshot();
        assertThrows(IllegalStateException.class, () -> snapshot.registerHolder(minted.policyId(), bytes(tokens.get(1)),
                second, custody.signRegistration(context, t1, second)));

        var onChain = new OnChainNullifierService(backend, operator, prover);
        ReflectionTestUtils.setField(onChain, "yaciAdminUrl", ADMIN_URL);
        var deployment = onChain.deploy(root, context);
        System.out.println("Event deployed: zk=" + deployment.zkPolicyHex() + " list=" + deployment.listPolicyHex());

        // Holder 1 is admitted.
        var proof1 = prove(prover, snapshot, secrets.get(0), tokens.get(0), root, context);
        String tx1 = onChain.insertNullifier(proof1.proof(), proof1.nullifier());
        System.out.println("Holder 1 admitted: " + tx1);
        assertTrue(onChain.isUsed(proof1.nullifier()));

        // The same nullifier again: refused by the client, and by the list script when forced in.
        assertThrows(IllegalStateException.class, () -> onChain.insertNullifier(proof1.proof(), proof1.nullifier()));
        assertScriptRejected(() -> onChain.insertAt(proof1.proof(), proof1.nullifier(),
                onChain.anchorForDuplicate(proof1.nullifier())), "a second use of one nullifier");

        // A valid proof for another event (other context): the ZK policy rejects it.
        BigInteger otherContext = NftScheme.contextId("another-event");
        var foreign = prove(prover, snapshot, secrets.get(1), tokens.get(1), root, otherContext);
        assertScriptRejected(() -> onChain.insertNullifier(foreign.proof(), foreign.nullifier()),
                "a proof made for another event");
        assertFalse(onChain.isUsed(foreign.nullifier()), "the rejected insert left no trace");

        // Holder 2 is admitted.
        var proof2 = prove(prover, snapshot, secrets.get(1), tokens.get(1), root, context);
        System.out.println("Holder 2 admitted: " + onChain.insertNullifier(proof2.proof(), proof2.nullifier()));
        assertEquals(2, onChain.getUsedCount());

        // From chain data and the token names alone, the v1 nullifier links nothing.
        List<BigInteger> onChainNullifiers = new ArrayList<>(List.of(proof1.nullifier(), proof2.nullifier()));
        for (String token : tokens) {
            BigInteger v1 = NftScheme.poseidon(NftScheme.tokenField(token), context);
            assertFalse(onChainNullifiers.contains(v1), "nullifier must not be Poseidon(t, contextId)");
        }
        System.out.println("NFT gate on DevKit: 2 holders admitted, nullifiers "
                + HexUtil.encodeHexString(NftScheme.i2osp32(proof1.nullifier())).substring(0, 16) + "…, "
                + HexUtil.encodeHexString(NftScheme.i2osp32(proof2.nullifier())).substring(0, 16) + "…");
    }

    private static ProverService.ProofResult prove(ProverService prover, SnapshotService snapshot, BigInteger secret,
                                                   String token, BigInteger root, BigInteger context) {
        BigInteger t = NftScheme.tokenField(token);
        int index = snapshot.findLeafIndex(NftScheme.leaf(secret, t));
        var path = snapshot.getProof(index);
        return prover.prove(secret, t, root, context, path.siblings(), path.pathBits());
    }

    private interface Submission {
        String run() throws Exception;
    }

    /** The submission failed in script evaluation, not earlier in the client. */
    private static void assertScriptRejected(Submission submission, String what) {
        var rejected = assertThrows(Exception.class, submission::run, what + " must be rejected");
        String message = String.valueOf(rejected.getMessage());
        System.out.println("Rejected (" + what + "): " + message.substring(0, Math.min(140, message.length())));
        assertTrue(message.toLowerCase().contains("script") || message.toLowerCase().contains("evaluat"),
                what + " must be rejected by a script: " + message);
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
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
