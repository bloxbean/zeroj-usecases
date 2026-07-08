package com.bloxbean.cardano.zeroj.usecases.recovery;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.crypto.bip32.HdKeyGenerator;
import com.bloxbean.cardano.client.crypto.bip32.HdKeyPair;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.cryptoblst.BlstProverBackend;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.OnChainOwnershipService;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.OwnershipCircuitService;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * ADR-0029 M5 — the <b>practical</b> account-ownership recovery gate, end to end on Yaci DevKit:
 * prove the REAL ownership statement (root key derives via the full CIP-1852 path to the address's
 * payment key hash — the 19,075,097-constraint {@code OwnershipProof} circuit) and verify that
 * Groth16 proof <em>on-chain</em> with the {@code OwnershipProofValidator}. No registered
 * auxiliary secret — a passing proof is proof of seed ownership.
 *
 * <p>Heavy + gated. Needs: {@code ZEROJ_YACI_E2E=true} with a running Yaci DevKit, a large heap
 * (~70 GB warm), and ideally a warm PK cache ({@code -Dzeroj.pkcache}, else the one-time ~47 min
 * setup runs first). Run standalone (see {@link #main}) — gradle's daemon dislikes heavy-heap runs.</p>
 */
class OwnershipGateOnChainE2ETest {

    private static final String YACI_ADMIN_URL = "http://localhost:10000";
    private static final String YACI_BASE_URL = "http://localhost:8080/api/v1/";
    private static final String MNEMONIC = "test test test test test test test test test test test test "
            + "test test test test test test test test test test test sauce";

    private final HdKeyGenerator hd = new HdKeyGenerator();

    @Test
    void ownershipGate_realDerivationProof_verifiesOnChain() throws Exception {
        assumeTrue(yaciEnabled(), "Set ZEROJ_YACI_E2E=true (with Yaci DevKit running) to run");
        runE2E();
    }

    /** Standalone entry point (no gradle daemon — required for the heavy heap). */
    public static void main(String[] args) throws Exception {
        new OwnershipGateOnChainE2ETest().runE2E();
        System.out.println("[standalone] ownership on-chain E2E complete.");
    }

    void runE2E() throws Exception {
        // The claimant's wallet: root key + the address it derives to
        var root = hd.getRootKeyPairFromMnemonic(MNEMONIC);
        HdKeyPair leaf = derivePaymentLeaf();
        byte[] pkh = Blake2bUtil.blake2bHash224(leaf.getPublicKey().getKeyData());
        byte[] kL = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 0, 32);
        byte[] kR = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 32, 64);
        byte[] cc = root.getPrivateKey().getChainCode();

        Path cache = Path.of(System.getProperty("zeroj.pkcache",
                System.getProperty("java.io.tmpdir") + "/zeroj-pk-derivation"));
        var circuitService = new OwnershipCircuitService(cache);

        System.out.println("[ownership] compiling circuit + loading proving key (" + cache + ") ...");
        long t = System.nanoTime();
        circuitService.init();
        System.out.printf("[ownership] ready: %,d constraints | %.1fs%n",
                circuitService.numConstraints(), (System.nanoTime() - t) / 1e9);

        System.out.println("[ownership] proving the real CIP-1852 derivation (blst, multi-core) ...");
        t = System.nanoTime();
        Groth16ProofBLS381 proof = circuitService.prove(kL, kR, cc, pkh, BlstProverBackend.create());
        System.out.printf("[ownership] proof generated in %.1fs%n", (System.nanoTime() - t) / 1e9);
        assertTrue(proof.a().isOnCurve() && proof.b().isOnCurve() && proof.c().isOnCurve(), "proof on curve");

        var admin = new Account(Networks.testnet(), MNEMONIC);
        topUp(admin.baseAddress(), 10000);

        var onChain = new OnChainOwnershipService(new BFBackendService(YACI_BASE_URL, ""), admin, circuitService);
        System.out.println("[ownership] gate script address: " + onChain.scriptAddress());

        t = System.nanoTime();
        String txHash = onChain.verifyOwnershipOnChain(proof, pkh);
        System.out.printf("[ownership] REAL derivation proof verified ON-CHAIN in %.1fs: tx=%s%n",
                (System.nanoTime() - t) / 1e9, txHash);
        assertNotNull(txHash);
    }

    private HdKeyPair derivePaymentLeaf() {
        var r = hd.getRootKeyPairFromMnemonic(MNEMONIC);
        var n1 = hd.getChildKeyPair(r, 1852L, true);
        var n2 = hd.getChildKeyPair(n1, 1815L, true);
        var n3 = hd.getChildKeyPair(n2, 0L, true);
        var n4 = hd.getChildKeyPair(n3, 0L, false);
        return hd.getChildKeyPair(n4, 0L, false);
    }

    private static boolean yaciEnabled() {
        return "true".equalsIgnoreCase(System.getenv("ZEROJ_YACI_E2E")) || Boolean.getBoolean("zeroj.yaci.e2e");
    }

    private static void topUp(String address, int adaAmount) throws Exception {
        String body = "{\"address\":\"" + address + "\",\"adaAmount\":" + adaAmount + "}";
        HttpRequest request = HttpRequest.newBuilder(URI.create(YACI_ADMIN_URL + "/local-cluster/api/addresses/topup"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300)
            throw new IllegalStateException("Yaci top-up failed: HTTP " + response.statusCode() + " " + response.body());
    }
}
