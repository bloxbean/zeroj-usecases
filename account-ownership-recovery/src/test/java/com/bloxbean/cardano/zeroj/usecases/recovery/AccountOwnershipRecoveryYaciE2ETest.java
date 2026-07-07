package com.bloxbean.cardano.zeroj.usecases.recovery;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.crypto.bip32.HdKeyGenerator;
import com.bloxbean.cardano.client.crypto.bip32.HdKeyPair;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.usecases.recovery.circuit.OwnershipProofCircuit;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.OnChainRecoveryService;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.PoseidonCompute;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.RecoveryCircuitService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * End-to-end demonstration of ZK account-ownership recovery (motivated by the SecondFi exploit).
 *
 * <ol>
 *   <li><b>Off-chain ownership proof</b> (the new derivation gadgets): prove the claimant's wallet
 *       <i>root key</i> derives, via the full CIP-1852 path, to the target address's payment key
 *       hash — i.e. they know the seed, which the exploit's attacker (holding only the leaf spending
 *       key) does not. Validated in-circuit against cardano-client's derivation. (Heavy; gated.)</li>
 *   <li><b>On-chain recovery gate</b>: a provable Groth16-BLS12381 recovery-commitment proof,
 *       bound to the address, verified <i>on-chain</i> by the {@link com.bloxbean.cardano.zeroj.usecases.recovery.onchain.RecoveryProofValidator}
 *       Julc validator on the running Yaci DevKit.</li>
 * </ol>
 */
class AccountOwnershipRecoveryYaciE2ETest {

    private static final String YACI_ADMIN_URL = "http://localhost:10000";
    private static final String YACI_BASE_URL = "http://localhost:8080/api/v1/";
    private static final String MNEMONIC = "test test test test test test test test test test test test "
            + "test test test test test test test test test test test sauce";

    private final HdKeyGenerator hd = new HdKeyGenerator();

    // ------------------------------------------------------------------
    // 1. Off-chain ownership proof: root key -> address payment key hash
    // ------------------------------------------------------------------

    @Test
    @EnabledIfSystemProperty(named = "zeroj.heavy", matches = "true")
    void ownershipProof_rootKeyDerivesToAddress() {
        var root = hd.getRootKeyPairFromMnemonic(MNEMONIC);
        HdKeyPair leaf = derivePaymentLeaf();
        byte[] expectedPkh = Blake2bUtil.blake2bHash224(leaf.getPublicKey().getKeyData());

        byte[] kL = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 0, 32);
        byte[] kR = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 32, 64);
        byte[] cc = root.getPrivateKey().getChainCode();

        // Concise annotation-DSL circuit (OwnershipProof @ZKCircuit via ZkCip1852): it derives the
        // pkh from the root key and asserts it equals the public pkh internally.
        var builder = OwnershipProofCircuit.build();
        Map<String, List<BigInteger>> in = new HashMap<>();
        putBytesU(in, "rootKL", kL);
        putBytesU(in, "rootKR", kR);
        putBytesU(in, "rootChainCode", cc);
        putBytesU(in, "pkh", expectedPkh);
        assertDoesNotThrow(() -> builder.calculateWitness(in, CurveId.BN254),
                "annotation-DSL ownership proof must reproduce the address pkh from the root key");
    }

    /** ZkBytes input keys are {@code base_i}. */
    private static void putBytesU(Map<String, List<BigInteger>> in, String base, byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) in.put(base + "_" + i, List.of(BigInteger.valueOf(bytes[i] & 0xff)));
    }

    // ------------------------------------------------------------------
    // 2. Recovery-commitment circuit proves + (fast) structural check
    // ------------------------------------------------------------------

    @Test
    void recoveryCommitment_provesForAddress() {
        BigInteger addrField = addressKeyHashField();
        BigInteger secret = new BigInteger("123456789012345678901234567890");
        BigInteger commitment = PoseidonCompute.poseidon(secret, addrField);

        var circuitService = new RecoveryCircuitService();
        circuitService.init();
        Groth16ProofBLS381 proof = circuitService.prove(secret, addrField, commitment);

        assertTrue(proof.a().isOnCurve() && proof.c().isOnCurve(), "proof G1 points on curve");
        assertTrue(proof.b().isOnCurve(), "proof G2 point on curve");
        System.out.println("[recovery] commitment circuit constraints = " + circuitService.numConstraints());
    }

    // ------------------------------------------------------------------
    // 3. On-chain recovery gate on Yaci DevKit
    // ------------------------------------------------------------------

    @Test
    void recoveryGate_verifiesOnChain() throws Exception {
        assumeTrue(yaciEnabled(), "Set ZEROJ_YACI_E2E=true to run the Yaci DevKit on-chain E2E");

        BigInteger addrField = addressKeyHashField();
        BigInteger secret = new BigInteger("987654321098765432109876543210");
        BigInteger commitment = PoseidonCompute.poseidon(secret, addrField);

        var circuitService = new RecoveryCircuitService();
        circuitService.init();
        Groth16ProofBLS381 proof = circuitService.prove(secret, addrField, commitment);

        var admin = new Account(Networks.testnet(), MNEMONIC);
        topUp(admin.baseAddress(), 10000);

        var onChain = new OnChainRecoveryService(new BFBackendService(YACI_BASE_URL, ""), admin, circuitService);
        String txHash = onChain.verifyRecoveryOnChain(proof, commitment, addrField);
        assertNotNull(txHash, "on-chain recovery proof verification must produce a tx hash");
        System.out.println("[recovery] on-chain recovery proof verified: tx=" + txHash);
    }

    // ------------------------------------------------------------------

    private HdKeyPair derivePaymentLeaf() {
        var root = hd.getRootKeyPairFromMnemonic(MNEMONIC);
        var n1 = hd.getChildKeyPair(root, 1852L, true);
        var n2 = hd.getChildKeyPair(n1, 1815L, true);
        var n3 = hd.getChildKeyPair(n2, 0L, true);
        var n4 = hd.getChildKeyPair(n3, 0L, false);
        return hd.getChildKeyPair(n4, 0L, false);
    }

    /** Address payment key hash (m/1852'/1815'/0'/0/0) as a field element. */
    private BigInteger addressKeyHashField() {
        byte[] pkh = Blake2bUtil.blake2bHash224(derivePaymentLeaf().getPublicKey().getKeyData());
        return new BigInteger(1, pkh); // 224 bits < BLS12-381 scalar field
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
