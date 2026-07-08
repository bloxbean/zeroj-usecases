package com.bloxbean.cardano.zeroj.usecases.recovery;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.crypto.bip32.HdKeyGenerator;
import com.bloxbean.cardano.client.crypto.bip32.HdKeyPair;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.usecases.recovery.circuit.OwnershipProofCircuit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * Fast(er) sanity check of the ownership circuit at the <b>witness</b> level: the in-circuit
 * CIP-1852 derivation from a real root key must reproduce the address payment key hash computed by
 * cardano-client-lib — the circuit's internal {@code assertEqual(pkh)} throws otherwise. No setup,
 * no proof — the full prove + on-chain flow is {@link OwnershipGateOnChainE2ETest} (standalone).
 */
class OwnershipProofWitnessTest {

    private static final String MNEMONIC = "test test test test test test test test test test test test "
            + "test test test test test test test test test test test sauce";

    private final HdKeyGenerator hd = new HdKeyGenerator();

    @Test
    @EnabledIfSystemProperty(named = "zeroj.heavy", matches = "true")
    void ownershipWitness_rootKeyDerivesToAddress() {
        var root = hd.getRootKeyPairFromMnemonic(MNEMONIC);
        HdKeyPair leaf = derivePaymentLeaf();
        byte[] expectedPkh = Blake2bUtil.blake2bHash224(leaf.getPublicKey().getKeyData());

        byte[] kL = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 0, 32);
        byte[] kR = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 32, 64);
        byte[] cc = root.getPrivateKey().getChainCode();

        var builder = OwnershipProofCircuit.build();
        Map<String, List<BigInteger>> in = new HashMap<>();
        putBytes(in, "rootKL", kL);
        putBytes(in, "rootKR", kR);
        putBytes(in, "rootChainCode", cc);
        putBytes(in, "pkh", expectedPkh);
        assertDoesNotThrow(() -> builder.calculateWitness(in, CurveId.BLS12_381),
                "in-circuit CIP-1852 derivation must reproduce the address pkh from the root key");
    }

    private HdKeyPair derivePaymentLeaf() {
        var r = hd.getRootKeyPairFromMnemonic(MNEMONIC);
        var n1 = hd.getChildKeyPair(r, 1852L, true);
        var n2 = hd.getChildKeyPair(n1, 1815L, true);
        var n3 = hd.getChildKeyPair(n2, 0L, true);
        var n4 = hd.getChildKeyPair(n3, 0L, false);
        return hd.getChildKeyPair(n4, 0L, false);
    }

    private static void putBytes(Map<String, List<BigInteger>> in, String base, byte[] bytes) {
        for (int i = 0; i < bytes.length; i++)
            in.put(base + "_" + i, List.of(BigInteger.valueOf(bytes[i] & 0xff)));
    }
}
