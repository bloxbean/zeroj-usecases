package com.bloxbean.cardano.zeroj.usecases.nft.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.address.Credential;
import com.bloxbean.cardano.client.cip.cip30.CIP30DataSigner;
import com.bloxbean.cardano.client.cip.cip30.DataSignature;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.util.HexUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Snapshot registration (ADR-0009 D2, M5 unit tests): one leaf per token, holder secrets of 252
 * bits, a CIP-8 signature by the payment key of the token's on-chain holder, and registration
 * frozen by the snapshot build.
 */
class SnapshotRegistrationTest {

    /** DevKit's well-known test mnemonic, which anyone can sign with (the list operator). */
    private static final String DEVKIT_MNEMONIC = "test test test test test test test test test test test test "
            + "test test test test test test test test test test test sauce";
    private static final String POLICY = "ab".repeat(28);
    private static final String CONTEXT = "nft-test-event";
    private static final SecureRandom RANDOM = new SecureRandom();

    @TempDir
    Path dataDir;

    private CustodyWallet custody;
    private FakeChain chain;
    private SnapshotService snapshot;
    private BigInteger contextId;

    @BeforeEach
    void setup() {
        custody = new CustodyWallet(dataDir, Networks.testnet());
        chain = new FakeChain();
        snapshot = new SnapshotService(chain, 3, CONTEXT);
        contextId = NftScheme.contextId(CONTEXT);
        // The custody wallet holds three NFTs of the collection.
        for (int i = 1; i <= 3; i++) chain.hold(custody.address(), "Ticket_" + i);
    }

    @Test
    @DisplayName("A registration signed by the token's holder is accepted")
    void holderRegistrationAccepted() {
        assertEquals(1, register("Ticket_1", NftScheme.newSecret(RANDOM)));
        assertEquals(2, register("Ticket_2", NftScheme.newSecret(RANDOM)));
    }

    @Test
    @DisplayName("A second leaf for a token already in the snapshot is refused (one leaf per token)")
    void duplicateTokenRefused() {
        register("Ticket_1", NftScheme.newSecret(RANDOM));
        var e = assertThrows(IllegalArgumentException.class, () -> register("Ticket_1", NftScheme.newSecret(RANDOM)));
        assertTrue(e.getMessage().contains("already in the snapshot"), e.getMessage());
        assertEquals(1, snapshot.getHolderCount());
    }

    @Test
    @DisplayName("Short holder secrets are refused; generated secrets have 252-bit width")
    void shortSecretRefused() {
        for (String typed : new String[] {"42", "12345", "0x" + BigInteger.ONE.shiftLeft(200).toString(16)}) {
            assertThrows(IllegalArgumentException.class, () -> NftScheme.parseSecret(typed), typed);
        }
        assertThrows(IllegalArgumentException.class, () -> NftScheme.requireSecret(BigInteger.ONE.shiftLeft(252)));
        assertThrows(IllegalArgumentException.class, () -> NftScheme.requireSecret(BigInteger.valueOf(-5)));
        for (int i = 0; i < 64; i++) {
            BigInteger s = NftScheme.newSecret(RANDOM);
            assertTrue(s.bitLength() >= NftScheme.MIN_SECRET_BITS && s.bitLength() <= NftScheme.SECRET_BITS);
            assertEquals(s, NftScheme.parseSecret("0x" + s.toString(16)));
        }
    }

    @Test
    @DisplayName("A registration signed with the public DevKit operator key is refused")
    void devkitOperatorSignatureRefused() throws Exception {
        Account operator = new Account(Networks.testnet(), DEVKIT_MNEMONIC);
        BigInteger token = NftScheme.tokenField("Ticket_1");
        BigInteger leaf = NftScheme.leaf(NftScheme.newSecret(RANDOM), token);
        byte[] payload = NftScheme.registrationPayload(contextId, token, leaf);

        // (a) The operator signs, naming the custody address that holds the token.
        DataSignature claimingHolder = CIP30DataSigner.INSTANCE.signData(
                new Address(custody.address()).getBytes(), payload, operator);
        assertThrows(IllegalArgumentException.class, () -> snapshot.registerHolder(POLICY, name("Ticket_1"), leaf, claimingHolder));

        // (b) The operator signs as itself: its address does not hold the token.
        DataSignature asItself = CIP30DataSigner.INSTANCE.signData(
                new Address(operator.baseAddress()).getBytes(), payload, operator);
        assertThrows(IllegalArgumentException.class, () -> snapshot.registerHolder(POLICY, name("Ticket_1"), leaf, asItself));

        assertEquals(0, snapshot.getHolderCount());
        assertNotEquals(operator.baseAddress(), custody.address(), "the custody key is not the DevKit key");
    }

    @Test
    @DisplayName("A signature over another leaf, token or event, or by an address without the token, is refused")
    void boundPayloadRefused() {
        BigInteger token = NftScheme.tokenField("Ticket_1");
        BigInteger leaf = NftScheme.leaf(NftScheme.newSecret(RANDOM), token);
        BigInteger otherLeaf = NftScheme.leaf(NftScheme.newSecret(RANDOM), token);

        DataSignature forOtherLeaf = custody.signRegistration(contextId, token, otherLeaf);
        assertThrows(IllegalArgumentException.class, () -> snapshot.registerHolder(POLICY, name("Ticket_1"), leaf, forOtherLeaf));

        DataSignature forOtherToken = custody.signRegistration(contextId, NftScheme.tokenField("Ticket_2"), leaf);
        assertThrows(IllegalArgumentException.class, () -> snapshot.registerHolder(POLICY, name("Ticket_1"), leaf, forOtherToken));

        DataSignature forOtherEvent = custody.signRegistration(NftScheme.contextId("another-event"), token, leaf);
        assertThrows(IllegalArgumentException.class, () -> snapshot.registerHolder(POLICY, name("Ticket_1"), leaf, forOtherEvent));

        // The custody wallet signs honestly, but no longer holds the token (it was transferred).
        chain.release(custody.address(), "Ticket_3");
        BigInteger token3 = NftScheme.tokenField("Ticket_3");
        BigInteger leaf3 = NftScheme.leaf(NftScheme.newSecret(RANDOM), token3);
        assertThrows(IllegalArgumentException.class, () -> snapshot.registerHolder(POLICY, name("Ticket_3"), leaf3,
                custody.signRegistration(contextId, token3, leaf3)));

        assertThrows(IllegalArgumentException.class, () -> snapshot.registerHolder(POLICY, name("Ticket_1"), leaf, null));
        assertEquals(0, snapshot.getHolderCount());
    }

    @Test
    @DisplayName("Registration freezes when the snapshot is built; a second build is refused")
    void registrationFrozenAfterBuild() {
        register("Ticket_1", NftScheme.newSecret(RANDOM));
        snapshot.buildSnapshot();
        assertTrue(snapshot.isFrozen());
        assertThrows(IllegalStateException.class, () -> register("Ticket_2", NftScheme.newSecret(RANDOM)));
        assertThrows(IllegalStateException.class, () -> snapshot.buildSnapshot());
        assertEquals(1, snapshot.getHolderCount());
    }

    @Test
    @DisplayName("Every registration of an event uses one collection")
    void oneCollection() {
        register("Ticket_1", NftScheme.newSecret(RANDOM));
        String other = "cd".repeat(28);
        chain.holdUnit(custody.address(), other + HexUtil.encodeHexString(name("Ticket_2")));
        BigInteger token = NftScheme.tokenField("Ticket_2");
        BigInteger leaf = NftScheme.leaf(NftScheme.newSecret(RANDOM), token);
        assertThrows(IllegalArgumentException.class, () -> snapshot.registerHolder(other, name("Ticket_2"), leaf,
                custody.signRegistration(contextId, token, leaf)));
    }

    @Test
    @DisplayName("A stake-key-signed reward address, a script address and a holding of 2 units are refused")
    void paymentKeyChecks() throws Exception {
        Account holder = new Account(Networks.testnet());
        BigInteger token = NftScheme.tokenField("Ticket_1");
        BigInteger leaf = NftScheme.leaf(NftScheme.newSecret(RANDOM), token);
        byte[] payload = NftScheme.registrationPayload(contextId, token, leaf);

        // (a) A reward address signed by its stake key (CIP-30 verifies it), even if it "holds" the token.
        String reward = holder.stakeAddress();
        chain.hold(reward, "Ticket_1");
        var stakeKey = holder.stakeHdKeyPair();
        DataSignature byStakeKey = CIP30DataSigner.INSTANCE.signData(new Address(reward).getBytes(), payload,
                stakeKey.getPrivateKey().getKeyData(), stakeKey.getPublicKey().getKeyData());
        assertTrue(CIP30DataSigner.INSTANCE.verify(byStakeKey), "the signature itself is valid CIP-30");
        assertThrows(IllegalArgumentException.class, () -> snapshot.registerHolder(POLICY, name("Ticket_1"), leaf, byStakeKey));

        // (b) A script address whose script hash equals the signer's key hash.
        byte[] keyHash = new Address(holder.baseAddress()).getPaymentCredentialHash().orElseThrow();
        String script = AddressProvider.getEntAddress(Credential.fromScript(keyHash), Networks.testnet()).toBech32();
        chain.hold(script, "Ticket_1");
        DataSignature forScript = CIP30DataSigner.INSTANCE.signData(new Address(script).getBytes(), payload, holder);
        assertTrue(CIP30DataSigner.INSTANCE.verify(forScript), "CIP-30 alone accepts it; the credential-type check must refuse");
        assertThrows(IllegalArgumentException.class, () -> snapshot.registerHolder(POLICY, name("Ticket_1"), leaf, forScript));

        // (c) The signing address holds 2 units of the token.
        chain.holdUnit(holder.baseAddress(), POLICY + HexUtil.encodeHexString(name("Ticket_1")), BigInteger.TWO);
        DataSignature twoUnits = CIP30DataSigner.INSTANCE.signData(new Address(holder.baseAddress()).getBytes(), payload, holder);
        assertTrue(CIP30DataSigner.INSTANCE.verify(twoUnits));
        assertThrows(IllegalArgumentException.class, () -> snapshot.registerHolder(POLICY, name("Ticket_1"), leaf, twoUnits));

        assertEquals(0, snapshot.getHolderCount());
    }

    @Test
    @DisplayName("The holder lookup failing refuses the registration (fail closed)")
    void lookupFailureFailsClosed() {
        chain.fail = true;
        assertThrows(IllegalStateException.class, () -> register("Ticket_1", NftScheme.newSecret(RANDOM)));
        assertEquals(0, snapshot.getHolderCount());
    }

    private int register(String assetName, BigInteger secret) {
        BigInteger token = NftScheme.tokenField(assetName);
        BigInteger leaf = NftScheme.leaf(NftScheme.requireSecret(secret), token);
        return snapshot.registerHolder(POLICY, name(assetName), leaf, custody.signRegistration(contextId, token, leaf));
    }

    private static byte[] name(String assetName) {
        return assetName.getBytes(StandardCharsets.UTF_8);
    }

    /** Holdings by (address, unit), standing in for the chain indexer. */
    private static final class FakeChain implements HolderLookup {
        private final Map<String, BigInteger> holdings = new HashMap<>();
        boolean fail;

        void hold(String address, String assetName) {
            holdUnit(address, POLICY + HexUtil.encodeHexString(name(assetName)));
        }

        void holdUnit(String address, String unit) {
            holdUnit(address, unit, BigInteger.ONE);
        }

        void holdUnit(String address, String unit, BigInteger quantity) {
            holdings.put(address + "|" + unit, quantity);
        }

        void release(String address, String assetName) {
            holdings.remove(address + "|" + POLICY + HexUtil.encodeHexString(name(assetName)));
        }

        @Override
        public BigInteger quantityAt(String address, String unit) throws Exception {
            if (fail) throw new Exception("indexer unavailable");
            return holdings.getOrDefault(address + "|" + unit, BigInteger.ZERO);
        }
    }
}
