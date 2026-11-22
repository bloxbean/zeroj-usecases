package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.bloxbean.cardano.client.util.HexUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Key lifecycle of the issuer and faucet admin keys (ADR-0009 D11). */
class AirdropKeysTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final BigInteger OLD_PUBLISHED_SEED = new BigInteger(
            "deadbeefcafef00d0123456789abcdefdeadbeefcafef00d0123456789abcdef", 16);

    @Test
    void freshKeysAreRandomPersistedOwnerOnlyAndSurviveRestart(@TempDir Path dir) throws Exception {
        var data = new AirdropDataDir(dir);
        var first = new AirdropKeys(data);
        assertTrue(Files.exists(data.issuerKey()));
        assertTrue(Files.exists(data.adminKey()));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(data.issuerKey())));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(data.adminKey())));

        var restarted = new AirdropKeys(new AirdropDataDir(dir));
        assertEquals(first.issuer().pk(), restarted.issuer().pk());
        assertArrayEquals(first.adminKeyHash(), restarted.adminKeyHash());

        var oldSeed = EdDSAJubjub.keypairFromSecret(OLD_PUBLISHED_SEED.mod(JubjubCurve.SUBGROUP_ORDER));
        assertNotEquals(oldSeed.pk(), first.issuer().pk(), "the published seed must not be the issuer key");
        var other = new AirdropKeys(new AirdropDataDir(dir.resolve("other")));
        assertNotEquals(first.issuer().pk(), other.issuer().pk(), "each install gets its own issuer key");
        assertFalse(Arrays.equals(first.adminKeyHash(), other.adminKeyHash()),
                "each install gets its own admin key");
    }

    @Test
    void deletedIssuerKeyWithExistingStateFailsClosed(@TempDir Path dir) throws Exception {
        var data = new AirdropDataDir(dir);
        new AirdropKeys(data);
        withState(data);
        Files.delete(data.issuerKey());
        var e = assertThrows(IllegalStateException.class, () -> new AirdropKeys(new AirdropDataDir(dir)));
        assertTrue(e.getMessage().contains("Refusing to create a new key"), e.getMessage());
        assertFalse(Files.exists(data.issuerKey()), "no replacement key is written");
    }

    @Test
    void deletedAdminKeyWithExistingStateFailsClosed(@TempDir Path dir) throws Exception {
        var data = new AirdropDataDir(dir);
        new AirdropKeys(data);
        withState(data);
        Files.delete(data.adminKey());
        assertThrows(IllegalStateException.class, () -> new AirdropKeys(new AirdropDataDir(dir)));
        assertFalse(Files.exists(data.adminKey()), "no replacement key is written");
    }

    @Test
    void corruptKeysFailClosed(@TempDir Path dir) throws Exception {
        var data = new AirdropDataDir(dir);
        new AirdropKeys(data);
        String issuerJson = Files.readString(data.issuerKey());

        Files.writeString(data.issuerKey(), "{ not json");
        assertThrows(IllegalStateException.class, () -> new AirdropKeys(new AirdropDataDir(dir)));

        // A secret that no longer matches its recorded public key.
        ObjectNode issuerKey = (ObjectNode) JSON.readTree(issuerJson);
        issuerKey.put("sk", new BigInteger(issuerKey.get("sk").asText(), 16).add(BigInteger.ONE).toString(16));
        Files.writeString(data.issuerKey(), JSON.writeValueAsString(issuerKey));
        assertThrows(IllegalStateException.class, () -> new AirdropKeys(new AirdropDataDir(dir)));

        Files.writeString(data.issuerKey(), issuerJson);
        new AirdropKeys(new AirdropDataDir(dir));

        // A mnemonic that no longer matches its recorded key hash.
        ObjectNode adminKey = (ObjectNode) JSON.readTree(Files.readString(data.adminKey()));
        adminKey.put("paymentKeyHash", HexUtil.encodeHexString(new byte[28]));
        Files.writeString(data.adminKey(), JSON.writeValueAsString(adminKey));
        assertThrows(IllegalStateException.class, () -> new AirdropKeys(new AirdropDataDir(dir)));

        Files.writeString(data.adminKey(), "");
        assertThrows(IllegalStateException.class, () -> new AirdropKeys(new AirdropDataDir(dir)));
    }

    @Test
    void keysMismatchingTheRecordedDeploymentFailClosed(@TempDir Path dir) throws Exception {
        var data = new AirdropDataDir(dir);
        var keys = new AirdropKeys(data);
        var issuer = new PersonhoodIssuerService(keys, data);
        var ledger = new PaidNullifierLedger(data);
        var deployment = DemoFiles.object();
        deployment.put("seedTxHash", "00".repeat(32));
        deployment.put("seedIndex", "0");
        deployment.put("issuerPkU", issuer.publicKey().affineU().toString(16));
        deployment.put("issuerPkV", issuer.publicKey().affineV().toString(16));
        deployment.put("adminKeyHash", HexUtil.encodeHexString(new byte[28]));   // not this admin
        DemoFiles.writeAtomic(data.deployment(), deployment);

        var service = new OnChainAirdropService(null, keys, null, issuer, ledger, data,
                1, 2, false, "http://localhost:10000", 0, null);
        var e = assertThrows(IllegalStateException.class, service::initialize);
        assertTrue(e.getMessage().contains("other keys"), e.getMessage());
    }

    @Test
    void paidNullifiersWithoutTheirDeploymentFailClosed(@TempDir Path dir) {
        var data = new AirdropDataDir(dir);
        var keys = new AirdropKeys(data);
        var issuer = new PersonhoodIssuerService(keys, data);
        var ledger = new PaidNullifierLedger(data);
        ledger.reserve(BigInteger.valueOf(12345));
        var service = new OnChainAirdropService(null, keys, null, issuer, ledger, data,
                1, 2, false, "http://localhost:10000", 0, null);
        var e = assertThrows(IllegalStateException.class, service::initialize);
        assertTrue(e.getMessage().contains("refusing to redeploy"), e.getMessage());
    }

    private static void withState(AirdropDataDir data) {
        DemoFiles.writeAtomic(data.paidNullifiers(), DemoFiles.object().set("nullifiers",
                DemoFiles.object().arrayNode()));
    }
}
