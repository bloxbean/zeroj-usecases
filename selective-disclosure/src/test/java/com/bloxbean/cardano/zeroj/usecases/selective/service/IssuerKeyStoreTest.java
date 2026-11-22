package com.bloxbean.cardano.zeroj.usecases.selective.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;
import org.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The issuer key lifecycle of ADR-0009 D11: random, persisted, and fail closed. */
class IssuerKeyStoreTest {

    /** The seed earlier versions published in {@code RichCredentialIssuerService}. */
    static final BigInteger OLD_PUBLISHED_SEED = new BigInteger(
            "feedfacecafebeef1234567890abcdef0fedcba9876543210feedface00112233", 16);

    @TempDir
    Path dir;

    @Test
    void firstStartCreatesAnOwnerOnlyKeyAndTheDeploymentState() throws IOException {
        var keypair = load();
        Path key = dir.resolve(IssuerKeyStore.KEY_FILE);
        assertTrue(Files.isRegularFile(key));
        assertTrue(Files.isRegularFile(dir.resolve(IssuerKeyStore.DEPLOYMENT_FILE)));
        if (dir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            assertEquals(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                    Files.getPosixFilePermissions(key));
        }
        // No temp file is left behind by the atomic writes.
        try (Stream<Path> files = Files.list(dir)) {
            assertEquals(2, files.count());
        }
        assertNotEquals(oldSeedKeypair().pk().affineU(), keypair.pk().affineU(),
                "the key must not be the one derived from the published seed");
    }

    @Test
    void twoFreshInstallsGetDifferentKeys(@TempDir Path other) {
        var a = load();
        var b = IssuerKeyStore.loadOrCreate(other, "selective-disclosure", new SecureRandom());
        assertNotEquals(a.pk().affineU(), b.pk().affineU());
    }

    @Test
    void keySurvivesARestart() {
        var first = load();
        var second = load();
        assertEquals(first.sk(), second.sk());
        assertEquals(first.pk().affineU(), second.pk().affineU());
        assertEquals(first.pk().affineV(), second.pk().affineV());
    }

    @Test
    void deletedKeyWithExistingStateFailsClosed() throws IOException {
        load();
        Files.delete(dir.resolve(IssuerKeyStore.KEY_FILE));
        var e = assertThrows(IllegalStateException.class, this::load);
        assertTrue(e.getMessage().contains("missing"), e.getMessage());
        assertTrue(e.getMessage().contains("--clean-cache"), e.getMessage());
        assertFalse(Files.exists(dir.resolve(IssuerKeyStore.KEY_FILE)), "no new key may be created");
    }

    @Test
    void corruptedKeyWithExistingStateFailsClosed() throws IOException {
        load();
        Path key = dir.resolve(IssuerKeyStore.KEY_FILE);
        Files.writeString(key, "format=zeroj-usecases.issuer-key.eddsa-jubjub.v1\nsk=not-hex\n");
        assertThrows(IllegalStateException.class, this::load);
        Files.write(key, new byte[]{0, 1, 2, 3});
        assertThrows(IllegalStateException.class, this::load);
        // A well-formed but out-of-range scalar (the subgroup order itself).
        Files.writeString(key, "format=zeroj-usecases.issuer-key.eddsa-jubjub.v1\nsk="
                + hex64(JubjubCurve.SUBGROUP_ORDER) + "\n");
        assertThrows(IllegalStateException.class, this::load);
    }

    @Test
    void keyThatDoesNotMatchTheDeployedParameterFailsClosed(@TempDir Path other) throws IOException {
        load();
        // Another valid key, as if the key file were swapped after deployment.
        IssuerKeyStore.loadOrCreate(other, "selective-disclosure", new SecureRandom());
        Files.copy(other.resolve(IssuerKeyStore.KEY_FILE), dir.resolve(IssuerKeyStore.KEY_FILE),
                StandardCopyOption.REPLACE_EXISTING);
        var e = assertThrows(IllegalStateException.class, this::load);
        assertTrue(e.getMessage().contains("does not match"), e.getMessage());
    }

    @Test
    void corruptedDeploymentStateFailsClosed() throws IOException {
        load();
        Files.writeString(dir.resolve(IssuerKeyStore.DEPLOYMENT_FILE), "garbage");
        assertThrows(IllegalStateException.class, this::load);
    }

    @Test
    void keyWithoutDeploymentStateIsKeptAndRecorded() throws IOException {
        var first = load();
        Files.delete(dir.resolve(IssuerKeyStore.DEPLOYMENT_FILE));
        var second = load();
        assertEquals(first.sk(), second.sk());
        assertTrue(Files.exists(dir.resolve(IssuerKeyStore.DEPLOYMENT_FILE)));
    }

    @Test
    void issuerServiceKeepsItsKeyAcrossARestartAndStopsWhenItIsLost() throws IOException {
        var first = issuerService();
        var second = issuerService();
        assertEquals(first.issuerPk().affineU(), second.issuerPk().affineU());
        assertEquals(first.issuerPk().affineV(), second.issuerPk().affineV());
        Files.delete(dir.resolve(IssuerKeyStore.KEY_FILE));
        assertThrows(IllegalStateException.class, this::issuerService);
    }

    private RichCredentialIssuerService issuerService() {
        var service = new RichCredentialIssuerService();
        ReflectionTestUtils.setField(service, "dataDir", dir.toString());
        service.setup();
        return service;
    }

    private EdDSAJubjub.Keypair load() {
        return IssuerKeyStore.loadOrCreate(dir, "selective-disclosure", new SecureRandom());
    }

    static EdDSAJubjub.Keypair oldSeedKeypair() {
        return EdDSAJubjub.keypairFromSecret(OLD_PUBLISHED_SEED.mod(JubjubCurve.SUBGROUP_ORDER));
    }

    private static String hex64(BigInteger value) {
        String hex = value.toString(16);
        return "0".repeat(64 - hex.length()) + hex;
    }
}
