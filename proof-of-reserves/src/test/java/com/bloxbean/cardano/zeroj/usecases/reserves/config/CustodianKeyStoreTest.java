package com.bloxbean.cardano.zeroj.usecases.reserves.config;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.common.model.Networks;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0009 D11 for the reserves custodian: the key is random, owner-only, atomic, survives a
 * restart, and a missing, corrupt or mismatched key for an existing deployment fails closed.
 */
class CustodianKeyStoreTest {

    /** The public DevKit test mnemonic the custodian used before D11. */
    private static final String DEVKIT_MNEMONIC = "test test test test test test test test test test test test "
            + "test test test test test test test test test test test sauce";

    @TempDir
    Path dir;

    private Account load(Path d) {
        return CustodianKeyStore.loadOrCreate(d, Networks.testnet(), new SecureRandom());
    }

    private void deploy(Path d, Account custodian) throws Exception {
        new DeploymentState(CustodianKeyStore.keyHash(custodian), 1_800_000_000_000L, 300_000L, "ab".repeat(28)).write(d);
    }

    @Test
    void freshKeyIsRandomOwnerOnlyAndNotTheDevKitKey() throws Exception {
        Account a = load(dir);
        Path file = CustodianKeyStore.path(dir);
        assertTrue(Files.exists(file));
        if (Files.getFileStore(file).supportsFileAttributeView("posix")) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
        }
        String devkit = CustodianKeyStore.keyHash(new Account(Networks.testnet(), DEVKIT_MNEMONIC));
        assertNotEquals(devkit, CustodianKeyStore.keyHash(a));
        assertEquals(56, CustodianKeyStore.keyHash(a).length());
        Account other = load(Files.createDirectory(dir.resolve("other")));
        assertNotEquals(CustodianKeyStore.keyHash(a), CustodianKeyStore.keyHash(other));
        try (Stream<Path> files = Files.list(dir)) {
            assertTrue(files.noneMatch(p -> p.getFileName().toString().endsWith(".tmp")), "temporary file left behind");
        }
    }

    @Test
    void keySurvivesARestart() throws Exception {
        Account a = load(dir);
        deploy(dir, a);
        assertEquals(CustodianKeyStore.keyHash(a), CustodianKeyStore.keyHash(load(dir)));
    }

    @Test
    void deletedKeyWithExistingDeploymentFailsClosed() throws Exception {
        deploy(dir, load(dir));
        Files.delete(CustodianKeyStore.path(dir));
        assertThrows(IllegalStateException.class, () -> load(dir));
        assertTrue(Files.notExists(CustodianKeyStore.path(dir)), "a replacement key was created");
    }

    @Test
    void corruptKeyFailsClosed() throws Exception {
        Account a = load(dir);
        deploy(dir, a);
        Path file = CustodianKeyStore.path(dir);
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        String[] words = lines.get(1).split(" ");
        String swapped = words[0];
        words[0] = words[1];
        words[1] = swapped;
        for (String corrupt : List.of("garbage\n", "", lines.get(0) + "\n",
                lines.get(0) + "\n" + String.join(" ", words) + "\n",
                lines.get(0) + "\n" + lines.get(1).substring(0, lines.get(1).lastIndexOf(' ')) + "\n")) {
            if (corrupt.equals(lines.get(0) + "\n" + lines.get(1) + "\n")) continue;
            Files.writeString(file, corrupt, StandardCharsets.UTF_8);
            assertThrows(IllegalStateException.class, () -> load(dir), "accepted: " + corrupt);
        }
    }

    @Test
    void corruptKeyWithoutDeploymentIsNotReplacedEither() throws Exception {
        load(dir);
        Files.writeString(CustodianKeyStore.path(dir), "garbage\n", StandardCharsets.UTF_8);
        assertThrows(IllegalStateException.class, () -> load(dir));
        assertEquals("garbage\n", Files.readString(CustodianKeyStore.path(dir)));
    }

    @Test
    void keyNotMatchingTheDeploymentFailsClosed() throws Exception {
        load(dir);
        Account stranger = load(Files.createDirectory(dir.resolve("stranger")));
        deploy(dir, stranger);
        assertThrows(IllegalStateException.class, () -> load(dir));
    }

    @Test
    void corruptDeploymentStateFailsClosed() throws Exception {
        load(dir);
        Files.writeString(DeploymentState.path(dir), "custodianPkh=zz\n", StandardCharsets.UTF_8);
        assertThrows(IllegalStateException.class, () -> load(dir));
    }
}
