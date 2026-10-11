package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.common.model.Networks;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The DPP manufacturer and auditor keys (ADR-0009 D11, I10): random, persisted, fail closed. */
class RoleKeysTest {

    private static final String DEVKIT_MNEMONIC = "test test test test test test test test test test test test "
            + "test test test test test test test test test test test sauce";

    @TempDir
    Path dir;

    @Test
    @DisplayName("A fresh data directory gets two random 24-word keys, owner-only, and the deployment state")
    void freshKeys() throws Exception {
        RoleKeys keys = RoleKeys.loadOrCreate(dir, Networks.testnet());
        for (RoleKeys.Role role : RoleKeys.Role.values()) {
            Path file = dir.resolve(role.fileName());
            assertTrue(Files.isRegularFile(file));
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
            assertEquals(24, Files.readString(file).trim().split("\\s+").length);
        }
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.resolve(RoleKeys.STATE_FILE))));
        assertFalse(Arrays.equals(RoleKeys.pkh(keys.manufacturer()), RoleKeys.pkh(keys.auditor())));
        // Neither is the published DevKit wallet, and two installs never share a key.
        byte[] devkit = RoleKeys.pkh(Account.createFromMnemonic(Networks.testnet(), DEVKIT_MNEMONIC));
        assertFalse(Arrays.equals(devkit, RoleKeys.pkh(keys.manufacturer())));
        assertFalse(Arrays.equals(devkit, RoleKeys.pkh(keys.auditor())));
        RoleKeys other = RoleKeys.loadOrCreate(dir.resolve("other"), Networks.testnet());
        assertFalse(Arrays.equals(RoleKeys.pkh(other.manufacturer()), RoleKeys.pkh(keys.manufacturer())));
        // No temporary files are left behind.
        try (var files = Files.list(dir)) {
            assertTrue(files.noneMatch(p -> p.getFileName().toString().endsWith(".tmp")));
        }
    }

    @Test
    @DisplayName("The keys survive a restart")
    void restart() {
        RoleKeys first = RoleKeys.loadOrCreate(dir, Networks.testnet());
        RoleKeys again = RoleKeys.loadOrCreate(dir, Networks.testnet());
        assertArrayEquals(RoleKeys.pkh(first.manufacturer()), RoleKeys.pkh(again.manufacturer()));
        assertArrayEquals(RoleKeys.pkh(first.auditor()), RoleKeys.pkh(again.auditor()));
    }

    @Test
    @DisplayName("With deployment state, a deleted key fails closed and no new key is created")
    void deletedKeyFailsClosed() throws Exception {
        RoleKeys.loadOrCreate(dir, Networks.testnet());
        Files.delete(dir.resolve(RoleKeys.Role.AUDITOR.fileName()));
        assertThrows(IllegalStateException.class, () -> RoleKeys.loadOrCreate(dir, Networks.testnet()));
        assertFalse(Files.exists(dir.resolve(RoleKeys.Role.AUDITOR.fileName())), "no replacement key");
    }

    @Test
    @DisplayName("With deployment state, a corrupted key fails closed")
    void corruptedKeyFailsClosed() throws Exception {
        RoleKeys.loadOrCreate(dir, Networks.testnet());
        Files.writeString(dir.resolve(RoleKeys.Role.MANUFACTURER.fileName()), "not a mnemonic", StandardCharsets.UTF_8);
        assertThrows(IllegalStateException.class, () -> RoleKeys.loadOrCreate(dir, Networks.testnet()));
        Files.writeString(dir.resolve(RoleKeys.Role.MANUFACTURER.fileName()),
                "abandon ".repeat(23) + "zoo", StandardCharsets.UTF_8);     // 24 words, bad checksum
        assertThrows(IllegalStateException.class, () -> RoleKeys.loadOrCreate(dir, Networks.testnet()));
    }

    @Test
    @DisplayName("A valid key that is not the deployed one fails closed")
    void mismatchedKeyFailsClosed() throws Exception {
        RoleKeys.loadOrCreate(dir, Networks.testnet());
        // Swap the auditor's key for the manufacturer's: both valid, neither matches the other's hash.
        Files.copy(dir.resolve(RoleKeys.Role.MANUFACTURER.fileName()), dir.resolve(RoleKeys.Role.AUDITOR.fileName()),
                StandardCopyOption.REPLACE_EXISTING);
        assertThrows(IllegalStateException.class, () -> RoleKeys.loadOrCreate(dir, Networks.testnet()));
        // So does a fresh random key in the manufacturer's place.
        Path other = dir.resolve("other");
        RoleKeys.loadOrCreate(other, Networks.testnet());
        RoleKeys.loadOrCreate(dir.resolve("third"), Networks.testnet());
        Files.copy(dir.resolve("third").resolve(RoleKeys.Role.MANUFACTURER.fileName()),
                other.resolve(RoleKeys.Role.MANUFACTURER.fileName()), StandardCopyOption.REPLACE_EXISTING);
        assertThrows(IllegalStateException.class, () -> RoleKeys.loadOrCreate(other, Networks.testnet()));
    }

    @Test
    @DisplayName("The deployed policy is recorded once; a different policy later fails closed")
    void policyBinding() throws Exception {
        RoleKeys keys = RoleKeys.loadOrCreate(dir, Networks.testnet());
        keys.bindPolicy("aa".repeat(28));
        assertDoesNotThrow(() -> keys.bindPolicy("aa".repeat(28)));
        RoleKeys again = RoleKeys.loadOrCreate(dir, Networks.testnet());
        assertDoesNotThrow(() -> again.bindPolicy("aa".repeat(28)));
        assertThrows(IllegalStateException.class, () -> again.bindPolicy("bb".repeat(28)));
        Properties state = new Properties();
        state.load(Files.newBufferedReader(dir.resolve(RoleKeys.STATE_FILE)));
        assertEquals("aa".repeat(28), state.getProperty("policyId"));
    }
}
