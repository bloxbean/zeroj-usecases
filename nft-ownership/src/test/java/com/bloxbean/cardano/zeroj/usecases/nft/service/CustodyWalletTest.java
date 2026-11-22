package com.bloxbean.cardano.zeroj.usecases.nft.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.common.model.Networks;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The NFT custody wallet key lifecycle (ADR-0009 D11): random, persisted atomically with
 * owner-only permissions, stable across restarts, and fail-closed when the key is missing,
 * corrupt or does not match the deployment state.
 */
class CustodyWalletTest {

    private static final String DEVKIT_MNEMONIC = "test test test test test test test test test test test test "
            + "test test test test test test test test test test test sauce";

    @TempDir
    Path dataDir;

    @Test
    @DisplayName("A fresh install gets a random key, not the DevKit key, and a different one each time")
    void randomKey(@TempDir Path otherDir) {
        var first = new CustodyWallet(dataDir, Networks.testnet());
        var second = new CustodyWallet(otherDir, Networks.testnet());
        assertNotEquals(first.address(), second.address());
        assertNotEquals(new Account(Networks.testnet(), DEVKIT_MNEMONIC).baseAddress(), first.address());
        assertEquals(28, first.paymentKeyHash().length);
    }

    @Test
    @DisplayName("The key survives a restart, and is stored owner-only next to the deployment state")
    void survivesRestart() throws Exception {
        String address = new CustodyWallet(dataDir, Networks.testnet()).address();
        assertEquals(address, new CustodyWallet(dataDir, Networks.testnet()).address());
        Path key = dataDir.resolve(CustodyWallet.KEY_FILE);
        assertTrue(Files.exists(key));
        assertTrue(Files.exists(dataDir.resolve(CustodyWallet.STATE_FILE)));
        if (key.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                    Files.getPosixFilePermissions(key));
        }
        try (var files = Files.list(dataDir)) {
            assertTrue(files.noneMatch(p -> p.getFileName().toString().endsWith(".tmp")), "no temp files left");
        }
    }

    @Test
    @DisplayName("A deleted key with existing deployment state fails closed; no new key is created")
    void deletedKeyFailsClosed() throws Exception {
        new CustodyWallet(dataDir, Networks.testnet());
        Files.delete(dataDir.resolve(CustodyWallet.KEY_FILE));
        assertThrows(IllegalStateException.class, () -> new CustodyWallet(dataDir, Networks.testnet()));
        assertFalse(Files.exists(dataDir.resolve(CustodyWallet.KEY_FILE)), "no replacement key was written");
    }

    @Test
    @DisplayName("A corrupted key fails closed")
    void corruptedKeyFailsClosed() throws Exception {
        new CustodyWallet(dataDir, Networks.testnet());
        Path key = dataDir.resolve(CustodyWallet.KEY_FILE);
        Files.writeString(key, "not a mnemonic");
        assertThrows(IllegalStateException.class, () -> new CustodyWallet(dataDir, Networks.testnet()));
        assertEquals("not a mnemonic", Files.readString(key), "the corrupt key is left for inspection");
    }

    @Test
    @DisplayName("A key that does not match the deployed custody address fails closed")
    void mismatchedKeyFailsClosed(@TempDir Path otherDir) throws Exception {
        new CustodyWallet(dataDir, Networks.testnet());
        new CustodyWallet(otherDir, Networks.testnet());
        Files.copy(otherDir.resolve(CustodyWallet.KEY_FILE), dataDir.resolve(CustodyWallet.KEY_FILE),
                StandardCopyOption.REPLACE_EXISTING);
        assertThrows(IllegalStateException.class, () -> new CustodyWallet(dataDir, Networks.testnet()));
    }

    @Test
    @DisplayName("Reset removes the key and the state together, which is a fresh deployment")
    void resetIsFresh() throws Exception {
        String before = new CustodyWallet(dataDir, Networks.testnet()).address();
        Files.delete(dataDir.resolve(CustodyWallet.KEY_FILE));
        Files.delete(dataDir.resolve(CustodyWallet.STATE_FILE));
        assertNotEquals(before, new CustodyWallet(dataDir, Networks.testnet()).address());
    }
}
