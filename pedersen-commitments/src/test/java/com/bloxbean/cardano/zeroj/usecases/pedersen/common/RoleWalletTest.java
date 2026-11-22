package com.bloxbean.cardano.zeroj.usecases.pedersen.common;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.crypto.bip39.MnemonicCode;
import com.bloxbean.cardano.client.crypto.bip39.MnemonicException;
import com.bloxbean.cardano.client.util.HexUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0009 D11 key lifecycle for role wallets (the solvency exchange): random, persisted
 * owner-only, loaded on restart, and fail closed when the key is missing, damaged or does not
 * match the deployment state.
 */
class RoleWalletTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ROLE = "solvency-exchange";
    /** DevKit's well-known test mnemonic, as published in the demos' application.yml files. */
    private static final String DEVKIT_MNEMONIC = "test test test test test test test test test test test test"
            + " test test test test test test test test test test test sauce";

    @TempDir
    Path dir;

    @Test
    @DisplayName("A random key is created once, survives a restart, and is written owner-only")
    void keySurvivesRestart() throws IOException {
        var first = RoleWallet.loadOrCreate(dir, ROLE, RANDOM);
        assertTrue(first.created());
        byte[] key = Files.readAllBytes(RoleWallet.keyFile(dir, ROLE));
        byte[] deployment = Files.readAllBytes(RoleWallet.deploymentFile(dir, ROLE));

        var second = RoleWallet.loadOrCreate(dir, ROLE, RANDOM);
        assertFalse(second.created());
        assertArrayEquals(first.keyHash(), second.keyHash());
        assertEquals(first.account().baseAddress(), second.account().baseAddress());
        assertArrayEquals(key, Files.readAllBytes(RoleWallet.keyFile(dir, ROLE)), "a restart does not rewrite the key");
        assertArrayEquals(deployment, Files.readAllBytes(RoleWallet.deploymentFile(dir, ROLE)));
        assertEquals("paymentKeyHash=" + HexUtil.encodeHexString(first.keyHash()),
                Files.readAllLines(RoleWallet.deploymentFile(dir, ROLE)).get(2));

        if (Files.getFileAttributeView(dir, PosixFileAttributeView.class) != null) {
            for (Path p : List.of(RoleWallet.keyFile(dir, ROLE), RoleWallet.deploymentFile(dir, ROLE))) {
                assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(p)), p.toString());
            }
        }
        try (var listing = Files.list(dir)) {
            assertEquals(2, listing.count(), "no temporary file left behind");
        }
    }

    @Test
    @DisplayName("The key is not derivable from published data: fresh per install, never the DevKit mnemonic")
    void keyIsNotPublic() {
        byte[] devkit = RoleWallet.keyHash(Account.createFromMnemonic(Networks.testnet(), DEVKIT_MNEMONIC));
        var a = RoleWallet.loadOrCreate(dir.resolve("a"), ROLE, RANDOM);
        var b = RoleWallet.loadOrCreate(dir.resolve("b"), ROLE, RANDOM);
        assertFalse(Arrays.equals(a.keyHash(), b.keyHash()));
        assertFalse(Arrays.equals(a.keyHash(), devkit));
        assertFalse(Arrays.equals(b.keyHash(), devkit));
        assertEquals(24, a.account().mnemonic().split(" ").length, "256 bits of entropy");
    }

    @Test
    @DisplayName("Deployment state with a deleted key fails closed and creates no new key")
    void deletedKeyFailsClosed() throws IOException {
        RoleWallet.loadOrCreate(dir, ROLE, RANDOM);
        Files.delete(RoleWallet.keyFile(dir, ROLE));
        var e = assertThrows(IllegalStateException.class, () -> RoleWallet.loadOrCreate(dir, ROLE, RANDOM));
        assertTrue(e.getMessage().contains("--clean-cache"), e.getMessage());
        assertFalse(Files.exists(RoleWallet.keyFile(dir, ROLE)), "no key was created silently");
    }

    @Test
    @DisplayName("A corrupted key, a mismatched key or damaged deployment state fails closed, files untouched")
    void damagedFilesFailClosed() throws IOException {
        RoleWallet.loadOrCreate(dir, ROLE, RANDOM);
        Path keyFile = RoleWallet.keyFile(dir, ROLE);
        Path deploymentFile = RoleWallet.deploymentFile(dir, ROLE);
        List<String> key = Files.readAllLines(keyFile);
        List<String> deployment = Files.readAllLines(deploymentFile);
        String[] words = key.get(1).split(" ");
        String other = RoleWallet.loadOrCreate(dir.resolve("other"), ROLE, RANDOM).account().mnemonic();

        Map<String, UnaryOperator<List<String>>> keyDamage = new LinkedHashMap<>();
        keyDamage.put("garbage", l -> List.of("garbage"));
        keyDamage.put("empty", l -> List.of());
        keyDamage.put("wrong header", l -> List.of("zeroj.pedersen.role-wallet-key.v0", l.get(1)));
        keyDamage.put("23 words", l -> List.of(l.get(0), String.join(" ", Arrays.copyOf(words, 23))));
        keyDamage.put("bad checksum", l -> List.of(l.get(0), withBadChecksum(words)));
        keyDamage.put("unknown word", l -> List.of(l.get(0), l.get(1).replaceFirst("^\\S+", "zzzz")));
        keyDamage.put("another valid key", l -> List.of(l.get(0), other));
        for (var damage : keyDamage.entrySet()) {
            assertFailsClosed(keyFile, damage.getValue().apply(new ArrayList<>(key)), damage.getKey());
        }
        Files.write(keyFile, key, StandardCharsets.UTF_8);

        Map<String, UnaryOperator<List<String>>> deploymentDamage = new LinkedHashMap<>();
        deploymentDamage.put("garbage", l -> List.of("garbage"));
        deploymentDamage.put("another role", l -> List.of(l.get(0), "role=auction-seller", l.get(2)));
        deploymentDamage.put("short hash", l -> List.of(l.get(0), l.get(1), l.get(2).substring(0, l.get(2).length() - 2)));
        deploymentDamage.put("another key hash", l -> List.of(l.get(0), l.get(1), "paymentKeyHash="
                + HexUtil.encodeHexString(RoleWallet.keyHash(Account.createFromMnemonic(Networks.testnet(), other)))));
        for (var damage : deploymentDamage.entrySet()) {
            assertFailsClosed(deploymentFile, damage.getValue().apply(new ArrayList<>(deployment)), damage.getKey());
        }
        Files.write(deploymentFile, deployment, StandardCharsets.UTF_8);
        assertFalse(RoleWallet.loadOrCreate(dir, ROLE, RANDOM).created(), "the restored files load again");
    }

    @Test
    @DisplayName("A key without deployment state (an interrupted first start) is kept, and the state written")
    void keyWithoutDeploymentIsAdopted() throws IOException {
        var first = RoleWallet.loadOrCreate(dir, ROLE, RANDOM);
        Files.delete(RoleWallet.deploymentFile(dir, ROLE));
        var again = RoleWallet.loadOrCreate(dir, ROLE, RANDOM);
        assertFalse(again.created());
        assertArrayEquals(first.keyHash(), again.keyHash());
        assertTrue(Files.exists(RoleWallet.deploymentFile(dir, ROLE)));
    }

    private void assertFailsClosed(Path file, List<String> lines, String what) throws IOException {
        Files.write(file, lines, StandardCharsets.UTF_8);
        byte[] key = Files.readAllBytes(RoleWallet.keyFile(dir, ROLE));
        byte[] deployment = Files.readAllBytes(RoleWallet.deploymentFile(dir, ROLE));
        var e = assertThrows(IllegalStateException.class, () -> RoleWallet.loadOrCreate(dir, ROLE, RANDOM), what);
        assertTrue(e.getMessage().contains("--clean-cache"), what + ": " + e.getMessage());
        assertArrayEquals(key, Files.readAllBytes(RoleWallet.keyFile(dir, ROLE)), what + ": key file replaced");
        assertArrayEquals(deployment, Files.readAllBytes(RoleWallet.deploymentFile(dir, ROLE)), what + ": state replaced");
    }

    /** The mnemonic with its last word replaced by one whose checksum fails. */
    private static String withBadChecksum(String[] words) {
        for (String candidate : MnemonicCode.INSTANCE.getWordList()) {
            String[] w = words.clone();
            w[w.length - 1] = candidate;
            try {
                MnemonicCode.INSTANCE.check(List.of(w));
            } catch (MnemonicException e) {
                return String.join(" ", w);
            }
        }
        throw new AssertionError("no invalid last word");
    }
}
