package com.bloxbean.cardano.zeroj.usecases.voting.service;

import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.zeroj.usecases.voting.VotingFixture;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0009 D5: the test voters' keys are uniform in the scalar field, survive a restart, and a
 * damaged key file stops the demo instead of being replaced.
 */
class VoterKeyStoreTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    /** The BLS12-381 scalar field order, as published for the curve (not read from the code under test). */
    private static final BigInteger R = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    @TempDir
    Path dir;

    @Test
    @DisplayName("Keys are uniform in [1, r): full width, every bit used, never the old 10000 + i")
    void keysHaveFullEntropy() {
        assertEquals(R, ElectionService.FR, "the store samples in the ballot circuit's field");
        int samples = 1_000;
        int topBitSet = 0;
        BigInteger or = BigInteger.ZERO;
        for (int i = 0; i < samples; i++) {
            BigInteger k = VoterKeyStore.randomSecretKey(RANDOM);
            assertTrue(k.signum() > 0 && k.compareTo(R) < 0, "key in [1, r)");
            assertTrue(k.bitLength() > 200, "a small key would be guessable");
            if (k.testBit(254)) topBitSet++;
            or = or.or(k);
        }
        // Bit 254 is set for (r − 2^254)/r ≈ 45% of [1, r); a 252-bit or narrower sampler gives 0%.
        assertTrue(topBitSet > 350 && topBitSet < 550, "top bit set in " + topBitSet + "/" + samples);
        for (int bit = 0; bit < 255; bit++) assertTrue(or.testBit(bit), "bit " + bit + " never set");

        Map<String, BigInteger> keys = VoterKeyStore.loadOrCreate(dir.resolve(VoterKeyStore.FILE_NAME), 5, RANDOM);
        assertEquals(List.of("voter1", "voter2", "voter3", "voter4", "voter5"), List.copyOf(keys.keySet()));
        assertEquals(5, new HashSet<>(keys.values()).size(), "distinct keys");
        for (int i = 1; i <= 5; i++) {
            BigInteger k = keys.get("voter" + i);
            assertTrue(k.bitLength() > 200 && k.compareTo(R) < 0);
            assertFalse(k.equals(BigInteger.valueOf(10000 + i)));
        }
    }

    @Test
    @DisplayName("Keys survive a restart, and the file is written owner-only")
    void keysSurviveRestart() throws IOException {
        Path file = dir.resolve("data").resolve(VoterKeyStore.FILE_NAME);
        Map<String, BigInteger> first = VoterKeyStore.loadOrCreate(file, 5, RANDOM);
        byte[] written = Files.readAllBytes(file);
        Map<String, BigInteger> second = VoterKeyStore.loadOrCreate(file, 5, RANDOM);
        assertEquals(first, second);
        assertArrayEquals(written, Files.readAllBytes(file), "a restart does not rewrite the file");
        if (Files.getFileAttributeView(file, PosixFileAttributeView.class) != null) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
        }
        try (var listing = Files.list(file.getParent())) {
            assertEquals(List.of(file), listing.toList(), "no temporary file left behind");
        }
        // Another install draws other keys.
        assertFalse(first.equals(VoterKeyStore.loadOrCreate(dir.resolve("other").resolve(VoterKeyStore.FILE_NAME), 5, RANDOM)));
    }

    @Test
    @DisplayName("A damaged key file fails closed and is left untouched")
    void damagedFileFailsClosed() throws IOException {
        Path file = dir.resolve(VoterKeyStore.FILE_NAME);
        VoterKeyStore.loadOrCreate(file, 3, RANDOM);
        List<String> good = Files.readAllLines(file, StandardCharsets.UTF_8);
        String hexR = R.toString(16);
        Map<String, UnaryOperator<List<String>>> damage = Map.of(
                "garbage", l -> List.of("not a key file"),
                "empty", l -> List.of(),
                "wrong header", l -> replace(l, 0, "zeroj.private-voting.voter-keys.v0"),
                "truncated", l -> l.subList(0, 3),
                "short key", l -> replace(l, 1, "voter1 " + "ab".repeat(31)),
                "upper-case hex", l -> replace(l, 1, l.get(1).toUpperCase().replace("VOTER", "voter")),
                "key = r", l -> replace(l, 2, "voter2 " + "0".repeat(64 - hexR.length()) + hexR),
                "key = 0", l -> replace(l, 2, "voter2 " + "0".repeat(64)),
                "duplicate key", l -> replace(l, 3, "voter3 " + l.get(1).substring(7)),
                "wrong label", l -> replace(l, 3, "voter9 " + l.get(3).substring(7)));
        for (var entry : damage.entrySet()) {
            List<String> lines = entry.getValue().apply(new ArrayList<>(good));
            Files.write(file, lines, StandardCharsets.UTF_8);
            byte[] before = Files.readAllBytes(file);
            var e = assertThrows(IllegalStateException.class, () -> VoterKeyStore.loadOrCreate(file, 3, RANDOM),
                    entry.getKey());
            assertTrue(e.getMessage().contains("--clean-cache"), entry.getKey() + ": " + e.getMessage());
            assertArrayEquals(before, Files.readAllBytes(file), entry.getKey() + ": the file is not replaced");
        }
        // An intact file under a changed election.voter-count is refused too.
        Files.write(file, good, StandardCharsets.UTF_8);
        assertThrows(IllegalStateException.class, () -> VoterKeyStore.loadOrCreate(file, 4, RANDOM));
        assertEquals(3, VoterKeyStore.loadOrCreate(file, 3, RANDOM).size());
        // An unreadable path (a directory where the file should be) fails closed as well.
        Path asDirectory = dir.resolve("as-directory");
        Files.createDirectories(asDirectory.resolve(VoterKeyStore.FILE_NAME));
        assertThrows(IllegalStateException.class,
                () -> VoterKeyStore.loadOrCreate(asDirectory.resolve(VoterKeyStore.FILE_NAME), 3, RANDOM));
    }

    @Test
    @DisplayName("A restarted demo registers the same voters: same public keys and voter root")
    void restartRegistersTheSameVoters() {
        var circuits = VotingFixture.get().circuits;
        List<BigInteger> first = setup(circuits);
        List<BigInteger> second = setup(circuits);
        assertEquals(first, second);
        assertEquals(3, new HashSet<>(first.subList(0, 3)).size());
    }

    /** One demo start on {@link #dir}: the three voters' public keys, then the voter root. */
    private List<BigInteger> setup(VoteCircuitService circuits) {
        var election = new ElectionService(circuits);
        var accounts = new AccountSetupService(election, circuits, (BackendService) null);
        ReflectionTestUtils.setField(accounts, "voterCount", 3);
        ReflectionTestUtils.setField(accounts, "defaultElectionName", "restart test");
        ReflectionTestUtils.setField(accounts, "yaciAdminUrl", "");
        ReflectionTestUtils.setField(accounts, "topUpEnabled", false);
        ReflectionTestUtils.setField(accounts, "dataDir", dir.toString());
        accounts.setup();
        List<BigInteger> out = new ArrayList<>();
        for (var voter : accounts.getVoters()) {
            assertEquals(circuits.computePublicKey(election.getSecretKey(voter.label())), voter.publicKey());
            out.add(voter.publicKey());
        }
        out.add(election.getVoterRoot());
        return out;
    }

    private static List<String> replace(List<String> lines, int index, String line) {
        lines.set(index, line);
        return lines;
    }
}
