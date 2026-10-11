package com.bloxbean.cardano.zeroj.usecases.voting.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The test voters' secret keys, random and persisted in the demo data directory (ADR-0009 D5).
 *
 * <p>Each key is uniform in {@code [1, r)}, where {@code r} is the BLS12-381 scalar field the
 * ballot circuit works in: candidates of 255 bits from {@link SecureRandom} are rejected until
 * one lies in range, so no key is reduced and each has {@code log2(r − 1) ≈ 254.9} bits of
 * entropy. A nullifier {@code Poseidon(sk, electionId)} or a leaf {@code Poseidon(sk, 0)} can then
 * not be matched to a voter by guessing keys.
 *
 * <p>File format (UTF-8, one entry per line): the header {@value #HEADER}, then
 * {@code voter<i> <64 hex digits>} for {@code i = 1..n}. The file is written once, atomically (a
 * temporary file in the same directory, then a rename) and readable by its owner only.
 *
 * <p><b>Fail closed.</b> A file that is present but unreadable, malformed, out of range, holds a
 * duplicate key or a different number of voters stops the demo; it is never replaced silently.
 * The demo keeps no other election state across restarts, so a missing file is a fresh install.
 * {@code ./demo.sh private-voting --clean-cache} removes it with the rest of the data directory.
 */
public final class VoterKeyStore {

    private static final Logger log = LoggerFactory.getLogger(VoterKeyStore.class);

    /** The file name under the demo data directory. */
    public static final String FILE_NAME = "voter-keys.txt";
    static final String HEADER = "zeroj.private-voting.voter-keys.v1";

    private VoterKeyStore() {}

    /** A voter secret key, uniform in {@code [1, r)}. */
    public static BigInteger randomSecretKey(SecureRandom random) {
        while (true) {
            BigInteger candidate = new BigInteger(255, random);
            if (candidate.signum() > 0 && candidate.compareTo(ElectionService.FR) < 0) return candidate;
        }
    }

    /**
     * The keys of voters {@code voter1..voter<count>} from {@code file}, generating and writing
     * them first if the file does not exist.
     *
     * @throws IllegalStateException if the file exists but cannot be used (fail closed)
     */
    public static Map<String, BigInteger> loadOrCreate(Path file, int count, SecureRandom random) {
        if (count < 1) throw new IllegalArgumentException("voter count must be positive");
        if (Files.exists(file)) {
            Map<String, BigInteger> keys = load(file, count);
            log.info("Loaded {} voter keys from {}", keys.size(), file);
            return keys;
        }
        Map<String, BigInteger> keys = new LinkedHashMap<>();
        Set<BigInteger> seen = new HashSet<>();
        for (int i = 1; i <= count; i++) {
            BigInteger key;
            do {
                key = randomSecretKey(random);
            } while (!seen.add(key));
            keys.put(label(i), key);
        }
        write(file, keys);
        log.info("Generated {} random voter keys in {}", count, file);
        return keys;
    }

    static String label(int i) {
        return "voter" + i;
    }

    private static Map<String, BigInteger> load(Path file, int count) {
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException e) {
            throw failClosed(file, "cannot be read (" + e.getMessage() + ")");
        }
        if (lines.isEmpty() || !lines.getFirst().equals(HEADER)) throw failClosed(file, "has no valid header");
        if (lines.size() - 1 != count) {
            throw failClosed(file, "holds " + (lines.size() - 1) + " voters, but election.voter-count is " + count);
        }
        Map<String, BigInteger> keys = new LinkedHashMap<>();
        Set<BigInteger> seen = new HashSet<>();
        for (int i = 1; i <= count; i++) {
            String[] parts = lines.get(i).split(" ", -1);
            if (parts.length != 2 || !parts[0].equals(label(i)) || !parts[1].matches("[0-9a-f]{64}")) {
                throw failClosed(file, "line " + (i + 1) + " is malformed");
            }
            BigInteger key = new BigInteger(parts[1], 16);
            if (key.signum() <= 0 || key.compareTo(ElectionService.FR) >= 0) {
                throw failClosed(file, "the key of " + label(i) + " is outside [1, r)");
            }
            if (!seen.add(key)) throw failClosed(file, "holds a duplicate key");
            keys.put(label(i), key);
        }
        return keys;
    }

    private static void write(Path file, Map<String, BigInteger> keys) {
        StringBuilder text = new StringBuilder(HEADER).append('\n');
        keys.forEach((label, key) -> text.append(label).append(' ').append(hex64(key)).append('\n'));
        try {
            Path dir = file.toAbsolutePath().getParent();
            Files.createDirectories(dir);
            Path tmp = ownerOnlyTempFile(dir);
            try {
                try (FileChannel channel = FileChannel.open(tmp, StandardOpenOption.WRITE,
                        StandardOpenOption.TRUNCATE_EXISTING)) {
                    channel.write(ByteBuffer.wrap(text.toString().getBytes(StandardCharsets.UTF_8)));
                    channel.force(true);
                }
                try {
                    Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException e) {
                    throw new IOException("the file system cannot rename atomically", e);
                }
                syncDirectory(dir);
            } finally {
                Files.deleteIfExists(tmp);
            }
        } catch (IOException e) {
            throw new IllegalStateException("could not write the voter keys to " + file + ": " + e.getMessage(), e);
        }
    }

    /**
     * Makes the rename durable: on POSIX file systems the directory entry is flushed too. (Windows
     * cannot open a directory as a channel; there the rename's own durability applies.)
     */
    private static void syncDirectory(Path dir) throws IOException {
        if (!dir.getFileSystem().supportedFileAttributeViews().contains("posix")) return;
        try (FileChannel channel = FileChannel.open(dir, StandardOpenOption.READ)) {
            channel.force(true);
        }
    }

    private static Path ownerOnlyTempFile(Path dir) throws IOException {
        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
        try {
            return Files.createTempFile(dir, ".voter-keys-", ".tmp", PosixFilePermissions.asFileAttribute(ownerOnly));
        } catch (UnsupportedOperationException e) {
            // Not a POSIX file system (Windows): the file inherits the directory's access control.
            log.warn("Cannot set owner-only permissions in {}; protect the directory yourself", dir);
            return Files.createTempFile(dir, ".voter-keys-", ".tmp");
        }
    }

    private static String hex64(BigInteger key) {
        String hex = key.toString(16);
        return "0".repeat(64 - hex.length()) + hex;
    }

    private static IllegalStateException failClosed(Path file, String problem) {
        return new IllegalStateException("The voter key file " + file + " " + problem + ". The demo does not"
                + " replace voter keys silently: restore the file, or reset the demo's data with"
                + " ./demo.sh private-voting --clean-cache (or delete the data directory).");
    }
}
