package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code import} must be told whether the .zkey is pinned to a published hash, and it rejects bad
 * input before the (slow) circuit compile. Every case here returns before compiling, so none of them
 * creates the keys directory.
 */
class ImportCommandOptionsTest {

    private static final String HASH = "a".repeat(64);

    @Test
    void requiresAPinOrAnExplicitUnpinnedChoice(@TempDir Path dir) throws Exception {
        Path zkey = Files.createFile(dir.resolve("key_final.zkey"));
        Path keys = dir.resolve("keys");

        assertEquals(2, run("--zkey", zkey.toString(), "--keys", keys.toString()));
        assertFalse(Files.exists(keys));
    }

    @Test
    void rejectsBothAPinAndUnpinned(@TempDir Path dir) throws Exception {
        Path zkey = Files.createFile(dir.resolve("key_final.zkey"));
        Path keys = dir.resolve("keys");

        assertEquals(2, run("--zkey", zkey.toString(), "--keys", keys.toString(),
                "--sha256", HASH, "--allow-unpinned"));
        assertFalse(Files.exists(keys));
    }

    @Test
    void rejectsAMalformedHash(@TempDir Path dir) throws Exception {
        Path zkey = Files.createFile(dir.resolve("key_final.zkey"));
        Path keys = dir.resolve("keys");

        for (String bad : new String[]{"abc", HASH.substring(1), HASH + "0", "g".repeat(64)}) {
            assertEquals(2, run("--zkey", zkey.toString(), "--keys", keys.toString(), "--sha256", bad), bad);
        }
        assertFalse(Files.exists(keys));
    }

    @Test
    void refusesANonEmptyDirectoryThatIsNotAKeyBundle(@TempDir Path dir) throws Exception {
        Path zkey = Files.createFile(dir.resolve("key_final.zkey"));
        Path keys = Files.createDirectory(dir.resolve("keys"));
        Path unrelated = Files.writeString(keys.resolve("notes.txt"), "not a key bundle");

        assertEquals(2, run("--zkey", zkey.toString(), "--keys", keys.toString(), "--sha256", HASH, "--force"));
        assertTrue(Files.isRegularFile(unrelated), "an unrelated directory is never deleted, even with --force");
    }

    private static int run(String... args) {
        return new CommandLine(new ImportCommand()).execute(args);
    }
}
