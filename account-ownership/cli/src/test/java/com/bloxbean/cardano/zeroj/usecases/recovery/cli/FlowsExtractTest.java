package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link Flows#extractBundle} unpacks a bundle ZIP, validates it is a real bundle, and refuses
 * zip-slip entries. (No crypto — just the archive handling.)
 */
class FlowsExtractTest {

    @Test
    void extractsBundle_andReturnsFingerprint(@TempDir Path dir) throws Exception {
        Path zip = dir.resolve("bundle.zip");
        try (var zos = new ZipOutputStream(Files.newOutputStream(zip))) {
            // the two files Bundle/PkStore look for, plus a point file
            put(zos, "manifest.properties", "numPublic=28\nnumB2=1\nnumIc=2\ndomain=4\n");
            put(zos, "bundle.properties", "setupMode=local\nfingerprint=c19075365-w43743286-p28\n");
            put(zos, "pointsA.bin", "not-real-points");
        }
        Path bundle = dir.resolve("keys");
        String fp = Flows.extractBundle(zip, bundle, s -> {});

        assertEquals("c19075365-w43743286-p28", fp);
        assertTrue(Flows.hasKeys(bundle), "extracted dir is a valid bundle");
        assertTrue(Files.isRegularFile(bundle.resolve("pointsA.bin")));
    }

    @Test
    void rejectsZipSlip(@TempDir Path dir) throws Exception {
        Path zip = dir.resolve("evil.zip");
        try (var zos = new ZipOutputStream(Files.newOutputStream(zip))) {
            put(zos, "../escaped.txt", "pwned");
        }
        Path bundle = dir.resolve("keys");
        var ex = assertThrows(IOException.class, () -> Flows.extractBundle(zip, bundle, s -> {}));
        assertTrue(ex.getMessage().contains("zip-slip"));
        assertFalse(Files.exists(dir.resolve("escaped.txt")), "escaped file must not be written");
    }

    @Test
    void rejectsArchiveThatIsNotABundle(@TempDir Path dir) throws Exception {
        Path zip = dir.resolve("junk.zip");
        try (var zos = new ZipOutputStream(Files.newOutputStream(zip))) {
            put(zos, "readme.txt", "hello");
        }
        var ex = assertThrows(IOException.class, () -> Flows.extractBundle(zip, dir.resolve("keys"), s -> {}));
        assertTrue(ex.getMessage().contains("not a valid key bundle"));
    }

    private static void put(ZipOutputStream zos, String name, String content) throws IOException {
        zos.putNextEntry(new ZipEntry(name));
        zos.write(content.getBytes(StandardCharsets.UTF_8));
        zos.closeEntry();
    }
}
