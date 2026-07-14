package com.bloxbean.cardano.zeroj.usecases.recovery.ui.download;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link ResumableDownloader} against an in-process HTTP server that honours {@code Range}:
 * a fresh download verifies its SHA-256; a pre-existing {@code .part} resumes (only the missing
 * suffix is transferred); a wrong digest fails and keeps the partial file.
 */
class ResumableDownloaderTest {

    private static final byte[] PAYLOAD = payload(300_000); // ~293 KiB, multi-buffer
    private static final String SHA = sha256Hex(PAYLOAD);

    private HttpServer server;
    private URI url;
    private final AtomicBoolean rangeSeen = new AtomicBoolean(false);

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/bundle.bin", exchange -> {
            String range = exchange.getRequestHeaders().getFirst("Range");
            if (range != null && range.startsWith("bytes=")) {
                rangeSeen.set(true);
                long start = Long.parseLong(range.substring(6, range.indexOf('-')));
                long end = PAYLOAD.length - 1;
                long len = end - start + 1;
                exchange.getResponseHeaders().set("Accept-Ranges", "bytes");
                exchange.getResponseHeaders().set("Content-Range", "bytes " + start + "-" + end + "/" + PAYLOAD.length);
                exchange.sendResponseHeaders(206, len);
                try (var os = exchange.getResponseBody()) { os.write(PAYLOAD, (int) start, (int) len); }
            } else {
                exchange.sendResponseHeaders(200, PAYLOAD.length);
                try (var os = exchange.getResponseBody()) { os.write(PAYLOAD); }
            }
        });
        server.start();
        url = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/bundle.bin");
    }

    @AfterEach
    void stopServer() { server.stop(0); }

    @Test
    void freshDownload_verifiesShaAndContent(@TempDir Path dir) throws Exception {
        Path dest = dir.resolve("bundle.bin");
        long[] last = {0, 0};
        var out = new ResumableDownloader().download(url, dest, SHA,
                (done, total) -> { last[0] = done; last[1] = total; }, () -> false);

        assertEquals(dest, out);
        assertArrayEquals(PAYLOAD, Files.readAllBytes(dest), "downloaded content");
        assertEquals(PAYLOAD.length, last[0], "final progress done");
        assertEquals(PAYLOAD.length, last[1], "advertised total");
        assertFalse(Files.exists(dir.resolve("bundle.bin.part")), ".part promoted to dest");
    }

    @Test
    void resumesFromPartialFile(@TempDir Path dir) throws Exception {
        Path dest = dir.resolve("bundle.bin");
        int half = PAYLOAD.length / 2;
        Files.write(dir.resolve("bundle.bin.part"), Arrays.copyOfRange(PAYLOAD, 0, half));

        var dl = new ResumableDownloader();
        long[] first = {-1};
        dl.download(url, dest, SHA, (done, total) -> { if (first[0] < 0) first[0] = done; }, () -> false);

        assertTrue(rangeSeen.get(), "server must have received a Range request");
        assertEquals(half, first[0], "progress starts at the bytes already on disk");
        assertArrayEquals(PAYLOAD, Files.readAllBytes(dest), "resumed content is the full payload");
    }

    @Test
    void shaMismatch_throwsAndKeepsPartial(@TempDir Path dir) {
        Path dest = dir.resolve("bundle.bin");
        String wrong = "0".repeat(64);
        var ex = assertThrows(IOException.class, () -> new ResumableDownloader()
                .download(url, dest, wrong, (d, t) -> {}, () -> false));
        assertTrue(ex.getMessage().contains("SHA-256 mismatch"));
        assertFalse(Files.exists(dest), "dest not created on mismatch");
        assertTrue(Files.exists(dir.resolve("bundle.bin.part")), ".part kept for retry");
    }

    private static byte[] payload(int n) {
        byte[] b = new byte[n];
        new Random(42).nextBytes(b);
        return b;
    }

    private static String sha256Hex(byte[] data) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte x : d) sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
            return sb.toString();
        } catch (Exception e) { throw new RuntimeException(e); }
    }
}
