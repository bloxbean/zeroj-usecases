package com.bloxbean.cardano.zeroj.usecases.recovery.ui.download;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.OptionalLong;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Resumable HTTP download for the (~9.6 GB) key bundle — the piece that must be robust.
 *
 * <ul>
 *   <li><b>Resumable</b>: a partial {@code .part} file is continued with an HTTP {@code Range}
 *       request; if the server ignores {@code Range} (200 instead of 206) it restarts cleanly.</li>
 *   <li><b>Progress</b>: {@link ProgressListener} is notified per chunk (bytes done / total) — the
 *       JavaFX screen binds this to a {@code ProgressBar}.</li>
 *   <li><b>Integrity</b>: after the transfer the full file is SHA-256'd and compared to the
 *       expected digest before it is promoted to the destination name.</li>
 *   <li><b>Pre-flight</b>: refuses to start if the filesystem lacks room for the remaining bytes.</li>
 *   <li><b>Cancellable</b>: {@code cancelled} is polled per chunk; on cancel the {@code .part} file
 *       is left in place so a later run resumes.</li>
 * </ul>
 *
 * No JavaFX dependency — unit-tested against an in-process HTTP server.
 */
public final class ResumableDownloader {

    /** Notified as bytes arrive. {@code total} is -1 if the server didn't advertise a length. */
    public interface ProgressListener {
        void onProgress(long done, long total);
    }

    private static final int BUFFER = 1 << 20;         // 1 MiB
    private static final long DISK_SAFETY_MARGIN = 256L << 20; // keep 256 MiB free headroom

    private final HttpClient http;

    public ResumableDownloader() {
        this(HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(30))
                .build());
    }

    ResumableDownloader(HttpClient http) {
        this.http = http;
    }

    /**
     * Download {@code url} to {@code dest}, resuming a prior {@code dest.part} if present.
     *
     * @param expectedSha256Hex lowercase hex SHA-256 to verify, or {@code null} to skip
     * @throws java.io.IOException on HTTP error, disk shortage, or SHA-256 mismatch
     * @throws java.util.concurrent.CancellationException if {@code cancelled} becomes true mid-transfer
     */
    public Path download(URI url, Path dest, String expectedSha256Hex,
                         ProgressListener listener, BooleanSupplier cancelled)
            throws IOException, InterruptedException {
        Path part = dest.resolveSibling(dest.getFileName() + ".part");
        if (dest.getParent() != null) Files.createDirectories(dest.getParent());
        long have = Files.exists(part) ? Files.size(part) : 0;

        var builder = HttpRequest.newBuilder(url).GET().timeout(Duration.ofHours(6));
        if (have > 0) builder.header("Range", "bytes=" + have + "-");
        HttpResponse<InputStream> resp = http.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());

        int status = resp.statusCode();
        boolean append;
        long total;
        if (status == 206) {                       // Partial Content — resuming
            append = true;
            final long haveNow = have;
            total = contentRangeTotal(resp).orElseGet(() -> haveNow + lengthOrNeg(resp));
        } else if (status == 200) {                // server ignored Range — start over
            append = false;
            have = 0;
            total = lengthOrNeg(resp);
        } else {
            resp.body().close();
            throw new IOException("Unexpected HTTP status " + status + " for " + url);
        }

        long remaining = total > 0 ? total - have : -1;
        if (remaining > 0) {
            Path probe = dest.getParent() != null ? dest.getParent() : Path.of(".");
            long usable = Files.getFileStore(probe).getUsableSpace();
            if (usable < remaining + DISK_SAFETY_MARGIN)
                throw new IOException("Not enough disk space at " + probe + ": need ~"
                        + human(remaining) + ", have " + human(usable));
        }

        StandardOpenOption[] opts = append
                ? new StandardOpenOption[]{StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND}
                : new StandardOpenOption[]{StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING};

        long done = have;
        listener.onProgress(done, total);
        try (InputStream in = resp.body();
             OutputStream out = new BufferedOutputStream(Files.newOutputStream(part, opts), BUFFER)) {
            byte[] buf = new byte[BUFFER];
            int n;
            while ((n = in.read(buf)) != -1) {
                if (cancelled.getAsBoolean()) throw new CancellationException("download cancelled");
                out.write(buf, 0, n);
                done += n;
                listener.onProgress(done, total);
            }
        }

        if (expectedSha256Hex != null) {
            String actual = sha256Hex(part);
            if (!actual.equalsIgnoreCase(expectedSha256Hex)) {
                throw new IOException("SHA-256 mismatch for " + dest.getFileName()
                        + " — expected " + expectedSha256Hex + " but got " + actual
                        + " (the .part file is kept; delete it to re-download from scratch)");
            }
        }
        Files.move(part, dest, StandardCopyOption.REPLACE_EXISTING);
        return dest;
    }

    private static long lengthOrNeg(HttpResponse<?> resp) {
        return resp.headers().firstValueAsLong("Content-Length").orElse(-1);
    }

    /** Parse the {@code total} from a {@code Content-Range: bytes start-end/total} header. */
    private static OptionalLong contentRangeTotal(HttpResponse<?> resp) {
        return resp.headers().firstValue("Content-Range").map(v -> {
            int slash = v.indexOf('/');
            if (slash < 0) return OptionalLong.empty();
            String t = v.substring(slash + 1).trim();
            try { return OptionalLong.of(Long.parseLong(t)); }
            catch (NumberFormatException e) { return OptionalLong.empty(); }
        }).orElse(OptionalLong.empty());
    }

    static String sha256Hex(Path file) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (InputStream in = Files.newInputStream(file)) {
                byte[] buf = new byte[BUFFER];
                int n;
                while ((n = in.read(buf)) != -1) md.update(buf, 0, n);
            }
            StringBuilder sb = new StringBuilder(64);
            for (byte b : md.digest()) sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    static String human(long bytes) {
        if (bytes < 1024) return bytes + " B";
        String[] u = {"KB", "MB", "GB", "TB"};
        double v = bytes;
        int i = -1;
        do { v /= 1024; i++; } while (v >= 1024 && i < u.length - 1);
        return String.format("%.1f %s", v, u[i]);
    }
}
