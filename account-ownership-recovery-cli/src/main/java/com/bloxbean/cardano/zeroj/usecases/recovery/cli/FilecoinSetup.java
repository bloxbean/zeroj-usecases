package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Obtains a prepared powers-of-tau from a publicly-attested phase-1 (e.g. the Filecoin BLS12-381
 * ceremony) so the phase-2 setup inherits real multi-party trust instead of a single machine's
 * randomness. Orchestration only — snarkjs does the cryptography:
 *
 * <pre>
 *   [download (resumable)] → [convert to .ptau if needed] → powersoftau verify (independent check)
 *     → [optional truncate] → powersoftau prepare phase2 → prepared .ptau
 * </pre>
 *
 * <p><b>Coordinator-grade, best effort.</b> The phase-1 file is large (tens of GB) and
 * {@code prepare phase2} at 2^25 is a one-time multi-hour job; the result is cached forever. The
 * exact download/convert step depends on the ceremony's published format and is not universally
 * validated — every step is resumable and, on failure, prints the snarkjs command to finish by hand.
 * A coordinator who has already produced a prepared {@code .ptau} out of band should pass it via
 * {@code --phase1-file} to skip download/convert/truncate.</p>
 */
public final class FilecoinSetup {

    private final Path workDir;
    private final long timeoutSeconds;
    private final SnarkjsSetup snark;

    // Set by SetupCommand before downloadAndPrepare().
    private String url;
    private Path phase1File;
    private boolean ackCost;
    private int truncateTo = -1;

    public FilecoinSetup(Path workDir, long timeoutSeconds) {
        this.workDir = workDir;
        this.timeoutSeconds = timeoutSeconds;
        this.snark = new SnarkjsSetup(workDir, timeoutSeconds);
    }

    public FilecoinSetup source(String url, Path phase1File) { this.url = url; this.phase1File = phase1File; return this; }
    public FilecoinSetup ackCost(boolean ack) { this.ackCost = ack; return this; }
    public FilecoinSetup truncateTo(int power) { this.truncateTo = power; return this; }

    /** Returns the prepared {@code .ptau} ready for {@code groth16 setup}, or null on a handled error. */
    public Path downloadAndPrepare(boolean force) throws Exception {
        if (phase1File == null && (url == null || url.isBlank())) {
            System.err.println("--tau filecoin needs --filecoin-url <url> (a phase-1 source) or "
                    + "--phase1-file <local.ptau>.");
            return null;
        }
        if (!ackCost) {
            System.err.println("""
                    --tau filecoin downloads a large attested phase-1 (tens of GB) and runs a one-time
                    `prepare phase2` that can take many hours at 2^25. It is coordinator-grade and best
                    effort — the download/convert step depends on the ceremony's published format.
                    Re-run with --i-understand-filecoin-cost to proceed. (Already have a prepared .ptau?
                    Use --tau ptau --ptau <file>, or --phase1-file <file> here.)""");
            return null;
        }
        if (!snark.available()) {
            System.err.println("snarkjs not found (npm i -g snarkjs) — required for the filecoin path.");
            return null;
        }

        Path raw = phase1File != null ? phase1File : download(force);
        if (raw == null) return null;

        // Ensure snarkjs .ptau format: verify as-is; if that fails, try `powersoftau convert`.
        Path ptau = raw;
        if (!isValidPtau(raw)) {
            System.out.println("Phase-1 file is not a verifiable .ptau — attempting `powersoftau convert` ...");
            ptau = workDir.resolve("phase1.ptau");
            snark.run(force, "phase1.ptau", "powersoftau", "convert", raw.toString(), "phase1.ptau");
        }
        System.out.println("Independent check: powersoftau verify ...");
        snark.run(true, null, "powersoftau", "verify", ptau.toString());

        if (truncateTo > 0) {
            System.out.println("Truncating to 2^" + truncateTo + " (best effort) ...");
            try {
                snark.run(force, null, "powersoftau", "truncate", ptau.toString());
                Path tr = workDir.resolve(baseName(ptau) + "_" + String.format("%02d", truncateTo) + ".ptau");
                if (Files.isRegularFile(tr)) ptau = tr;
                else System.out.println("  (truncated file not found; continuing with the full phase-1)");
            } catch (Exception e) {
                System.out.println("  (truncate failed: " + e.getMessage() + "; continuing with the full phase-1)");
            }
        }

        Path prepared = workDir.resolve("prepared.ptau");
        System.out.println("Preparing phase 2 (one-time, can take hours at 2^25) ...");
        snark.run(force, "prepared.ptau", "powersoftau", "prepare", "phase2", ptau.toString(), "prepared.ptau");
        return prepared;
    }

    private boolean isValidPtau(Path f) {
        try {
            snark.run(true, null, "powersoftau", "verify", f.toString());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** Resumable HTTP download to {@code workDir/phase1.raw}. */
    private Path download(boolean force) throws IOException, InterruptedException {
        Path out = workDir.resolve("phase1.raw");
        if (force) Files.deleteIfExists(out);
        long have = Files.isRegularFile(out) ? Files.size(out) : 0;

        var client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();
        var reqB = HttpRequest.newBuilder(URI.create(url)).GET();
        if (have > 0) { reqB.header("Range", "bytes=" + have + "-"); System.out.println("Resuming download at " + human(have)); }
        else System.out.println("Downloading phase-1 from " + url + " ...");

        HttpResponse<java.io.InputStream> resp = client.send(reqB.build(), HttpResponse.BodyHandlers.ofInputStream());
        int sc = resp.statusCode();
        if (sc == 416) { System.out.println("Download already complete (" + human(have) + ")."); return out; }
        if (sc != 200 && sc != 206) {
            System.err.println("Download failed: HTTP " + sc);
            return null;
        }
        boolean append = (sc == 206 && have > 0);
        long total = resp.headers().firstValueAsLong("Content-Length").orElse(-1) + (append ? have : 0);
        try (var in = resp.body();
             var os = Files.newOutputStream(out, append
                     ? new StandardOpenOption[]{StandardOpenOption.APPEND}
                     : new StandardOpenOption[]{StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING})) {
            byte[] buf = new byte[1 << 20];
            long done = append ? have : 0;
            int n; long lastLog = 0;
            while ((n = in.read(buf)) != -1) {
                os.write(buf, 0, n);
                done += n;
                if (done - lastLog > (1L << 30)) { // every ~1 GB
                    System.out.println("  " + human(done) + (total > 0 ? " / " + human(total) : ""));
                    lastLog = done;
                }
            }
            System.out.println("Downloaded " + human(done));
        }
        return out;
    }

    private static String baseName(Path p) {
        String n = p.getFileName().toString();
        int dot = n.lastIndexOf('.');
        return dot > 0 ? n.substring(0, dot) : n;
    }

    private static String human(long bytes) {
        if (bytes < 1L << 30) return String.format("%.1f MB", bytes / (double) (1 << 20));
        return String.format("%.2f GB", bytes / (double) (1 << 30));
    }
}
