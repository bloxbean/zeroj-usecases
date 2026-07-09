package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Helpers for a prepared powers-of-tau file: a resumable downloader (for {@code --ptau-url}) and a
 * fast header pre-check that fails early on the wrong curve or size.
 *
 * <p>The circuit is on <b>BLS12-381</b>, so the ptau must be BLS12-381 too — a BN254 ptau (e.g. the
 * PSE Perpetual Powers of Tau) cannot be used. The check reads only the iden3 ptau header (a few
 * bytes), so it's instant even for a 32 GB file.</p>
 */
public final class PtauFile {

    /** BLS12-381 base field: element byte size and modulus (the ptau header's {@code q}). */
    private static final int BLS381_N8 = 48;
    private static final BigInteger BLS381_Q = MontFp381.modulus();

    private PtauFile() {}

    public record Header(int n8, BigInteger q, int power) {}

    /** Reject anything that isn't a BLS12-381 ptau of at least {@code minPower}. */
    public static void requireBls381(Path ptau, int minPower) throws IOException {
        Header h = readHeader(ptau);
        boolean bls381 = h.n8() == BLS381_N8 && BLS381_Q.equals(h.q());
        if (!bls381) {
            String hint = h.n8() == 32 ? " — this looks like a BN254 ptau (e.g. the PSE Perpetual "
                    + "Powers of Tau), which is a different curve and cannot be used" : "";
            throw new IllegalArgumentException("Not a BLS12-381 ptau (field element size "
                    + h.n8() + " bytes" + hint + "). This circuit needs a BLS12-381 ptau.");
        }
        if (h.power() < minPower)
            throw new IllegalArgumentException("ptau is 2^" + h.power() + " but the circuit needs 2^"
                    + minPower + "+ (a larger prepared powers-of-tau).");
    }

    /** Parse the iden3 ptau header (magic + section 1: {@code n8}, {@code q}, {@code power}). */
    public static Header readHeader(Path ptau) throws IOException {
        try (FileChannel ch = FileChannel.open(ptau, StandardOpenOption.READ)) {
            ByteBuffer top = read(ch, 0, 12);
            byte[] magic = new byte[4];
            top.get(magic);
            if (!"ptau".equals(new String(magic, StandardCharsets.ISO_8859_1)))
                throw new IOException(ptau.getFileName() + " is not a .ptau file (bad magic).");
            top.getInt();                       // version
            int nSections = top.getInt();

            long pos = 12;
            for (int i = 0; i < nSections; i++) {
                ByteBuffer sh = read(ch, pos, 12);
                int type = sh.getInt();
                long size = sh.getLong();
                long dataStart = pos + 12;
                if (type == 1) {                // header section
                    ByteBuffer d = read(ch, dataStart, Math.min(size, 128));
                    int n8 = d.getInt();
                    byte[] qle = new byte[n8];
                    d.get(qle);
                    int power = d.getInt();
                    return new Header(n8, new BigInteger(1, reverse(qle)), power);
                }
                pos = dataStart + size;
            }
            throw new IOException("ptau header section not found in " + ptau.getFileName());
        }
    }

    private static ByteBuffer read(FileChannel ch, long pos, long len) throws IOException {
        ByteBuffer b = ByteBuffer.allocate((int) len).order(ByteOrder.LITTLE_ENDIAN);
        int n = ch.read(b, pos);
        if (n < len) throw new IOException("truncated ptau (wanted " + len + " bytes at " + pos + ")");
        return b.flip().order(ByteOrder.LITTLE_ENDIAN);
    }

    private static byte[] reverse(byte[] a) {
        byte[] r = new byte[a.length];
        for (int i = 0; i < a.length; i++) r[i] = a[a.length - 1 - i];
        return r;
    }

    /** Resumable download of {@code url} to {@code dest} (skips if already complete). */
    public static Path download(String url, Path dest, boolean force) throws IOException, InterruptedException {
        if (force) Files.deleteIfExists(dest);
        long have = Files.isRegularFile(dest) ? Files.size(dest) : 0;

        var client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();
        var req = HttpRequest.newBuilder(URI.create(url)).GET();
        if (have > 0) {
            req.header("Range", "bytes=" + have + "-");
            System.out.println("Resuming ptau download at " + human(have));
        } else {
            System.out.println("Downloading ptau from " + url + " ...");
        }
        HttpResponse<java.io.InputStream> resp = client.send(req.build(), HttpResponse.BodyHandlers.ofInputStream());
        int sc = resp.statusCode();
        if (sc == 416) { System.out.println("ptau already downloaded (" + human(have) + ")."); return dest; }
        if (sc != 200 && sc != 206) throw new IOException("ptau download failed: HTTP " + sc);
        boolean append = sc == 206 && have > 0;
        long total = resp.headers().firstValueAsLong("Content-Length").orElse(-1) + (append ? have : 0);

        try (var in = resp.body();
             var os = Files.newOutputStream(dest, append
                     ? new StandardOpenOption[]{StandardOpenOption.APPEND}
                     : new StandardOpenOption[]{StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING})) {
            byte[] buf = new byte[1 << 20];
            long done = append ? have : 0, lastLog = 0;
            int n;
            while ((n = in.read(buf)) != -1) {
                os.write(buf, 0, n);
                done += n;
                if (done - lastLog > (1L << 30)) {
                    System.out.println("  " + human(done) + (total > 0 ? " / " + human(total) : ""));
                    lastLog = done;
                }
            }
            System.out.println("Downloaded " + human(done) + " -> " + dest.getFileName());
        }
        return dest;
    }

    private static String human(long bytes) {
        if (bytes < 1L << 30) return String.format("%.1f MB", bytes / (double) (1 << 20));
        return String.format("%.2f GB", bytes / (double) (1 << 30));
    }
}
