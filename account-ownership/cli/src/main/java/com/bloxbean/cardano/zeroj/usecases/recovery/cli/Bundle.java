package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import org.zeroj.crypto.groth16.Groth16PkStore;
import org.zeroj.crypto.groth16.Groth16Pipeline;
import org.zeroj.crypto.setup.Groth16SetupBLS381;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.TreeMap;

/**
 * The on-disk <b>key bundle</b> a coordinator produces with {@code setup} and users consume with
 * {@code prove}/{@code verify}. It wraps a {@link Groth16PkStore} directory (the proving key + VK)
 * with two extra artifacts:
 * <ul>
 *   <li>{@code bundle.properties} — setup mode, circuit fingerprint, zeroj version,
 *       creation time;</li>
 *   <li>{@code SHA256SUMS} — per-file digests for integrity verification.</li>
 * </ul>
 *
 * <p>For bound stores the fingerprint includes the canonical R1CS hash, copied from the
 * validated key store. Dimensions alone do not identify a relation. Unbound legacy stores retain
 * their dimensions-only label; writing metadata does not bind or certify a key.</p>
 */
public final class Bundle {

    public static final String BUNDLE_PROPS = "bundle.properties";
    public static final String SHA256SUMS = "SHA256SUMS";

    private final Path dir;

    public Bundle(Path dir) { this.dir = dir; }

    public Path dir() { return dir; }

    /** True if {@code dir} holds both a proving-key store and CLI bundle metadata. */
    public boolean exists() {
        return Groth16PkStore.exists(dir) && Files.isRegularFile(dir.resolve(BUNDLE_PROPS));
    }

    /** Legacy dimensions-only label; bound stores use their exact relation fingerprint instead. */
    public static String fingerprint(int numConstraints, int numWires, int numPublic) {
        return Groth16Pipeline.fingerprint(numConstraints, numWires, numPublic);
    }

    /** Write {@code bundle.properties} (call after the proving-key store has been saved to {@code dir}). */
    public void writeMetadata(String setupMode, int numConstraints, int numWires, int numPublic,
                              String zerojVersion, String createdAt) throws IOException {
        String keyFingerprint = metadataFingerprint(numConstraints, numWires, numPublic);
        Properties p = new Properties();
        p.setProperty("setupMode", setupMode);
        p.setProperty("numConstraints", Integer.toString(numConstraints));
        p.setProperty("numWires", Integer.toString(numWires));
        p.setProperty("numPublic", Integer.toString(numPublic));
        p.setProperty("fingerprint", keyFingerprint);
        p.setProperty("zerojVersion", zerojVersion);
        p.setProperty("createdAt", createdAt);
        // snarkjs-based setups (ptau) append public-input binding rows — the prover needs to know.
        p.setProperty("snarkjsConstraints", Boolean.toString(!"local".equals(setupMode)));
        try (var out = Files.newOutputStream(dir.resolve(BUNDLE_PROPS))) {
            p.store(out, "Account-ownership proof key bundle (ADR-0001)");
        }
    }

    private String metadataFingerprint(int numConstraints, int numWires, int numPublic) throws IOException {
        String legacy = fingerprint(numConstraints, numWires, numPublic);
        var loaded = Groth16PkStore.load(dir);
        try {
            if (loaded.readers().a().count() != numWires || loaded.pk().numPublic() != numPublic) {
                throw new IOException("Bundle dimensions do not match the proving-key store");
            }
            String exact = loaded.circuitFingerprint();
            if (exact == null) return legacy;
            var dimensions = Groth16Pipeline.parseFingerprint(exact);
            if (dimensions == null || dimensions.numConstraints() != numConstraints
                    || dimensions.numWires() != numWires || dimensions.numPublic() != numPublic) {
                throw new IOException("Bundle dimensions do not match the exact circuit fingerprint");
            }
            return exact;
        } finally {
            closeQuietly(loaded);
        }
    }

    public Properties metadata() {
        Properties p = new Properties();
        try (var in = Files.newInputStream(dir.resolve(BUNDLE_PROPS))) {
            p.load(in);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read " + BUNDLE_PROPS + " in " + dir, e);
        }
        return p;
    }

    /** True when the bundle was produced by an snarkjs/ptau ceremony (binding rows present). */
    public boolean isSnarkjsKey() {
        return Boolean.parseBoolean(metadata().getProperty("snarkjsConstraints", "false"));
    }

    /** Reconstruct the verification-key components from a loaded proving-key store. */
    public static Groth16SetupBLS381.SetupResult vkSetup(Groth16PkStore.Loaded loaded) {
        return new Groth16SetupBLS381.SetupResult(loaded.pk(), loaded.gammaG2(), loaded.ic());
    }

    /**
     * Close a loaded store, ignoring failures. In a GraalVM native image the store's shared mmap
     * Arena cannot be closed — the close fatally aborts the process ({@code VMError.unsupportedFeature},
     * which is not a catchable throwable), so we skip it entirely there. The OS reclaims the mapping
     * on exit regardless. On the JVM, close frees the mapping normally.
     */
    public static void closeQuietly(AutoCloseable c) {
        if (c == null) return;
        if (System.getProperty("org.graalvm.nativeimage.imagecode") != null) return; // skip in native image
        try { c.close(); } catch (Throwable ignored) {}
    }

    /** Write bundle metadata + integrity manifest and print a ready-summary. Shared by setup + import. */
    public void finalizeAndReport(String mode, int numConstraints, int numWires, int numPublic) throws IOException {
        System.out.println("Writing bundle metadata + integrity manifest ...");
        writeMetadata(mode, numConstraints, numWires, numPublic, zerojVersion(), java.time.Instant.now().toString());
        writeIntegrityManifest();
        System.out.printf("%nKey bundle ready at %s (%.1f GB)%n", dir.toAbsolutePath(), dirSize(dir) / 1e9);
        System.out.println("  mode: " + mode + "   fingerprint: " + metadata().getProperty("fingerprint"));
        System.out.println("Next: `info` to inspect, `prove` to generate a proof, or publish this directory.");
    }

    public static String zerojVersion() {
        String v = Groth16PkStore.class.getPackage().getImplementationVersion();
        return v != null ? v : "unknown";
    }

    static long dirSize(Path d) throws IOException {
        try (var s = Files.walk(d)) {
            return s.filter(Files::isRegularFile).mapToLong(p -> {
                try { return Files.size(p); } catch (IOException e) { return 0; }
            }).sum();
        }
    }

    // ---- integrity ----

    /** Compute + write {@code SHA256SUMS} over every regular file in {@code dir} (except SHA256SUMS itself). */
    public void writeIntegrityManifest() throws IOException {
        var lines = new ArrayList<String>();
        for (var name : sortedFiles()) {
            if (name.equals(SHA256SUMS)) continue;
            lines.add(sha256(dir.resolve(name)) + "  " + name);
        }
        Files.write(dir.resolve(SHA256SUMS), lines);
    }

    /** Verify every file against {@code SHA256SUMS}. Returns the list of problems (empty = OK). */
    public List<String> verifyIntegrity() throws IOException {
        var problems = new ArrayList<String>();
        Path sums = dir.resolve(SHA256SUMS);
        if (!Files.isRegularFile(sums)) return List.of("missing " + SHA256SUMS);
        for (String line : Files.readAllLines(sums)) {
            int i = line.indexOf("  ");
            if (i < 0) continue;
            String expected = line.substring(0, i), name = line.substring(i + 2);
            Path f = dir.resolve(name);
            if (!Files.isRegularFile(f)) { problems.add("missing " + name); continue; }
            if (!expected.equals(sha256(f))) problems.add("digest mismatch: " + name);
        }
        return problems;
    }

    private List<String> sortedFiles() throws IOException {
        var names = new TreeMap<String, Boolean>();
        try (var s = Files.list(dir)) {
            s.filter(Files::isRegularFile).forEach(p -> names.put(p.getFileName().toString(), true));
        }
        return new ArrayList<>(names.keySet());
    }

    static String sha256(Path f) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (InputStream in = Files.newInputStream(f)) {
                byte[] buf = new byte[1 << 20];
                int n;
                while ((n = in.read(buf)) != -1) md.update(buf, 0, n);
            }
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest()) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
