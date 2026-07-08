package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.crypto.groth16.R1csExporter;
import com.bloxbean.cardano.zeroj.crypto.groth16.ZkeyPkStoreImporter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Orchestrates a real (phase-2) Groth16 setup by shelling out to <a href="https://github.com/iden3/snarkjs">snarkjs</a>:
 * export the ZeroJ circuit to an iden3 {@code .r1cs}, run {@code groth16 setup} against a prepared
 * powers-of-tau, optionally add coordinator contributions + a finalization beacon, let snarkjs's own
 * {@code zkey verify} independently validate the transcript, and import the resulting {@code .zkey}
 * into a {@link com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore}.
 *
 * <p>Steps are resumable: a step whose output file already exists is skipped unless {@code force}.
 * For a genuine multi-party ceremony, run the contributions out of band (snarkjs or the
 * {@code zeroj-ceremony} tool) and hand the finalized {@code .zkey} to {@code setup --tau ptau
 * --zkey <file>} — this class then only imports + independently verifies it.</p>
 */
public final class SnarkjsSetup {

    private final Path workDir;
    private final String snarkjs;
    private final long timeoutSeconds;

    public SnarkjsSetup(Path workDir, long timeoutSeconds) {
        this.workDir = workDir;
        this.snarkjs = findSnarkjs();
        this.timeoutSeconds = timeoutSeconds;
    }

    public boolean available() { return snarkjs != null; }

    public String snarkjsPath() { return snarkjs; }

    public static String findSnarkjs() {
        String prop = System.getProperty("zeroj.snarkjs", System.getenv("SNARKJS"));
        List<String> cands = new ArrayList<>();
        if (prop != null) cands.add(prop);
        cands.add(System.getProperty("user.home") + "/.npm-global/bin/snarkjs");
        cands.add("/usr/local/bin/snarkjs");
        cands.add("/opt/homebrew/bin/snarkjs");
        cands.add("snarkjs"); // PATH
        for (String c : cands) {
            try {
                var pb = new ProcessBuilder(c, "--version").redirectErrorStream(true);
                pb.environment().put("PATH", augmentedPath());
                Process p = pb.start();
                // snarkjs prints its banner ("snarkjs@x.y.z ...") then exits 99, not 0 — match the
                // banner rather than the exit code.
                String out;
                try (var r = p.inputReader()) { out = r.lines().reduce("", (a, b) -> a + "\n" + b); }
                if (p.waitFor(20, TimeUnit.SECONDS) && out.toLowerCase().contains("snarkjs")) return c;
            } catch (Exception ignored) {}
        }
        return null;
    }

    /**
     * PATH augmented with the usual {@code node} install dirs. snarkjs is a Node script with a
     * {@code #!/usr/bin/env node} shebang, so it needs {@code node} on PATH — which a minimal
     * launcher (gradle test JVM, a bare fat-jar run script, cron) may lack.
     */
    static String augmentedPath() {
        String path = System.getenv("PATH");
        var extra = List.of("/usr/local/bin", "/opt/homebrew/bin",
                System.getProperty("user.home") + "/.npm-global/bin");
        StringBuilder sb = new StringBuilder(path == null ? "" : path);
        for (String d : extra) if (path == null || !path.contains(d)) sb.append(':').append(d);
        return sb.toString();
    }

    /** Export the circuit to {@code circuit.r1cs} (skipped if present). */
    public Path exportR1cs(List<R1CSConstraint> cons, int numWires, int numPublic, boolean force) throws IOException {
        Path r1cs = workDir.resolve("circuit.r1cs");
        if (force || !Files.isRegularFile(r1cs)) {
            log("exporting R1CS -> " + r1cs.getFileName());
            R1csExporter.export(cons, numWires, numPublic, r1cs);
        } else log("R1CS present, skipping export");
        return r1cs;
    }

    /**
     * Run {@code groth16 setup} + one coordinator {@code zkey contribute} + a finalization
     * {@code zkey beacon}, then {@code zkey verify}. Returns the finalized {@code .zkey}.
     */
    public Path runCeremony(Path r1cs, Path ptau, int contributions, boolean force) throws Exception {
        require(ptau != null && Files.isRegularFile(ptau), "prepared .ptau not found: " + ptau);
        run(force, "key_0000.zkey", "groth16", "setup", r1cs.toString(), ptau.toString(), "key_0000.zkey");

        String cur = "key_0000.zkey";
        for (int i = 1; i <= Math.max(1, contributions); i++) {
            String next = "key_" + String.format("%04d", i) + ".zkey";
            run(force, next, "zkey", "contribute", cur, next,
                    "--name=coordinator-" + i, "-v", "-e=" + entropy(i));
            cur = next;
        }
        Path finalZkey = workDir.resolve("key_final.zkey");
        // Finalize with a public-randomness beacon so the last contributor's toxic waste can't alone
        // compromise the key (standard snarkjs finalization).
        run(force, "key_final.zkey", "zkey", "beacon", cur, "key_final.zkey",
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "10", "-n=final beacon");
        verify(r1cs, ptau, finalZkey);
        return finalZkey;
    }

    /** Independently validate a finalized zkey against the r1cs + ptau (snarkjs's own check). */
    public void verify(Path r1cs, Path ptau, Path zkey) throws Exception {
        log("independent check: snarkjs zkey verify");
        run(true, null, "zkey", "verify", r1cs.toString(), ptau.toString(), zkey.toString());
    }

    /** Import a finalized zkey into the proving-key store at {@code keysDir}. */
    public ZkeyPkStoreImporter.Imported importToStore(Path zkey, Path keysDir) throws IOException {
        log("importing zkey -> proving-key store");
        return ZkeyPkStoreImporter.importToPkStore(zkey, keysDir);
    }

    // ---- snarkjs exec ----

    /** Run one snarkjs subcommand. Skips when {@code outputName} already exists and not {@code force}. */
    public void run(boolean force, String outputName, String... args) throws Exception {
        if (outputName != null && !force && Files.isRegularFile(workDir.resolve(outputName))) {
            log("skip (exists): " + outputName);
            return;
        }
        List<String> cmd = new ArrayList<>();
        cmd.add(snarkjs);
        java.util.Collections.addAll(cmd, args);
        log("$ snarkjs " + String.join(" ", args));
        var pb = new ProcessBuilder(cmd).directory(workDir.toFile()).redirectErrorStream(true);
        pb.environment().put("PATH", augmentedPath());
        Process p = pb.start();
        try (var r = p.inputReader()) {
            String line;
            while ((line = r.readLine()) != null) System.out.println("    " + line);
        }
        if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IllegalStateException("snarkjs timed out after " + timeoutSeconds + "s: " + String.join(" ", args));
        }
        if (p.exitValue() != 0)
            throw new IllegalStateException("snarkjs failed (exit " + p.exitValue() + "): " + String.join(" ", args));
    }

    private static String entropy(int i) {
        // Coordinator-side entropy; a real ceremony's security comes from the independent contributors
        // and the finalization beacon, not this value.
        return "aor-cli-coordinator-contribution-" + i + "-" + Integer.toHexString((i * 2654435761L & 0xffffffffL) != 0 ? (int) (i * 2654435761L) : i);
    }

    private static void require(boolean cond, String msg) {
        if (!cond) throw new IllegalArgumentException(msg);
    }

    private static void log(String s) { System.out.println("  [snarkjs] " + s); }
}
