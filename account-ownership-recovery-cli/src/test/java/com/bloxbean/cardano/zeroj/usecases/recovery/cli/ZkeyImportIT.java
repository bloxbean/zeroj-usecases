package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.R1csExporter;
import com.bloxbean.cardano.zeroj.crypto.groth16.ZkeyPkStoreImporter;
import com.bloxbean.cardano.zeroj.cryptoblst.BlstProverBackend;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Validates the {@code import} path end to end on a small circuit: a full <b>external</b> snarkjs
 * phase-2 ceremony (powers-of-tau → groth16 setup → contribute → beacon → zkey verify) produces a
 * finalized {@code .zkey}, which {@link ZkeyPkStoreImporter} imports into a {@link Groth16PkStore};
 * then prove + off-chain pairing verify. snarkjs is used only to <em>produce the zkey</em> (a
 * test-time tool) — the CLI import itself is pure Java. The real circuit uses this same import path
 * at 2^25. Skipped when snarkjs is not installed.
 */
class ZkeyImportIT {

    private static final BigInteger FR = MontFr381.modulus();

    @Test
    void externalCeremonyZkey_import_provesAndVerifies(@TempDir Path dir) throws Exception {
        assumeTrue(findSnarkjs() != null, "snarkjs not installed");

        // a ZeroJ R1CS: a squaring chain with 1 public input (wire 1 = final value)
        int n = 64, numWires = n + 2, numPublic = 1;
        List<R1CSConstraint> cons = chain(n);
        BigInteger[] witness = witness(n);
        Path r1cs = dir.resolve("circuit.r1cs");
        R1csExporter.export(cons, numWires, numPublic, r1cs);

        // external ceremony (exactly what a coordinator runs outside the CLI)
        sh(dir, "powersoftau", "new", "bls12-381", "8", "pot0.ptau");
        sh(dir, "powersoftau", "contribute", "pot0.ptau", "pot1.ptau", "--name=it", "-e=it");
        sh(dir, "powersoftau", "prepare", "phase2", "pot1.ptau", "pot_final.ptau");
        sh(dir, "groth16", "setup", "circuit.r1cs", "pot_final.ptau", "key_0000.zkey");
        sh(dir, "zkey", "contribute", "key_0000.zkey", "key_final.zkey", "--name=c1", "-e=c1");
        sh(dir, "zkey", "verify", "circuit.r1cs", "pot_final.ptau", "key_final.zkey");

        // the CLI import path (pure Java) + the circuit dimension check ImportCommand performs
        Path keys = dir.resolve("keys");
        var imported = ZkeyPkStoreImporter.importToPkStore(dir.resolve("key_final.zkey"), keys);
        assertEquals(numWires, imported.numWires(), "wire count preserved through the ceremony");
        assertEquals(numPublic, imported.numPublic(), "public count preserved");

        try (var loaded = Groth16PkStore.load(keys)) {
            var cs = ZkeyPkStoreImporter.snarkjsConstraints(cons, numPublic);
            Groth16ProofBLS381 proof = Groth16ProverBLS381.proveWithReaders(
                    loaded.pk(), loaded.readers(), BlstProverBackend.create(), witness, cs, numWires, loaded.domain());
            assertTrue(proof.a().isOnCurve() && proof.b().isOnCurve() && proof.c().isOnCurve());

            // round-trip the proof through the CLI JSON and verify with the exported vk.json
            VkIO.write(keys, Bundle.vkSetup(loaded));
            ProofIO.writeProof(dir, proof);
            var pts = ProofIO.readProof(dir.resolve(ProofIO.PROOF_FILE));
            assertTrue(OffchainVerifier.verify(VkIO.readVk(keys), pts, new BigInteger[]{witness[1]}),
                    "proof under the imported ceremony key must pairing-verify");
        }
    }

    // ---- small circuit ----

    private static List<R1CSConstraint> chain(int n) {
        List<R1CSConstraint> c = new ArrayList<>(n);
        BigInteger one = BigInteger.ONE;
        for (int i = 0; i < n - 1; i++)
            c.add(new R1CSConstraint(Map.of(2 + i, one), Map.of(2 + i, one), Map.of(3 + i, one)));
        c.add(new R1CSConstraint(Map.of(n + 1, one), Map.of(0, one), Map.of(1, one)));
        return c;
    }

    private static BigInteger[] witness(int n) {
        BigInteger[] w = new BigInteger[n + 2];
        w[0] = BigInteger.ONE;
        BigInteger a = BigInteger.valueOf(5);
        for (int i = 0; i < n; i++) { w[2 + i] = a; a = a.multiply(a).mod(FR); }
        w[1] = w[n + 1];
        return w;
    }

    // ---- snarkjs exec (test-time only) ----

    static String findSnarkjs() {
        for (String c : new String[]{System.getProperty("zeroj.snarkjs"),
                System.getProperty("user.home") + "/.npm-global/bin/snarkjs",
                "/usr/local/bin/snarkjs", "/opt/homebrew/bin/snarkjs", "snarkjs"}) {
            if (c == null) continue;
            try {
                var pb = new ProcessBuilder(c, "--version").redirectErrorStream(true);
                pb.environment().put("PATH", augmentedPath());
                Process p = pb.start();
                String out;
                try (var r = p.inputReader()) { out = r.lines().reduce("", (a, b) -> a + "\n" + b); }
                if (p.waitFor(20, TimeUnit.SECONDS) && out.toLowerCase().contains("snarkjs")) return c;
            } catch (Exception ignored) {}
        }
        return null;
    }

    static String augmentedPath() {
        String path = System.getenv("PATH");
        StringBuilder sb = new StringBuilder(path == null ? "" : path);
        for (String d : List.of("/usr/local/bin", "/opt/homebrew/bin",
                System.getProperty("user.home") + "/.npm-global/bin"))
            if (path == null || !path.contains(d)) sb.append(':').append(d);
        return sb.toString();
    }

    private static void sh(Path dir, String... args) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(findSnarkjs());
        java.util.Collections.addAll(cmd, args);
        var pb = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true);
        pb.environment().put("PATH", augmentedPath());
        Process p = pb.start();
        try (var r = p.inputReader()) { while (r.readLine() != null) {} }
        assertTrue(p.waitFor(300, TimeUnit.SECONDS), "snarkjs timed out: " + String.join(" ", args));
        assertEquals(0, p.exitValue(), "snarkjs failed: " + String.join(" ", args));
    }
}
