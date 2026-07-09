package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
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
 * Validates the {@code setup --tau ptau} orchestration end to end on a small circuit: a prepared
 * powers-of-tau → {@link SnarkjsSetup} (groth16 setup + contribution + beacon + snarkjs's own zkey
 * verify) → import into a {@link Groth16PkStore} → prove → off-chain pairing verify. The real
 * account-ownership circuit uses the identical path at 2^25; this exercises it in seconds.
 *
 * <p>Skipped when snarkjs is not installed.</p>
 */
class SnarkjsSetupIT {

    private static final BigInteger FR = MontFr381.modulus();

    @Test
    void ptauCeremony_importToStore_provesAndVerifies(@TempDir Path dir) throws Exception {
        assumeTrue(SnarkjsSetup.findSnarkjs() != null, "snarkjs not installed");

        // A ZeroJ R1CS: a squaring chain with 1 public input (wire 1 = final value).
        int n = 64, numWires = n + 2, numPublic = 1;
        List<R1CSConstraint> cons = chain(n);
        BigInteger[] witness = witness(n);

        var snark = new SnarkjsSetup(dir, 300);
        Path r1cs = snark.exportR1cs(cons, numWires, numPublic, true);

        // Phase 1 (universal) — the CLI's ptau mode consumes an already-prepared .ptau.
        sh(dir, "powersoftau", "new", "bls12-381", "8", "pot0.ptau");
        sh(dir, "powersoftau", "contribute", "pot0.ptau", "pot1.ptau", "--name=it", "-e=it-entropy");
        sh(dir, "powersoftau", "prepare", "phase2", "pot1.ptau", "pot_final.ptau");

        // Phase 2 via the class under test.
        Path finalZkey = snark.runCeremony(r1cs, dir.resolve("pot_final.ptau"), 1, true);

        Path keys = dir.resolve("keys");
        var imported = snark.importToStore(finalZkey, keys);
        assertEquals(numWires, imported.numWires(), "wire count preserved");
        assertEquals(numPublic, imported.numPublic(), "public count preserved");

        try (var loaded = Groth16PkStore.load(keys)) {
            // snarkjs setup appends public-input binding rows — prove with the snarkjs constraint set.
            var cs = ZkeyPkStoreImporter.snarkjsConstraints(cons, numPublic);
            Groth16ProofBLS381 proof = Groth16ProverBLS381.proveWithReaders(
                    loaded.pk(), loaded.readers(), BlstProverBackend.create(),
                    witness, cs, numWires, loaded.domain());
            assertTrue(proof.a().isOnCurve() && proof.b().isOnCurve() && proof.c().isOnCurve());

            // Round-trip the proof through the CLI's JSON, then verify with the exported vk.json.
            VkIO.write(keys, Bundle.vkSetup(loaded));
            ProofIO.writeProof(dir, proof);
            var pts = ProofIO.readProof(dir.resolve(ProofIO.PROOF_FILE));
            BigInteger[] publicInputs = { witness[1] };
            assertTrue(OffchainVerifier.verify(VkIO.readVk(keys), pts, publicInputs),
                    "proof under the snarkjs ceremony key must pairing-verify");
        }
    }

    @Test
    void ptauPrecheck_acceptsBls381_rejectsWrongCurveAndSize(@TempDir Path dir) throws Exception {
        assumeTrue(SnarkjsSetup.findSnarkjs() != null, "snarkjs not installed");

        // A small BLS12-381 ptau (power 8): accepted at 2^8, rejected when a larger power is required.
        sh(dir, "powersoftau", "new", "bls12-381", "8", "bls.ptau");
        Path bls = dir.resolve("bls.ptau");
        var h = PtauFile.readHeader(bls);
        assertEquals(48, h.n8(), "BLS12-381 field element is 48 bytes");
        assertEquals(8, h.power());
        PtauFile.requireBls381(bls, 8); // OK
        assertThrows(IllegalArgumentException.class, () -> PtauFile.requireBls381(bls, 25),
                "must reject a ptau that is too small for the circuit");

        // A BN254 ptau (e.g. PSE Perpetual Powers of Tau) must be rejected as the wrong curve.
        sh(dir, "powersoftau", "new", "bn128", "8", "bn.ptau");
        Path bn = dir.resolve("bn.ptau");
        assertEquals(32, PtauFile.readHeader(bn).n8(), "BN254 field element is 32 bytes");
        var ex = assertThrows(IllegalArgumentException.class, () -> PtauFile.requireBls381(bn, 8));
        assertTrue(ex.getMessage().toLowerCase().contains("bls12-381"), "message should name the required curve");
    }

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

    private static void sh(Path dir, String... args) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(SnarkjsSetup.findSnarkjs());
        java.util.Collections.addAll(cmd, args);
        var pb = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true);
        pb.environment().put("PATH", SnarkjsSetup.augmentedPath());
        Process p = pb.start();
        try (var r = p.inputReader()) { while (r.readLine() != null) {} }
        assertTrue(p.waitFor(300, TimeUnit.SECONDS), "snarkjs timed out: " + String.join(" ", args));
        assertEquals(0, p.exitValue(), "snarkjs failed: " + String.join(" ", args));
    }
}
