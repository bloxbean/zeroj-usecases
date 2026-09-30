package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import org.zeroj.api.R1CSFlat;
import org.zeroj.crypto.groth16.Groth16Keys;
import org.zeroj.crypto.groth16.Groth16Pipeline;
import org.zeroj.crypto.groth16.Groth16PkStore;
import org.zeroj.crypto.groth16.ProverBackend;
import org.zeroj.crypto.msm.FlatScalars;
import org.zeroj.crypto.setup.Groth16SetupBLS381;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class BundleFingerprintTest {
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TAU = BigInteger.valueOf(42);
    private static final Groth16Pipeline.Progress PROGRESS = new Groth16Pipeline.Progress() {};

    /**
     * {@code coefficient * a * b = c} over wires {@code [1, c, a, b]} plus the trivially satisfied
     * {@code 1 * 1 = 1} row: zeroj ADR-0045 rejects a relation whose constant wire is unreferenced
     * (its {@code IC[0]} would be the point at infinity, which every verifier rejects).
     */
    /** Rows in {@link #circuit}: the multiplier row plus the constant-wire binding row. */
    private static final int ROWS = 2;

    private static Groth16Pipeline.Compiled circuit(BigInteger coefficient) {
        var builder = R1CSFlat.builder();
        builder.add(Map.of(2, coefficient), Map.of(3, ONE), Map.of(1, ONE));
        builder.add(Map.of(0, ONE), Map.of(0, ONE), Map.of(0, ONE));
        return new Groth16Pipeline.Compiled(builder.build(), 2, 4, 1);
    }

    private static Bundle setup(Path dir, boolean sparse) throws IOException {
        Groth16Pipeline.setup(circuit(ONE), TAU, dir, sparse, PROGRESS);
        return new Bundle(dir);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void finalizedBundlePreservesExactFingerprintAndProves(boolean sparse, @TempDir Path dir) throws Exception {
        var bundle = setup(dir, sparse);
        bundle.finalizeAndReport("local", ROWS, 4, 1);
        String fingerprint = bundle.metadata().getProperty("fingerprint");
        assertEquals(circuit(ONE).fingerprint(), fingerprint);
        assertEquals(fingerprint, Flows.keyFingerprint(dir));
        assertTrue(Groth16Pipeline.isExactFingerprint(fingerprint));
        assertTrue(bundle.verifyIntegrity().isEmpty());

        try (var loaded = Groth16PkStore.load(dir)) {
            assertEquals(loaded.circuitFingerprint(), fingerprint);
            var proof = Groth16Pipeline.prove(Groth16Keys.of(loaded), dir.resolve(Groth16Pipeline.R1CS_CACHE),
                    fingerprint, () -> { throw new AssertionError("Exact cache must avoid recompilation"); },
                    () -> FlatScalars.pack(new BigInteger[]{ONE, BigInteger.valueOf(33),
                            BigInteger.valueOf(3), BigInteger.valueOf(11)}, 4),
                    0, ProverBackend.PURE_JAVA, PROGRESS);
            var points = new ProofIO.ProofPoints(OffchainVerifier.toG1(proof.a()),
                    OffchainVerifier.toG2(proof.b()), OffchainVerifier.toG1(proof.c()));
            assertTrue(OffchainVerifier.verify(loaded, points, new BigInteger[]{BigInteger.valueOf(33)}));
            assertFalse(OffchainVerifier.verify(loaded, points, new BigInteger[]{BigInteger.valueOf(34)}));
        }
    }

    @Test
    void wrongDimensionsDoNotReplaceMetadata(@TempDir Path dir) throws Exception {
        var bundle = setup(dir, true);
        bundle.writeMetadata("local", ROWS, 4, 1, "test", "test");
        byte[] original = Files.readAllBytes(dir.resolve(Bundle.BUNDLE_PROPS));
        for (int[] dims : new int[][]{{ROWS + 1, 4, 1}, {ROWS, 5, 1}, {ROWS, 4, 2}}) {
            assertThrows(IOException.class, () -> bundle.writeMetadata("local", dims[0], dims[1], dims[2], "test", "test"));
            assertArrayEquals(original, Files.readAllBytes(dir.resolve(Bundle.BUNDLE_PROPS)));
        }
    }

    @Test
    void missingOrCorruptStoreCannotProduceMetadata(@TempDir Path dir) throws Exception {
        var bundle = new Bundle(dir);
        assertThrows(IOException.class, () -> bundle.writeMetadata("local", ROWS, 4, 1, "test", "test"));
        setup(dir, true);
        Files.writeString(dir.resolve("manifest.properties"), "circuitFingerprint=invalid\n");
        assertThrows(IOException.class, () -> bundle.writeMetadata("local", ROWS, 4, 1, "test", "test"));
        assertFalse(Files.exists(dir.resolve(Bundle.BUNDLE_PROPS)));
    }

    @Test
    void unboundStoreRemainsUnbound(@TempDir Path dir) throws Exception {
        var compiled = circuit(ONE);
        Groth16PkStore.save(Groth16SetupBLS381.setup(compiled.flat().asList(), 4, 1, TAU), dir);
        var bundle = new Bundle(dir);
        bundle.writeMetadata("ceremony", ROWS, 4, 1, "test", "test");
        assertEquals(Bundle.fingerprint(ROWS, 4, 1), bundle.metadata().getProperty("fingerprint"));
        assertTrue(bundle.isSnarkjsKey());
        try (var loaded = Groth16PkStore.load(dir)) {
            assertNull(loaded.circuitFingerprint(), "Metadata must not bind an unverified key");
        }
    }

    @Test
    void differentRelationWithSameDimensionsStillFailsBeforeWitness(@TempDir Path dir) throws Exception {
        var bundle = setup(dir, true);
        bundle.writeMetadata("local", ROWS, 4, 1, "test", "test");
        var foreign = circuit(BigInteger.TWO);
        assertNotEquals(bundle.metadata().getProperty("fingerprint"), foreign.fingerprint());
        try (var loaded = Groth16PkStore.load(dir)) {
            assertThrows(IllegalStateException.class, () -> Groth16Pipeline.prove(Groth16Keys.of(loaded),
                    dir.resolve(Groth16Pipeline.R1CS_CACHE), foreign.fingerprint(),
                    () -> { throw new AssertionError("Must fail before compile"); },
                    () -> { throw new AssertionError("Must fail before witness"); },
                    0, ProverBackend.PURE_JAVA, PROGRESS));
        }
    }
}
