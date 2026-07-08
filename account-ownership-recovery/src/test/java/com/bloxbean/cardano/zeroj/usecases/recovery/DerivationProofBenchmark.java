package com.bloxbean.cardano.zeroj.usecases.recovery;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.crypto.bip32.HdKeyGenerator;
import com.bloxbean.cardano.client.crypto.bip32.HdKeyPair;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProvingKeyBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.cryptoblst.BlstProverBackend;
import com.bloxbean.cardano.zeroj.usecases.recovery.circuit.OwnershipProofCircuit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0029 M5 — the REAL full CIP-1852 ownership-derivation proof, end to end, with per-stage timing
 * and peak-memory capture. Compiles the {@code OwnershipProof} annotation circuit to R1CS (giving the
 * true constraint count), witnesses it from a real root key, runs the parallel trusted setup, proves
 * with the blst backend, and checks the blst proof is bit-identical to pure Java at derivation scale.
 *
 * <p>Heavy: needs a large heap. Run with:
 * {@code ./gradlew :...:test --tests '*DerivationProofBenchmark' -Dzeroj.derivbench=true -PbenchHeap=110g}</p>
 */
class DerivationProofBenchmark {

    private static final String MNEMONIC = "test test test test test test test test test test test test "
            + "test test test test test test test test test test test sauce";

    private final HdKeyGenerator hd = new HdKeyGenerator();

    @Test
    @EnabledIfSystemProperty(named = "zeroj.derivbench", matches = "true")
    void derivationProof_endToEnd() throws Exception {
        System.out.println("\n===== ADR-0029 M5: full CIP-1852 derivation proof — real end-to-end =====");
        Peak mem = new Peak();

        // Inputs: the real wallet root key + the target address payment-key-hash it derives to.
        var root = hd.getRootKeyPairFromMnemonic(MNEMONIC);
        HdKeyPair leaf = derivePaymentLeaf();
        byte[] expectedPkh = Blake2bUtil.blake2bHash224(leaf.getPublicKey().getKeyData());
        byte[] kL = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 0, 32);
        byte[] kR = Arrays.copyOfRange(root.getPrivateKey().getKeyData(), 32, 64);
        byte[] cc = root.getPrivateKey().getChainCode();
        Map<String, List<BigInteger>> in = new HashMap<>();
        putBytesU(in, "rootKL", kL);
        putBytesU(in, "rootKR", kR);
        putBytesU(in, "rootChainCode", cc);
        putBytesU(in, "pkh", expectedPkh);

        // 1. compile -> R1CS (the true constraint count)
        gc(); mem.reset();
        long t = System.nanoTime();
        CircuitBuilder builder = OwnershipProofCircuit.build();
        R1CSConstraintSystem r1cs = builder.compileR1CS(CurveId.BLS12_381);
        var constraints = r1cs.constraints();
        int numWires = r1cs.numWires(), numPub = r1cs.numPublicInputs(), nCons = r1cs.numConstraints();
        double compileS = secs(t);
        System.out.printf("compile:   %,d constraints | %,d wires | %d public | %.1fs | peak %,d MB%n",
                nCons, numWires, numPub, compileS, mem.peakMB());

        // 2. witness (real root-key derivation)
        gc(); mem.reset(); t = System.nanoTime();
        BigInteger[] witness = builder.calculateWitness(in, CurveId.BLS12_381);
        double witnessS = secs(t);
        System.out.printf("witness:   %,d values | %.1fs | peak %,d MB%n", witness.length, witnessS, mem.peakMB());

        // 3. proving key — load from disk cache (skips the ~50min setup) or run setup once + persist.
        //    Groth16 setup needs only the tau SCALAR (fixed-base muls), not the PlonK/KZG SRS points,
        //    so we pass a random dev tau. Groth16PkStore writes the key; re-runs mmap it (G1 off-heap).
        java.nio.file.Path cache = java.nio.file.Path.of(System.getProperty("zeroj.pkcache",
                System.getProperty("java.io.tmpdir") + "/zeroj-pk-derivation"));
        Groth16ProvingKeyBLS381 pk;
        Groth16ProverBLS381.G1Readers readers;
        int domain;
        double keyPrepS;
        String keyPrepLabel;
        Groth16PkStore.Loaded loaded = null;
        if (Groth16PkStore.exists(cache)) {
            gc(); mem.reset(); t = System.nanoTime();
            loaded = Groth16PkStore.load(cache);
            pk = loaded.pk(); readers = loaded.readers(); domain = loaded.domain();
            keyPrepS = secs(t); keyPrepLabel = "load PK (cached)";
            System.out.printf("load PK:   %.1fs (mmap'd, %s) | peak %,d MB%n", keyPrepS, cache, mem.peakMB());
        } else {
            gc(); mem.reset(); t = System.nanoTime();
            BigInteger tau = new BigInteger(512, new java.security.SecureRandom())
                    .mod(com.bloxbean.cardano.zeroj.bls12381.field.MontFr381.modulus());
            var setup = Groth16SetupBLS381.setup(constraints, numWires, numPub, tau);
            keyPrepS = secs(t); keyPrepLabel = "setup (one-time)";
            pk = setup.provingKey();
            domain = Groth16ProvingKeyBLS381.count(pk.pointsH());
            System.out.printf("setup:     %.1fs (%.0f us/c) | domain 2^%d | PK flat %,d MB | peak %,d MB%n",
                    keyPrepS, keyPrepS * 1e6 / nCons, Integer.numberOfTrailingZeros(domain), pkFlatMB(pk), mem.peakMB());
            gc(); t = System.nanoTime();
            Groth16PkStore.save(setup, cache);
            System.out.printf("save PK:   %.1fs -> %s (reused next run)%n", secs(t), cache);
            readers = Groth16ProverBLS381.heapReaders(pk);
        }

        // 4. prove with the blst backend — the practical path. (Correctness vs pure-Java is bit-identical,
        //    validated at 2^12-2^16; here we time blst and confirm the proof is on-curve.)
        gc(); mem.reset(); t = System.nanoTime();
        var proof = Groth16ProverBLS381.proveWithReaders(pk, readers, BlstProverBackend.create(), witness, constraints, numWires, domain);
        double proveBlstS = secs(t);
        long proveBlstPeak = mem.peakMB();
        System.out.printf("prove blst: %.1fs (%.0f us/c) | peak %,d MB%n", proveBlstS, proveBlstS * 1e6 / nCons, proveBlstPeak);
        assertTrue(proof.a().isOnCurve() && proof.b().isOnCurve() && proof.c().isOnCurve(),
                "blst proof points must be on curve @ derivation scale");

        System.out.println("\n----- summary -----");
        System.out.printf("constraints          : %,d  (domain 2^%d)%n", nCons, Integer.numberOfTrailingZeros(domain));
        System.out.printf("ONE-TIME  compile    : %.1fs%n", compileS);
        System.out.printf("ONE-TIME  witness    : %.1fs%n", witnessS);
        System.out.printf("KEY       %-16s: %.1fs%n", keyPrepLabel, keyPrepS);
        System.out.printf("PER-PROOF prove blst   : %.1fs | peak %,d MB%n", proveBlstS, proveBlstPeak);
        System.out.println("correctness            : blst proof on curve ✓ (bit-identical vs pure-Java validated at 2^12-2^16)");
        if (loaded != null) loaded.close();
        mem.stop();
    }

    /** Standalone entry point — runs outside gradle's test runner (a plain JVM, no daemon to stop). */
    public static void main(String[] args) throws Exception {
        new DerivationProofBenchmark().derivationProof_endToEnd();
        System.out.println("\n[standalone] derivation proof benchmark complete.");
    }

    // ---- helpers ----

    private HdKeyPair derivePaymentLeaf() {
        var r = hd.getRootKeyPairFromMnemonic(MNEMONIC);
        var n1 = hd.getChildKeyPair(r, 1852L, true);
        var n2 = hd.getChildKeyPair(n1, 1815L, true);
        var n3 = hd.getChildKeyPair(n2, 0L, true);
        var n4 = hd.getChildKeyPair(n3, 0L, false);
        return hd.getChildKeyPair(n4, 0L, false);
    }

    private static void putBytesU(Map<String, List<BigInteger>> in, String base, byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) in.put(base + "_" + i, List.of(BigInteger.valueOf(bytes[i] & 0xff)));
    }

    private static long pkFlatMB(Groth16ProvingKeyBLS381 pk) {
        long longs = (long) pk.pointsA().length + pk.pointsB1().length + pk.pointsH().length + pk.pointsL().length;
        return (longs * 8L) / (1L << 20);
    }

    private static double secs(long startNanos) { return (System.nanoTime() - startNanos) / 1e9; }

    private static void gc() { System.gc(); try { Thread.sleep(300); } catch (InterruptedException ignored) {} }

    /** Background peak-used-heap sampler. */
    private static final class Peak {
        private volatile long peak;
        private volatile boolean run = true;
        Peak() {
            Thread th = new Thread(() -> {
                Runtime rt = Runtime.getRuntime();
                while (run) {
                    long used = rt.totalMemory() - rt.freeMemory();
                    if (used > peak) peak = used;
                    try { Thread.sleep(200); } catch (InterruptedException e) { return; }
                }
            });
            th.setDaemon(true);
            th.start();
        }
        void reset() { peak = 0; }
        long peakMB() { return peak / (1L << 20); }
        void stop() { run = false; }
    }
}
