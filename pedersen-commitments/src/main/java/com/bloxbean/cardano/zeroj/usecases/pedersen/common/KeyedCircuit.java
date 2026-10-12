package com.bloxbean.cardano.zeroj.usecases.pedersen.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.R1CSConstraint;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;
import org.zeroj.codec.SnarkjsJsonCodec;
import org.zeroj.crypto.groth16.Groth16Keys;
import org.zeroj.crypto.groth16.Groth16Pipeline;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.crypto.setup.Groth16SetupBLS381;
import org.zeroj.crypto.setup.Groth16SetupCache;
import org.zeroj.crypto.snarkjs.SnarkjsGroth16Json;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import org.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.TreeMap;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

/**
 * One compiled circuit with its Groth16 keys: proves witnesses, verifies proofs from their
 * snarkjs-format JSON, and exports the verification key in the compressed form the on-chain
 * verifier takes.
 *
 * <p>Keys come from a single-party <b>development</b> setup (requires
 * {@code -Dzeroj.allowInsecureTrustedSetup=true}). They are cached under {@code ./data}, keyed by
 * the circuit fingerprint ({@code c<rows>-w<wires>-p<public>}) and a SHA-256 of its constraints, so
 * a changed circuit never reuses stale keys, even one with the same shape. Production needs keys
 * from an MPC ceremony.
 *
 * <p>Loading a cached key validates every point (ZeroJ's {@code Groth16SetupCache}), which takes
 * about two minutes for the largest circuits. So each key file is loaded once per process and shared
 * by every demo that compiles the same circuit, and {@link #compileAll} loads several in parallel.
 */
public final class KeyedCircuit {

    private static final Logger log = LoggerFactory.getLogger(KeyedCircuit.class);
    private static final Path CACHE_DIR = Path.of("./data");
    /** Keys by cache file: a second demo compiling the same circuit waits for the first load. */
    private static final Map<Path, CompletableFuture<Groth16SetupBLS381.SetupResult>> SETUPS = new ConcurrentHashMap<>();

    private final String name;
    private final CircuitBuilder circuit;
    private final R1CSConstraintSystem r1cs;
    private final Groth16SetupBLS381.SetupResult setup;
    private final Groth16Keys keys;
    private final String verificationKeyJson;

    private KeyedCircuit(String name, CircuitBuilder circuit, R1CSConstraintSystem r1cs,
                         Groth16SetupBLS381.SetupResult setup) {
        this.name = name;
        this.circuit = circuit;
        this.r1cs = r1cs;
        this.setup = setup;
        this.keys = Groth16Keys.of(setup);
        this.verificationKeyJson = SnarkjsGroth16Json.verificationKeyJson(setup);
    }

    public static KeyedCircuit compile(String name, CircuitBuilder circuit) {
        R1CSConstraintSystem r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        String fingerprint = Groth16Pipeline.fingerprint(
                r1cs.numConstraints(), r1cs.numWires(), r1cs.numPublicInputs());
        log.info("Circuit {}: {} constraints, {} public inputs ({})",
                name, r1cs.numConstraints(), r1cs.numPublicInputs(), fingerprint);
        Path cache = CACHE_DIR.resolve("setup-" + name + "-" + fingerprint + "-" + r1csDigest(r1cs.constraints()) + ".bin");
        var mine = new CompletableFuture<Groth16SetupBLS381.SetupResult>();
        var shared = SETUPS.putIfAbsent(cache, mine);
        Groth16SetupBLS381.SetupResult setup;
        if (shared != null) {
            setup = join(shared);
        } else {
            try {
                setup = loadOrGenerate(name, r1cs, cache);
                mine.complete(setup);
            } catch (RuntimeException e) {
                SETUPS.remove(cache, mine);
                mine.completeExceptionally(e);
                throw e;
            }
        }
        return new KeyedCircuit(name, circuit, r1cs, setup);
    }

    /** Compiles several circuits concurrently, in the order given. */
    public static List<KeyedCircuit> compileAll(Map<String, Supplier<CircuitBuilder>> circuits) {
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            List<CompletableFuture<KeyedCircuit>> futures = circuits.entrySet().stream()
                    .map(e -> CompletableFuture.supplyAsync(() -> compile(e.getKey(), e.getValue().get()), pool))
                    .toList();
            return futures.stream().map(KeyedCircuit::join).toList();
        }
    }

    private static Groth16SetupBLS381.SetupResult loadOrGenerate(String name, R1CSConstraintSystem r1cs, Path cache) {
        Groth16SetupBLS381.SetupResult setup = null;
        try {
            if (Files.exists(cache)) {
                long start = System.nanoTime();
                setup = Groth16SetupCache.loadBls12381Setup(cache);
                log.info("Loaded and validated the keys for {} in {} s", name, (System.nanoTime() - start) / 1_000_000_000L);
            }
        } catch (Exception e) {
            log.warn("Key cache {} unreadable ({}); regenerating", cache, e.getMessage());
        }
        if (setup == null) {
            log.info("Running single-party DEV setup for {} (not for production)...", name);
            setup = Groth16SetupBLS381.setup(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(),
                    Fields.randomFr(new SecureRandom()));
            try {
                Files.createDirectories(CACHE_DIR);
                Groth16SetupCache.saveBls12381Setup(setup, cache);
            } catch (Exception e) {
                log.warn("Could not cache keys for {}: {}", name, e.getMessage());
            }
        }
        return setup;
    }

    private static <T> T join(CompletableFuture<T> future) {
        try {
            return future.join();
        } catch (CompletionException e) {
            if (e.getCause() instanceof RuntimeException r) throw r;
            if (e.getCause() instanceof Error err) throw err;
            throw e;
        }
    }

    /** Computes the witness for {@code inputs} (throws if the relation does not hold) and proves it. */
    public Groth16ProofBLS381 prove(Map<String, List<BigInteger>> inputs) {
        BigInteger[] witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);
        return keys.prove(witness, r1cs.constraints());
    }

    /** Verifies a proof against {@code publicInputs} with ZeroJ's pure-Java verifier, from JSON. */
    public boolean verify(Groth16ProofBLS381 proof, List<BigInteger> publicInputs) {
        var circuitId = new CircuitId(name);
        String proofJson = SnarkjsGroth16Json.proofJson(proof);
        String publicJson = SnarkjsGroth16Json.publicJson(publicInputs.toArray(new BigInteger[0]));
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, verificationKeyJson, publicJson, circuitId);
        var material = VerificationMaterial.of(verificationKeyJson.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, circuitId);
        return new Groth16BLS12381PureJavaVerifier().verify(envelope, material).proofValid();
    }

    /** The verification key compressed for {@code Groth16BLS12381Lib} on-chain. */
    public SnarkjsToCardano.VkCompressed compressedVk() {
        return ProverToCardano.compressVk(setup);
    }

    public CircuitBuilder circuit() { return circuit; }

    public int numConstraints() { return r1cs.numConstraints(); }

    public int numPublicInputs() { return r1cs.numPublicInputs(); }

    /** SHA-256 over every constraint's A, B and C terms, in order, wires sorted; first 8 bytes, hex. */
    static String r1csDigest(List<R1CSConstraint> constraints) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            for (R1CSConstraint row : constraints) {
                for (Map<Integer, BigInteger> terms : List.of(row.a(), row.b(), row.c())) {
                    sha.update(ByteBuffer.allocate(4).putInt(terms.size()).array());
                    for (var term : new TreeMap<>(terms).entrySet()) {
                        sha.update(ByteBuffer.allocate(4).putInt(term.getKey()).array());
                        byte[] coefficient = term.getValue().toByteArray();
                        sha.update(ByteBuffer.allocate(4).putInt(coefficient.length).array());
                        sha.update(coefficient);
                    }
                }
            }
            return HexFormat.of().formatHex(sha.digest(), 0, 8);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
