package com.bloxbean.cardano.zeroj.usecases.recovery.service;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.ProverBackend;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.usecases.recovery.circuit.OwnershipProofCircuit;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds, keys, and proves the <b>real</b> account-ownership circuit (ADR-0029 M5): the full
 * CIP-1852 derivation from root key to address payment key hash — 19,075,097 constraints.
 *
 * <p>The expensive trusted setup runs <em>once</em>: the proving key is persisted via
 * {@link Groth16PkStore} (~23 GB) and mmap'd back on subsequent runs (~2 min load instead of
 * ~47 min setup). Proofs take ~2.5 min with the blst backend on a 12-core box (~9 min pure-Java
 * multi-core). Prover backend is injectable so the core service stays native-free; pass
 * {@code BlstProverBackend.create()} for the fast path.</p>
 *
 * <p><b>Dev/demo setup only:</b> the in-process setup is single-party (tau is known to this JVM).
 * A production deployment must derive the key from an MPC ceremony.</p>
 */
public class OwnershipCircuitService {

    private final Path pkCacheDir;

    private CircuitBuilder circuit;
    private R1CSConstraintSystem r1cs;
    private List<R1CSConstraint> constraints;
    private Groth16PkStore.Loaded key;

    public OwnershipCircuitService(Path pkCacheDir) {
        this.pkCacheDir = pkCacheDir;
    }

    /** Compile the circuit and load (or create + persist) the proving key. */
    public synchronized void init() throws IOException {
        if (key != null) return;
        circuit = OwnershipProofCircuit.build();
        r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        constraints = r1cs.constraints();

        if (!Groth16PkStore.exists(pkCacheDir)) {
            // one-time: ~47 min at 19M on a 12-core box; needs a large heap (~90 GB)
            BigInteger tau = new BigInteger(512, new SecureRandom()).mod(MontFr381.modulus());
            var setup = Groth16SetupBLS381.setup(constraints, r1cs.numWires(), r1cs.numPublicInputs(), tau);
            Groth16PkStore.save(setup, pkCacheDir);
        }
        key = Groth16PkStore.load(pkCacheDir);
    }

    /**
     * Prove the ownership statement: the root key ({@code kL,kR,chainCode}) derives via
     * {@code m/1852'/1815'/0'/0/0} to {@code pkh}.
     */
    public Groth16ProofBLS381 prove(byte[] rootKL, byte[] rootKR, byte[] rootChainCode, byte[] pkh,
                                    ProverBackend backend) throws IOException {
        init();
        Map<String, List<BigInteger>> in = new HashMap<>();
        putBytes(in, "rootKL", rootKL);
        putBytes(in, "rootKR", rootKR);
        putBytes(in, "rootChainCode", rootChainCode);
        putBytes(in, "pkh", pkh);
        BigInteger[] witness = circuit.calculateWitness(in, CurveId.BLS12_381);
        return Groth16ProverBLS381.proveWithReaders(key.pk(), key.readers(), backend,
                witness, constraints, r1cs.numWires(), key.domain());
    }

    /** The VK components (for the on-chain validator), assembled from the persisted key. */
    public Groth16SetupBLS381.SetupResult vkSetupResult() {
        try { init(); } catch (IOException e) { throw new UncheckedIOException(e); }
        return new Groth16SetupBLS381.SetupResult(key.pk(), key.gammaG2(), key.ic());
    }

    public int numConstraints() {
        try { init(); } catch (IOException e) { throw new UncheckedIOException(e); }
        return r1cs.numConstraints();
    }

    /** ZkBytes input keys are {@code base_i}, one byte per element. */
    private static void putBytes(Map<String, List<BigInteger>> in, String base, byte[] bytes) {
        for (int i = 0; i < bytes.length; i++)
            in.put(base + "_" + i, List.of(BigInteger.valueOf(bytes[i] & 0xff)));
    }
}
