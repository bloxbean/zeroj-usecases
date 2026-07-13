package com.bloxbean.cardano.zeroj.usecases.recovery.service;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Pipeline;
import com.bloxbean.cardano.zeroj.crypto.msm.FlatScalars;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.usecases.recovery.circuit.OwnershipProofCircuit;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Compiles, keys, and proves the account-ownership circuit: the full CIP-1852 derivation from a
 * root key to an address's payment key hash (19,075,097 constraints).
 *
 * <p>The CLI drives the individual steps directly (the trusted setup, the prove, and the on-chain
 * verify are separate CLI commands), so this service exposes them granularly rather than as one
 * {@code init()}. Compilation is idempotent and cached.</p>
 */
public class OwnershipCircuitService {

    private CircuitBuilder circuit;
    private R1CSConstraintSystem r1cs;

    /**
     * Build the circuit graph only (idempotent) — enough for witness calculation. The R1CS
     * compile is separate ({@link #compile}) so a prove with a cached {@code r1cs.bin}
     * (ADR-0034 M4) never pays it.
     */
    public synchronized CircuitBuilder graph() {
        if (circuit == null) circuit = OwnershipProofCircuit.build();
        return circuit;
    }

    /** Compile the {@code @ZKCircuit} to R1CS over BLS12-381 (idempotent). */
    public synchronized R1CSConstraintSystem compile() {
        if (r1cs == null) {
            r1cs = graph().compileR1CS(CurveId.BLS12_381);
        }
        return r1cs;
    }

    public List<R1CSConstraint> constraints() { return compile().constraints(); }

    public int numWires() { return compile().numWires(); }

    public int numPublicInputs() { return compile().numPublicInputs(); }

    public int numConstraints() { return compile().numConstraints(); }

    /**
     * Single-party (development) trusted setup from a random tau. Returns the {@link
     * Groth16SetupBLS381.SetupResult} for the caller to persist ({@code Groth16PkStore.save}) and
     * export the VK from. <b>Insecure</b>: this JVM knows tau and could forge proofs — use only for
     * testing, or produce the key bundle via the ptau ceremony path.
     */
    public Groth16SetupBLS381.SetupResult localSetup() {
        compile();
        BigInteger tau = new BigInteger(512, new SecureRandom()).mod(MontFr381.modulus());
        return Groth16SetupBLS381.setup(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(), tau);
    }

    /**
     * {@link #localSetup()} streamed straight into the {@code Groth16PkStore} layout at
     * {@code dir} (ADR-0035 M2/M3): the circuit graph and constraint system are released before
     * the point generation, the QAP evaluations live as flat limbs, and every point is written
     * into the mmap'd key files — no proving-key array is ever heap-resident. Byte-identical
     * output to {@code localSetup()} + {@code Groth16PkStore.save}. <b>Insecure</b> (single
     * party) — testing only.
     */
    public Groth16SetupBLS381.SetupResult localSetupToStore(java.nio.file.Path dir) throws java.io.IOException {
        return localSetupToStore(dir, true);
    }

    /**
     * {@link #localSetupToStore(java.nio.file.Path)} choosing the store format (ADR-0035 M6a).
     * Orchestration (graph release + {@code r1cs.bin} emission + streamed store) lives in
     * {@link Groth16Pipeline#setup} since it is circuit-agnostic; this method only compiles,
     * drops its references, and delegates.
     */
    public Groth16SetupBLS381.SetupResult localSetupToStore(java.nio.file.Path dir, boolean sparse)
            throws java.io.IOException {
        compile();
        var cc = new Groth16Pipeline.Compiled(r1cs.flat(),
                r1cs.numConstraints(), r1cs.numWires(), r1cs.numPublicInputs());
        circuit = null; // ADR-0035 M2: graph (~5.7 GB) + CS released before the heavy phase
        r1cs = null;
        BigInteger tau = new BigInteger(512, new SecureRandom()).mod(MontFr381.modulus());
        return Groth16Pipeline.setup(cc, tau, dir, sparse, new Groth16Pipeline.Progress() {
            @Override public void constraintCacheWriteFailed(Exception e) {
                System.err.println("  (could not write r1cs cache: " + e.getMessage() + " — continuing)");
            }
        });
    }

    /** The witness for "root key ({@code kL,kR,cc}) derives via m/1852'/1815'/0'/role/index to {@code pkh}". */
    public BigInteger[] witness(byte[] rootKL, byte[] rootKR, byte[] rootChainCode,
                                int role, int index, byte[] pkh) {
        Map<String, List<BigInteger>> in = new HashMap<>();
        putBytes(in, "rootKL", rootKL);
        putBytes(in, "rootKR", rootKR);
        putBytes(in, "rootChainCode", rootChainCode);
        putBytes(in, "role", le4(role));
        putBytes(in, "index", le4(index));
        putBytes(in, "pkh", pkh);
        return graph().calculateWitness(in, CurveId.BLS12_381);
    }

    /** A soft derivation index as the circuit's 4 little-endian bytes. */
    private static byte[] le4(int v) {
        if (v < 0) throw new IllegalArgumentException("soft index must be in [0, 2^31): " + v);
        return new byte[]{(byte) v, (byte) (v >>> 8), (byte) (v >>> 16), (byte) (v >>> 24)};
    }

    /**
     * {@link #witness} born flat (ADR-0034 M7): the calculator writes canonical limbs directly
     * (32 B/wire — no boxed {@code BigInteger[]}, no packing step), and the circuit graph
     * (~3 GB, only needed for witness calculation) is released before returning, so neither is
     * resident during the prove. A later {@code witness()} in the same process recompiles.
     */
    public FlatScalars witnessFlat(byte[] rootKL, byte[] rootKR, byte[] rootChainCode,
                                   int role, int index, byte[] pkh) {
        // Measured (ADR-0034 phase 2): the BOXED witness wins here — this circuit is bit-heavy,
        // so most wires alias the shared ONE/ZERO BigIntegers (~0.4 GB extra beside the 5.7 GB
        // graph), while flat storage always costs the full 32 B/wire (1.4 GB) and pushed the
        // witness-generation peak past the 7 GB floor. Pack to flat AFTER the graph is released;
        // packConsuming drops the boxed elements as they convert.
        BigInteger[] w = witness(rootKL, rootKR, rootChainCode, role, index, pkh);
        // Both compiled references go here (ADR-0033 M2): Groth16Pipeline already extracted the
        // packed matrices it needs, so nothing of the compile survives into the H/MSM phase.
        circuit = null;
        r1cs = null;
        return FlatScalars.packConsuming(w, w.length);
    }

    // The prove orchestration (cache-aware compile, deferred mapped constraints, H split, flat
    // scalars end-to-end) moved to Groth16Pipeline.prove (zeroj-crypto) — it was circuit-agnostic.
    // ProveCommand drives it directly with this service's compile/witness as the two suppliers.

    /** ZkBytes input keys are {@code base_i}, one byte per element. */
    private static void putBytes(Map<String, List<BigInteger>> in, String base, byte[] bytes) {
        for (int i = 0; i < bytes.length; i++)
            in.put(base + "_" + i, List.of(BigInteger.valueOf(bytes[i] & 0xff)));
    }
}
