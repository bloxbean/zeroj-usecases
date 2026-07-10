package com.bloxbean.cardano.zeroj.usecases.recovery.service;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.R1CSFlat;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.ProverBackend;
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

    /** The witness for "root key ({@code kL,kR,cc}) derives via m/1852'/1815'/0'/0/0 to {@code pkh}". */
    public BigInteger[] witness(byte[] rootKL, byte[] rootKR, byte[] rootChainCode, byte[] pkh) {
        Map<String, List<BigInteger>> in = new HashMap<>();
        putBytes(in, "rootKL", rootKL);
        putBytes(in, "rootKR", rootKR);
        putBytes(in, "rootChainCode", rootChainCode);
        putBytes(in, "pkh", pkh);
        return graph().calculateWitness(in, CurveId.BLS12_381);
    }

    /**
     * {@link #witness} packed to flat canonical limbs (ADR-0034 M3, 32 B/scalar) — the boxed
     * {@code BigInteger[]} (~3 GB at 43.7M wires) is consumed during packing and the circuit
     * graph (~3 GB, only needed for witness calculation) is released first, so neither is
     * resident during the prove. A later {@code witness()} in the same process recompiles.
     */
    public FlatScalars witnessFlat(byte[] rootKL, byte[] rootKR, byte[] rootChainCode, byte[] pkh) {
        BigInteger[] w = witness(rootKL, rootKR, rootChainCode, pkh);
        circuit = null; // graph served its purpose; r1cs (the packed constraints) stays for prove()
        return FlatScalars.packConsuming(w, w.length);
    }

    /**
     * Prove against a loaded key.
     *
     * @param snarkjsKey true when the key came from an snarkjs/ptau ceremony — snarkjs's
     *                   Groth16 setup appends one public-input binding row per public signal, so the
     *                   prover's QAP must use {@link ZkeyPkStoreImporter#snarkjsConstraints}. A local
     *                   setup uses the raw constraints.
     */
    /**
     * Prove with an explicitly supplied packed constraint system — from a fresh compile or the
     * {@code r1cs.bin} cache (ADR-0034 M4), so a cache-hit prove never runs {@code compileR1CS}.
     *
     * @param bindingRows snarkjs ceremony keys append one public-input binding row per public
     *                    signal ({@code numPublic + 1}); 0 for a local-setup key.
     */
    public Groth16ProofBLS381 prove(Groth16PkStore.Loaded key, FlatScalars witness,
                                    R1CSFlat flat, int bindingRows, ProverBackend backend) {
        int domain = key.domain();

        // ADR-0033 M2 / ADR-0034 M1: the compiled circuit graph (~3 GB at 19M) is only needed for
        // witness calculation — already done by the caller — so release any cached compile state
        // BEFORE computeH. The packed matrices are computeH's input and the caller should drop
        // its own reference after this call; nothing heavy is resident during the five MSMs.
        // ADR-0034 M3: witness and hCoeffs stay flat (32 B/scalar) end-to-end — nothing on the
        // prove path boxes a field element.
        circuit = null;
        r1cs = null;
        FlatScalars hCoeffs = Groth16ProverBLS381.computeHFlat(flat, witness, bindingRows, domain);
        flat = null;

        return Groth16ProverBLS381.proveWithHCoeffs(key.pk(), key.readers(), backend, witness, hCoeffs);
    }

    /** ZkBytes input keys are {@code base_i}, one byte per element. */
    private static void putBytes(Map<String, List<BigInteger>> in, String base, byte[] bytes) {
        for (int i = 0; i < bytes.length; i++)
            in.put(base + "_" + i, List.of(BigInteger.valueOf(bytes[i] & 0xff)));
    }
}
