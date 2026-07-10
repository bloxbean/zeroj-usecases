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
import com.bloxbean.cardano.zeroj.crypto.groth16.ZkeyPkStoreImporter;
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

    /** Compile the {@code @ZKCircuit} to R1CS over BLS12-381 (idempotent). */
    public synchronized R1CSConstraintSystem compile() {
        if (r1cs == null) {
            circuit = OwnershipProofCircuit.build();
            r1cs = circuit.compileR1CS(CurveId.BLS12_381);
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
        compile();
        Map<String, List<BigInteger>> in = new HashMap<>();
        putBytes(in, "rootKL", rootKL);
        putBytes(in, "rootKR", rootKR);
        putBytes(in, "rootChainCode", rootChainCode);
        putBytes(in, "pkh", pkh);
        return circuit.calculateWitness(in, CurveId.BLS12_381);
    }

    /**
     * Prove against a loaded key.
     *
     * @param snarkjsKey true when the key came from an snarkjs/ptau ceremony — snarkjs's
     *                   Groth16 setup appends one public-input binding row per public signal, so the
     *                   prover's QAP must use {@link ZkeyPkStoreImporter#snarkjsConstraints}. A local
     *                   setup uses the raw constraints.
     */
    public Groth16ProofBLS381 prove(Groth16PkStore.Loaded key, BigInteger[] witness,
                                    ProverBackend backend, boolean snarkjsKey) {
        compile();
        List<R1CSConstraint> cons = snarkjsKey
                ? ZkeyPkStoreImporter.snarkjsConstraints(r1cs.constraints(), r1cs.numPublicInputs())
                : r1cs.constraints();
        int domain = key.domain();

        // ADR-0033 M2 / ADR-0034 M1: the compiled circuit graph (~3 GB at 19M) is only needed for
        // witness calculation — already done by the caller — so release it (and r1cs; the local
        // `cons` holds the constraint list) BEFORE computeH, which was the measured 16.8 GB peak.
        // The constraints are computeH's input and are released right after it, so neither is
        // resident during the five MSMs. `compile()` is idempotent, so a later prove in the same
        // process simply recompiles.
        circuit = null;
        r1cs = null;
        BigInteger[] hCoeffs = Groth16ProverBLS381.computeH(cons, witness, cons.size(), domain);
        cons = null;

        return Groth16ProverBLS381.proveWithHCoeffs(key.pk(), key.readers(), backend, witness, hCoeffs);
    }

    /** ZkBytes input keys are {@code base_i}, one byte per element. */
    private static void putBytes(Map<String, List<BigInteger>> in, String base, byte[] bytes) {
        for (int i = 0; i < bytes.length; i++)
            in.put(base + "_" + i, List.of(BigInteger.valueOf(bytes[i] & 0xff)));
    }
}
