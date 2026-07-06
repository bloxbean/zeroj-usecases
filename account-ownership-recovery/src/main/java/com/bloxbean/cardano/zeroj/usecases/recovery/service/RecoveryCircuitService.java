package com.bloxbean.cardano.zeroj.usecases.recovery.service;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.circuit.lib.Poseidon;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * Builds, sets up, and proves the account-ownership recovery-commitment circuit on BLS12-381.
 *
 * <p>Circuit statement: {@code Poseidon(recoverySecret, addressKeyHashField) == commitment}, with
 * {@code commitment} and {@code addressKeyHashField} public and {@code recoverySecret} secret. A
 * valid proof shows the prover knows the recovery secret behind the commitment registered for that
 * address — the on-chain recovery authorization (the proactive-commitment variant, see DESIGN §14).
 * The same Groth16-BLS12381 proof verifies off-chain (pure Java) and on-chain (Julc validator).</p>
 */
public class RecoveryCircuitService {

    private CircuitBuilder circuit;
    private R1CSConstraintSystem r1cs;
    private List<R1CSConstraint> constraints;
    private Groth16SetupBLS381.SetupResult setupResult;

    /** Build the circuit and run a (dev-only) Groth16 setup. */
    public void init() {
        circuit = CircuitBuilder.create("account-recovery-commitment")
                .publicVar("commitment")
                .publicVar("addr")
                .secretVar("secret")
                .define(api -> {
                    var h = Poseidon.hash(api, PoseidonParamsBLS12_381T3.INSTANCE,
                            api.var("secret"), api.var("addr"));
                    api.assertEqual(h, api.var("commitment"));
                });

        r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        constraints = r1cs.constraints();

        var srs = PowersOfTauBLS381.generate(Math.max(4, 32 - Integer.numberOfLeadingZeros(r1cs.numConstraints())));
        setupResult = Groth16SetupBLS381.setup(constraints, r1cs.numWires(), r1cs.numPublicInputs(), srs.tauScalar());
    }

    /** Prove knowledge of {@code secret} such that Poseidon(secret, addr) == commitment. */
    public Groth16ProofBLS381 prove(BigInteger secret, BigInteger addr, BigInteger commitment) {
        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "commitment", List.of(commitment),
                "addr", List.of(addr),
                "secret", List.of(secret)), CurveId.BLS12_381);
        return Groth16ProverBLS381.prove(setupResult.provingKey(), witness, constraints, r1cs.numWires());
    }

    public Groth16SetupBLS381.SetupResult getSetupResult() { return setupResult; }
    public int numConstraints() { return r1cs.numConstraints(); }
}
