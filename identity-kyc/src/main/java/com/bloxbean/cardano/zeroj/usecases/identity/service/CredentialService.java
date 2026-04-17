package com.bloxbean.cardano.zeroj.usecases.identity.service;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Prover;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.usecases.identity.circuit.CredentialCircuit;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class CredentialService {

    private static final Logger log = LoggerFactory.getLogger(CredentialService.class);
    private static final BigInteger PRIME = FieldConfig.BLS12_381.prime();

    @Value("${zk.country-tree-depth}")
    private int countryTreeDepth;

    @Value("${zk.pot-power}")
    private int potPower;

    private CircuitBuilder circuit;
    private R1CSConstraintSystem r1cs;
    private Groth16Prover.R1CSConstraint[] constraints;
    private Groth16SetupBLS381.SetupResult setupResult;

    @PostConstruct
    public void init() {
        log.info("Compiling credential circuit (countryTreeDepth={})...", countryTreeDepth);

        circuit = CredentialCircuit.build(countryTreeDepth);
        r1cs = circuit.compileR1CS(CurveId.BLS12_381);

        log.info("Circuit compiled: {} constraints, {} wires, {} public inputs",
                r1cs.numConstraints(), r1cs.numWires(), r1cs.numPublicInputs());

        constraints = r1cs.constraints().stream()
                .map(c -> new Groth16Prover.R1CSConstraint(c.a(), c.b(), c.c()))
                .toArray(Groth16Prover.R1CSConstraint[]::new);

        log.info("Running dev trusted setup (power={})...", potPower);
        var srs = PowersOfTauBLS381.generate(potPower);
        setupResult = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                r1cs.numPublicInputs(), srs.tauScalar());

        log.info("Trusted setup complete. Ready to verify credentials.");
    }

    public ProofResult prove(BigInteger credentialSecret, BigInteger age, BigInteger country,
                              BigInteger credentialHash, BigInteger minAge, BigInteger countryRoot,
                              BigInteger[] siblings, BigInteger[] pathBits) {

        BigInteger eligible = age.compareTo(minAge) >= 0 ? BigInteger.ONE : BigInteger.ZERO;

        Map<String, List<BigInteger>> inputs = new HashMap<>();
        inputs.put("credentialSecret", List.of(credentialSecret));
        inputs.put("age", List.of(age));
        inputs.put("country", List.of(country));
        inputs.put("credentialHash", List.of(credentialHash));
        inputs.put("minAge", List.of(minAge));
        inputs.put("countryRoot", List.of(countryRoot));
        inputs.put("eligible", List.of(eligible));

        for (int i = 0; i < countryTreeDepth; i++) {
            inputs.put("sibling_" + i, List.of(siblings[i]));
            inputs.put("pathBit_" + i, List.of(pathBits[i]));
        }

        BigInteger[] witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);

        var proof = Groth16ProverBLS381.prove(setupResult.provingKey(), witness,
                constraints, r1cs.numWires());

        return new ProofResult(proof, eligible.equals(BigInteger.ONE), witness);
    }

    public BigInteger computeCredentialHash(BigInteger credentialSecret, BigInteger age, BigInteger country) {
        BigInteger claimsHash = computePoseidon(age, country);
        return computePoseidon(credentialSecret, claimsHash);
    }

    public Groth16SetupBLS381.SetupResult getSetupResult() { return setupResult; }
    public int getCountryTreeDepth() { return countryTreeDepth; }

    // --- Poseidon ---

    private final ConcurrentHashMap<String, BigInteger> cache = new ConcurrentHashMap<>();

    public BigInteger computePoseidon(BigInteger a, BigInteger b) {
        String key = a.toString(16) + ":" + b.toString(16);
        return cache.computeIfAbsent(key, k -> {
            try {
                var cField = Class.forName("com.bloxbean.cardano.zeroj.circuit.lib.PoseidonConstants")
                        .getDeclaredField("C");
                cField.setAccessible(true);
                BigInteger[] C = (BigInteger[]) cField.get(null);
                var mField = Class.forName("com.bloxbean.cardano.zeroj.circuit.lib.PoseidonConstants")
                        .getDeclaredField("M");
                mField.setAccessible(true);
                BigInteger[] M = (BigInteger[]) mField.get(null);

                BigInteger p = PRIME;
                BigInteger[] state = {BigInteger.ZERO, a.mod(p), b.mod(p)};
                int RF = 8, RP = 57, N = RF + RP;
                for (int r = 0; r < N; r++) {
                    for (int j = 0; j < 3; j++) state[j] = state[j].add(C[r * 3 + j]).mod(p);
                    if (r < RF / 2 || r >= RF / 2 + RP) {
                        for (int j = 0; j < 3; j++) {
                            BigInteger x = state[j], x2 = x.multiply(x).mod(p), x4 = x2.multiply(x2).mod(p);
                            state[j] = x4.multiply(x).mod(p);
                        }
                    } else {
                        BigInteger x = state[0], x2 = x.multiply(x).mod(p), x4 = x2.multiply(x2).mod(p);
                        state[0] = x4.multiply(x).mod(p);
                    }
                    BigInteger[] t = new BigInteger[3];
                    for (int i = 0; i < 3; i++) {
                        t[i] = BigInteger.ZERO;
                        for (int j = 0; j < 3; j++)
                            t[i] = t[i].add(state[j].multiply(M[i * 3 + j])).mod(p);
                    }
                    state = t;
                }
                return state[0];
            } catch (Exception e) {
                throw new RuntimeException("Poseidon failed", e);
            }
        });
    }

    public record ProofResult(Groth16ProofBLS381 proof, boolean eligible, BigInteger[] witness) {}
}
