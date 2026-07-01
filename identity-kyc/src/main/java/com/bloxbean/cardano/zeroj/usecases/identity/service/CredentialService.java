package com.bloxbean.cardano.zeroj.usecases.identity.service;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitEdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubPoint;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.usecases.identity.circuit.CredentialProofCircuit;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Proves possession of an issuer-signed KYC credential, using in-circuit
 * EdDSA-Jubjub verification (ADR-0016).
 *
 * <p>The flow is:
 * <ol>
 *   <li>{@link IssuerService} signs {@code Poseidon(age, country)} with the
 *       issuer's Jubjub secret key at credential issuance. Holder receives
 *       {@code (age, country, sigR, sigS)}.</li>
 *   <li>{@link #prove} runs the credential circuit which:
 *     <ul>
 *       <li>Recomputes {@code claimsMsg = Poseidon(age, country)}.</li>
 *       <li>Asserts {@code EdDSA.verify(issuerPk, claimsMsg, sigR, sigS)}.</li>
 *       <li>Asserts {@code age ≥ minAge}.</li>
 *       <li>Verifies the country Merkle-inclusion proof against the
 *           approved-countries root.</li>
 *     </ul>
 *   </li>
 *   <li>Returns a Groth16 BLS12-381 proof that can be verified on-chain by
 *       the existing Plutus V3 Groth16 verifier.</li>
 * </ol>
 */
@Service
public class CredentialService {

    private static final Logger log = LoggerFactory.getLogger(CredentialService.class);

    @Value("${zk.country-tree-depth}")
    private int countryTreeDepth;

    @Value("${zk.pot-power}")
    private int potPower;

    private CircuitBuilder circuit;
    private R1CSConstraintSystem r1cs;
    private List<R1CSConstraint> constraints;
    private Groth16SetupBLS381.SetupResult setupResult;

    @PostConstruct
    public void init() {
        log.info("Compiling credential circuit (EdDSA-Jubjub, countryTreeDepth={})...",
                countryTreeDepth);

        circuit = CredentialProofCircuit.build(countryTreeDepth);
        r1cs = circuit.compileR1CS(CurveId.BLS12_381);

        log.info("Circuit compiled: {} constraints, {} wires, {} public inputs",
                r1cs.numConstraints(), r1cs.numWires(), r1cs.numPublicInputs());

        constraints = r1cs.constraints();

        log.info("Running dev trusted setup (power={})...", potPower);
        var srs = PowersOfTauBLS381.generate(potPower);
        setupResult = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                r1cs.numPublicInputs(), srs.tauScalar());

        log.info("Trusted setup complete. Ready to verify credentials.");
    }

    /**
     * Generates a ZK proof that the caller possesses a valid signed credential
     * with {@code age ≥ minAge} and {@code country ∈} approved-set.
     *
     * @param issuerPk  issuer's Jubjub public key (pk.u, pk.v appear as public inputs)
     * @param sig       issuer's EdDSA signature over {@code Poseidon(age, country)}
     * @param age       holder's age (secret)
     * @param country   holder's country code (secret)
     * @param minAge    minimum required age (public)
     * @param countryRoot root of approved-countries Merkle tree (public)
     * @param siblings  country Merkle proof siblings (secret)
     * @param pathBits  country Merkle proof path bits (secret)
     */
    public ProofResult prove(JubjubPoint issuerPk, EdDSAJubjub.Signature sig,
                             BigInteger age, BigInteger country,
                             BigInteger minAge, BigInteger countryRoot,
                             BigInteger[] siblings, BigInteger[] pathBits) {

        BigInteger eligible = age.compareTo(minAge) >= 0 ? BigInteger.ONE : BigInteger.ZERO;

        // Compute the challenge-reduction witnesses required by
        // InCircuitEdDSAJubjub.verify.
        var kReduction = InCircuitEdDSAJubjub.witnessComputeKReduction(
                sig.r(), issuerPk, computePoseidon(age, country));

        Map<String, List<BigInteger>> inputs = new HashMap<>();
        inputs.put("pkU", List.of(issuerPk.affineU()));
        inputs.put("pkV", List.of(issuerPk.affineV()));
        inputs.put("minAge", List.of(minAge));
        inputs.put("countryRoot", List.of(countryRoot));
        inputs.put("eligible", List.of(eligible));
        inputs.put("age", List.of(age));
        inputs.put("country", List.of(country));
        inputs.put("sigRU", List.of(sig.r().affineU()));
        inputs.put("sigRV", List.of(sig.r().affineV()));
        inputs.put("sigS", List.of(sig.s()));
        inputs.put("kModL", List.of(kReduction.kModL()));
        inputs.put("kQuotient", List.of(kReduction.kQuotient()));

        for (int i = 0; i < countryTreeDepth; i++) {
            inputs.put("sibling_" + i, List.of(siblings[i]));
            inputs.put("pathBit_" + i, List.of(pathBits[i]));
        }

        BigInteger[] witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);

        var proof = Groth16ProverBLS381.prove(setupResult.provingKey(), witness,
                constraints, r1cs.numWires());

        return new ProofResult(proof, eligible.equals(BigInteger.ONE), witness);
    }

    public Groth16SetupBLS381.SetupResult getSetupResult() { return setupResult; }
    public int getCountryTreeDepth() { return countryTreeDepth; }

    // --- Poseidon (standards-compatible BLS12-381, per ADR-0015) ---

    private final ConcurrentHashMap<String, BigInteger> cache = new ConcurrentHashMap<>();

    public BigInteger computePoseidon(BigInteger a, BigInteger b) {
        String key = a.toString(16) + ":" + b.toString(16);
        return cache.computeIfAbsent(key, k ->
                com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash.hash(
                        com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3.INSTANCE,
                        a, b));
    }

    public record ProofResult(Groth16ProofBLS381 proof, boolean eligible, BigInteger[] witness) {}
}
