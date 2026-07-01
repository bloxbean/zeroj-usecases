package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitEdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubPoint;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupCache;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import java.nio.file.Files;
import java.nio.file.Path;
import com.bloxbean.cardano.zeroj.usecases.airdrop.circuit.PersonhoodAirdropProofCircuit;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Compiles the airdrop circuit, runs trusted setup, and generates the
 * per-claim Groth16 proof.
 */
@Service
public class AirdropProofService {

    private static final Logger log = LoggerFactory.getLogger(AirdropProofService.class);

    @Value("${zk.pot-power}")
    private int potPower;

    private CircuitBuilder circuit;
    private R1CSConstraintSystem r1cs;
    private List<R1CSConstraint> constraints;
    private Groth16SetupBLS381.SetupResult setupResult;

    @PostConstruct
    public void init() {
        log.info("Compiling airdrop circuit...");
        circuit = PersonhoodAirdropProofCircuit.build();
        r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        log.info("Circuit compiled: {} constraints, {} wires, {} public inputs",
                r1cs.numConstraints(), r1cs.numWires(), r1cs.numPublicInputs());

        constraints = r1cs.constraints();

        setupResult = loadOrRunSetup();
        log.info("Trusted setup ready. Faucet can accept claims.");
    }

    private Groth16SetupBLS381.SetupResult loadOrRunSetup() {
        Path cacheDir = Path.of("./data");
        Path setupCache = cacheDir.resolve("setup-airdrop.bin");
        try { Files.createDirectories(cacheDir); } catch (Exception ignore) {}

        // Setup
        try {
            if (Files.exists(setupCache)) {
                log.info("Loading Groth16 setup from cache...");
                long t = System.currentTimeMillis();
                var s = Groth16SetupCache.loadBls12381Setup(setupCache);
                if (matchesCurrentCircuit(s)) {
                    log.info("Setup loaded from cache in {}ms", System.currentTimeMillis() - t);
                    return s;
                }
                log.warn("Setup cache shape does not match current circuit; regenerating");
            }
        } catch (Exception e) {
            log.warn("Setup cache load failed: {}", e.getMessage());
        }

        var srs = generateDevSrs();
        log.info("Running Groth16 Phase-2 setup (power={})...", potPower);
        var s = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                r1cs.numPublicInputs(), srs.tauScalar());
        try { Groth16SetupCache.saveBls12381Setup(s, setupCache); log.info("Cached setup → {}", setupCache); }
        catch (Exception e) { log.warn("Setup cache save failed: {}", e.getMessage()); }
        return s;
    }

    private boolean matchesCurrentCircuit(Groth16SetupBLS381.SetupResult setup) {
        var pk = setup.provingKey();
        return pk.numPublic() == r1cs.numPublicInputs()
                && pk.pointsA().length == r1cs.numWires();
    }

    private com.bloxbean.cardano.zeroj.crypto.plonk.PtauImporterBLS381.SRS generateDevSrs() {
        log.info("Running in-memory dev Powers of Tau (power={})...", potPower);
        return PowersOfTauBLS381.generate(potPower);
    }

    /**
     * Generates the airdrop proof for one claim.
     *
     * @param issuerPk    Jubjub public key of the personhood issuer
     * @param sig         issuer signature on Poseidon(personhoodId, 0)
     * @param personhoodId secret personhood identifier
     * @param epoch       current epoch (binds proof + nullifier to time period)
     * @param recipient   Cardano recipient identifier (low 254 bits of pkh)
     * @return proof + computed nullifier
     */
    public ClaimProof prove(JubjubPoint issuerPk, EdDSAJubjub.Signature sig,
                            BigInteger personhoodId, BigInteger epoch, BigInteger recipient) {
        BigInteger msg = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE,
                personhoodId, BigInteger.ZERO);
        var kReduction = InCircuitEdDSAJubjub.witnessComputeKReduction(sig.r(), issuerPk, msg);
        BigInteger nullifier = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE,
                personhoodId, epoch);

        Map<String, List<BigInteger>> inputs = new HashMap<>();
        inputs.put("pkU", List.of(issuerPk.affineU()));
        inputs.put("pkV", List.of(issuerPk.affineV()));
        inputs.put("epoch", List.of(epoch));
        inputs.put("nullifier", List.of(nullifier));
        inputs.put("recipient", List.of(recipient));
        inputs.put("eligible", List.of(BigInteger.ONE));
        inputs.put("personhoodId", List.of(personhoodId));
        inputs.put("sigRU", List.of(sig.r().affineU()));
        inputs.put("sigRV", List.of(sig.r().affineV()));
        inputs.put("sigS", List.of(sig.s()));
        inputs.put("kModL", List.of(kReduction.kModL()));
        inputs.put("kQuotient", List.of(kReduction.kQuotient()));

        BigInteger[] witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);
        var proof = Groth16ProverBLS381.prove(setupResult.provingKey(), witness,
                constraints, r1cs.numWires());

        return new ClaimProof(proof, nullifier);
    }

    public Groth16SetupBLS381.SetupResult getSetupResult() {
        return setupResult;
    }

    public R1CSConstraintSystem getR1cs() {
        return r1cs;
    }

    /** Bundle of the Groth16 proof and the nullifier it commits to. */
    public record ClaimProof(Groth16ProofBLS381 proof, BigInteger nullifier) {}
}
