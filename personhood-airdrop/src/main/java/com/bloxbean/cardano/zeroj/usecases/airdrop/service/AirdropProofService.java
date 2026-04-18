package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitEdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubPoint;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Prover;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.SetupCache;
import java.nio.file.Files;
import java.nio.file.Path;
import com.bloxbean.cardano.zeroj.usecases.airdrop.circuit.PersonhoodAirdropCircuit;
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
    private Groth16Prover.R1CSConstraint[] constraints;
    private Groth16SetupBLS381.SetupResult setupResult;

    @PostConstruct
    public void init() {
        log.info("Compiling airdrop circuit...");
        circuit = PersonhoodAirdropCircuit.build();
        r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        log.info("Circuit compiled: {} constraints, {} wires, {} public inputs",
                r1cs.numConstraints(), r1cs.numWires(), r1cs.numPublicInputs());

        constraints = r1cs.constraints().stream()
                .map(c -> new Groth16Prover.R1CSConstraint(c.a(), c.b(), c.c()))
                .toArray(Groth16Prover.R1CSConstraint[]::new);

        setupResult = loadOrRunSetup();
        log.info("Trusted setup ready. Faucet can accept claims.");
    }

    private Groth16SetupBLS381.SetupResult loadOrRunSetup() {
        Path cacheDir = Path.of("./data");
        Path srsCache = cacheDir.resolve("srs.bin");
        Path setupCache = cacheDir.resolve("setup-airdrop.bin");
        try { Files.createDirectories(cacheDir); } catch (Exception ignore) {}

        // Setup
        try {
            if (Files.exists(setupCache)) {
                log.info("Loading Groth16 setup from cache...");
                long t = System.currentTimeMillis();
                var s = SetupCache.loadSetup(setupCache);
                log.info("Setup loaded from cache in {}ms", System.currentTimeMillis() - t);
                return s;
            }
        } catch (Exception e) {
            log.warn("Setup cache load failed: {}", e.getMessage());
        }

        var srs = loadOrGenerateSrs(srsCache);
        log.info("Running Groth16 Phase-2 setup (power={})...", potPower);
        var s = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                r1cs.numPublicInputs(), srs.tauScalar());
        try { SetupCache.saveSetup(s, setupCache); log.info("Cached setup → {}", setupCache); }
        catch (Exception e) { log.warn("Setup cache save failed: {}", e.getMessage()); }
        return s;
    }

    private com.bloxbean.cardano.zeroj.crypto.plonk.PtauImporterBLS381.SRS loadOrGenerateSrs(Path srsCache) {
        try {
            if (Files.exists(srsCache)) {
                log.info("Loading SRS from cache...");
                long t = System.currentTimeMillis();
                var srs = SetupCache.loadSrs(srsCache);
                log.info("SRS loaded in {}ms", System.currentTimeMillis() - t);
                return srs;
            }
        } catch (Exception e) {
            log.warn("SRS cache load failed: {}", e.getMessage());
        }
        log.info("Running Powers of Tau (power={})...", potPower);
        var srs = PowersOfTauBLS381.generate(potPower);
        try { SetupCache.saveSrs(srs, srsCache); log.info("Cached SRS"); }
        catch (Exception e) { log.warn("SRS cache save failed: {}", e.getMessage()); }
        return srs;
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
