package com.bloxbean.cardano.zeroj.usecases.selective.service;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitEdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubPoint;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.SetupCache;
import java.nio.file.Files;
import java.nio.file.Path;
import com.bloxbean.cardano.zeroj.usecases.selective.circuit.AdultResidentCircuit;
import com.bloxbean.cardano.zeroj.usecases.selective.circuit.CredentialSchema;
import com.bloxbean.cardano.zeroj.usecases.selective.circuit.SeniorDoctorCircuit;
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
 * Compiles the two predicate circuits (Adult Resident, Senior Doctor) and
 * exposes prove-functions for each. Both circuits share a compiled SRS but
 * each has its own Phase-2 setup result (different vk/pk per circuit).
 */
@Service
public class PredicateProofService {

    private static final Logger log = LoggerFactory.getLogger(PredicateProofService.class);

    @Value("${zk.pot-power}")
    private int potPower;

    @Value("${credential.current-year}")
    private int currentYear;

    private CompiledPredicate adultResident;
    private CompiledPredicate seniorDoctor;

    @PostConstruct
    public void init() {
        log.info("Compiling predicate circuits...");
        var cacheDir = Path.of("./data");
        try { Files.createDirectories(cacheDir); } catch (Exception ignore) {}

        var srs = loadOrGenerateSrs(cacheDir.resolve("srs.bin"));

        adultResident = compile("adult-resident",
                AdultResidentCircuit.build(RichCredentialIssuerService.COUNTRY_TREE_DEPTH),
                srs, cacheDir.resolve("setup-adult.bin"));
        seniorDoctor = compile("senior-doctor", SeniorDoctorCircuit.build(),
                srs, cacheDir.resolve("setup-doctor.bin"));

        log.info("All predicate circuits compiled. Ready for proofs.");
    }

    private com.bloxbean.cardano.zeroj.crypto.plonk.PtauImporterBLS381.SRS loadOrGenerateSrs(Path cache) {
        try {
            if (Files.exists(cache)) {
                log.info("Loading SRS from cache...");
                long t = System.currentTimeMillis();
                var s = SetupCache.loadSrs(cache);
                log.info("SRS loaded in {}ms", System.currentTimeMillis() - t);
                return s;
            }
        } catch (Exception e) { log.warn("SRS cache load failed: {}", e.getMessage()); }
        log.info("Running Powers of Tau (power={})...", potPower);
        var srs = PowersOfTauBLS381.generate(potPower);
        try { SetupCache.saveSrs(srs, cache); log.info("Cached SRS"); } catch (Exception ignore) {}
        return srs;
    }

    private CompiledPredicate compile(String name, CircuitBuilder circuit,
                                      com.bloxbean.cardano.zeroj.crypto.plonk.PtauImporterBLS381.SRS srs,
                                      Path setupCache) {
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        log.info("  {} — {} constraints, {} wires, {} public",
                name, r1cs.numConstraints(), r1cs.numWires(), r1cs.numPublicInputs());
        var constraints = r1cs.constraints();

        Groth16SetupBLS381.SetupResult setup = null;
        try {
            if (Files.exists(setupCache)) {
                long t = System.currentTimeMillis();
                setup = SetupCache.loadSetup(setupCache);
                log.info("  {} — loaded setup from cache in {}ms", name, System.currentTimeMillis() - t);
            }
        } catch (Exception e) { log.warn("  {} — cache load failed: {}", name, e.getMessage()); }

        if (setup == null) {
            log.info("  {} — running Phase-2 setup...", name);
            setup = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                    r1cs.numPublicInputs(), srs.tauScalar());
            try { SetupCache.saveSetup(setup, setupCache); log.info("  {} — cached setup", name); }
            catch (Exception e) { log.warn("  {} — cache save failed: {}", name, e.getMessage()); }
        }
        return new CompiledPredicate(circuit, r1cs, constraints, setup);
    }

    public ProofBundle proveAdultResident(JubjubPoint pk, EdDSAJubjub.Signature sig,
                                           RichCredentialIssuerService.RichCredential cred,
                                           BigInteger countryRoot,
                                           BigInteger[] siblings, BigInteger[] pathBits) {
        BigInteger dob = BigInteger.valueOf(cred.dobYear());
        BigInteger ctry = BigInteger.valueOf(cred.countryCode());
        BigInteger sal = BigInteger.valueOf(cred.salaryBracket());
        BigInteger msg = CredentialSchema.claimsMessage(dob, ctry, cred.roleId(), sal, cred.nameHash());
        var kRed = InCircuitEdDSAJubjub.witnessComputeKReduction(sig.r(), pk, msg);

        BigInteger eligible = (currentYear - cred.dobYear()) >= AdultResidentCircuit.MIN_AGE
                ? BigInteger.ONE : BigInteger.ZERO;

        Map<String, List<BigInteger>> inputs = new HashMap<>();
        inputs.put("pkU", List.of(pk.affineU()));
        inputs.put("pkV", List.of(pk.affineV()));
        inputs.put("currentYear", List.of(BigInteger.valueOf(currentYear)));
        inputs.put("countryRoot", List.of(countryRoot));
        inputs.put("eligible", List.of(eligible));
        inputs.put("dobYear", List.of(dob));
        inputs.put("country", List.of(ctry));
        inputs.put("roleId", List.of(cred.roleId()));
        inputs.put("salaryBracket", List.of(sal));
        inputs.put("nameHash", List.of(cred.nameHash()));
        inputs.put("sigRU", List.of(sig.r().affineU()));
        inputs.put("sigRV", List.of(sig.r().affineV()));
        inputs.put("sigS", List.of(sig.s()));
        inputs.put("kModL", List.of(kRed.kModL()));
        inputs.put("kQuotient", List.of(kRed.kQuotient()));
        for (int i = 0; i < RichCredentialIssuerService.COUNTRY_TREE_DEPTH; i++) {
            inputs.put("sibling_" + i, List.of(siblings[i]));
            inputs.put("pathBit_" + i, List.of(pathBits[i]));
        }

        BigInteger[] witness = adultResident.circuit.calculateWitness(inputs, CurveId.BLS12_381);
        var proof = Groth16ProverBLS381.prove(adultResident.setup.provingKey(), witness,
                adultResident.constraints, adultResident.r1cs.numWires());
        return new ProofBundle(proof, eligible.equals(BigInteger.ONE));
    }

    public ProofBundle proveSeniorDoctor(JubjubPoint pk, EdDSAJubjub.Signature sig,
                                          RichCredentialIssuerService.RichCredential cred) {
        BigInteger dob = BigInteger.valueOf(cred.dobYear());
        BigInteger ctry = BigInteger.valueOf(cred.countryCode());
        BigInteger sal = BigInteger.valueOf(cred.salaryBracket());
        BigInteger msg = CredentialSchema.claimsMessage(dob, ctry, cred.roleId(), sal, cred.nameHash());
        var kRed = InCircuitEdDSAJubjub.witnessComputeKReduction(sig.r(), pk, msg);

        BigInteger eligible = (cred.roleId().equals(CredentialSchema.Roles.DOCTOR)
                && (currentYear - cred.dobYear()) >= SeniorDoctorCircuit.MIN_AGE)
                ? BigInteger.ONE : BigInteger.ZERO;

        Map<String, List<BigInteger>> inputs = new HashMap<>();
        inputs.put("pkU", List.of(pk.affineU()));
        inputs.put("pkV", List.of(pk.affineV()));
        inputs.put("currentYear", List.of(BigInteger.valueOf(currentYear)));
        inputs.put("eligible", List.of(eligible));
        inputs.put("dobYear", List.of(dob));
        inputs.put("country", List.of(ctry));
        inputs.put("roleId", List.of(cred.roleId()));
        inputs.put("salaryBracket", List.of(sal));
        inputs.put("nameHash", List.of(cred.nameHash()));
        inputs.put("sigRU", List.of(sig.r().affineU()));
        inputs.put("sigRV", List.of(sig.r().affineV()));
        inputs.put("sigS", List.of(sig.s()));
        inputs.put("kModL", List.of(kRed.kModL()));
        inputs.put("kQuotient", List.of(kRed.kQuotient()));

        BigInteger[] witness = seniorDoctor.circuit.calculateWitness(inputs, CurveId.BLS12_381);
        var proof = Groth16ProverBLS381.prove(seniorDoctor.setup.provingKey(), witness,
                seniorDoctor.constraints, seniorDoctor.r1cs.numWires());
        return new ProofBundle(proof, eligible.equals(BigInteger.ONE));
    }

    public CompiledPredicate adultResident() { return adultResident; }
    public CompiledPredicate seniorDoctor()  { return seniorDoctor; }
    public int currentYear() { return currentYear; }

    public record CompiledPredicate(CircuitBuilder circuit, R1CSConstraintSystem r1cs,
                                    List<R1CSConstraint> constraints,
                                    Groth16SetupBLS381.SetupResult  setup) {}

    public record ProofBundle(Groth16ProofBLS381 proof, boolean eligible) {}
}
