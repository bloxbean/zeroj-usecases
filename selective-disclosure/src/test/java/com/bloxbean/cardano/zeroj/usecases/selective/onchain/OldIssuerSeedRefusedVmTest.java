package com.bloxbean.cardano.zeroj.usecases.selective.onchain;

import com.bloxbean.cardano.zeroj.usecases.selective.circuit.CredentialSchema;
import com.bloxbean.cardano.zeroj.usecases.selective.service.PredicateProofService;
import com.bloxbean.cardano.zeroj.usecases.selective.service.RichCredentialIssuerService;
import com.bloxbean.cardano.zeroj.usecases.selective.service.RichCredentialIssuerService.RichCredential;
import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.testkit.ContractTest;
import org.julclang.testkit.TestDataBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;
import org.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubMessage;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.crypto.setup.Groth16SetupBLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0009 D11 in the Julc VM: a credential signed with the issuer seed that earlier versions
 * published is refused by both predicate validators, which pin the demo's random issuer key. The
 * refused proofs are genuine, valid Groth16 proofs: each circuit accepts any issuer key as a public
 * input, so only the validator's issuer parameter stops them.
 */
class OldIssuerSeedRefusedVmTest extends ContractTest {

    /** The seed earlier versions published in {@code RichCredentialIssuerService}. */
    private static final BigInteger OLD_PUBLISHED_SEED = new BigInteger(
            "feedfacecafebeef1234567890abcdef0fedcba9876543210feedface00112233", 16);
    private static final int CURRENT_YEAR = 2026;

    @TempDir
    static Path dataDir;

    private static PredicateProofService proofs;
    private static RichCredentialIssuerService issuer;
    private static EdDSAJubjub.Keypair old;
    private static Program adultProgram;
    private static Program doctorProgram;

    @BeforeAll
    static void deploy() {
        issuer = new RichCredentialIssuerService();
        ReflectionTestUtils.setField(issuer, "dataDir", dataDir.toString());
        issuer.setup();

        proofs = new PredicateProofService();
        ReflectionTestUtils.setField(proofs, "potPower", 14);
        ReflectionTestUtils.setField(proofs, "currentYear", CURRENT_YEAR);
        ReflectionTestUtils.setField(proofs, "dataDir", dataDir.toString());
        proofs.init();

        old = EdDSAJubjub.keypairFromSecret(OLD_PUBLISHED_SEED.mod(JubjubCurve.SUBGROUP_ORDER));
        assertNotEquals(old.pk().affineU(), issuer.issuerPk().affineU());

        JubjubPoint pk = issuer.issuerPk();
        adultProgram = new OldIssuerSeedRefusedVmTest().compileValidator(AdultResidentValidator.class).program()
                .applyParams(vkParams(proofs.adultResident().setup(), PlutusData.integer(pk.affineU()),
                        PlutusData.integer(pk.affineV()), PlutusData.integer(BigInteger.valueOf(CURRENT_YEAR)),
                        PlutusData.integer(issuer.countryRoot())));
        doctorProgram = new OldIssuerSeedRefusedVmTest().compileValidator(SeniorDoctorValidator.class).program()
                .applyParams(vkParams(proofs.seniorDoctor().setup(), PlutusData.integer(pk.affineU()),
                        PlutusData.integer(pk.affineV()), PlutusData.integer(BigInteger.valueOf(CURRENT_YEAR))));
    }

    @Test
    void adultResidentGateAcceptsTheDeployedKeyAndRefusesTheOldSeed() {
        RichCredential alice = issuer.get("Alice");
        assertSuccess(evaluate(adultProgram, adultCtx(adultProof(issuer.issuerPk(), alice), issuer.issuerPk())));

        RichCredential forged = forge("Alice", 1995, 840, CredentialSchema.Roles.ENGINEER, 5);
        Groth16ProofBLS381 proof = adultProof(old.pk(), forged);
        assertFailure(evaluate(adultProgram, adultCtx(proof, old.pk())));
        assertFailure(evaluate(adultProgram, adultCtx(proof, issuer.issuerPk())));
    }

    @Test
    void seniorDoctorGateAcceptsTheDeployedKeyAndRefusesTheOldSeed() {
        RichCredential bob = issuer.get("Bob");
        assertSuccess(evaluate(doctorProgram, doctorCtx(doctorProof(issuer.issuerPk(), bob), issuer.issuerPk())));

        RichCredential forged = forge("Mallory", 1970, 250, CredentialSchema.Roles.DOCTOR, 9);
        Groth16ProofBLS381 proof = doctorProof(old.pk(), forged);
        assertFailure(evaluate(doctorProgram, doctorCtx(proof, old.pk())));
        assertFailure(evaluate(doctorProgram, doctorCtx(proof, issuer.issuerPk())));
    }

    /** A credential anyone could have signed before D11, with the published seed. */
    private static RichCredential forge(String name, int dobYear, int country, BigInteger role, int salary) {
        BigInteger nameHash = CredentialSchema.nameHash(name);
        BigInteger msg = CredentialSchema.claimsMessage(BigInteger.valueOf(dobYear), BigInteger.valueOf(country),
                role, BigInteger.valueOf(salary), nameHash);
        EdDSAJubjub.Signature sig = EdDSAJubjub.signCompatibilityOffline(old, canonicalMessage(msg));
        assertTrue(EdDSAJubjub.verify(old.pk(), canonicalMessage(msg), sig));
        return new RichCredential(name, dobYear, country, role, salary, nameHash, sig);
    }

    private static Groth16ProofBLS381 adultProof(JubjubPoint pk, RichCredential cred) {
        var path = issuer.getCountryProof(cred.countryCode());
        var bundle = proofs.proveAdultResident(pk, cred.signature(), cred, issuer.countryRoot(),
                path.siblings(), path.pathBits());
        assertTrue(bundle.eligible());
        return bundle.proof();
    }

    private static Groth16ProofBLS381 doctorProof(JubjubPoint pk, RichCredential cred) {
        var bundle = proofs.proveSeniorDoctor(pk, cred.signature(), cred);
        assertTrue(bundle.eligible());
        return bundle.proof();
    }

    private PlutusData adultCtx(Groth16ProofBLS381 proof, JubjubPoint claimedIssuer) {
        var c = ProverToCardano.compressProof(proof);
        return ctx(PlutusData.constr(0,
                PlutusData.bytes(c.piA()), PlutusData.bytes(c.piB()), PlutusData.bytes(c.piC()),
                PlutusData.bytes(minimal(claimedIssuer.affineU())), PlutusData.bytes(minimal(claimedIssuer.affineV())),
                PlutusData.bytes(minimal(BigInteger.valueOf(CURRENT_YEAR))),
                PlutusData.bytes(minimal(issuer.countryRoot())),
                PlutusData.bytes(minimal(BigInteger.ONE))));
    }

    private PlutusData doctorCtx(Groth16ProofBLS381 proof, JubjubPoint claimedIssuer) {
        var c = ProverToCardano.compressProof(proof);
        return ctx(PlutusData.constr(0,
                PlutusData.bytes(c.piA()), PlutusData.bytes(c.piB()), PlutusData.bytes(c.piC()),
                PlutusData.bytes(minimal(claimedIssuer.affineU())), PlutusData.bytes(minimal(claimedIssuer.affineV())),
                PlutusData.bytes(minimal(BigInteger.valueOf(CURRENT_YEAR))),
                PlutusData.bytes(minimal(BigInteger.ONE))));
    }

    private PlutusData ctx(PlutusData redeemer) {
        return spendingContext(TestDataBuilder.randomTxOutRef_typed(), PlutusData.constr(0))
                .redeemer(redeemer).buildPlutusData();
    }

    private static PlutusData[] vkParams(Groth16SetupBLS381.SetupResult setup, PlutusData... rest) {
        var vk = ProverToCardano.compressVk(setup);
        List<PlutusData> ic = new ArrayList<>();
        for (byte[] point : vk.ic()) ic.add(PlutusData.bytes(point));
        List<PlutusData> params = new ArrayList<>(List.of(PlutusData.bytes(vk.alpha()), PlutusData.bytes(vk.beta()),
                PlutusData.bytes(vk.gamma()), PlutusData.bytes(vk.delta()),
                PlutusData.list(ic.toArray(new PlutusData[0]))));
        params.addAll(List.of(rest));
        return params.toArray(new PlutusData[0]);
    }

    /** As {@code OnChainGateService.toMin}: big-endian, no sign byte. */
    private static byte[] minimal(BigInteger v) {
        byte[] b = v.toByteArray();
        return (b.length > 1 && b[0] == 0) ? Arrays.copyOfRange(b, 1, b.length) : b;
    }

    /** As {@code RichCredentialIssuerService}: the claims field element as a canonical 32-byte message. */
    private static JubjubMessage canonicalMessage(BigInteger fieldElement) {
        byte[] raw = fieldElement.toByteArray();
        int offset = raw.length == JubjubMessage.CANONICAL_BYTES + 1 && raw[0] == 0 ? 1 : 0;
        byte[] canonical = new byte[JubjubMessage.CANONICAL_BYTES];
        System.arraycopy(raw, offset, canonical, canonical.length - (raw.length - offset), raw.length - offset);
        return JubjubMessage.fromCanonicalFieldBytes(canonical);
    }
}
