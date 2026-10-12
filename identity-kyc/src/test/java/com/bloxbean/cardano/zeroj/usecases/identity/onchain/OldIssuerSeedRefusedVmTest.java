package com.bloxbean.cardano.zeroj.usecases.identity.onchain;

import com.bloxbean.cardano.zeroj.usecases.identity.service.CredentialService;
import com.bloxbean.cardano.zeroj.usecases.identity.service.IssuerService;
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
 * published is refused by {@link CredentialGatedValidator}, which pins the demo's random issuer key.
 * The refused proof is a genuine, valid Groth16 proof: the circuit accepts any issuer key as a public
 * input, so only the validator's issuer parameter stops it.
 */
class OldIssuerSeedRefusedVmTest extends ContractTest {

    /** The seed earlier versions published in {@code IssuerService}. */
    private static final BigInteger OLD_PUBLISHED_SEED = new BigInteger(
            "deadbeefcafef00d1234567890abcdefdeadbeefcafef00d1234567890abcdef", 16);

    @TempDir
    static Path dataDir;

    private static CredentialService credentials;
    private static IssuerService issuer;
    private static Program program;

    @BeforeAll
    static void deploy() {
        credentials = new CredentialService();
        ReflectionTestUtils.setField(credentials, "countryTreeDepth", 4);
        ReflectionTestUtils.setField(credentials, "potPower", 14);
        credentials.init();

        issuer = new IssuerService(credentials);
        ReflectionTestUtils.setField(issuer, "countryTreeDepth", 4);
        ReflectionTestUtils.setField(issuer, "minAge", 18);
        ReflectionTestUtils.setField(issuer, "dataDir", dataDir.toString());
        issuer.setup();

        var vk = ProverToCardano.compressVk(credentials.getSetupResult());
        List<PlutusData> ic = new ArrayList<>();
        for (byte[] point : vk.ic()) ic.add(PlutusData.bytes(point));
        JubjubPoint pk = issuer.getIssuerPublicKey();
        program = new OldIssuerSeedRefusedVmTest().compileValidator(CredentialGatedValidator.class).program()
                .applyParams(PlutusData.bytes(vk.alpha()), PlutusData.bytes(vk.beta()),
                        PlutusData.bytes(vk.gamma()), PlutusData.bytes(vk.delta()),
                        PlutusData.list(ic.toArray(new PlutusData[0])),
                        PlutusData.integer(pk.affineU()), PlutusData.integer(pk.affineV()),
                        PlutusData.integer(BigInteger.valueOf(issuer.getMinAge())),
                        PlutusData.integer(issuer.getCountryRoot()));
    }

    @Test
    void credentialFromTheDeployedRandomKeyIsAccepted() {
        var alice = issuer.getUser("Alice");
        var proof = prove(issuer.getIssuerPublicKey(), alice.signature(), alice.age(), alice.countryCode());
        assertSuccess(evaluate(program, ctx(proof, issuer.getIssuerPublicKey())));
    }

    @Test
    void credentialSignedWithTheOldPublishedSeedIsRefused() {
        EdDSAJubjub.Keypair old = EdDSAJubjub.keypairFromSecret(OLD_PUBLISHED_SEED.mod(JubjubCurve.SUBGROUP_ORDER));
        assertNotEquals(old.pk().affineU(), issuer.getIssuerPublicKey().affineU());
        // Anyone could have forged this credential for an eligible holder before D11.
        BigInteger claims = credentials.computePoseidon(BigInteger.valueOf(30), BigInteger.valueOf(840));
        EdDSAJubjub.Signature forged = EdDSAJubjub.signCompatibilityOffline(old, canonicalMessage(claims));
        assertTrue(EdDSAJubjub.verify(old.pk(), canonicalMessage(claims), forged));

        var proof = prove(old.pk(), forged, 30, 840);
        // Honest public inputs (the old key): the issuer parameter refuses it.
        assertFailure(evaluate(program, ctx(proof, old.pk())));
        // Relabelled as the deployed key: the proof no longer verifies.
        assertFailure(evaluate(program, ctx(proof, issuer.getIssuerPublicKey())));
    }

    private static Groth16ProofBLS381 prove(JubjubPoint pk, EdDSAJubjub.Signature sig, int age, int country) {
        var path = issuer.getCountryProof(country);
        return credentials.prove(pk, sig, BigInteger.valueOf(age), BigInteger.valueOf(country),
                BigInteger.valueOf(issuer.getMinAge()), issuer.getCountryRoot(),
                path.siblings(), path.pathBits()).proof();
    }

    private PlutusData ctx(Groth16ProofBLS381 proof, JubjubPoint claimedIssuer) {
        var c = ProverToCardano.compressProof(proof);
        var redeemer = PlutusData.constr(0,
                PlutusData.bytes(c.piA()), PlutusData.bytes(c.piB()), PlutusData.bytes(c.piC()),
                PlutusData.bytes(minimal(claimedIssuer.affineU())), PlutusData.bytes(minimal(claimedIssuer.affineV())),
                PlutusData.bytes(minimal(BigInteger.valueOf(issuer.getMinAge()))),
                PlutusData.bytes(minimal(issuer.getCountryRoot())),
                PlutusData.bytes(minimal(BigInteger.ONE)));
        return spendingContext(TestDataBuilder.randomTxOutRef_typed(), PlutusData.constr(0))
                .redeemer(redeemer).buildPlutusData();
    }

    /** As {@code OnChainCredentialService.toMinimalBytes}: big-endian, no sign byte. */
    private static byte[] minimal(BigInteger v) {
        byte[] b = v.toByteArray();
        return (b.length > 1 && b[0] == 0) ? Arrays.copyOfRange(b, 1, b.length) : b;
    }

    /** As {@code IssuerService}: the claims field element as a canonical 32-byte message. */
    private static JubjubMessage canonicalMessage(BigInteger fieldElement) {
        byte[] raw = fieldElement.toByteArray();
        int offset = raw.length == JubjubMessage.CANONICAL_BYTES + 1 && raw[0] == 0 ? 1 : 0;
        byte[] canonical = new byte[JubjubMessage.CANONICAL_BYTES];
        System.arraycopy(raw, offset, canonical, canonical.length - (raw.length - offset), raw.length - offset);
        return JubjubMessage.fromCanonicalFieldBytes(canonical);
    }
}
