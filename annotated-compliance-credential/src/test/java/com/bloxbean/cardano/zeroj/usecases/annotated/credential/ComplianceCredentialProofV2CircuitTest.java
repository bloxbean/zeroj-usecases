package com.bloxbean.cardano.zeroj.usecases.annotated.credential;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitEdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.usecases.annotated.credential.circuit.ComplianceCredentialProofV2Circuit;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ComplianceCredentialProofV2CircuitTest {

    private static final PoseidonParams PARAMS = PoseidonParamsBLS12_381T3.INSTANCE;

    /** Deterministic trusted-issuer secret (mirrors IssuerService's seed-mod-l pattern). */
    private static final BigInteger ISSUER_SECRET = new BigInteger(
            "deadbeefcafef00d1234567890abcdefdeadbeefcafef00d1234567890abcdef", 16);
    /** A different keypair: an attacker who is NOT the trusted issuer. */
    private static final BigInteger ATTACKER_SECRET = new BigInteger(
            "0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de", 16);

    private static final BigInteger MIN_AGE = BigInteger.valueOf(18);
    private static final BigInteger REQUIRED_COUNTRY = BigInteger.valueOf(840); // US

    @Test
    void validIssuerSignedCredentialPasses() {
        var fixture = issuerSigned(ISSUER_SECRET, 21, 840, BigInteger.ONE);
        var circuit = ComplianceCredentialProofV2Circuit.build();

        assertDoesNotThrow(() -> ComplianceCredentialProofV2Circuit.calculateWitness(
                circuit, fixture.inputs(), CurveId.BLS12_381));

        // Public inputs in @Prove declaration order: pkU, pkV, minimumAge, requiredCountryCode.
        assertEquals(
                List.of(fixture.pkU(), fixture.pkV(), MIN_AGE, REQUIRED_COUNTRY),
                ComplianceCredentialProofV2Circuit.publicInputs(fixture.inputs()));
    }

    @Test
    void forgedCredentialFromUntrustedKeyFails() {
        // The core fix: an attacker fabricates a fully-compliant credential and signs it with
        // THEIR OWN key, but the verifier pins the real issuer's public key. The in-circuit
        // EdDSA check fails -> no valid witness. (This is the attack v1 could not stop.)
        var forged = forgedAgainstIssuer(ATTACKER_SECRET, ISSUER_SECRET, 99, 840, BigInteger.ONE);
        var circuit = ComplianceCredentialProofV2Circuit.build();

        assertThrows(ArithmeticException.class, () ->
                ComplianceCredentialProofV2Circuit.calculateWitness(circuit, forged, CurveId.BLS12_381));
    }

    @Test
    void tamperedAttributeBreaksSignatureBinding() {
        // Issuer signs an UNDERAGE credential (age 17). Holder submits age 21 to pass the
        // predicate but reuses the signature over 17 -> the in-circuit claimsMsg no longer
        // matches what was signed -> EdDSA verification fails.
        var tampered = tamperedAge(ISSUER_SECRET, /*signedAge*/ 17, /*claimedAge*/ 21, 840, BigInteger.ONE);
        var circuit = ComplianceCredentialProofV2Circuit.build();

        assertThrows(ArithmeticException.class, () ->
                ComplianceCredentialProofV2Circuit.calculateWitness(circuit, tampered, CurveId.BLS12_381));
    }

    @Test
    void underAgeSignedCredentialFails() {
        // Genuinely issuer-signed but age 17 < minimumAge 18 -> predicate false -> assertTrue fails.
        var fixture = issuerSigned(ISSUER_SECRET, 17, 840, BigInteger.ONE);
        var circuit = ComplianceCredentialProofV2Circuit.build();

        assertThrows(ArithmeticException.class, () ->
                ComplianceCredentialProofV2Circuit.calculateWitness(circuit, fixture.inputs(), CurveId.BLS12_381));
    }

    @Test
    void wrongCountrySignedCredentialFails() {
        // Genuinely signed for country 124 (CA) but the verifier requires 840 (US).
        var fixture = issuerSigned(ISSUER_SECRET, 21, 124, BigInteger.ONE);
        var circuit = ComplianceCredentialProofV2Circuit.build();

        assertThrows(ArithmeticException.class, () ->
                ComplianceCredentialProofV2Circuit.calculateWitness(circuit, fixture.inputs(), CurveId.BLS12_381));
    }

    @Test
    void sanctionedSignedCredentialFails() {
        // Genuinely signed but notSanctioned == 0 -> predicate false.
        var fixture = issuerSigned(ISSUER_SECRET, 21, 840, BigInteger.ZERO);
        var circuit = ComplianceCredentialProofV2Circuit.build();

        assertThrows(ArithmeticException.class, () ->
                ComplianceCredentialProofV2Circuit.calculateWitness(circuit, fixture.inputs(), CurveId.BLS12_381));
    }

    @Test
    void bn254CompilationFailsBecauseCircuitUsesBlsPoseidon() {
        var fixture = issuerSigned(ISSUER_SECRET, 21, 840, BigInteger.ONE);
        var circuit = ComplianceCredentialProofV2Circuit.build();

        assertThrows(IllegalStateException.class, () ->
                ComplianceCredentialProofV2Circuit.calculateWitness(circuit, fixture.inputs(), CurveId.BN254));
    }

    // --- Fixtures ---------------------------------------------------------------------------

    /** A correctly issuer-signed credential over the given attributes. */
    private static Fixture issuerSigned(BigInteger issuerSecret, long age, long country, BigInteger notSanctioned) {
        var sk = issuerSecret.mod(JubjubCurve.SUBGROUP_ORDER);
        var issuer = EdDSAJubjub.keypairFromSecret(sk);

        var ageBig = BigInteger.valueOf(age);
        var countryBig = BigInteger.valueOf(country);
        var claimsMsg = PoseidonHash.hashN(PARAMS, ageBig, countryBig, notSanctioned);

        var sig = EdDSAJubjub.sign(sk, claimsMsg);
        var k = InCircuitEdDSAJubjub.witnessComputeKReduction(sig.r(), issuer.pk(), claimsMsg);

        var pkU = issuer.pk().affineU();
        var pkV = issuer.pk().affineV();

        var inputs = ComplianceCredentialProofV2Circuit.inputs()
                .pkU(pkU)
                .pkV(pkV)
                .minimumAge(MIN_AGE)
                .requiredCountryCode(REQUIRED_COUNTRY)
                .age(ageBig)
                .countryCode(countryBig)
                .notSanctioned(notSanctioned)
                .sigRU(sig.r().affineU())
                .sigRV(sig.r().affineV())
                .sigS(sig.s())
                .kModL(k.kModL())
                .kQuotient(k.kQuotient());

        return new Fixture(inputs, pkU, pkV);
    }

    /** Attacker-signed compliant claims, but verified against the real issuer's pinned key. */
    private static ComplianceCredentialProofV2Circuit.Inputs forgedAgainstIssuer(
            BigInteger attackerSecret, BigInteger realIssuerSecret,
            long age, long country, BigInteger notSanctioned) {
        var attackerSk = attackerSecret.mod(JubjubCurve.SUBGROUP_ORDER);
        var realIssuer = EdDSAJubjub.keypairFromSecret(realIssuerSecret.mod(JubjubCurve.SUBGROUP_ORDER));

        var ageBig = BigInteger.valueOf(age);
        var countryBig = BigInteger.valueOf(country);
        var claimsMsg = PoseidonHash.hashN(PARAMS, ageBig, countryBig, notSanctioned);

        // Signed with the attacker's key...
        var sig = EdDSAJubjub.sign(attackerSk, claimsMsg);
        // ...but the pinned public key and the challenge reduction use the REAL issuer key.
        var k = InCircuitEdDSAJubjub.witnessComputeKReduction(sig.r(), realIssuer.pk(), claimsMsg);

        return ComplianceCredentialProofV2Circuit.inputs()
                .pkU(realIssuer.pk().affineU())
                .pkV(realIssuer.pk().affineV())
                .minimumAge(MIN_AGE)
                .requiredCountryCode(REQUIRED_COUNTRY)
                .age(ageBig)
                .countryCode(countryBig)
                .notSanctioned(notSanctioned)
                .sigRU(sig.r().affineU())
                .sigRV(sig.r().affineV())
                .sigS(sig.s())
                .kModL(k.kModL())
                .kQuotient(k.kQuotient());
    }

    /** Issuer signs {@code signedAge}, but the witness submits a different {@code claimedAge}. */
    private static ComplianceCredentialProofV2Circuit.Inputs tamperedAge(
            BigInteger issuerSecret, long signedAge, long claimedAge, long country, BigInteger notSanctioned) {
        var sk = issuerSecret.mod(JubjubCurve.SUBGROUP_ORDER);
        var issuer = EdDSAJubjub.keypairFromSecret(sk);

        var countryBig = BigInteger.valueOf(country);
        var signedMsg = PoseidonHash.hashN(PARAMS, BigInteger.valueOf(signedAge), countryBig, notSanctioned);
        var sig = EdDSAJubjub.sign(sk, signedMsg);
        // Reduction computed over the genuinely-signed message; the circuit will recompute the
        // challenge from the tampered (claimed) age and the equation will not hold.
        var k = InCircuitEdDSAJubjub.witnessComputeKReduction(sig.r(), issuer.pk(), signedMsg);

        return ComplianceCredentialProofV2Circuit.inputs()
                .pkU(issuer.pk().affineU())
                .pkV(issuer.pk().affineV())
                .minimumAge(MIN_AGE)
                .requiredCountryCode(REQUIRED_COUNTRY)
                .age(BigInteger.valueOf(claimedAge))
                .countryCode(countryBig)
                .notSanctioned(notSanctioned)
                .sigRU(sig.r().affineU())
                .sigRV(sig.r().affineV())
                .sigS(sig.s())
                .kModL(k.kModL())
                .kQuotient(k.kQuotient());
    }

    private record Fixture(
            ComplianceCredentialProofV2Circuit.Inputs inputs,
            BigInteger pkU,
            BigInteger pkV) {
    }
}
