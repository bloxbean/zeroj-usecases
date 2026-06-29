package com.bloxbean.cardano.zeroj.usecases.plonk.credential;

import com.bloxbean.cardano.zeroj.usecases.plonk.credential.circuit.ComplianceCredentialGateProofCircuit;

import java.math.BigInteger;

/**
 * Deterministic sample data for the PlonK compliance credential demo.
 */
public final class SampleComplianceCredential {
    private SampleComplianceCredential() {
    }

    public static Fixture validFixture() {
        var age = BigInteger.valueOf(29);
        var minimumAge = BigInteger.valueOf(18);
        var ageSurplus = BigInteger.valueOf(11);
        var jurisdiction = BigInteger.ONE;
        var requiredJurisdiction = BigInteger.ONE;
        var notSanctioned = BigInteger.ONE;
        var credentialSalt = BigInteger.valueOf(555_777);
        var credentialCommitment = credentialCommitment(age, jurisdiction, notSanctioned, credentialSalt);

        var inputs = ComplianceCredentialGateProofCircuit.inputs()
                .credentialCommitment(credentialCommitment)
                .minimumAge(minimumAge)
                .requiredJurisdiction(requiredJurisdiction)
                .age(age)
                .ageSurplus(ageSurplus)
                .jurisdiction(jurisdiction)
                .notSanctioned(notSanctioned)
                .credentialSalt(credentialSalt);
        return new Fixture(
                inputs,
                credentialCommitment,
                minimumAge,
                requiredJurisdiction,
                age,
                ageSurplus,
                jurisdiction,
                notSanctioned,
                credentialSalt);
    }

    public static BigInteger credentialCommitment(
            BigInteger age,
            BigInteger jurisdiction,
            BigInteger notSanctioned,
            BigInteger credentialSalt) {
        return age.multiply(BigInteger.valueOf(17))
                .add(jurisdiction.multiply(BigInteger.valueOf(19)))
                .add(notSanctioned.multiply(BigInteger.valueOf(23)))
                .add(credentialSalt.multiply(BigInteger.valueOf(29)));
    }

    public record Fixture(
            ComplianceCredentialGateProofCircuit.Inputs inputs,
            BigInteger credentialCommitment,
            BigInteger minimumAge,
            BigInteger requiredJurisdiction,
            BigInteger age,
            BigInteger ageSurplus,
            BigInteger jurisdiction,
            BigInteger notSanctioned,
            BigInteger credentialSalt) {
    }
}
