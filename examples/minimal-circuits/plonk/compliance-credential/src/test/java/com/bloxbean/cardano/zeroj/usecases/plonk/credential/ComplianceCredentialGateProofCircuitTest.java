package com.bloxbean.cardano.zeroj.usecases.plonk.credential;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.usecases.plonk.credential.circuit.ComplianceCredentialGateProofCircuit;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ComplianceCredentialGateProofCircuitTest {
    @Test
    void validCredentialWitnessPasses() {
        var fixture = SampleComplianceCredential.validFixture();
        var circuit = ComplianceCredentialGateProofCircuit.build();

        assertDoesNotThrow(() -> ComplianceCredentialGateProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BLS12_381));
        assertEquals(
                List.of(fixture.credentialCommitment(), fixture.minimumAge(), fixture.requiredJurisdiction()),
                ComplianceCredentialGateProofCircuit.publicInputs(fixture.inputs()));
    }

    @Test
    void underAgeCredentialFailsEvenWithMatchingCommitment() {
        var fixture = fixture(
                BigInteger.valueOf(17),
                BigInteger.valueOf(18),
                BigInteger.ZERO,
                BigInteger.ONE,
                BigInteger.ONE);
        var circuit = ComplianceCredentialGateProofCircuit.build();

        assertThrows(ArithmeticException.class,
                () -> ComplianceCredentialGateProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BLS12_381));
    }

    @Test
    void sanctionedCredentialFailsEvenWithMatchingCommitment() {
        var fixture = fixture(
                BigInteger.valueOf(29),
                BigInteger.valueOf(18),
                BigInteger.valueOf(11),
                BigInteger.ONE,
                BigInteger.ZERO);
        var circuit = ComplianceCredentialGateProofCircuit.build();

        assertThrows(ArithmeticException.class,
                () -> ComplianceCredentialGateProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BLS12_381));
    }

    @Test
    void wrongJurisdictionFailsEvenWithMatchingCommitment() {
        var fixture = fixture(
                BigInteger.valueOf(29),
                BigInteger.valueOf(18),
                BigInteger.valueOf(11),
                BigInteger.TWO,
                BigInteger.ONE);
        var circuit = ComplianceCredentialGateProofCircuit.build();

        assertThrows(ArithmeticException.class,
                () -> ComplianceCredentialGateProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BLS12_381));
    }

    private static SampleComplianceCredential.Fixture fixture(
            BigInteger age,
            BigInteger minimumAge,
            BigInteger ageSurplus,
            BigInteger jurisdiction,
            BigInteger notSanctioned) {
        var requiredJurisdiction = BigInteger.ONE;
        var credentialSalt = BigInteger.valueOf(555_777);
        var credentialCommitment = SampleComplianceCredential.credentialCommitment(
                age,
                jurisdiction,
                notSanctioned,
                credentialSalt);

        var inputs = ComplianceCredentialGateProofCircuit.inputs()
                .credentialCommitment(credentialCommitment)
                .minimumAge(minimumAge)
                .requiredJurisdiction(requiredJurisdiction)
                .age(age)
                .ageSurplus(ageSurplus)
                .jurisdiction(jurisdiction)
                .notSanctioned(notSanctioned)
                .credentialSalt(credentialSalt);
        return new SampleComplianceCredential.Fixture(
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
}
