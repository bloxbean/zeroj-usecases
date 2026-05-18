package com.bloxbean.cardano.zeroj.usecases.annotated.credential;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.usecases.annotated.credential.circuit.ComplianceCredentialProofCircuit;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ComplianceCredentialProofCircuitTest {
    @Test
    void validCredentialWitnessPasses() {
        var fixture = fixture(BigInteger.valueOf(21), BigInteger.ONE);
        var circuit = ComplianceCredentialProofCircuit.build();

        assertDoesNotThrow(() -> ComplianceCredentialProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BLS12_381));
        assertEquals(
                List.of(fixture.minimumAge(), fixture.requiredCountryCode(), fixture.credentialCommitment()),
                ComplianceCredentialProofCircuit.publicInputs(fixture.inputs()));
    }

    @Test
    void bn254CompilationFailsBecauseCircuitUsesBlsPoseidon() {
        var fixture = fixture(BigInteger.valueOf(21), BigInteger.ONE);
        var circuit = ComplianceCredentialProofCircuit.build();

        assertThrows(IllegalStateException.class,
                () -> ComplianceCredentialProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BN254));
    }

    @Test
    void underAgeCredentialFailsEvenWithMatchingCommitment() {
        var fixture = fixture(BigInteger.valueOf(17), BigInteger.ONE);
        var circuit = ComplianceCredentialProofCircuit.build();

        assertThrows(ArithmeticException.class,
                () -> ComplianceCredentialProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BLS12_381));
    }

    @Test
    void sanctionedCredentialFailsEvenWithMatchingCommitment() {
        var fixture = fixture(BigInteger.valueOf(21), BigInteger.ZERO);
        var circuit = ComplianceCredentialProofCircuit.build();

        assertThrows(ArithmeticException.class,
                () -> ComplianceCredentialProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BLS12_381));
    }

    private static Fixture fixture(BigInteger age, BigInteger notSanctioned) {
        var countryCode = BigInteger.valueOf(840);
        var salt = BigInteger.valueOf(555_777);
        var minimumAge = BigInteger.valueOf(18);
        var requiredCountry = BigInteger.valueOf(840);
        var commitment = PoseidonHash.hashN(
                PoseidonParamsBLS12_381T3.INSTANCE,
                age,
                countryCode,
                notSanctioned,
                salt);

        var inputs = ComplianceCredentialProofCircuit.inputs()
                .age(age)
                .countryCode(countryCode)
                .notSanctioned(notSanctioned)
                .credentialSalt(salt)
                .minimumAge(minimumAge)
                .requiredCountryCode(requiredCountry)
                .credentialCommitment(commitment);
        return new Fixture(inputs, minimumAge, requiredCountry, commitment);
    }

    private record Fixture(
            ComplianceCredentialProofCircuit.Inputs inputs,
            BigInteger minimumAge,
            BigInteger requiredCountryCode,
            BigInteger credentialCommitment) {
    }
}
