package com.bloxbean.cardano.zeroj.usecases.selective.onchain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RegisteredIssuerBindingTest {

    private static final BigInteger U = BigInteger.valueOf(51);
    private static final BigInteger V = BigInteger.valueOf(61);
    private static final BigInteger CURRENT_YEAR = BigInteger.valueOf(2026);
    private static final BigInteger COUNTRY_ROOT = BigInteger.valueOf(71);

    @BeforeEach
    void configureRegisteredIssuer() {
        AdultResidentValidator.issuerPkU = U;
        AdultResidentValidator.issuerPkV = V;
        SeniorDoctorValidator.issuerPkU = U;
        SeniorDoctorValidator.issuerPkV = V;
        AdultResidentValidator.policyCurrentYear = CURRENT_YEAR;
        AdultResidentValidator.policyCountryRoot = COUNTRY_ROOT;
        SeniorDoctorValidator.policyCurrentYear = CURRENT_YEAR;
    }

    @Test
    void bothPredicatesAcceptOnlyTheParameterizedIssuerKey() {
        assertTrue(AdultResidentValidator.isRegisteredIssuer(U, V));
        assertTrue(SeniorDoctorValidator.isRegisteredIssuer(U, V));

        assertFalse(AdultResidentValidator.isRegisteredIssuer(U.add(BigInteger.ONE), V));
        assertFalse(AdultResidentValidator.isRegisteredIssuer(U, V.add(BigInteger.ONE)));
        assertFalse(SeniorDoctorValidator.isRegisteredIssuer(U.add(BigInteger.ONE), V));
        assertFalse(SeniorDoctorValidator.isRegisteredIssuer(U, V.add(BigInteger.ONE)));
    }

    @Test
    void bothPredicatesAcceptOnlyTheirParameterizedPolicy() {
        assertTrue(AdultResidentValidator.isRegisteredPolicy(CURRENT_YEAR, COUNTRY_ROOT));
        assertTrue(SeniorDoctorValidator.isRegisteredPolicy(CURRENT_YEAR));

        assertFalse(AdultResidentValidator.isRegisteredPolicy(
                CURRENT_YEAR.subtract(BigInteger.ONE), COUNTRY_ROOT));
        assertFalse(AdultResidentValidator.isRegisteredPolicy(
                CURRENT_YEAR, COUNTRY_ROOT.add(BigInteger.ONE)));
        assertFalse(SeniorDoctorValidator.isRegisteredPolicy(
                CURRENT_YEAR.subtract(BigInteger.ONE)));
    }
}
