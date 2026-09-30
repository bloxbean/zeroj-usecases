package com.bloxbean.cardano.zeroj.usecases.identity.onchain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RegisteredIssuerBindingTest {

    private static final BigInteger U = BigInteger.valueOf(11);
    private static final BigInteger V = BigInteger.valueOf(22);
    private static final BigInteger MIN_AGE = BigInteger.valueOf(18);
    private static final BigInteger COUNTRY_ROOT = BigInteger.valueOf(33);

    @BeforeEach
    void configureRegisteredIssuer() {
        CredentialGatedValidator.issuerPkU = U;
        CredentialGatedValidator.issuerPkV = V;
        CredentialGatedValidator.policyMinAge = MIN_AGE;
        CredentialGatedValidator.policyCountryRoot = COUNTRY_ROOT;
    }

    @Test
    void acceptsOnlyTheParameterizedIssuerKey() {
        assertTrue(CredentialGatedValidator.isRegisteredIssuer(U, V));
        assertFalse(CredentialGatedValidator.isRegisteredIssuer(U.add(BigInteger.ONE), V));
        assertFalse(CredentialGatedValidator.isRegisteredIssuer(U, V.add(BigInteger.ONE)));
    }

    @Test
    void acceptsOnlyTheParameterizedEligibilityPolicy() {
        assertTrue(CredentialGatedValidator.isRegisteredPolicy(MIN_AGE, COUNTRY_ROOT));
        assertFalse(CredentialGatedValidator.isRegisteredPolicy(
                MIN_AGE.subtract(BigInteger.ONE), COUNTRY_ROOT));
        assertFalse(CredentialGatedValidator.isRegisteredPolicy(
                MIN_AGE, COUNTRY_ROOT.add(BigInteger.ONE)));
    }
}
