package com.bloxbean.cardano.zeroj.usecases.airdrop.onchain;

import org.junit.jupiter.api.BeforeEach;
import org.zeroj.circuit.FieldConfig;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RegisteredIssuerBindingTest {

    private static final BigInteger U = BigInteger.valueOf(31);
    private static final BigInteger V = BigInteger.valueOf(41);
    private static final BigInteger EPOCH = BigInteger.valueOf(7);

    @BeforeEach
    void configureRegisteredIssuer() {
        FaucetMintingPolicy.issuerPkU = U;
        FaucetMintingPolicy.issuerPkV = V;
        FaucetMintingPolicy.policyEpoch = EPOCH;
    }

    @Test
    void acceptsOnlyTheParameterizedIssuerKey() {
        assertTrue(FaucetMintingPolicy.isRegisteredIssuer(U, V));
        assertFalse(FaucetMintingPolicy.isRegisteredIssuer(U.add(BigInteger.ONE), V));
        assertFalse(FaucetMintingPolicy.isRegisteredIssuer(U, V.add(BigInteger.ONE)));
    }

    @Test
    void acceptsOnlyTheParameterizedEpoch() {
        assertTrue(FaucetMintingPolicy.isRegisteredEpoch(EPOCH));
        assertFalse(FaucetMintingPolicy.isRegisteredEpoch(EPOCH.add(BigInteger.ONE)));
    }

    @Test
    void refusesAZeroOrOutOfFieldPolicyEpoch() {
        FaucetMintingPolicy.policyEpoch = BigInteger.ZERO;
        assertFalse(FaucetMintingPolicy.isRegisteredEpoch(BigInteger.ZERO));
        BigInteger r = FieldConfig.BLS12_381.prime();
        assertEquals(r, FaucetMintingPolicy.fr());
        FaucetMintingPolicy.policyEpoch = r;
        assertFalse(FaucetMintingPolicy.isRegisteredEpoch(r));
        FaucetMintingPolicy.policyEpoch = r.subtract(BigInteger.ONE);
        assertTrue(FaucetMintingPolicy.isRegisteredEpoch(r.subtract(BigInteger.ONE)));
    }
}
