package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The epoch domain tag (ADR-0009 D3.3). The blake2b-256 vectors were computed independently
 * with Python's {@code hashlib.blake2b(digest_size=32)}; Poseidon comes from ZeroJ's
 * {@link PoseidonHash}.
 */
class AirdropEpochTest {

    /** {@code bytes(range(32))} */
    private static final String TX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    @Test
    void tagIsBlake2bWithTopByteCleared() {
        assertEquals(new BigInteger("0083b5fe9fda3eb53daffd30e40fdcb01b0f2a92878ffd940ca702fbaac38585", 16),
                AirdropEpoch.tag(AirdropEpoch.EPOCH_TAG));
    }

    @Test
    void deploymentIdCoversTheWholeOutref() {
        assertEquals(new BigInteger("00a91e5dd42543849872dbaa4b0ef4c928c3936e3a1c09a0a03e1bb6bab38976", 16),
                AirdropEpoch.deploymentId(TX, 0));
        assertEquals(new BigInteger("00307dd5706a47e6e151fceb0b1e4d82b6d3f0e9717e0a05c5d22bf950279218", 16),
                AirdropEpoch.deploymentId(TX, 1));
        // I2OSP2: index 258 is 0x0102, both bytes count.
        assertEquals(new BigInteger("00f6b4898566ccbffd6fc0cf2d714cc411d3bd64ca4ca6d775e9269028e6fab0", 16),
                AirdropEpoch.deploymentId(TX, 258));
    }

    @Test
    void siblingSeedOutputsGiveDifferentDeploymentsAndEpochs() {
        BigInteger d0 = AirdropEpoch.deploymentId(TX, 0);
        BigInteger d1 = AirdropEpoch.deploymentId(TX, 1);
        assertNotEquals(d0, d1, "(T, 0) and (T, 1) must be different deployments");
        assertNotEquals(AirdropEpoch.policyEpoch(d0, 1), AirdropEpoch.policyEpoch(d1, 1));
        BigInteger pid = new BigInteger("123456789abcdef", 16);
        assertNotEquals(HolderWallet.nullifier(pid, AirdropEpoch.policyEpoch(d0, 1)),
                HolderWallet.nullifier(pid, AirdropEpoch.policyEpoch(d1, 1)),
                "one holder's nullifiers in two deployments must differ");
    }

    @Test
    void policyEpochIsTheNestedPoseidonDomainTag() {
        var params = PoseidonParamsBLS12_381T3.INSTANCE;
        BigInteger d = AirdropEpoch.deploymentId(TX, 0);
        BigInteger expected = PoseidonHash.hash(params,
                PoseidonHash.hash(params, AirdropEpoch.tag(AirdropEpoch.EPOCH_TAG), d), BigInteger.valueOf(7));
        assertEquals(expected, AirdropEpoch.policyEpoch(d, 7));
        assertNotEquals(AirdropEpoch.policyEpoch(d, 1), AirdropEpoch.policyEpoch(d, 2), "rounds differ");
        assertTrue(AirdropEpoch.policyEpoch(d, 1).signum() > 0);
    }

    @Test
    void roundAndIndexBoundsAreEnforced() {
        BigInteger d = AirdropEpoch.deploymentId(TX, 0);
        assertThrows(IllegalArgumentException.class, () -> AirdropEpoch.policyEpoch(d, 0));
        assertThrows(IllegalArgumentException.class, () -> AirdropEpoch.policyEpoch(d, 1L << 32));
        AirdropEpoch.policyEpoch(d, (1L << 32) - 1);
        assertThrows(IllegalArgumentException.class, () -> AirdropEpoch.deploymentId(TX, -1));
        assertThrows(IllegalArgumentException.class, () -> AirdropEpoch.deploymentId(TX, 0x10000));
        assertThrows(IllegalArgumentException.class, () -> AirdropEpoch.deploymentId(TX.substring(2), 0));
    }
}
