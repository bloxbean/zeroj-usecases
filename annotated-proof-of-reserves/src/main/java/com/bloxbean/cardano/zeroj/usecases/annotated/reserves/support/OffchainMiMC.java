package com.bloxbean.cardano.zeroj.usecases.annotated.reserves.support;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class OffchainMiMC {
    private static final int NUM_ROUNDS = 91;

    private OffchainMiMC() {
    }

    public static BigInteger hash(BigInteger left, BigInteger right, BigInteger prime) {
        var state = left.mod(prime);
        var key = right.mod(prime);

        for (int round = 0; round < NUM_ROUNDS; round++) {
            var t = state.add(roundConstant(round)).add(key).mod(prime);
            var t2 = t.multiply(t).mod(prime);
            var t4 = t2.multiply(t2).mod(prime);
            var t6 = t4.multiply(t2).mod(prime);
            state = t6.multiply(t).mod(prime);
        }

        return state.add(key).mod(prime);
    }

    private static BigInteger roundConstant(int round) {
        if (round == 0) {
            return BigInteger.ZERO;
        }
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            return new BigInteger(1, digest.digest(("mimc_round_" + round).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
