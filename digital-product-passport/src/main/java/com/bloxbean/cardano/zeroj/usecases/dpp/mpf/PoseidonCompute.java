package com.bloxbean.cardano.zeroj.usecases.dpp.mpf;

import com.bloxbean.cardano.zeroj.circuit.FieldConfig;

import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Poseidon hash computation for BLS12-381 scalar field.
 * <p>
 * Uses the same constants as zeroj-circuit-lib's Poseidon (from circomlibjs).
 * Parameters: t=3, RF=8, RP=57, S-box=x^5.
 */
public final class PoseidonCompute {

    private static final BigInteger PRIME = FieldConfig.BLS12_381.prime();
    private static final ConcurrentHashMap<String, BigInteger> CACHE = new ConcurrentHashMap<>();

    private static volatile BigInteger[] C;
    private static volatile BigInteger[] M;

    private PoseidonCompute() {}

    public static BigInteger poseidon(BigInteger a, BigInteger b) {
        String key = a.toString(16) + ":" + b.toString(16);
        return CACHE.computeIfAbsent(key, k -> computePoseidon(a, b));
    }

    private static BigInteger computePoseidon(BigInteger a, BigInteger b) {
        ensureConstants();
        BigInteger p = PRIME;
        BigInteger[] state = {BigInteger.ZERO, a.mod(p), b.mod(p)};
        int RF = 8, RP = 57, N = RF + RP;
        for (int r = 0; r < N; r++) {
            for (int j = 0; j < 3; j++)
                state[j] = state[j].add(C[r * 3 + j]).mod(p);
            if (r < RF / 2 || r >= RF / 2 + RP) {
                for (int j = 0; j < 3; j++) {
                    BigInteger x = state[j], x2 = x.multiply(x).mod(p), x4 = x2.multiply(x2).mod(p);
                    state[j] = x4.multiply(x).mod(p);
                }
            } else {
                BigInteger x = state[0], x2 = x.multiply(x).mod(p), x4 = x2.multiply(x2).mod(p);
                state[0] = x4.multiply(x).mod(p);
            }
            BigInteger[] t = new BigInteger[3];
            for (int i = 0; i < 3; i++) {
                t[i] = BigInteger.ZERO;
                for (int j = 0; j < 3; j++)
                    t[i] = t[i].add(state[j].multiply(M[i * 3 + j])).mod(p);
            }
            state = t;
        }
        return state[0];
    }

    private static synchronized void ensureConstants() {
        if (C != null) return;
        try {
            var cField = Class.forName("com.bloxbean.cardano.zeroj.circuit.lib.PoseidonConstants")
                    .getDeclaredField("C");
            cField.setAccessible(true);
            C = (BigInteger[]) cField.get(null);

            var mField = Class.forName("com.bloxbean.cardano.zeroj.circuit.lib.PoseidonConstants")
                    .getDeclaredField("M");
            mField.setAccessible(true);
            M = (BigInteger[]) mField.get(null);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load Poseidon constants", e);
        }
    }
}
