package com.bloxbean.cardano.zeroj.usecases.recovery.service;

import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thin cached facade over {@link PoseidonHash} for BLS12-381 Poseidon hashing.
 * Kept for backwards-compat with existing callers; new code may invoke
 * {@link PoseidonHash#hash} directly.
 *
 * <p>After ADR-0015, this produces <b>standards-compatible</b> BLS12-381
 * Poseidon (using {@link PoseidonParamsBLS12_381T3}). Prior to ADR-0015 this
 * class computed a non-standard hybrid (BN254 circomlib constants over the
 * BLS12-381 prime). All outputs have changed; any previously-persisted hashes
 * must be recomputed.
 */
public final class PoseidonCompute {

    private static final PoseidonParams PARAMS = PoseidonParamsBLS12_381T3.INSTANCE;
    private static final ConcurrentHashMap<String, BigInteger> CACHE = new ConcurrentHashMap<>();

    private PoseidonCompute() {}

    public static BigInteger poseidon(BigInteger a, BigInteger b) {
        String key = a.toString(16) + ":" + b.toString(16);
        return CACHE.computeIfAbsent(key, k -> PoseidonHash.hash(PARAMS, a, b));
    }
}
