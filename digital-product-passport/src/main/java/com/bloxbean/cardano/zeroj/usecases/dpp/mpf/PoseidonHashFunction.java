package com.bloxbean.cardano.zeroj.usecases.dpp.mpf;

import com.bloxbean.cardano.vds.core.api.HashFunction;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;

import java.math.BigInteger;

/**
 * Poseidon hash function implementing CCL's HashFunction interface.
 * <p>
 * Converts raw bytes to a BLS12-381 field element, hashes with Poseidon(input, 0),
 * and returns 32 bytes. This is used as the HashFunction for MPF key/value hashing.
 */
public class PoseidonHashFunction implements HashFunction {

    public static final PoseidonHashFunction INSTANCE = new PoseidonHashFunction();

    private static final BigInteger PRIME = FieldConfig.BLS12_381.prime();

    @Override
    public byte[] digest(byte[] in) {
        BigInteger input = new BigInteger(1, in).mod(PRIME);
        BigInteger result = PoseidonCompute.poseidon(input, BigInteger.ZERO);
        return toFixedWidth(result, 32);
    }

    /**
     * Hash two field elements: Poseidon(a, b).
     * Used internally by PoseidonCommitmentScheme for pairing.
     */
    public static byte[] digestPair(byte[] left, byte[] right) {
        BigInteger a = new BigInteger(1, left).mod(PRIME);
        BigInteger b = new BigInteger(1, right).mod(PRIME);
        BigInteger result = PoseidonCompute.poseidon(a, b);
        return toFixedWidth(result, 32);
    }

    private static byte[] toFixedWidth(BigInteger value, int width) {
        byte[] raw = value.toByteArray();
        byte[] result = new byte[width];
        int srcStart = Math.max(0, raw.length - width);
        int count = Math.min(raw.length, width);
        System.arraycopy(raw, srcStart, result, width - count, count);
        return result;
    }
}
