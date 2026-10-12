package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.util.HexUtil;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * The airdrop epoch as a domain tag (ADR-0009 D3.3):
 * <pre>
 *   policyEpoch  = Poseidon2(Poseidon2(tag("zeroj.airdrop.epoch.v1"), deploymentId), n)
 *   tag(s)       = integer(blake2b_256(UTF-8(s))) with the top byte cleared
 *   deploymentId = integer(blake2b_256(txId ‖ I2OSP2(index))) with the top byte cleared,
 *                  over the faucet's seed TxOutRef
 *   1 ≤ n < 2^32 (the round number)
 * </pre>
 * {@code Poseidon2} is ZeroJ's {@link PoseidonHash} over {@link PoseidonParamsBLS12_381T3}. The
 * nullifier is {@code Poseidon(personhoodId, policyEpoch)}, so two deployments, or two rounds of
 * one deployment, never share a nullifier.
 */
public final class AirdropEpoch {

    public static final String EPOCH_TAG = "zeroj.airdrop.epoch.v1";
    public static final long MAX_ROUND_EXCLUSIVE = 1L << 32;

    private AirdropEpoch() {}

    /** {@code tag(s)}: blake2b-256 of the UTF-8 bytes, top byte cleared (so below 2^248 < r). */
    public static BigInteger tag(String s) {
        return topByteCleared(Blake2bUtil.blake2bHash256(s.getBytes(StandardCharsets.UTF_8)));
    }

    /** {@code deploymentId} of a seed outref: covers the transaction id and the output index. */
    public static BigInteger deploymentId(String txIdHex, int index) {
        byte[] txId = HexUtil.decodeHexString(txIdHex);
        if (txId.length != 32) {
            throw new IllegalArgumentException("a transaction id is 32 bytes");
        }
        if (index < 0 || index > 0xFFFF) {
            throw new IllegalArgumentException("output index does not fit I2OSP2: " + index);
        }
        byte[] input = new byte[34];
        System.arraycopy(txId, 0, input, 0, 32);
        input[32] = (byte) (index >>> 8);
        input[33] = (byte) index;
        return topByteCleared(Blake2bUtil.blake2bHash256(input));
    }

    /** {@code policyEpoch} for round {@code n} of the deployment. */
    public static BigInteger policyEpoch(BigInteger deploymentId, long n) {
        if (n < 1 || n >= MAX_ROUND_EXCLUSIVE) {
            throw new IllegalArgumentException("round must satisfy 1 ≤ n < 2^32: " + n);
        }
        var params = PoseidonParamsBLS12_381T3.INSTANCE;
        BigInteger domain = PoseidonHash.hash(params, tag(EPOCH_TAG), deploymentId);
        return PoseidonHash.hash(params, domain, BigInteger.valueOf(n));
    }

    private static BigInteger topByteCleared(byte[] digest) {
        byte[] copy = digest.clone();
        copy[0] = 0;
        return new BigInteger(1, copy);
    }
}
