package com.bloxbean.cardano.zeroj.usecases.reserves.service;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Salted Merkle-sum-tree leaves (ADR-0009 D4).
 *
 * <pre>
 * idTag    = fold(Poseidon2, tag("zeroj.reserves.id.v1"), [len, c_0, …, c_k])
 * saltedId = Poseidon2(idTag, salt)
 * leaf     = Poseidon2(saltedId, balance)
 * </pre>
 *
 * <ul>
 *   <li>{@code Poseidon2} is ZeroJ's {@link PoseidonHash} over {@link PoseidonParamsBLS12_381T3};</li>
 *   <li>{@code tag(s)} is the integer of {@code blake2b_256(UTF-8(s))} with its top byte cleared;</li>
 *   <li>{@code len} is the UTF-8 byte length of the account id, and {@code c_i} are its UTF-8 bytes in
 *       31-byte big-endian chunks, the last right-padded with zeros (an empty id has no chunks), so
 *       no chunk reduces mod p;</li>
 *   <li>{@code fold(f, a, [x_0, …]) = f(…f(f(a, x_0), x_1)…)};</li>
 *   <li>{@code salt} is a fresh 252-bit value from {@link SecureRandom}, per account and snapshot.</li>
 * </ul>
 *
 * <p>The {@code SolvencyProof} circuit is unchanged: its {@code accountIds} witness is the salted
 * id, and it computes {@code leaf = Poseidon2(saltedId, balance)} itself.
 */
public final class ReserveLeaves {

    public static final String ID_DOMAIN = "zeroj.reserves.id.v1";
    public static final int SALT_BITS = 252;
    static final int CHUNK_BYTES = 31;

    private static final PoseidonParams PARAMS = PoseidonParamsBLS12_381T3.INSTANCE;

    /** {@code tag("zeroj.reserves.id.v1")}. */
    public static final BigInteger ID_TAG_DOMAIN = tag(ID_DOMAIN);

    private ReserveLeaves() {}

    /** The integer of {@code blake2b_256(UTF-8(s))} with its top byte cleared (248 bits). */
    public static BigInteger tag(String s) {
        byte[] digest = Blake2bUtil.blake2bHash256(s.getBytes(StandardCharsets.UTF_8));
        digest[0] = 0;
        return new BigInteger(1, digest);
    }

    /** The length-prefixed, chunked Poseidon fold of the account id's UTF-8 bytes. */
    public static BigInteger idTag(String accountId) {
        Objects.requireNonNull(accountId, "accountId");
        byte[] bytes = accountId.getBytes(StandardCharsets.UTF_8);
        BigInteger acc = poseidon(ID_TAG_DOMAIN, BigInteger.valueOf(bytes.length));
        for (int off = 0; off < bytes.length; off += CHUNK_BYTES) {
            byte[] chunk = Arrays.copyOfRange(bytes, off, off + CHUNK_BYTES); // right-pads with zeros
            acc = poseidon(acc, new BigInteger(1, chunk));
        }
        return acc;
    }

    /** {@code Poseidon2(idTag, salt)}: the circuit's {@code accountIds} witness. */
    public static BigInteger saltedId(String accountId, BigInteger salt) {
        return poseidon(idTag(accountId), requireSalt(salt));
    }

    /** {@code Poseidon2(saltedId, balance)}. */
    public static BigInteger leaf(BigInteger saltedId, BigInteger balance) {
        return poseidon(saltedId, balance);
    }

    /** An internal tree node, {@code Poseidon2(left, right)}. */
    public static BigInteger node(BigInteger left, BigInteger right) {
        return poseidon(left, right);
    }

    /** A fresh 252-bit salt. */
    public static BigInteger randomSalt(SecureRandom rng) {
        return new BigInteger(SALT_BITS, rng);
    }

    private static BigInteger requireSalt(BigInteger salt) {
        Objects.requireNonNull(salt, "salt");
        if (salt.signum() < 0 || salt.bitLength() > SALT_BITS) {
            throw new IllegalArgumentException("salt must be a non-negative " + SALT_BITS + "-bit value");
        }
        return salt;
    }

    private static BigInteger poseidon(BigInteger a, BigInteger b) {
        return PoseidonHash.hash(PARAMS, a, b);
    }
}
