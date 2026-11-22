package com.bloxbean.cardano.zeroj.usecases.nft.service;

import org.zeroj.circuit.FieldConfig;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * The host-side values of the NFT ownership scheme, circuit version 2 (ADR-0009 D2). Every value
 * here must match {@code NFTOwnershipProof}; the hashes are ZeroJ's {@link PoseidonHash} over
 * {@code PoseidonParamsBLS12_381T3}.
 *
 * <ul>
 *   <li>leaf: {@code Poseidon(Poseidon(s, 0), t)};</li>
 *   <li>nullifier: {@code Poseidon(Poseidon(s, t), contextId)};</li>
 *   <li>{@code t}: the asset name's bytes read as a big-endian integer (1–31 bytes, no leading
 *       zero byte, so each name has one field value);</li>
 *   <li>{@code contextId}: the event label's UTF-8 bytes read the same way;</li>
 *   <li>{@code s}: a holder secret, a {@value #SECRET_BITS}-bit value from {@link SecureRandom}.</li>
 * </ul>
 */
public final class NftScheme {

    /** Circuit version of the nullifier and leaf formulas. */
    public static final int CIRCUIT_VERSION = 2;

    /** Bits drawn for a holder secret. */
    public static final int SECRET_BITS = 252;

    /**
     * The smallest accepted bit length of a holder secret. A 252-bit random value is shorter than
     * this with probability 2^-12; the generator redraws it. Anything shorter (a typed-in number
     * such as {@code 42}) is refused.
     */
    public static final int MIN_SECRET_BITS = 240;

    /** Longest asset name or event label that encodes into one field element. */
    public static final int MAX_LABEL_BYTES = 31;

    /** Domain tag of the CIP-8 registration payload. */
    static final byte[] REGISTRATION_TAG = "zeroj.demo.nft.register.v2".getBytes(StandardCharsets.UTF_8);

    private static final BigInteger R = FieldConfig.BLS12_381.prime();

    private NftScheme() {}

    /** A fresh holder secret: {@value #SECRET_BITS} bits from {@code random}, at least {@value #MIN_SECRET_BITS} bits long. */
    public static BigInteger newSecret(SecureRandom random) {
        BigInteger s;
        do {
            s = new BigInteger(SECRET_BITS, random);
        } while (s.bitLength() < MIN_SECRET_BITS);
        return s;
    }

    /**
     * Refuses a holder secret that is short (below 2^{@value #MIN_SECRET_BITS}) or wider than
     * {@value #SECRET_BITS} bits.
     *
     * @return {@code secret}
     */
    public static BigInteger requireSecret(BigInteger secret) {
        if (secret == null || secret.signum() < 0) {
            throw new IllegalArgumentException("holder secret is missing or negative");
        }
        if (secret.bitLength() < MIN_SECRET_BITS) {
            throw new IllegalArgumentException("holder secret is too short: " + secret.bitLength()
                    + " bits; use a " + SECRET_BITS + "-bit random secret (the app generates one)");
        }
        if (secret.bitLength() > SECRET_BITS) {
            throw new IllegalArgumentException("holder secret is wider than " + SECRET_BITS + " bits");
        }
        return secret;
    }

    /** Parses a secret given as decimal or {@code 0x}-prefixed hex, and checks it. */
    public static BigInteger parseSecret(String text) {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("holder secret is missing");
        }
        String t = text.trim();
        BigInteger s = t.startsWith("0x") || t.startsWith("0X")
                ? new BigInteger(t.substring(2), 16)
                : new BigInteger(t);
        return requireSecret(s);
    }

    /** The field value of an asset name. */
    public static BigInteger tokenField(byte[] assetName) {
        return label(assetName, "asset name");
    }

    /** The field value of an asset name given as text (UTF-8). */
    public static BigInteger tokenField(String assetName) {
        return tokenField(assetName.getBytes(StandardCharsets.UTF_8));
    }

    /** The field value of an event label (UTF-8). */
    public static BigInteger contextId(String label) {
        return label(label.getBytes(StandardCharsets.UTF_8), "event label");
    }

    public static BigInteger ownerHash(BigInteger secret) {
        return poseidon(secret, BigInteger.ZERO);
    }

    /** {@code Poseidon(Poseidon(s, 0), t)}. */
    public static BigInteger leaf(BigInteger secret, BigInteger token) {
        return poseidon(ownerHash(secret), token);
    }

    /** {@code Poseidon(Poseidon(s, t), contextId)}. */
    public static BigInteger nullifier(BigInteger secret, BigInteger token, BigInteger contextId) {
        return poseidon(poseidon(secret, token), contextId);
    }

    /**
     * The bytes a holder signs to register a leaf (CIP-8):
     * {@code "zeroj.demo.nft.register.v2" ‖ I2OSP32(contextId) ‖ I2OSP32(t) ‖ I2OSP32(leaf)}.
     */
    public static byte[] registrationPayload(BigInteger contextId, BigInteger token, BigInteger leaf) {
        byte[] out = new byte[REGISTRATION_TAG.length + 96];
        System.arraycopy(REGISTRATION_TAG, 0, out, 0, REGISTRATION_TAG.length);
        System.arraycopy(i2osp32(contextId), 0, out, REGISTRATION_TAG.length, 32);
        System.arraycopy(i2osp32(token), 0, out, REGISTRATION_TAG.length + 32, 32);
        System.arraycopy(i2osp32(leaf), 0, out, REGISTRATION_TAG.length + 64, 32);
        return out;
    }

    /** Poseidon(a, b) over BLS12-381, the hash the circuit uses for leaves, nodes and nullifiers. */
    public static BigInteger poseidon(BigInteger a, BigInteger b) {
        return PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, a, b);
    }

    /** The unsigned 32-byte big-endian encoding of a field element. */
    public static byte[] i2osp32(BigInteger value) {
        if (value.signum() < 0 || value.compareTo(R) >= 0) {
            throw new IllegalArgumentException("not a canonical field element");
        }
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        return out;
    }

    private static BigInteger label(byte[] bytes, String what) {
        if (bytes.length == 0 || bytes.length > MAX_LABEL_BYTES) {
            throw new IllegalArgumentException(what + " must be 1-" + MAX_LABEL_BYTES + " bytes");
        }
        if (bytes[0] == 0) {
            throw new IllegalArgumentException(what + " must not start with a zero byte");
        }
        return new BigInteger(1, bytes);
    }
}
