package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import java.math.BigInteger;
import java.security.SecureRandom;

/** BLS12-381 scalar-field constants and fixed-width encodings. */
public final class Fields {

    /** The BLS12-381 scalar field order {@code p}, which is also Jubjub's base field. */
    public static final BigInteger FR = new BigInteger(
            "52435875175126190479447740508185965837690552500527637822603658699938581184513");

    private Fields() {}

    public static BigInteger randomFr(SecureRandom random) {
        byte[] bytes = new byte[64];
        random.nextBytes(bytes);
        return new BigInteger(1, bytes).mod(FR);
    }

    public static boolean canonical(BigInteger value) {
        return value.signum() >= 0 && value.compareTo(FR) < 0;
    }

    /** {@code I2OSP(value, width)}: big-endian, left-padded; throws if it does not fit. */
    public static byte[] i2osp(BigInteger value, int width) {
        if (value.signum() < 0 || value.bitLength() > width * 8) {
            throw new IllegalArgumentException("value does not fit in " + width + " bytes");
        }
        byte[] raw = value.toByteArray();
        byte[] out = new byte[width];
        int copy = Math.min(raw.length, width);
        System.arraycopy(raw, raw.length - copy, out, width - copy, copy);
        return out;
    }
}
