package com.bloxbean.cardano.zeroj.usecases.reserves.service;

import com.bloxbean.cardano.client.util.HexUtil;

import java.math.BigInteger;

/**
 * The attestation clock of {@code ReserveAttestation} (ADR-0009 D4): period {@code p} is
 * {@code [genesisMs + p·periodMs, genesisMs + (p+1)·periodMs)} in POSIX milliseconds, and its
 * token name is {@code I2OSP8(p)}, the 8-byte big-endian encoding.
 */
public record AttestationPeriods(long genesisMs, long periodMs) {

    public AttestationPeriods {
        if (genesisMs < 0) throw new IllegalArgumentException("genesisMs must be >= 0");
        if (periodMs <= 0) throw new IllegalArgumentException("periodMs must be > 0");
    }

    /** The period containing {@code posixMs}; refuses a time before genesis. */
    public long periodAt(long posixMs) {
        if (posixMs < genesisMs) throw new IllegalArgumentException("time is before the attestation genesis");
        return Math.floorDiv(posixMs - genesisMs, periodMs);
    }

    public long start(long period) {
        return Math.addExact(genesisMs, Math.multiplyExact(period, periodMs));
    }

    /** The first millisecond after the period: a burn needs a validity lower bound at or after it. */
    public long end(long period) {
        return start(Math.addExact(period, 1));
    }

    /** {@code I2OSP8(period)}. */
    public static byte[] tokenName(long period) {
        if (period < 0) throw new IllegalArgumentException("period must be >= 0");
        byte[] out = new byte[8];
        byte[] raw = BigInteger.valueOf(period).toByteArray();
        int len = Math.min(raw.length, 8);
        System.arraycopy(raw, raw.length - len, out, 8 - len, len);
        return out;
    }

    /** The token's unit, {@code policyId ‖ hex(I2OSP8(period))}. */
    public static String unit(String policyId, long period) {
        return policyId + HexUtil.encodeHexString(tokenName(period));
    }
}
