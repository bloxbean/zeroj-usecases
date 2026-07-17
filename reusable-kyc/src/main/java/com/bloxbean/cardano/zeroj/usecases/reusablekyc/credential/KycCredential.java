package com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * A reusable-KYC credential's cleartext attribute values, in {@link KycSchema} order. The holder
 * keeps this privately; the issuer signs its {@link #messages()} with BBS.
 *
 * @param givenName the subject's given name (kept private in most presentations)
 * @param dob       date of birth {@code YYYY-MM-DD} (kept private)
 * @param country   ISO country code (often disclosed)
 * @param kycLevel  KYC assurance level, e.g. {@code verified} (often disclosed)
 * @param docHash   hex hash of the underlying identity document (kept private)
 */
public record KycCredential(String givenName, String dob, String country, String kycLevel, String docHash) {

    /** The attribute values as ordered BBS messages (one {@code byte[]} per {@link KycSchema} index). */
    public List<byte[]> messages() {
        return List.of(
                givenName.getBytes(StandardCharsets.UTF_8),
                dob.getBytes(StandardCharsets.UTF_8),
                country.getBytes(StandardCharsets.UTF_8),
                kycLevel.getBytes(StandardCharsets.UTF_8),
                docHash.getBytes(StandardCharsets.UTF_8));
    }
}
