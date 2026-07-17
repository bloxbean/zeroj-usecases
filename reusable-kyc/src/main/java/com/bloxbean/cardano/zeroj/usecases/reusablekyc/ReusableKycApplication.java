package com.bloxbean.cardano.zeroj.usecases.reusablekyc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Reusable-KYC demo — BBS selective disclosure (ADR-0003).
 *
 * <p>A KYC provider signs a multi-attribute credential once; the holder proves only the attributes a
 * verifier needs (e.g. {@code kycLevel=verified}, {@code country}) without revealing the rest, and a
 * claim can be gated on-chain on Cardano. See {@code README.md} and {@code docs} in this module.</p>
 */
@SpringBootApplication
public class ReusableKycApplication {
    public static void main(String[] args) {
        SpringApplication.run(ReusableKycApplication.class, args);
    }
}
