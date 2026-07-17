package com.bloxbean.cardano.zeroj.usecases.reusablekyc.service;

import com.bloxbean.cardano.zeroj.bbs.BbsPresentation;
import com.bloxbean.cardano.zeroj.bbs.cardano.BbsToCardano;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential.KycSchema;

import java.nio.charset.StandardCharsets;

/**
 * Adapts ZeroJ's {@link BbsToCardano} off-chain codec to this usecase's on-chain records. All the BBS
 * → Cardano derivation (generators, domain, DSTs, flattening a presentation) lives in the library now;
 * this class only maps the library's output onto {@link OnChainKycClaimService.BbsParams} /
 * {@link OnChainKycClaimService.Claim} and pins the demo's disclosed attributes.
 */
public final class BbsParamsFactory {

    private BbsParamsFactory() {}

    /** The validator params for {@code issuer}: public key, generators, domain, and the two DSTs. */
    public static OnChainKycClaimService.BbsParams of(IssuerService issuer) {
        BbsToCardano.VerifierParams p =
                BbsToCardano.verifierParams(issuer.publicKey(), issuer.header(), KycSchema.ATTRIBUTES.size());
        return new OnChainKycClaimService.BbsParams(
                p.publicKey(), p.g2Generator(), p.p1(), p.q1(), p.h(),
                p.domain(), p.dstHashToScalar(), p.dstMapToScalar());
    }

    /** Flatten a presentation (disclosing country + kycLevel) into the claim redeemer. */
    public static OnChainKycClaimService.Claim claimFrom(BbsPresentation presentation,
                                                        String country, String kycLevel, byte[] ph) {
        BbsToCardano.OnChainProof proof = BbsToCardano.onChainProof(presentation);
        return new OnChainKycClaimService.Claim(
                proof.aBar(), proof.bBar(), proof.d(),
                proof.eHat(), proof.r1Hat(), proof.r3Hat(), proof.mHats(), proof.challenge(),
                country.getBytes(StandardCharsets.UTF_8), kycLevel.getBytes(StandardCharsets.UTF_8), ph);
    }
}
