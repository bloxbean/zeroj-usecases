package com.bloxbean.cardano.zeroj.usecases.reusablekyc.service;

import com.bloxbean.cardano.zeroj.bbs.BbsPresentation;
import com.bloxbean.cardano.zeroj.bbs.BbsService;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential.KycSchema;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential.SignedCredential;

import java.util.List;

/**
 * The holder's wallet. Stores one signed credential and derives a fresh selective-disclosure
 * presentation per verifier — revealing only the requested attributes and proving knowledge of the
 * issuer's signature over <b>all</b> of them, without revealing the rest.
 */
public class HolderService {

    private final BbsService bbs = BbsService.pureJava();
    private final SignedCredential credential;

    public HolderService(SignedCredential credential) {
        this.credential = credential;
    }

    /**
     * Produce a presentation revealing exactly {@code revealAttributes} (by schema name).
     *
     * @param revealAttributes   attribute names to disclose (e.g. {@code ["kycLevel","country"]})
     * @param presentationHeader a fresh, verifier-supplied nonce (binds this presentation to a
     *                           session / claim context so it can't be replayed)
     */
    public BbsPresentation present(List<String> revealAttributes, byte[] presentationHeader) {
        int[] indexes = revealAttributes.stream()
                .mapToInt(KycSchema::indexOf)
                .sorted()                       // BBS requires strictly ascending revealed indexes
                .distinct()
                .toArray();
        return bbs.derivePresentation(
                credential.issuerPublicKey(),
                credential.signature(),
                credential.credential().messages(),
                credential.header(),
                presentationHeader,
                indexes);
    }
}
