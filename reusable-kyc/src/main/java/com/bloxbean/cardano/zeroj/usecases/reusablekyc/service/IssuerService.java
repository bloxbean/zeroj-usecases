package com.bloxbean.cardano.zeroj.usecases.reusablekyc.service;

import com.bloxbean.cardano.zeroj.bbs.BbsKeyPair;
import com.bloxbean.cardano.zeroj.bbs.BbsPublicKey;
import com.bloxbean.cardano.zeroj.bbs.BbsService;
import com.bloxbean.cardano.zeroj.bbs.BbsSignature;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential.KycCredential;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential.KycSchema;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential.SignedCredential;

import java.nio.charset.StandardCharsets;

/**
 * The KYC provider. Holds a BBS key pair and issues credentials by signing the subject's attributes.
 * The issuer verifies the subject <b>once</b> (out of band); this service is the on-line part that
 * mints the reusable credential.
 *
 * <p>The BBS {@code header} binds the schema id + issuer id (a domain separator baked into the
 * signature), so a signature for this schema/issuer can't be re-interpreted under another.</p>
 */
public class IssuerService {

    private final BbsService bbs = BbsService.pureJava();
    private final BbsKeyPair keyPair;
    private final String issuerId;
    private final byte[] header;

    public IssuerService(byte[] keyMaterial, String issuerId) {
        this.issuerId = issuerId;
        this.keyPair = bbs.keyPair(keyMaterial, issuerId.getBytes(StandardCharsets.UTF_8));
        this.header = (KycSchema.SCHEMA_ID + "|issuer=" + issuerId).getBytes(StandardCharsets.UTF_8);
    }

    /** The issuer's BBS public key — published so any verifier can check presentations. */
    public BbsPublicKey publicKey() {
        return keyPair.publicKey();
    }

    public String issuerId() {
        return issuerId;
    }

    /** The domain-separating header the credential is signed under. */
    public byte[] header() {
        return header.clone();
    }

    /** Sign the subject's attributes and return everything the holder needs to present them. */
    public SignedCredential issue(KycCredential credential) {
        BbsSignature signature =
                bbs.sign(keyPair.secretKey(), keyPair.publicKey(), credential.messages(), header);
        return new SignedCredential(credential, signature, keyPair.publicKey(), header);
    }
}
