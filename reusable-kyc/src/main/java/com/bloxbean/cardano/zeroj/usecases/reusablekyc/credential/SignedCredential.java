package com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential;

import com.bloxbean.cardano.zeroj.bbs.BbsPublicKey;
import com.bloxbean.cardano.zeroj.bbs.BbsSignature;

/**
 * A credential the holder stores after issuance: the cleartext attributes, the issuer's BBS
 * signature over them, the issuer's public key, and the {@code header} the signature was made under
 * (schema id + issuer + validity). Everything the holder needs to derive selective-disclosure
 * presentations.
 */
public record SignedCredential(KycCredential credential, BbsSignature signature,
                               BbsPublicKey issuerPublicKey, byte[] header) {}
