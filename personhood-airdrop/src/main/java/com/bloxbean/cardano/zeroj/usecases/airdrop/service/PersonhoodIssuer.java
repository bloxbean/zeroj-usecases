package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import org.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;

import java.math.BigInteger;

/**
 * What a holder sees of the personhood issuer (ADR-0009 D3.1). The holder sends only
 * {@code m = Poseidon(personhoodId, 0)}; the issuer never receives {@code personhoodId}, so it
 * cannot compute the holder's nullifier {@code Poseidon(personhoodId, epoch)}.
 */
public interface PersonhoodIssuer {

    /**
     * Signs {@code m} for {@code person}, after the issuer's one-human check, at most once per
     * person.
     *
     * @param person the person, as identified by the issuer's out-of-band one-human check
     * @param m      {@code Poseidon(personhoodId, 0)}, a canonical BLS12-381 scalar
     * @throws AlreadyIssuedException if {@code person} already has a credential
     */
    EdDSAJubjub.Signature issue(String person, BigInteger m);

    /** The issuer's public key, pinned as a {@code FaucetMintingPolicy} parameter. */
    JubjubPoint publicKey();

    /** A second issuance for the same person (ADR-0009 D3.2): refused, never overwritten. */
    final class AlreadyIssuedException extends IllegalStateException {
        public AlreadyIssuedException(String person) {
            super("A personhood credential was already issued to " + person
                    + "; the issuer issues one credential per person and never re-issues");
        }
    }
}
