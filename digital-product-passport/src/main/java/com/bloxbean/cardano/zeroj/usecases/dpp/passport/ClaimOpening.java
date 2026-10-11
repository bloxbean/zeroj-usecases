package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;
import org.zeroj.circuit.lib.jubjub.PedersenVectorCommitment;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * The opening {@code (m…, r)} of one claim's commitment: the values the auditor measured, in
 * schema order, and the blinding it chose. The auditor gives it to the manufacturer with its
 * report; it is the manufacturer's secret and never goes on-chain.
 */
public record ClaimOpening(Claim claim, List<BigInteger> values, BigInteger blinding) {

    private static final SecureRandom RANDOM = new SecureRandom();

    public ClaimOpening {
        Objects.requireNonNull(claim, "claim");
        values = List.copyOf(values);
        Objects.requireNonNull(blinding, "blinding");
        if (values.size() != claim.schema().dimension()) {
            throw new IllegalArgumentException(claim + " has " + claim.schema().dimension() + " entries");
        }
        for (int i = 0; i < values.size(); i++) {
            BigInteger value = values.get(i);
            if (value.signum() < 0 || value.bitLength() > claim.schema().width(i)) {
                throw new IllegalArgumentException(claim.schema().entries().get(i).label() + " does not fit "
                        + claim.schema().width(i) + " bits");
            }
        }
    }

    /** A fresh 252-bit blinding from {@code SecureRandom} ({@code PedersenCommitment.randomBlinding}). */
    public static ClaimOpening fresh(Claim claim, List<BigInteger> values) {
        return new ClaimOpening(claim, values, PedersenCommitment.randomBlinding(RANDOM));
    }

    public static ClaimOpening fresh(Claim claim, long... values) {
        return fresh(claim, Arrays.stream(values).mapToObj(BigInteger::valueOf).toList());
    }

    public PedersenVectorCommitment commitment() {
        return PedersenVectorCommitment.commit(claim.schema(), values, blinding);
    }

    /** The commitment's affine point. */
    public JubjubPoint point() {
        return commitment().point().normalized();
    }

    /** This claim's entry for a passport datum. */
    public PassportDatum.Entry entry() {
        JubjubPoint p = point();
        return new PassportDatum.Entry(claim.id(), claim.sigma(), p.affineU(), p.affineV());
    }
}
