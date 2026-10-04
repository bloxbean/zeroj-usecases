package com.bloxbean.cardano.zeroj.usecases.voting.crypto;

import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.Set;

/**
 * Host-side exponential ElGamal over the Jubjub prime-order subgroup (ADR-0005).
 *
 * <p>{@code Enc(v; k) = (A, B) = ([k]·G, [v]·G + [k]·PK)}. Ciphertexts add component-wise, so the
 * sum of ballots encrypts the sum of votes. Decryption removes {@code [sk]·ΣA} from {@code ΣB},
 * with {@code sk = Σ sk_j} applied share by share, and recovers the small total by search.
 *
 * <p>Arithmetic is ZeroJ's {@link JubjubPoint}. This class only composes it; it introduces no
 * new primitive. It is variable-time and must not be given secrets an attacker can time.
 */
public final class JubjubElGamal {

    /** Message and key base: the {@code pedersen-jubjub-v1} value base. */
    public static final JubjubPoint G = JubjubPoint.SUBGROUP_GENERATOR;

    /** Subgroup order {@code l}. */
    public static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;

    private JubjubElGamal() {}

    /** A ballot: decryption handle {@code A} and blinded vote {@code B}, both normalized. */
    public record Ciphertext(JubjubPoint handle, JubjubPoint ballot) {
        public Ciphertext {
            Objects.requireNonNull(handle, "handle");
            Objects.requireNonNull(ballot, "ballot");
            handle = handle.normalized();
            ballot = ballot.normalized();
        }

        public Ciphertext add(Ciphertext other) {
            return new Ciphertext(handle.add(other.handle), ballot.add(other.ballot));
        }

        /** The identity ciphertext {@code (O, O)}, an encryption of 0 with {@code k = 0}. */
        public static Ciphertext zero() {
            return new Ciphertext(JubjubPoint.IDENTITY, JubjubPoint.IDENTITY);
        }

        /**
         * A ciphertext read from the ledger. Rejects coordinates that are not canonical field
         * elements, not on the curve, or not in the prime-order subgroup.
         */
        public static Ciphertext fromAffine(BigInteger handleU, BigInteger handleV,
                                            BigInteger ballotU, BigInteger ballotV) {
            return new Ciphertext(subgroupPoint(handleU, handleV), subgroupPoint(ballotU, ballotV));
        }
    }

    /** A uniform scalar in {@code [0, l)}: 64 random bytes reduced mod {@code l}. */
    public static BigInteger randomScalar(SecureRandom random) {
        return PedersenCommitment.randomBlinding(random);
    }

    /** A uniform non-zero scalar in {@code [1, l)}, for key shares. */
    public static BigInteger randomNonZeroScalar(SecureRandom random) {
        BigInteger s;
        do {
            s = randomScalar(random);
        } while (s.signum() == 0);
        return s;
    }

    /** {@code ([k]·G, [vote]·G + [k]·PK)} for a vote of 0 or 1. */
    public static Ciphertext encrypt(int vote, BigInteger k, JubjubPoint electionKey) {
        if (vote != 0 && vote != 1) {
            throw new IllegalArgumentException("vote must be 0 or 1");
        }
        requireScalar(k, "k");
        JubjubPoint message = vote == 1 ? G : JubjubPoint.IDENTITY;
        return new Ciphertext(G.scalarMul(k), message.add(electionKey.scalarMul(k)));
    }

    /** The component-wise sum of {@code ciphertexts}; {@link Ciphertext#zero()} when empty. */
    public static Ciphertext sum(List<Ciphertext> ciphertexts) {
        Ciphertext total = Ciphertext.zero();
        for (Ciphertext c : ciphertexts) {
            total = total.add(c);
        }
        return total;
    }

    /**
     * The joint election key {@code PK = Σ PK_j}. Each share must be a non-identity subgroup point,
     * the shares must be pairwise distinct, and the sum must not be the identity (ADR-0005 V9).
     * Proofs of possession are checked separately, by the caller.
     */
    public static JubjubPoint jointKey(List<JubjubPoint> trusteeKeys) {
        if (trusteeKeys.isEmpty()) {
            throw new IllegalArgumentException("at least one trustee key is required");
        }
        Set<List<BigInteger>> seen = new HashSet<>();
        JubjubPoint key = JubjubPoint.IDENTITY;
        for (JubjubPoint k : trusteeKeys) {
            JubjubPoint share = k.normalized();
            if (share.isIdentity() || !share.isInSubgroup()) {
                throw new IllegalArgumentException("trustee key must be a non-identity subgroup point");
            }
            if (!seen.add(List.of(share.affineU(), share.affineV()))) {
                throw new IllegalArgumentException("trustee keys must be distinct");
            }
            key = key.add(share);
        }
        key = key.normalized();
        if (key.isIdentity()) {
            throw new IllegalArgumentException("joint election key is the identity");
        }
        return key;
    }

    /** Trustee {@code j}'s decryption share {@code D_j = [sk_j]·ΣA}. */
    public static JubjubPoint decryptionShare(BigInteger secretShare, JubjubPoint aggregateHandle) {
        requireScalar(secretShare, "secretShare");
        return aggregateHandle.scalarMul(secretShare).normalized();
    }

    /** {@code M = ΣB − Σ D_j}, which equals {@code [T]·G} when every share is correct. */
    public static JubjubPoint unmask(JubjubPoint aggregateBallot, List<JubjubPoint> shares) {
        JubjubPoint m = aggregateBallot;
        for (JubjubPoint d : shares) {
            m = m.add(d.negate());
        }
        return m.normalized();
    }

    /** The unique {@code t ∈ [0, max]} with {@code [t]·G = m}, if any. */
    public static OptionalInt discreteLog(JubjubPoint m, int max) {
        JubjubPoint target = m.normalized();
        JubjubPoint candidate = JubjubPoint.IDENTITY;
        for (int t = 0; t <= max; t++) {
            if (candidate.projectiveEquals(target)) {
                return OptionalInt.of(t);
            }
            candidate = candidate.add(G);
        }
        return OptionalInt.empty();
    }

    /** A point from canonical affine coordinates, required to be on the curve and in the subgroup. */
    public static JubjubPoint subgroupPoint(BigInteger u, BigInteger v) {
        BigInteger p = JubjubCurve.BASE_FIELD_PRIME;
        if (u.signum() < 0 || u.compareTo(p) >= 0 || v.signum() < 0 || v.compareTo(p) >= 0) {
            throw new IllegalArgumentException("coordinates must be canonical field elements");
        }
        JubjubPoint point = JubjubPoint.fromAffine(u, v);
        if (!point.isInSubgroup()) {
            throw new IllegalArgumentException("point is not in the prime-order subgroup");
        }
        return point;
    }

    private static void requireScalar(BigInteger s, String name) {
        Objects.requireNonNull(s, name);
        if (s.signum() < 0 || s.compareTo(L) >= 0) {
            throw new IllegalArgumentException(name + " must be in [0, l)");
        }
    }
}
