package com.bloxbean.cardano.zeroj.usecases.voting.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalPublicKey;
import org.zeroj.circuit.lib.jubjub.ElGamalSecretKey;
import org.zeroj.circuit.lib.jubjub.EncryptionStatementVerifier;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.NOfNKeyContext;
import org.zeroj.circuit.lib.jubjub.RawElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.VerifiedDecryptionShare;
import org.zeroj.circuit.lib.jubjub.VerifiedKeyShare;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Ciphertext compatibility (ZeroJ ADR-0052 M3): the prototype's ballots, as fixed by the
 * independent Python reference ({@code src/test/resources/elgamal-reference/elgamal_reference.py},
 * which re-implements Jubjub and the tally from the curve definition without ZeroJ), are
 * {@code elgamal-jubjub-v1} ciphertexts that ZeroJ's library API admits, sums and decrypts to
 * the reference tally.
 *
 * <p>The reference's trustee secrets become the key context ({@link VerifiedKeyShare#fromSecret});
 * each reference ciphertext enters through {@link RawElGamalCiphertext#fromAffine}, the ledger
 * path, and is admitted with a verifier that checks its opening ({@code A = [k]·G},
 * {@code B = [v]·G + [k]·PK} with the reference's {@code k} and {@code v}) using raw point
 * arithmetic. The library's decryption shares and plaintext must equal the reference's
 * {@code D_j} and {@code T}.
 */
class ElGamalCompatibilityTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final JubjubPoint G = JubjubPoint.SUBGROUP_GENERATOR;
    /** {@code encode(G)}, pinned in {@code elgamal-jubjub-v1} §1. */
    private static final String SPEC_G_ENCODING = "cb550cd538ea0cc1138480408e6eaab9b36c613f0dd3f7784fdb6eea837b13d7";

    @Test
    @DisplayName("Reference vectors: keys, admitted ballots, sum, shares and tally match the Python reference")
    void prototypeVectorsAdmitAndDecrypt() throws IOException {
        Map<String, String[]> ref = reference();
        // One generator: the reference's G is the profile's G.
        assertPoint(ref, "G", G);
        assertEquals(SPEC_G_ENCODING, HexFormat.of().formatHex(G.normalized().toBytes()));

        List<ElGamalSecretKey> trustees = new ArrayList<>();
        for (int j = 1; j <= 3; j++) {
            ElGamalSecretKey sk = ElGamalSecretKey.of(new BigInteger(ref.get("scalar sk" + j)[0], 16));
            assertPoint(ref, "PK" + j, sk.publicKey().point());
            trustees.add(sk);
        }
        NOfNKeyContext context = ElGamalPublicKey.aggregate(trustees.stream().map(VerifiedKeyShare::fromSecret).toList());
        assertPoint(ref, "PK", context.jointKey().point());

        List<ElGamalCiphertext> admitted = new ArrayList<>();
        int yes = 0;
        for (int i = 1; i <= 5; i++) {
            BigInteger k = new BigInteger(ref.get("scalar k" + i)[0], 16);
            int vote = Integer.parseInt(ref.get("vote v" + i)[0]);
            yes += vote;
            RawElGamalCiphertext raw = fromVector(ref, i);
            ElGamalCiphertext ciphertext = ElGamal.admit(raw, context, 1, opening(k, vote));
            assertEquals(BigInteger.ONE, ciphertext.bound());
            assertPoint(ref, "A" + i, ciphertext.handle());
            assertPoint(ref, "B" + i, ciphertext.blinded());
            admitted.add(ciphertext);
        }
        ElGamalCiphertext total = ElGamalCiphertext.sum(admitted);
        assertPoint(ref, "sumA", total.handle());
        assertPoint(ref, "sumB", total.blinded());
        assertEquals(BigInteger.valueOf(5), total.bound());

        List<VerifiedDecryptionShare> shares = new ArrayList<>();
        for (int j = 1; j <= 3; j++) {
            VerifiedDecryptionShare share = ElGamal.decryptionShare(trustees.get(j - 1), total);
            assertPoint(ref, "D" + j, share.share());
            assertEquals(List.of(total.handle().affineU(), total.handle().affineV()), share.statement().publicInputs().subList(0, 2),
                    "the share's DLEQ base is the admitted sum's handle");
            shares.add(share);
        }
        assertPoint(ref, "M", RawElGamalCiphertext.unmask(total.blinded(), shares.stream().map(VerifiedDecryptionShare::share).toList()));
        long tally = ElGamal.decrypt(total, shares, total.bound().longValueExact());
        assertEquals(Long.parseLong(ref.get("tally T")[0]), tally);
        assertEquals(yes, tally);
    }

    @Test
    @DisplayName("Reference ciphertexts: a wrong opening, a tampered B, another context and a missing share are refused")
    void referenceNegatives() throws IOException {
        Map<String, String[]> ref = reference();
        List<ElGamalSecretKey> trustees = new ArrayList<>();
        for (int j = 1; j <= 3; j++) {
            trustees.add(ElGamalSecretKey.of(new BigInteger(ref.get("scalar sk" + j)[0], 16)));
        }
        NOfNKeyContext context = ElGamalPublicKey.aggregate(trustees.stream().map(VerifiedKeyShare::fromSecret).toList());
        BigInteger k1 = new BigInteger(ref.get("scalar k1")[0], 16);
        RawElGamalCiphertext ballot1 = fromVector(ref, 1);

        // Ballot 1 encrypts 1: the opening check refuses it as a 0, and with another k.
        assertThrows(IllegalArgumentException.class, () -> ElGamal.admit(ballot1, context, 1, opening(k1, 0)));
        assertThrows(IllegalArgumentException.class, () -> ElGamal.admit(ballot1, context, 1, opening(k1.add(BigInteger.ONE), 1)));
        // B + G with the reference opening: refused.
        RawElGamalCiphertext tampered = RawElGamalCiphertext.of(ballot1.handle(), ballot1.blinded().add(G));
        assertThrows(IllegalArgumentException.class, () -> ElGamal.admit(tampered, context, 1, opening(k1, 1)));
        // Under a single trustee's context the statement's key differs: refused.
        NOfNKeyContext single = NOfNKeyContext.singleKey(trustees.getFirst());
        assertThrows(IllegalArgumentException.class, () -> ElGamal.admit(ballot1, single, 1, opening(k1, 1)));

        ElGamalCiphertext admitted = ElGamal.admit(ballot1, context, 1, opening(k1, 1));
        // n-of-n: two shares do not decrypt, a repeated share does not stand in for the third.
        List<VerifiedDecryptionShare> two = List.of(
                ElGamal.decryptionShare(trustees.get(0), admitted), ElGamal.decryptionShare(trustees.get(1), admitted));
        assertThrows(IllegalArgumentException.class, () -> ElGamal.decrypt(admitted, two, 1));
        assertThrows(IllegalArgumentException.class, () -> ElGamal.decrypt(admitted,
                List.of(two.get(0), two.get(1), two.get(0)), 1));
        // A ciphertext under another context cannot be added to this one.
        ElGamalCiphertext foreign = ElGamal.encrypt(single, BigInteger.ONE, 1, RANDOM);
        assertThrows(IllegalArgumentException.class, () -> admitted.add(foreign));
    }

    @Test
    @DisplayName("Random elections: the decrypted sum is the number of YES votes")
    void randomRoundTrips() {
        for (int round = 0; round < 5; round++) {
            List<ElGamalSecretKey> trustees = List.of(ElGamalSecretKey.generate(RANDOM),
                    ElGamalSecretKey.generate(RANDOM), ElGamalSecretKey.generate(RANDOM));
            NOfNKeyContext context = ElGamalPublicKey.aggregate(trustees.stream().map(VerifiedKeyShare::fromSecret).toList());
            List<ElGamalCiphertext> ballots = new ArrayList<>();
            int yes = 0;
            for (int i = 0; i < 7; i++) {
                int vote = RANDOM.nextBoolean() ? 1 : 0;
                yes += vote;
                ballots.add(ElGamal.encrypt(context, BigInteger.valueOf(vote), 1, RANDOM));
            }
            ElGamalCiphertext sum = ElGamalCiphertext.sum(ballots);
            List<VerifiedDecryptionShare> shares = trustees.stream().map(t -> ElGamal.decryptionShare(t, sum)).toList();
            assertEquals(yes, ElGamal.decrypt(sum, shares, sum.bound().longValueExact()));
        }
    }

    @Test
    @DisplayName("Joint key: empty, duplicate, identity, non-subgroup and cancelling keys are refused")
    void jointKeyChecks() {
        ElGamalSecretKey a = ElGamalSecretKey.of(BigInteger.valueOf(5));
        ElGamalSecretKey minusA = ElGamalSecretKey.of(JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.valueOf(5)));
        assertThrows(IllegalArgumentException.class, () -> ElGamalPublicKey.aggregate(List.of()));
        assertThrows(IllegalArgumentException.class, () -> ElGamalPublicKey.aggregate(
                List.of(VerifiedKeyShare.fromSecret(a), VerifiedKeyShare.fromSecret(a))));
        assertThrows(IllegalArgumentException.class, () -> ElGamalPublicKey.aggregate(
                List.of(VerifiedKeyShare.fromSecret(a), VerifiedKeyShare.fromSecret(minusA))));
        // Neither the identity nor a point with a small-order component is a registrable key,
        // even with a verifier that accepts anything.
        assertThrows(IllegalArgumentException.class, () -> VerifiedKeyShare.verify(JubjubPoint.IDENTITY, s -> true));
        JubjubPoint smallOrder = JubjubPoint.fromAffine(BigInteger.ZERO, JubjubCurve.BASE_FIELD_PRIME.subtract(BigInteger.ONE));
        assertThrows(IllegalArgumentException.class,
                () -> VerifiedKeyShare.verify(a.publicKey().point().add(smallOrder), s -> true));
        assertThrows(IllegalArgumentException.class, () -> ElGamalSecretKey.of(BigInteger.ZERO));
    }

    @Test
    @DisplayName("Ledger points: non-canonical, off-curve and small-order coordinates are refused")
    void ledgerPointChecks() {
        JubjubPoint g = G.normalized();
        BigInteger p = JubjubCurve.BASE_FIELD_PRIME;
        BigInteger u = g.affineU();
        BigInteger v = g.affineV();
        assertThrows(IllegalArgumentException.class, () -> RawElGamalCiphertext.fromAffine(u.add(p), v, u, v));
        assertThrows(IllegalArgumentException.class, () -> RawElGamalCiphertext.fromAffine(u, v, u, v.add(p)));
        assertThrows(IllegalArgumentException.class, () -> RawElGamalCiphertext.fromAffine(BigInteger.ONE, BigInteger.ONE, u, v));
        assertThrows(IllegalArgumentException.class,
                () -> RawElGamalCiphertext.fromAffine(u, v, BigInteger.ZERO, p.subtract(BigInteger.ONE)));
        assertThrows(IllegalArgumentException.class,
                () -> RawElGamalCiphertext.fromAffine(u, v, u.negate(), v));
        RawElGamalCiphertext ok = RawElGamalCiphertext.fromAffine(u, v, BigInteger.ZERO, BigInteger.ONE);
        assertTrue(ok.handle().projectiveEquals(g));
        assertTrue(ok.blinded().isIdentity(), "the identity is a valid A or B (spec §7.2)");
    }

    @Test
    @DisplayName("Encryption refuses votes outside the 1-bit width")
    void encryptRejectsBadInput() {
        NOfNKeyContext context = NOfNKeyContext.singleKey(ElGamalSecretKey.generate(RANDOM));
        assertThrows(IllegalArgumentException.class, () -> ElGamal.encrypt(context, BigInteger.TWO, 1, RANDOM));
        assertThrows(IllegalArgumentException.class, () -> ElGamal.encrypt(context, BigInteger.ONE.negate(), 1, RANDOM));
        assertThrows(IllegalArgumentException.class, () -> ElGamal.encrypt(context, BigInteger.ONE, 0, RANDOM));
    }

    // ------------------------------------------------------------------

    /**
     * Admission by opening: accepts only width 1, a vote of 0 or 1, and
     * {@code A = [k]·G}, {@code B = [v]·G + [k]·PK} for the statement's own key. Raw point
     * arithmetic on public test values.
     */
    private static EncryptionStatementVerifier opening(BigInteger k, int vote) {
        return statement -> statement.width() == 1 && (vote == 0 || vote == 1)
                && statement.handle().projectiveEquals(G.scalarMul(k))
                && statement.blinded().projectiveEquals(
                        G.scalarMul(BigInteger.valueOf(vote)).add(statement.key().point().scalarMul(k)));
    }

    private static RawElGamalCiphertext fromVector(Map<String, String[]> ref, int i) {
        String[] a = ref.get("A" + i);
        String[] b = ref.get("B" + i);
        return RawElGamalCiphertext.fromAffine(new BigInteger(a[0], 16), new BigInteger(a[1], 16),
                new BigInteger(b[0], 16), new BigInteger(b[1], 16));
    }

    private static Map<String, String[]> reference() throws IOException {
        Map<String, String[]> out = new HashMap<>();
        try (InputStream in = ElGamalCompatibilityTest.class.getResourceAsStream("/elgamal-reference/reference-output.txt")) {
            String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            for (String line : text.split("\n")) {
                String[] f = line.trim().split(" ");
                if (f[0].equals("scalar") || f[0].equals("vote") || f[0].equals("tally")) {
                    out.put(f[0] + " " + f[1], new String[] {f[2]});
                } else if (f.length == 3) {
                    out.put(f[0], new String[] {f[1], f[2]});
                }
            }
        }
        return out;
    }

    private static void assertPoint(Map<String, String[]> ref, String name, JubjubPoint actual) {
        String[] uv = ref.get(name);
        JubjubPoint n = actual.normalized();
        assertEquals(new BigInteger(uv[0], 16), n.affineU(), name + ".u");
        assertEquals(new BigInteger(uv[1], 16), n.affineV(), name + ".v");
    }
}
