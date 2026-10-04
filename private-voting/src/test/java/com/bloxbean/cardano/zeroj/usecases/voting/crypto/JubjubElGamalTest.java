package com.bloxbean.cardano.zeroj.usecases.voting.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Host-side ElGamal and tally (ADR-0005), checked against an independent Python reference
 * ({@code src/test/resources/elgamal-reference/elgamal_reference.py}) that re-implements Jubjub
 * from the curve definition without ZeroJ.
 */
class JubjubElGamalTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    @DisplayName("Reference vectors: keys, ballots, sums, shares and the tally match the Python reference")
    void matchesIndependentReference() throws IOException {
        Map<String, String[]> ref = reference();
        assertPoint(ref, "G", JubjubElGamal.G);

        List<BigInteger> sks = new ArrayList<>();
        List<JubjubPoint> pks = new ArrayList<>();
        for (int j = 1; j <= 3; j++) {
            BigInteger sk = new BigInteger(ref.get("scalar sk" + j)[0], 16);
            sks.add(sk);
            pks.add(JubjubElGamal.G.scalarMul(sk));
            assertPoint(ref, "PK" + j, pks.get(j - 1));
        }
        JubjubPoint pk = JubjubElGamal.jointKey(pks);
        assertPoint(ref, "PK", pk);

        List<JubjubElGamal.Ciphertext> ballots = new ArrayList<>();
        int yes = 0;
        for (int i = 1; i <= 5; i++) {
            BigInteger k = new BigInteger(ref.get("scalar k" + i)[0], 16);
            int vote = Integer.parseInt(ref.get("vote v" + i)[0]);
            yes += vote;
            var c = JubjubElGamal.encrypt(vote, k, pk);
            assertPoint(ref, "A" + i, c.handle());
            assertPoint(ref, "B" + i, c.ballot());
            ballots.add(c);
        }
        var sum = JubjubElGamal.sum(ballots);
        assertPoint(ref, "sumA", sum.handle());
        assertPoint(ref, "sumB", sum.ballot());

        List<JubjubPoint> shares = new ArrayList<>();
        for (int j = 1; j <= 3; j++) {
            JubjubPoint d = JubjubElGamal.decryptionShare(sks.get(j - 1), sum.handle());
            assertPoint(ref, "D" + j, d);
            shares.add(d);
        }
        JubjubPoint m = JubjubElGamal.unmask(sum.ballot(), shares);
        assertPoint(ref, "M", m);
        assertEquals(Integer.parseInt(ref.get("tally T")[0]), JubjubElGamal.discreteLog(m, 5).orElseThrow());
        assertEquals(yes, JubjubElGamal.discreteLog(m, 5).orElseThrow());
    }

    @Test
    @DisplayName("Random elections: the decrypted sum is the number of YES votes; missing a share fails")
    void randomRoundTrips() {
        for (int round = 0; round < 5; round++) {
            List<BigInteger> sks = List.of(JubjubElGamal.randomNonZeroScalar(RANDOM),
                    JubjubElGamal.randomNonZeroScalar(RANDOM), JubjubElGamal.randomNonZeroScalar(RANDOM));
            JubjubPoint pk = JubjubElGamal.jointKey(sks.stream().map(JubjubElGamal.G::scalarMul).toList());
            List<JubjubElGamal.Ciphertext> ballots = new ArrayList<>();
            int yes = 0;
            for (int i = 0; i < 7; i++) {
                int vote = RANDOM.nextBoolean() ? 1 : 0;
                yes += vote;
                ballots.add(JubjubElGamal.encrypt(vote, JubjubElGamal.randomScalar(RANDOM), pk));
            }
            var sum = JubjubElGamal.sum(ballots);
            List<JubjubPoint> shares = sks.stream().map(sk -> JubjubElGamal.decryptionShare(sk, sum.handle())).toList();
            assertEquals(yes, JubjubElGamal.discreteLog(JubjubElGamal.unmask(sum.ballot(), shares), 7).orElseThrow());
            // n-of-n: two shares are not enough.
            assertTrue(JubjubElGamal.discreteLog(JubjubElGamal.unmask(sum.ballot(), shares.subList(0, 2)), 7).isEmpty());
        }
    }

    @Test
    @DisplayName("Joint key: duplicate, identity, non-subgroup and cancelling keys are refused")
    void jointKeyChecks() {
        JubjubPoint a = JubjubElGamal.G.scalarMul(BigInteger.valueOf(5));
        assertThrows(IllegalArgumentException.class, () -> JubjubElGamal.jointKey(List.of()));
        assertThrows(IllegalArgumentException.class, () -> JubjubElGamal.jointKey(List.of(a, a)));
        assertThrows(IllegalArgumentException.class, () -> JubjubElGamal.jointKey(List.of(a, JubjubPoint.IDENTITY)));
        assertThrows(IllegalArgumentException.class, () -> JubjubElGamal.jointKey(List.of(a, a.negate())));
        JubjubPoint smallOrder = JubjubPoint.fromAffine(BigInteger.ZERO, JubjubCurve.BASE_FIELD_PRIME.subtract(BigInteger.ONE));
        assertThrows(IllegalArgumentException.class, () -> JubjubElGamal.jointKey(List.of(a, a.add(smallOrder))));
    }

    @Test
    @DisplayName("Ledger points: non-canonical, off-curve and small-order coordinates are refused")
    void ledgerPointChecks() {
        JubjubPoint g = JubjubElGamal.G.normalized();
        BigInteger p = JubjubCurve.BASE_FIELD_PRIME;
        assertThrows(IllegalArgumentException.class,
                () -> JubjubElGamal.subgroupPoint(g.affineU().add(p), g.affineV()));
        assertThrows(IllegalArgumentException.class,
                () -> JubjubElGamal.subgroupPoint(BigInteger.ONE, BigInteger.ONE));
        assertThrows(IllegalArgumentException.class,
                () -> JubjubElGamal.subgroupPoint(BigInteger.ZERO, p.subtract(BigInteger.ONE)));
        assertTrue(JubjubElGamal.subgroupPoint(g.affineU(), g.affineV()).projectiveEquals(g));
    }

    @Test
    @DisplayName("Encryption refuses votes other than 0/1 and scalars outside [0, l)")
    void encryptRejectsBadInput() {
        JubjubPoint pk = JubjubElGamal.G.scalarMul(BigInteger.TEN);
        assertThrows(IllegalArgumentException.class, () -> JubjubElGamal.encrypt(2, BigInteger.ONE, pk));
        assertThrows(IllegalArgumentException.class, () -> JubjubElGamal.encrypt(1, JubjubElGamal.L, pk));
        assertThrows(IllegalArgumentException.class, () -> JubjubElGamal.encrypt(1, BigInteger.valueOf(-1), pk));
        assertFalse(JubjubElGamal.encrypt(0, BigInteger.ONE, pk).ballot().isIdentity());
    }

    private static Map<String, String[]> reference() throws IOException {
        Map<String, String[]> out = new HashMap<>();
        try (InputStream in = JubjubElGamalTest.class.getResourceAsStream("/elgamal-reference/reference-output.txt")) {
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
