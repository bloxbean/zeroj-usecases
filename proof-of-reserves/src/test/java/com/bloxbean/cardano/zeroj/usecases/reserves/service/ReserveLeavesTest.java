package com.bloxbean.cardano.zeroj.usecases.reserves.service;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.zeroj.usecases.reserves.model.AccountEntity;
import com.bloxbean.cardano.zeroj.usecases.reserves.verify.CustomerCheck;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0009 D4.1: the id encoding, with vectors for the empty id, 31 and 32 bytes and leading zero
 * bytes. Expected values are spelled out here with ZeroJ's {@link PoseidonHash} and blake2b, not
 * taken from {@link ReserveLeaves}.
 */
class ReserveLeavesTest {

    private static final PoseidonParams P = PoseidonParamsBLS12_381T3.INSTANCE;

    private static BigInteger h(BigInteger a, BigInteger b) {
        return PoseidonHash.hash(P, a, b);
    }

    private static BigInteger domainTag() {
        byte[] d = Blake2bUtil.blake2bHash256("zeroj.reserves.id.v1".getBytes(StandardCharsets.UTF_8));
        d[0] = 0;
        return new BigInteger(1, d);
    }

    /** A 31-byte chunk: {@code bytes} at the front, zeros after. */
    private static BigInteger chunk(byte... bytes) {
        byte[] c = new byte[31];
        System.arraycopy(bytes, 0, c, 0, bytes.length);
        return new BigInteger(1, c);
    }

    private static byte[] repeat(char ch, int n) {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) ch);
        return b;
    }

    @Test
    void domainTagIsBlake2bWithTopByteCleared() {
        assertEquals(domainTag(), ReserveLeaves.ID_TAG_DOMAIN);
        assertTrue(ReserveLeaves.ID_TAG_DOMAIN.bitLength() <= 248);
    }

    @Test
    void emptyIdFoldsOnlyTheLength() {
        assertEquals(h(domainTag(), BigInteger.ZERO), ReserveLeaves.idTag(""));
    }

    @Test
    void thirtyOneBytesIsOneChunk() {
        BigInteger expected = h(h(domainTag(), BigInteger.valueOf(31)), new BigInteger(1, repeat('a', 31)));
        assertEquals(expected, ReserveLeaves.idTag("a".repeat(31)));
    }

    @Test
    void thirtyTwoBytesIsTwoChunksWithTheLastRightPadded() {
        BigInteger expected = h(h(h(domainTag(), BigInteger.valueOf(32)), new BigInteger(1, repeat('a', 31))), chunk((byte) 'a'));
        assertEquals(expected, ReserveLeaves.idTag("a".repeat(32)));
    }

    @Test
    void leadingZeroBytesAreKept() {
        byte[] alice = "alice".getBytes(StandardCharsets.UTF_8);
        byte[] zeros = new byte[] {0, 0, 'a', 'l', 'i', 'c', 'e'};
        assertEquals(h(h(domainTag(), BigInteger.valueOf(7)), chunk(zeros)), ReserveLeaves.idTag("\0\0alice"));
        assertEquals(h(h(domainTag(), BigInteger.valueOf(5)), chunk(alice)), ReserveLeaves.idTag("alice"));
        assertNotEquals(ReserveLeaves.idTag("alice"), ReserveLeaves.idTag("\0\0alice"));
        assertNotEquals(ReserveLeaves.idTag(""), ReserveLeaves.idTag("\0"));
    }

    @Test
    void lengthSeparatesTrailingZeros() {
        // "a" and "a\0" share their padded chunk; the length tells them apart.
        assertEquals(chunk((byte) 'a'), chunk((byte) 'a', (byte) 0));
        assertNotEquals(ReserveLeaves.idTag("a"), ReserveLeaves.idTag("a\0"));
    }

    @Test
    void distinctIdsGiveDistinctTags() {
        Set<BigInteger> tags = new HashSet<>();
        for (String id : List.of("", "\0", "\0\0", "a", "a\0", "\0a", "a".repeat(31), "a".repeat(32), "a".repeat(62),
                "a".repeat(63), "büro-€")) {
            assertTrue(tags.add(ReserveLeaves.idTag(id)), "collision for " + id);
        }
    }

    @Test
    void leafIsPoseidonOfSaltedIdAndBalance() {
        BigInteger salt = new BigInteger(252, new SecureRandom());
        BigInteger saltedId = h(ReserveLeaves.idTag("bob"), salt);
        assertEquals(saltedId, ReserveLeaves.saltedId("bob", salt));
        assertEquals(h(saltedId, BigInteger.valueOf(42)), ReserveLeaves.leaf(saltedId, BigInteger.valueOf(42)));
    }

    @Test
    void saltsAre252Bits() {
        var rng = new SecureRandom();
        for (int i = 0; i < 64; i++) assertTrue(ReserveLeaves.randomSalt(rng).bitLength() <= 252);
        assertThrows(IllegalArgumentException.class, () -> ReserveLeaves.saltedId("bob", BigInteger.ONE.shiftLeft(252)));
        assertThrows(IllegalArgumentException.class, () -> ReserveLeaves.saltedId("bob", BigInteger.valueOf(-1)));
    }

    // ------------------------------------------------------------------
    //  Snapshots
    // ------------------------------------------------------------------

    private static List<AccountEntity> book() {
        return List.of(new AccountEntity("alice", "Alice", 500_000_000L), new AccountEntity("bob", "Bob", 1_200_000_000L),
                new AccountEntity("charlie", "Charlie", 300_000_000L));
    }

    @Test
    void everySnapshotDrawsFreshSaltsAndPadding() {
        var rng = new SecureRandom();
        var a = MerkleSumTreeService.build(book(), 3, rng);
        var b = MerkleSumTreeService.build(book(), 3, rng);
        assertEquals(a.totalLiabilities(), b.totalLiabilities());
        assertNotEquals(a.root(), b.root());
        for (int i = 0; i < 8; i++) {
            assertNotEquals(a.leafIds()[i], b.leafIds()[i], "leaf " + i + " repeats across snapshots");
            assertNotEquals(h(BigInteger.ZERO, BigInteger.ZERO), a.tree()[0][i], "padding leaf is Poseidon(0, 0)");
        }
    }

    @Test
    void inclusionPathRecomputesTheRoot() {
        var s = MerkleSumTreeService.build(book(), 3, new SecureRandom());
        for (var acc : book()) {
            var p = s.inclusionProof(acc.getAccountId());
            var in = new CustomerCheck.Inclusion(acc.getAccountId(), p.salt(), p.balance(), p.leafIndex(),
                    Arrays.asList(p.siblings()));
            assertEquals(s.root(), CustomerCheck.recomputeRoot(in));
        }
        assertNull(s.inclusionProof("mallory"));
    }

    @Test
    void tooManyAccountsRefused() {
        assertThrows(IllegalStateException.class, () -> MerkleSumTreeService.build(book(), 1, new SecureRandom()));
    }
}
