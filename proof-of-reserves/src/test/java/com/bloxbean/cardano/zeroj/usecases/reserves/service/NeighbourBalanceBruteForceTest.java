package com.bloxbean.cardano.zeroj.usecases.reserves.service;

import com.bloxbean.cardano.zeroj.usecases.reserves.model.AccountEntity;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * ADR-0009 I1 regression for D4: a customer holds their own path, so they see their neighbour's
 * leaf. Knowing the neighbour's id and the balance domain (whole ADA up to 10,000), they try every
 * balance. Without the neighbour's salt nothing matches; the same search against the old unsalted
 * leaf, and against the salted leaf given the salt, finds the balance (the controls show the search
 * itself works). This is a regression check, not a proof of hiding.
 */
class NeighbourBalanceBruteForceTest {

    private static final long MAX_ADA = 10_000;

    @Test
    void neighbourBalanceIsNotRecoverableWithoutTheSalt() {
        var book = List.of(new AccountEntity("alice", "Alice", 500_000_000L),
                new AccountEntity("bob", "Bob", 1_200_000_000L));
        var snapshot = MerkleSumTreeService.build(book, 2, new SecureRandom());
        // Alice's path: her level-0 sibling is Bob's leaf.
        BigInteger bobLeaf = snapshot.inclusionProof("alice").siblings()[0];
        BigInteger bobTag = ReserveLeaves.idTag("bob");

        // The attacker's guesses: the salted id with a guessable salt, the id tag alone, the old encoding.
        assertNull(search(bobLeaf, ReserveLeaves.saltedId("bob", BigInteger.ZERO)));
        assertNull(search(bobLeaf, ReserveLeaves.saltedId("bob", BigInteger.ONE)));
        assertNull(search(bobLeaf, bobTag));
        assertNull(search(bobLeaf, new BigInteger(1, "bob".getBytes(StandardCharsets.UTF_8))));

        // Controls: with Bob's salt the search finds his balance, and the old unsalted leaf fell to it.
        BigInteger bobSalt = snapshot.salts()[1];
        assertEquals(1_200_000_000L, search(bobLeaf, ReserveLeaves.saltedId("bob", bobSalt)));
        BigInteger oldId = new BigInteger(1, "bob".getBytes(StandardCharsets.UTF_8));
        BigInteger oldLeaf = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, oldId, BigInteger.valueOf(1_200_000_000L));
        assertEquals(1_200_000_000L, search(oldLeaf, oldId));
    }

    /** The balance in whole ADA ≤ {@link #MAX_ADA} with {@code leaf = Poseidon(id, balance)}, or null. */
    private static Long search(BigInteger leaf, BigInteger id) {
        for (long ada = 0; ada <= MAX_ADA; ada++) {
            long lovelace = ada * 1_000_000L;
            if (ReserveLeaves.leaf(id, BigInteger.valueOf(lovelace)).equals(leaf)) return lovelace;
        }
        return null;
    }
}
