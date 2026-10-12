package com.bloxbean.cardano.zeroj.usecases.pedersen.solvency;

import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Attestation;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Check;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Customer;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Entry;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.circuit.HiddenLiabilitySolvencyProofCircuit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0009 D7 / I9: every attestation draws fresh salts and blindings and an independently
 * shuffled order; the proof, the entries and the deliveries follow that order, and each customer
 * still finds their own entry by id hash.
 */
class SolvencyFreshnessTest {

    private static final long RESERVES = 2_000_000_000L;
    private static final Map<String, NoteViewingKey> KEYS = SolvencyCircuitTest.KEYS;

    @Test
    @DisplayName("Two attestations of the same book differ in every id hash and every commitment")
    void attestationsShareNoIdHashOrCommitment() {
        List<Customer> book = SolvencyCircuitTest.book();
        List<Customer> first = SolvencyAttestation.forAttestation(book);
        List<Customer> second = SolvencyAttestation.forAttestation(book);
        List<List<Entry>> published = List.of(SolvencyAttestation.entries(book),
                SolvencyAttestation.entries(first), SolvencyAttestation.entries(second));
        Set<String> idHashes = new HashSet<>();
        Set<String> commitments = new HashSet<>();
        for (List<Entry> entries : published) {
            for (Entry e : entries) {
                assertTrue(idHashes.add(HexUtil.encodeHexString(e.idHash())), "an id hash repeats across attestations");
                var c = e.commitment().normalized();
                assertTrue(commitments.add(c.affineU() + ":" + c.affineV()), "a commitment repeats across attestations");
            }
        }
        // Same customers and balances, with their salt and blinding redrawn.
        for (Customer c : book) {
            Customer a = byId(first, c.id());
            Customer b = byId(second, c.id());
            assertEquals(c.balance(), a.balance());
            assertEquals(c.balance(), b.balance());
            assertTrue(a.readerKey() == c.readerKey() && b.readerKey() == c.readerKey());
            assertFalse(Arrays.equals(a.salt(), b.salt()) || Arrays.equals(a.salt(), c.salt()));
            assertFalse(a.blinding().equals(b.blinding()) || a.blinding().equals(c.blinding()));
        }
        assertEquals(book.size(), first.size());
    }

    @Test
    @DisplayName("Customers find their own entry by id hash in a shuffled attestation; a stale record finds nothing")
    void customersStillVerifyTheirOwnEntry() {
        List<Customer> book = SolvencyCircuitTest.book();
        List<Customer> previous = SolvencyAttestation.forAttestation(book);
        List<Customer> current = SolvencyAttestation.forAttestation(book);
        List<Entry> entries = SolvencyAttestation.entries(current);
        for (Customer c : current) {
            assertEquals(Check.LISTED_ONCE_CORRECT, SolvencyAttestation.customerCheck(entries, c, KEYS.get(c.id())), c.id());
            // Last period's salt matches nothing in this period: the two cannot be linked by id hash.
            assertEquals(Check.MISSING, SolvencyAttestation.customerCheck(entries, byId(previous, c.id()), KEYS.get(c.id())));
        }
        // The garbage cheat finds its victim by id hash, wherever the shuffle put them.
        var garbled = SolvencyAttestation.withGarbageFor(entries, current, "bob");
        for (Customer c : current) {
            assertEquals(c.id().equals("bob") ? Check.UNOPENABLE : Check.LISTED_ONCE_CORRECT,
                    SolvencyAttestation.customerCheck(garbled, c, KEYS.get(c.id())), c.id());
        }
        // The auditor's aggregate opening is order-independent and opens against these entries.
        NoteViewingKey auditor = NoteViewingKey.generate(new SecureRandom());
        byte[] delivery = SolvencyAttestation.auditorDelivery(current, auditor.readerKey());
        assertEquals(BigInteger.valueOf(RESERVES),
                SolvencyAttestation.auditorCheck(new Attestation(entries, delivery), auditor).orElseThrow());
    }

    @Test
    @DisplayName("The proof follows the shuffled order: it verifies against the datum's entries, not the book order")
    void proofFollowsTheShuffledOrder() {
        List<Customer> book = SolvencyCircuitTest.book();
        List<Customer> shuffled;
        do {
            shuffled = SolvencyAttestation.forAttestation(book);
        } while (ids(shuffled).equals(ids(book)));
        List<Customer> attested = shuffled;
        var solvency = new SolvencyAttestation(SolvencyCircuitTest.N);
        var proof = solvency.prove(RESERVES, attested);
        // Public inputs as the vault reads them from the datum: [R, u_1..u_N, v_1..v_N] in entry order.
        List<Entry> entries = SolvencyAttestation.entries(attested);
        List<BigInteger> fromDatum = new ArrayList<>();
        fromDatum.add(BigInteger.valueOf(RESERVES));
        entries.forEach(e -> fromDatum.add(e.commitment().normalized().affineU()));
        entries.forEach(e -> fromDatum.add(e.commitment().normalized().affineV()));
        assertEquals(fromDatum, HiddenLiabilitySolvencyProofCircuit.publicInputs(SolvencyAttestation.inputs(RESERVES, attested)));
        assertTrue(solvency.circuit().verify(proof, fromDatum));
        // The same customers' commitments in book order are another statement.
        List<Customer> inBookOrder = book.stream().map(c -> byId(attested, c.id())).toList();
        assertFalse(solvency.circuit().verify(proof,
                HiddenLiabilitySolvencyProofCircuit.publicInputs(SolvencyAttestation.inputs(RESERVES, inBookOrder))));
    }

    @Test
    @DisplayName("The entry order is shuffled uniformly and independently per attestation (statistical)")
    void orderIsShuffled() {
        List<Customer> book = SolvencyCircuitTest.book();
        int draws = 1_200;
        Map<List<String>, Integer> orders = new HashMap<>();
        int[] alicePosition = new int[book.size()];
        int repeatsOfPrevious = 0;
        List<String> previous = null;
        for (int i = 0; i < draws; i++) {
            List<String> order = ids(SolvencyAttestation.forAttestation(book));
            orders.merge(order, 1, Integer::sum);
            alicePosition[order.indexOf("alice")]++;
            if (order.equals(previous)) repeatsOfPrevious++;
            previous = order;
        }
        // 24 orders, each expected 50 times: all appear (a missing one has probability below 1e-20).
        assertEquals(24, orders.size(), "orders seen: " + orders.size());
        // Alice's position: 300 expected in each of four places, standard deviation 15.
        for (int count : alicePosition) assertTrue(count > 200 && count < 400, Arrays.toString(alicePosition));
        // Consecutive attestations repeat an order 1/24 of the time (about 50), not always.
        assertTrue(repeatsOfPrevious > 15 && repeatsOfPrevious < 100, "repeats: " + repeatsOfPrevious);
    }

    private static Customer byId(List<Customer> customers, String id) {
        return customers.stream().filter(c -> c.id().equals(id)).findFirst().orElseThrow();
    }

    private static List<String> ids(List<Customer> customers) {
        return customers.stream().map(Customer::id).toList();
    }
}
