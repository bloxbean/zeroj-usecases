package com.bloxbean.cardano.zeroj.usecases.pedersen.solvency;

import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.AuditOpening;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Customer;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Entry;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.circuit.HiddenLiabilitySolvencyProofCircuit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Check;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Attestation;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;
import org.zeroj.circuit.lib.jubjub.NoteOpening;
import org.zeroj.circuit.lib.jubjub.ConfidentialNotes;
import java.util.Map;
import java.util.LinkedHashMap;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Demo C: the solvency relation, the customer check and the auditor's aggregate opening. */
class SolvencyCircuitTest {

    static final int N = 4;
    private static SolvencyAttestation solvency;

    static final Map<String, NoteViewingKey> KEYS = new LinkedHashMap<>();

    static {
        for (String id : List.of("alice", "bob", "carol", "dave")) KEYS.put(id, NoteViewingKey.generate(new SecureRandom()));
    }

    static List<Customer> book() {
        return List.of(Customer.of("alice", 500_000_000L, KEYS.get("alice").readerKey()),
                Customer.of("bob", 1_200_000_000L, KEYS.get("bob").readerKey()),
                Customer.of("carol", 300_000_000L, KEYS.get("carol").readerKey()),
                Customer.of("dave", 0, KEYS.get("dave").readerKey()));
    }

    @BeforeAll
    static void setup() {
        solvency = new SolvencyAttestation(N);
    }

    @Test
    @DisplayName("Solvent book proves; every public input is bound; liabilities equal to reserves are allowed")
    void solventProves() {
        var book = book();
        long reserves = 2_000_000_000L;
        var proof = solvency.prove(reserves, book);
        List<BigInteger> pub = HiddenLiabilitySolvencyProofCircuit.publicInputs(SolvencyAttestation.inputs(reserves, book));
        assertTrue(solvency.circuit().verify(proof, pub));
        for (int i = 0; i < pub.size(); i++) {
            List<BigInteger> changed = new ArrayList<>(pub);
            changed.set(i, changed.get(i).add(BigInteger.ONE));
            assertFalse(solvency.circuit().verify(proof, changed), "public input " + i + " not bound");
        }
        assertDoesNotThrow(() -> solvency.circuit().circuit().calculateWitness(
                SolvencyAttestation.inputs(2_000_000_000L, book).toWitnessMap(), CurveId.BLS12_381));
        System.out.println("[hidden-liability-solvency-n4] constraints: " + solvency.circuit().numConstraints());
    }

    @Test
    @DisplayName("No witness when liabilities exceed reserves, a commitment is wrong, or a balance is not 64-bit")
    void insolventOrMalformedHasNoWitness() {
        var circuit = solvency.circuit().circuit();
        var book = book();
        assertThrows(RuntimeException.class, () -> circuit.calculateWitness(
                SolvencyAttestation.inputs(1_999_999_999L, book).toWitnessMap(), CurveId.BLS12_381));
        // Understating alice's balance in the proof while publishing her real commitment.
        var understated = SolvencyAttestation.inputs(2_000_000_000L, book);
        understated.balances(List.of(BigInteger.ONE, BigInteger.valueOf(1_200_000_000L),
                BigInteger.valueOf(300_000_000L), BigInteger.ZERO));
        assertThrows(RuntimeException.class, () -> circuit.calculateWitness(understated.toWitnessMap(), CurveId.BLS12_381));
        // A balance of 2^64 cannot be committed as a 64-bit amount.
        BigInteger huge = BigInteger.ONE.shiftLeft(64);
        BigInteger r = PedersenCommitment.randomBlinding(new SecureRandom());
        var c = PedersenCommitment.commit(huge, r).normalized();
        var overflow = SolvencyAttestation.inputs(2_000_000_000L, book);
        var us = new ArrayList<>(book.stream().map(x -> x.commitment().affineU()).toList());
        var vs = new ArrayList<>(book.stream().map(x -> x.commitment().affineV()).toList());
        us.set(3, c.affineU());
        vs.set(3, c.affineV());
        overflow.liabilityU(us).liabilityV(vs)
                .balances(List.of(BigInteger.valueOf(500_000_000L), BigInteger.valueOf(1_200_000_000L),
                        BigInteger.valueOf(300_000_000L), huge))
                .blindings(List.of(book.get(0).blinding(), book.get(1).blinding(), book.get(2).blinding(), r));
        assertThrows(RuntimeException.class, () -> circuit.calculateWitness(overflow.toWitnessMap(), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("Customer check from on-chain deliveries: own entry exactly once, opening to the balance; understated, duplicated and garbled entries are caught")
    void customerCheck() {
        var book = book();
        List<Entry> entries = SolvencyAttestation.entries(book);
        for (Customer c : book) {
            assertEquals(Check.LISTED_ONCE_CORRECT, SolvencyAttestation.customerCheck(entries, c, KEYS.get(c.id())));
        }
        Customer alice = book.getFirst();
        // Understated balance, delivered honestly: the opening is the understated one.
        var cheaper = new ArrayList<>(entries);
        BigInteger r = alice.blinding();
        var understated = NoteOpening.of(BigInteger.ONE, r);
        cheaper.set(0, new Entry(alice.idHash(), understated.commitment().normalized(),
                ConfidentialNotes.seal(understated, List.of(alice.readerKey()), new SecureRandom()).getFirst()));
        assertEquals(Check.WRONG_BALANCE, SolvencyAttestation.customerCheck(cheaper, alice, KEYS.get("alice")));
        // The real commitment with a delivery that does not open to it.
        var garbled = SolvencyAttestation.withGarbageFor(entries, book, "alice");
        assertEquals(Check.UNOPENABLE, SolvencyAttestation.customerCheck(garbled, alice, KEYS.get("alice")));
        // Another customer's key cannot read alice's entry.
        assertEquals(Check.UNOPENABLE, SolvencyAttestation.customerCheck(entries, alice, KEYS.get("bob")));
        // Listed twice (e.g. to show two views): refused.
        var twice = new ArrayList<>(entries);
        twice.set(3, entries.getFirst());
        assertEquals(Check.LISTED_TWICE, SolvencyAttestation.customerCheck(twice, alice, KEYS.get("alice")));
        assertEquals(Check.MISSING, SolvencyAttestation.customerCheck(entries.subList(1, 4), alice, KEYS.get("alice")));
        // Different ids give different id hashes. (The 32-byte salt is fixed-size, so id ‖ salt is
        // already unambiguous; the length prefix keeps it so if the salt format ever changes.) What
        // the encoding cannot stop is the exchange handing two customers the same id: ids must be
        // identifiers the customer can confirm and no one else shares (ADR-0006).
        byte[] s = new byte[32];
        assertFalse(Arrays.equals(new Customer("12", s, 1, BigInteger.ONE, alice.readerKey()).idHash(),
                new Customer("123", s, 1, BigInteger.ONE, alice.readerKey()).idHash()));
    }

    @Test
    @DisplayName("Auditor: its on-chain delivery opens to total liabilities against the sum of the commitments, and only there")
    void auditorOpening() {
        var book = book();
        List<Entry> entries = SolvencyAttestation.entries(book);
        NoteViewingKey auditor = NoteViewingKey.generate(new SecureRandom());
        byte[] delivery = SolvencyAttestation.auditorDelivery(book, auditor.readerKey());
        assertEquals(BigInteger.valueOf(2_000_000_000L),
                SolvencyAttestation.auditorCheck(new Attestation(entries, delivery), auditor).orElseThrow());
        // An entry dropped from the sum: the delivery no longer opens.
        assertTrue(SolvencyAttestation.auditorCheck(new Attestation(entries.subList(0, 3), delivery), auditor).isEmpty());
        // Another key cannot read it.
        assertTrue(SolvencyAttestation.auditorCheck(new Attestation(entries, delivery),
                NoteViewingKey.generate(new SecureRandom())).isEmpty());
        AuditOpening opening = SolvencyAttestation.auditOpening(book);
        assertEquals(BigInteger.valueOf(2_000_000_000L), opening.liabilities());
    }
}
