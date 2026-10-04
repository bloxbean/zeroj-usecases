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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Demo C: the solvency relation, the customer check and the auditor's aggregate opening. */
class SolvencyCircuitTest {

    static final int N = 4;
    private static SolvencyAttestation solvency;

    static List<Customer> book() {
        return List.of(Customer.of("alice", 500_000_000L), Customer.of("bob", 1_200_000_000L),
                Customer.of("carol", 300_000_000L), Customer.of("dave", 0));
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
    @DisplayName("Customer check: own entry exactly once and opening; ambiguous ids and duplicates are caught")
    void customerCheck() {
        var book = book();
        List<Entry> entries = SolvencyAttestation.entries(book);
        for (Customer c : book) assertTrue(SolvencyAttestation.customerCheck(entries, c));
        // Understated balance: the entry no longer opens to the customer's balance.
        Customer alice = book.getFirst();
        var cheaper = new ArrayList<>(entries);
        cheaper.set(0, new Entry(alice.idHash(), PedersenCommitment.commit(BigInteger.ONE, alice.blinding()).normalized()));
        assertFalse(SolvencyAttestation.customerCheck(cheaper, alice));
        // Listed twice (e.g. to show two views): refused.
        var twice = new ArrayList<>(entries);
        twice.set(3, entries.getFirst());
        assertFalse(SolvencyAttestation.customerCheck(twice, alice));
        // The encoding is unambiguous (length prefix, fixed-size salt): ids that share a prefix,
        // with salts chosen to line up the bytes, still hash differently.
        byte[] s = new byte[32];
        byte[] s3 = s.clone();
        s3[0] = '3';
        Customer a = new Customer("12", s3, 1, BigInteger.ONE);
        Customer b = new Customer("123", s, 1, BigInteger.ONE);
        assertFalse(Arrays.equals(a.idHash(), b.idHash()));
    }

    @Test
    @DisplayName("Auditor: the sum of the commitments opens to total liabilities, and to nothing else")
    void auditorOpening() {
        var book = book();
        List<Entry> entries = SolvencyAttestation.entries(book);
        AuditOpening opening = SolvencyAttestation.auditOpening(book);
        assertTrue(SolvencyAttestation.auditorCheck(entries, opening));
        assertFalse(SolvencyAttestation.auditorCheck(entries,
                new AuditOpening(opening.liabilities().subtract(BigInteger.ONE), opening.blinding())));
    }
}
