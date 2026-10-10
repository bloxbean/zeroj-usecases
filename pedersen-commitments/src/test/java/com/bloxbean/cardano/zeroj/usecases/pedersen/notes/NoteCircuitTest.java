package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.circuit.NoteIssueProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.circuit.NoteRedeemProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.circuit.NoteTransferProofCircuit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalSecretKey;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.NoteOpening;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The note circuits (ADR-0007 N3, N4): honest proofs verify against exactly the public inputs the
 * ledger rebuilds, and every invalid witness of ZeroJ ADR-0055 I12 has no satisfying assignment.
 */
class NoteCircuitTest {

    static final SecureRandom RANDOM = new SecureRandom();
    static final byte[] ALICE = filled(28, (byte) 0x0a);
    static final byte[] BOB = filled(28, (byte) 0x0b);
    static final BigInteger TWO_32 = BigInteger.ONE.shiftLeft(32);

    static NoteProofs proofs;
    static AuditorKeys auditorKeys;
    static AdmittedAuditor auditor;
    static NoteViewingKey aliceView = NoteViewingKey.generate(RANDOM);
    static NoteViewingKey bobView = NoteViewingKey.generate(RANDOM);

    @BeforeAll
    static void setup() {
        proofs = NoteProofs.withIssuance();
        auditorKeys = AuditorKeys.generate(RANDOM);
        KeyPossession possession = new KeyPossession();
        byte[] registry = filled(28, (byte) 0x3e);
        auditor = AdmittedAuditor.admit(registry, auditorKeys.entry(registry, filled(28, (byte) 0xa1), 0, possession), possession);
        System.out.printf("[note circuits] transfer %d constraints / %d public; redeem %d / %d; issue1 %d / %d; issue2 %d / %d%n",
                proofs.transfer().numConstraints(), proofs.transfer().numPublicInputs(),
                proofs.redeem().numConstraints(), proofs.redeem().numPublicInputs(),
                proofs.issue(1).numConstraints(), proofs.issue(1).numPublicInputs(),
                proofs.issue(2).numConstraints(), proofs.issue(2).numPublicInputs());
    }

    static NoteProofs.Spent spent(long amount) {
        NoteOpening o = NoteOpening.random(BigInteger.valueOf(amount), RANDOM);
        JubjubPoint c = o.commitment().normalized();
        return new NoteProofs.Spent(o, c.affineU(), c.affineV());
    }

    static AuditedNote note(byte[] owner, long amount, NoteViewingKey view) {
        return AuditedNote.create(owner, amount, view.readerKey(), auditor, RANDOM);
    }

    @Test
    @DisplayName("Honest transfer, redeem and issuance proofs verify against the ledger's public inputs, and only those")
    void honest() {
        long big = 0x1_2345_6789L; // above 2^32, so both limbs are non-zero
        NoteProofs.Spent in = spent(big);
        AuditedNote o1 = note(BOB, 700, bobView);
        AuditedNote o2 = note(ALICE, big - 700, aliceView);
        var t = NoteProofs.transferInputs(in, o1, o2, auditor);
        List<BigInteger> tPublic = NoteTransferProofCircuit.publicInputs(t);
        assertEquals(24, tPublic.size());
        var tProof = proofs.proveTransfer(in, o1, o2, auditor);
        assertTrue(proofs.transfer().verify(tProof, tPublic));
        List<BigInteger> wrong = new java.util.ArrayList<>(tPublic);
        wrong.set(10, wrong.get(10).add(BigInteger.ONE));
        assertTrue(!proofs.transfer().verify(tProof, wrong), "an audit coordinate is bound");

        AuditedNote change = note(ALICE, big - 120, aliceView);
        var r = NoteProofs.redeemInputs(in, change, 120, auditor);
        assertEquals(15, NoteRedeemProofCircuit.publicInputs(r).size());
        assertTrue(proofs.redeem().verify(proofs.proveRedeem(in, change, 120, auditor), NoteRedeemProofCircuit.publicInputs(r)));

        for (int n = 1; n <= 2; n++) {
            List<AuditedNote> issued = n == 1 ? List.of(note(ALICE, 5_000, aliceView))
                    : List.of(note(ALICE, 5_000, aliceView), note(BOB, big, bobView));
            var i = NoteProofs.issueInputs(issued, auditor);
            List<BigInteger> iPublic = NoteIssueProofCircuit.publicInputs(i);
            assertEquals(10 * n + 2, iPublic.size());
            assertTrue(proofs.issue(n).verify(proofs.proveIssue(issued, auditor), iPublic));
        }
    }

    @Test
    @DisplayName("I12 invalid witnesses: wrong limb, limb at 2^32, swapped limbs, swapped notes, another key, another amount")
    void invalidTransferWitnesses() {
        NoteProofs.Spent in = spent(1_000);
        AuditedNote o1 = note(BOB, 700, bobView);
        AuditedNote o2 = note(ALICE, 300, aliceView);
        List<BigInteger> a1 = o1.audit();
        List<BigInteger> a2 = o2.audit();

        noTransferWitness(in, o1, o2, i -> i.o1L0(o1.limbs().get(0).message().add(BigInteger.ONE)),
                "a limb that is not the encrypted message");
        // L0 + 2^32 and L1 - 1 recombine to the same amount; encrypt them honestly (test fixture).
        BigInteger k0 = o1.limbs().get(0).randomness();
        BigInteger k1 = o1.limbs().get(1).randomness();
        BigInteger hi0 = o1.limbs().get(0).message().add(TWO_32);
        BigInteger lo1 = BigInteger.valueOf(700 >> 32).subtract(BigInteger.ONE);
        noTransferWitness(in, o1, o2, i -> {
            List<BigInteger> c0 = fixtureLimb(hi0, k0, auditorKeys.elgamal().publicKey().point());
            List<BigInteger> c1 = fixtureLimb(lo1.mod(org.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER), k1,
                    auditorKeys.elgamal().publicKey().point());
            i.o1L0(hi0).o1L1(lo1.mod(org.zeroj.circuit.lib.jubjub.JubjubCurve.BASE_FIELD_PRIME))
                    .o1a0u(c0.get(0)).o1a0v(c0.get(1)).o1b0u(c0.get(2)).o1b0v(c0.get(3))
                    .o1a1u(c1.get(0)).o1a1v(c1.get(1)).o1b1u(c1.get(2)).o1b1v(c1.get(3));
        }, "a limb at or above 2^32");
        noTransferWitness(in, o1, o2, i -> i
                .o1a0u(a1.get(4)).o1a0v(a1.get(5)).o1b0u(a1.get(6)).o1b0v(a1.get(7))
                .o1a1u(a1.get(0)).o1a1v(a1.get(1)).o1b1u(a1.get(2)).o1b1v(a1.get(3)), "limb ciphertexts swapped");
        noTransferWitness(in, o1, o2, i -> i
                .o1a0u(a2.get(0)).o1a0v(a2.get(1)).o1b0u(a2.get(2)).o1b0v(a2.get(3))
                .o1a1u(a2.get(4)).o1a1v(a2.get(5)).o1b1u(a2.get(6)).o1b1v(a2.get(7))
                .o2a0u(a1.get(0)).o2a0v(a1.get(1)).o2b0u(a1.get(2)).o2b0v(a1.get(3))
                .o2a1u(a1.get(4)).o2a1v(a1.get(5)).o2b1u(a1.get(6)).o2b1v(a1.get(7)), "audit data swapped between notes");
        var stranger = ElGamalSecretKey.generate(RANDOM).publicKey();
        noTransferWitness(in, o1, o2, i -> i.pkU(stranger.affineU()).pkV(stranger.affineV()), "another key");
        var other = ElGamal.encryptWithOpening(auditor.context(), BigInteger.valueOf(701), 32, RANDOM);
        noTransferWitness(in, o1, o2, i -> {
            var ct = other.ciphertext();
            i.o1L0(other.message()).o1K0(other.randomness())
                    .o1a0u(ct.handle().affineU()).o1a0v(ct.handle().affineV())
                    .o1b0u(ct.blinded().affineU()).o1b0v(ct.blinded().affineV());
        }, "limbs of another amount");
    }

    @Test
    @DisplayName("Proved issuance: an issuer whose audit ciphertext under-reports the amount has no proof (Q9 (b))")
    void underReportedIssuanceHasNoProof() {
        AuditedNote honest = note(ALICE, 5_000, aliceView);
        AuditedNote understated = honest.withLimbs(AuditedNote.limbsOf(BigInteger.valueOf(500), auditor, RANDOM));
        assertThrows(RuntimeException.class, () -> proofs.proveIssue(List.of(understated), auditor));
        assertThrows(RuntimeException.class, () -> proofs.proveIssue(List.of(note(BOB, 9, bobView), understated), auditor));
        proofs.proveIssue(List.of(honest), auditor);
    }

    private static void noTransferWitness(NoteProofs.Spent in, AuditedNote o1, AuditedNote o2,
                                          Consumer<NoteTransferProofCircuit.Inputs> mutate, String what) {
        var inputs = NoteProofs.transferInputs(in, o1, o2, auditor);
        mutate.accept(inputs);
        Map<String, List<BigInteger>> w = inputs.toWitnessMap();
        assertThrows(RuntimeException.class, () -> proofs.transfer().prove(w), what);
    }

    /**
     * <b>Test fixture only.</b> A limb ciphertext from a chosen {@code m} and {@code k} with the
     * variable-time {@code scalarMul}, to build out-of-range limbs the library refuses to encrypt.
     */
    private static List<BigInteger> fixtureLimb(BigInteger m, BigInteger k, JubjubPoint pk) {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        JubjubPoint a = g.scalarMul(k).normalized();
        JubjubPoint b = g.scalarMul(m).add(pk.scalarMul(k)).normalized();
        return List.of(a.affineU(), a.affineV(), b.affineU(), b.affineV());
    }

    static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        java.util.Arrays.fill(out, value);
        return out;
    }
}
