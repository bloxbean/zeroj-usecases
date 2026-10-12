package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import com.bloxbean.cardano.zeroj.usecases.pedersen.common.KeyedCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.circuit.NoteIssueProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.circuit.NoteRedeemProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.circuit.NoteTransferProofCircuit;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.lib.jubjub.ElGamalEncryption;
import org.zeroj.circuit.lib.jubjub.NoteOpening;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * The note circuits with their keys (ADR-0007 N3, N4): transfer and redeem, and optionally proved
 * issuance for one and two notes. Witnesses are built from openings the prover holds and from
 * notes it created; every public input is in the order the ledger rebuilds it.
 */
public final class NoteProofs {

    /** A spent note as its owner knows it: the opening and the datum's coordinates. */
    public record Spent(NoteOpening opening, BigInteger u, BigInteger v) {}

    private final KeyedCircuit transfer;
    private final KeyedCircuit redeem;
    private final KeyedCircuit issue1;
    private final KeyedCircuit issue2;

    private NoteProofs(KeyedCircuit transfer, KeyedCircuit redeem, KeyedCircuit issue1, KeyedCircuit issue2) {
        this.transfer = transfer;
        this.redeem = redeem;
        this.issue1 = issue1;
        this.issue2 = issue2;
    }

    /** Transfer and redeem only (trusted issuance). */
    public static NoteProofs spendOnly() {
        Map<String, Supplier<CircuitBuilder>> circuits = new LinkedHashMap<>();
        circuits.put("note-transfer", NoteTransferProofCircuit::build);
        circuits.put("note-redeem", NoteRedeemProofCircuit::build);
        List<KeyedCircuit> c = KeyedCircuit.compileAll(circuits);
        return new NoteProofs(c.get(0), c.get(1), null, null);
    }

    /** Transfer, redeem and proved issuance (payroll). */
    public static NoteProofs withIssuance() {
        Map<String, Supplier<CircuitBuilder>> circuits = new LinkedHashMap<>();
        circuits.put("note-transfer", NoteTransferProofCircuit::build);
        circuits.put("note-redeem", NoteRedeemProofCircuit::build);
        circuits.put("note-issue-n1", () -> NoteIssueProofCircuit.build(1, 2, 8));
        circuits.put("note-issue-n2", () -> NoteIssueProofCircuit.build(2, 4, 16));
        List<KeyedCircuit> c = KeyedCircuit.compileAll(circuits);
        return new NoteProofs(c.get(0), c.get(1), c.get(2), c.get(3));
    }

    public KeyedCircuit transfer() { return transfer; }

    public KeyedCircuit redeem() { return redeem; }

    public KeyedCircuit issue(int notes) {
        KeyedCircuit c = notes == 1 ? issue1 : notes == 2 ? issue2 : null;
        if (c == null) throw new IllegalStateException("no issuance circuit for " + notes + " notes");
        return c;
    }

    public boolean provesIssuance() {
        return issue1 != null;
    }

    // ------------------------------------------------------------------ transfer

    public static NoteTransferProofCircuit.Inputs transferInputs(Spent in, AuditedNote o1, AuditedNote o2,
                                                                 AdmittedAuditor auditor) {
        List<BigInteger> a1 = o1.audit();
        List<BigInteger> a2 = o2.audit();
        return NoteTransferProofCircuit.inputs()
                .inU(in.u()).inV(in.v())
                .o1U(o1.u()).o1V(o1.v())
                .o2U(o2.u()).o2V(o2.v())
                .pkU(auditor.pkU()).pkV(auditor.pkV())
                .o1a0u(a1.get(0)).o1a0v(a1.get(1)).o1b0u(a1.get(2)).o1b0v(a1.get(3))
                .o1a1u(a1.get(4)).o1a1v(a1.get(5)).o1b1u(a1.get(6)).o1b1v(a1.get(7))
                .o2a0u(a2.get(0)).o2a0v(a2.get(1)).o2b0u(a2.get(2)).o2b0v(a2.get(3))
                .o2a1u(a2.get(4)).o2a1v(a2.get(5)).o2b1u(a2.get(6)).o2b1v(a2.get(7))
                .inAmount(in.opening().value()).inBlinding(in.opening().blinding())
                .o1Amount(o1.opening().value()).o1Blinding(o1.opening().blinding())
                .o2Amount(o2.opening().value()).o2Blinding(o2.opening().blinding())
                .o1L0(o1.limbs().get(0).message()).o1K0(o1.limbs().get(0).randomness())
                .o1L1(o1.limbs().get(1).message()).o1K1(o1.limbs().get(1).randomness())
                .o2L0(o2.limbs().get(0).message()).o2K0(o2.limbs().get(0).randomness())
                .o2L1(o2.limbs().get(1).message()).o2K1(o2.limbs().get(1).randomness());
    }

    /** Proves {@code in = o1 + o2} and both notes' audit limbs; throws if no witness exists. */
    public Groth16ProofBLS381 proveTransfer(Spent in, AuditedNote o1, AuditedNote o2, AdmittedAuditor auditor) {
        return transfer.prove(transferInputs(in, o1, o2, auditor).toWitnessMap());
    }

    // ------------------------------------------------------------------ redeem

    public static NoteRedeemProofCircuit.Inputs redeemInputs(Spent in, AuditedNote change, long price,
                                                             AdmittedAuditor auditor) {
        List<BigInteger> a = change.audit();
        return NoteRedeemProofCircuit.inputs()
                .inU(in.u()).inV(in.v())
                .changeU(change.u()).changeV(change.v())
                .price(price)
                .pkU(auditor.pkU()).pkV(auditor.pkV())
                .a0u(a.get(0)).a0v(a.get(1)).b0u(a.get(2)).b0v(a.get(3))
                .a1u(a.get(4)).a1v(a.get(5)).b1u(a.get(6)).b1v(a.get(7))
                .inAmount(in.opening().value()).inBlinding(in.opening().blinding())
                .changeAmount(change.opening().value()).changeBlinding(change.opening().blinding())
                .l0(change.limbs().get(0).message()).k0(change.limbs().get(0).randomness())
                .l1(change.limbs().get(1).message()).k1(change.limbs().get(1).randomness());
    }

    /** Proves {@code in = change + price} and the change's audit limbs; throws if no witness exists. */
    public Groth16ProofBLS381 proveRedeem(Spent in, AuditedNote change, long price, AdmittedAuditor auditor) {
        return redeem.prove(redeemInputs(in, change, price, auditor).toWitnessMap());
    }

    // ------------------------------------------------------------------ issue

    public static NoteIssueProofCircuit.Inputs issueInputs(List<AuditedNote> notes, AdmittedAuditor auditor) {
        int n = notes.size();
        List<BigInteger> us = new ArrayList<>();
        List<BigInteger> vs = new ArrayList<>();
        List<BigInteger> audit = new ArrayList<>();
        List<BigInteger> amounts = new ArrayList<>();
        List<BigInteger> blindings = new ArrayList<>();
        List<BigInteger> limbs = new ArrayList<>();
        List<BigInteger> randomness = new ArrayList<>();
        for (AuditedNote note : notes) {
            us.add(note.u());
            vs.add(note.v());
            audit.addAll(note.audit());
            amounts.add(note.opening().value());
            blindings.add(note.opening().blinding());
            for (ElGamalEncryption limb : note.limbs()) {
                limbs.add(limb.message());
                randomness.add(limb.randomness());
            }
        }
        return NoteIssueProofCircuit.inputs(n, 2 * n, 8 * n)
                .noteU(us).noteV(vs)
                .pkU(auditor.pkU()).pkV(auditor.pkV())
                .audit(audit)
                .amounts(amounts).blindings(blindings)
                .limbs(limbs).randomness(randomness);
    }

    /** Proves that every issued note's limbs encrypt its committed amount; throws if not. */
    public Groth16ProofBLS381 proveIssue(List<AuditedNote> notes, AdmittedAuditor auditor) {
        return issue(notes.size()).prove(issueInputs(notes, auditor).toWitnessMap());
    }
}
