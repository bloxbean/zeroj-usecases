package com.bloxbean.cardano.zeroj.usecases.pedersen.notes.circuit;

import org.zeroj.circuit.annotation.CircuitParam;
import org.zeroj.circuit.annotation.FixedSize;
import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.zk.ZkElGamalPublicKey;
import org.zeroj.circuit.lib.zk.ZkPedersenCommitment;

/**
 * Proof-enforced issuance (ADR-0007 N4; ZeroJ ADR-0055 Q9 (b)): every issued note's amount is
 * encrypted to the auditor, so an issuer cannot under-report it.
 *
 * <p>Public, in order: {@code u_1 … u_n}, {@code v_1 … v_n} (the issued notes' commitments, in
 * output order), {@code PK.u, PK.v}, then for each note in output order, limb 0 then limb 1,
 * {@code A.u, A.v, B.u, B.v}: {@code 2n + 2 + 8n} inputs. For each note the prover knows its
 * opening (64-bit amount, 252-bit blinding) and the limb relation of spec §8.1.
 */
@ZKCircuit(name = "note-issue", nameTemplate = "note-issue-n{notes}-l{limbs}-a{audit}", version = 1)
public class NoteIssueProof {

    private final int notes;

    /** {@code limbs = 2·notes} and {@code audit = 8·notes}: the array sizes, which must agree. */
    public NoteIssueProof(@CircuitParam("notes") int notes, @CircuitParam("limbs") int limbs,
                          @CircuitParam("audit") int audit) {
        if (notes < 1 || notes > 2) throw new IllegalArgumentException("notes must be 1 or 2");
        if (limbs != 2 * notes || audit != 8 * notes) {
            throw new IllegalArgumentException("limbs must be 2·notes and audit 8·notes");
        }
        this.notes = notes;
    }

    @Prove
    void prove(ZkContext zk,
               @Public @FixedSize(param = "notes") ZkArray<ZkField> noteU,
               @Public @FixedSize(param = "notes") ZkArray<ZkField> noteV,
               @Public ZkField pkU, @Public ZkField pkV,
               @Public @FixedSize(param = "audit") ZkArray<ZkField> audit,
               @Secret @UInt(bits = 64) @FixedSize(param = "notes") ZkArray<ZkUInt> amounts,
               @Secret @UInt(bits = 252) @FixedSize(param = "notes") ZkArray<ZkUInt> blindings,
               @Secret @UInt(bits = 32) @FixedSize(param = "limbs") ZkArray<ZkUInt> limbs,
               @Secret @UInt(bits = 252) @FixedSize(param = "limbs") ZkArray<ZkUInt> randomness) {
        var key = ZkElGamalPublicKey.fromVerifierFixedPublic(zk, pkU, pkV);
        for (int o = 0; o < notes; o++) {
            ZkPedersenCommitment.commit(zk, amounts.get(o), blindings.get(o))
                    .assertAffineEquals(zk, noteU.get(o), noteV.get(o));
            int c = 8 * o;
            AuditLimbs.assertAudited(zk, amounts.get(o), key,
                    limbs.get(2 * o), randomness.get(2 * o), limbs.get(2 * o + 1), randomness.get(2 * o + 1),
                    audit.get(c), audit.get(c + 1), audit.get(c + 2), audit.get(c + 3),
                    audit.get(c + 4), audit.get(c + 5), audit.get(c + 6), audit.get(c + 7));
        }
    }
}
