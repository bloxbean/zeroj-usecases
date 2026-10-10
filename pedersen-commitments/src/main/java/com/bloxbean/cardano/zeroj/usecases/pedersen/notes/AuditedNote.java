package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import org.zeroj.circuit.lib.jubjub.ConfidentialNotes;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalEncryption;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.NoteOpening;
import org.zeroj.circuit.lib.jubjub.NoteReaderKey;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * A note as its sender creates it (ADR-0007 N2, N5): the owner, the opening, the commitment, the
 * registry generation of the auditor it is audited for, the two D3a limb encryptions to that
 * auditor and one delivery per reader (owner, then auditor).
 *
 * <p>Limbs come only from {@link ElGamal#encryptWithOpening}, under the key context of an
 * {@link AdmittedAuditor} (ZeroJ ADR-0055 M3 criterion (b)); deliveries come from
 * {@link ConfidentialNotes#seal}. The limb openings (message and randomness) are kept only to
 * build the sender's proof.
 */
public record AuditedNote(byte[] owner, NoteOpening opening, JubjubPoint commitment, long generation,
                          List<ElGamalEncryption> limbs, List<byte[]> deliveries) {

    public static final BigInteger LIMB_MASK = BigInteger.ONE.shiftLeft(32).subtract(BigInteger.ONE);

    /** A fresh note of {@code amount} for {@code owner}, readable by {@code ownerKey} and the auditor. */
    public static AuditedNote create(byte[] owner, long amount, NoteReaderKey ownerKey, AdmittedAuditor auditor,
                                     SecureRandom random) {
        if (amount < 0) throw new IllegalArgumentException("amount must be non-negative");
        NoteOpening opening = NoteOpening.random(BigInteger.valueOf(amount), random);
        return new AuditedNote(owner.clone(), opening, opening.commitment().normalized(), auditor.generation(),
                limbsOf(opening.value(), auditor, random),
                ConfidentialNotes.seal(opening, List.of(ownerKey, auditor.viewKey()), random));
    }

    /** {@code L0 = v mod 2^32} and {@code L1 = v >> 32}, each encrypted with fresh randomness. */
    public static List<ElGamalEncryption> limbsOf(BigInteger value, AdmittedAuditor auditor, SecureRandom random) {
        return List.of(
                ElGamal.encryptWithOpening(auditor.context(), value.and(LIMB_MASK), 32, random),
                ElGamal.encryptWithOpening(auditor.context(), value.shiftRight(32), 32, random));
    }

    public long amount() {
        return opening.value().longValueExact();
    }

    public BigInteger u() {
        return commitment.affineU();
    }

    public BigInteger v() {
        return commitment.affineV();
    }

    /** The 8 audit coordinates: limb 0 then limb 1, each {@code A.u, A.v, B.u, B.v} (spec §8.1). */
    public List<BigInteger> audit() {
        List<BigInteger> out = new ArrayList<>(8);
        for (ElGamalEncryption limb : limbs) {
            ElGamalCiphertext ct = limb.ciphertext();
            out.add(ct.handle().affineU());
            out.add(ct.handle().affineV());
            out.add(ct.blinded().affineU());
            out.add(ct.blinded().affineV());
        }
        return out;
    }

    /** The same note with other deliveries (the "garbage delivery" cheat). */
    public AuditedNote withDeliveries(List<byte[]> other) {
        return new AuditedNote(owner, opening, commitment, generation, limbs, other);
    }

    /** The same note claiming another registry generation (the "retired key" cheat). */
    public AuditedNote atGeneration(long other) {
        return new AuditedNote(owner, opening, commitment, other, limbs, deliveries);
    }

    /** The same note with other limbs (the "under-reported amount" cheat). */
    public AuditedNote withLimbs(List<ElGamalEncryption> other) {
        return new AuditedNote(owner, opening, commitment, generation, other, deliveries);
    }

    /** {@code Note(owner, u, v, generation, audit, deliveries)}; the generation is the auditor entry's. */
    public ConstrPlutusData datum() {
        List<PlutusData> audit = new ArrayList<>();
        for (BigInteger c : audit()) audit.add(BigIntPlutusData.of(c));
        List<PlutusData> delivered = new ArrayList<>();
        for (byte[] d : deliveries) delivered.add(new BytesPlutusData(d));
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(owner),
                BigIntPlutusData.of(u()),
                BigIntPlutusData.of(v()),
                BigIntPlutusData.of(generation),
                ListPlutusData.of(audit.toArray(new PlutusData[0])),
                ListPlutusData.of(delivered.toArray(new PlutusData[0])))).build();
    }
}
