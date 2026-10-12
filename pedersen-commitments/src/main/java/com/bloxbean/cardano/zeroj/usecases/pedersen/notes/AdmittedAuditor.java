package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import org.zeroj.circuit.lib.jubjub.ElGamalPublicKey;
import org.zeroj.circuit.lib.jubjub.NOfNKeyContext;
import org.zeroj.circuit.lib.jubjub.NoteReaderKey;
import org.zeroj.circuit.lib.jubjub.VerifiedKeyShare;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * A registry entry a sender has admitted (ADR-0007 N5): both keys decoded strictly, their
 * possession proofs verified under this registry's and this auditor's context (N7), and each key
 * equal to the coordinates the validator reads. This is the only source of a key context for limb
 * encryption and of the auditor's reader key for deliveries (ZeroJ ADR-0055 M3 criterion (b)), so
 * it has no public constructor: {@link #admit} is the only way in.
 */
public final class AdmittedAuditor {

    private final byte[] auditor;
    private final long generation;
    private final NOfNKeyContext context;
    private final NoteReaderKey viewKey;

    private AdmittedAuditor(byte[] auditor, long generation, NOfNKeyContext context, NoteReaderKey viewKey) {
        this.auditor = auditor;
        this.generation = generation;
        this.context = context;
        this.viewKey = viewKey;
    }

    /**
     * @throws IllegalArgumentException if a key does not decode to a valid subgroup point, a
     *         possession proof does not verify under this registry and auditor, coordinates do not
     *         match an encoding, or the two keys are equal
     */
    public static AdmittedAuditor admit(byte[] registryPolicy, RegistryEntry entry, KeyPossession possession) {
        if (Arrays.equals(entry.pkEnc(), entry.viewKey())) {
            throw new IllegalArgumentException("the ElGamal key and the viewing key must differ");
        }
        var pkCtx = KeyPossession.ctx(KeyPossession.KeyType.ELGAMAL, registryPolicy, entry.auditor());
        var viewCtx = KeyPossession.ctx(KeyPossession.KeyType.VIEWING, registryPolicy, entry.auditor());
        VerifiedKeyShare share = VerifiedKeyShare.verify(entry.pkEnc(),
                statement -> possession.verifyPossession(pkCtx, statement, entry.pkProof()));
        NOfNKeyContext context = ElGamalPublicKey.aggregate(List.of(share));
        ElGamalPublicKey key = context.jointKey();
        if (!key.affineU().equals(entry.pkU()) || !key.affineV().equals(entry.pkV())) {
            throw new IllegalArgumentException("registry coordinates do not match the ElGamal key's encoding");
        }
        NoteReaderKey view = NoteReaderKey.verified(entry.viewKey(),
                statement -> possession.verifyPossession(viewCtx, statement, entry.viewProof()));
        if (!view.affineU().equals(entry.viewU()) || !view.affineV().equals(entry.viewV())) {
            throw new IllegalArgumentException("registry coordinates do not match the viewing key's encoding");
        }
        return new AdmittedAuditor(entry.auditor().clone(), entry.generation(), context, view);
    }

    public byte[] auditor() {
        return auditor.clone();
    }

    public long generation() {
        return generation;
    }

    public NOfNKeyContext context() {
        return context;
    }

    public NoteReaderKey viewKey() {
        return viewKey;
    }

    public BigInteger pkU() {
        return context.jointKey().affineU();
    }

    public BigInteger pkV() {
        return context.jointKey().affineV();
    }
}
