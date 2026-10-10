package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import org.zeroj.circuit.lib.jubjub.ElGamalPublicKey;
import org.zeroj.circuit.lib.jubjub.ElGamalSecretKey;
import org.zeroj.circuit.lib.jubjub.NOfNKeyContext;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;

import java.security.SecureRandom;

/**
 * An auditor's two secret keys (ZeroJ ADR-0055 D2): an {@code elgamal-jubjub-v1} key that
 * receives D3a limb ciphertexts, and a separate {@code confidential-note-jubjub-v1} viewing key
 * that receives D5 deliveries. Neither is derived from the other. One pair per generation.
 */
public final class AuditorKeys {

    private final ElGamalSecretKey elgamal;
    private final NoteViewingKey viewing;

    private AuditorKeys(ElGamalSecretKey elgamal, NoteViewingKey viewing) {
        this.elgamal = elgamal;
        this.viewing = viewing;
    }

    public static AuditorKeys generate(SecureRandom random) {
        return new AuditorKeys(ElGamalSecretKey.generate(random), NoteViewingKey.generate(random));
    }

    /**
     * The registry entry for these keys in the registry {@code registryPolicy}: both public keys
     * and a possession proof of each (ADR-0055 Q6), bound to the key type, the registry and
     * {@code auditorPkh} (ADR-0007 N7), at {@code generation}.
     */
    public RegistryEntry entry(byte[] registryPolicy, byte[] auditorPkh, long generation, KeyPossession possession) {
        byte[] pkProof = possession.prove(KeyPossession.ctx(KeyPossession.KeyType.ELGAMAL, registryPolicy, auditorPkh),
                elgamal.possessionStatement(), elgamal.secretScalar());
        var viewCtx = KeyPossession.ctx(KeyPossession.KeyType.VIEWING, registryPolicy, auditorPkh);
        byte[] viewProof = viewing.provePossession((statement, secret) -> possession.prove(viewCtx, statement, secret));
        ElGamalPublicKey pk = elgamal.publicKey();
        var reader = viewing.readerKey();
        return new RegistryEntry(auditorPkh.clone(), generation, pk.affineU(), pk.affineV(), pk.encode(),
                reader.affineU(), reader.affineV(), reader.encode(), pkProof, viewProof);
    }

    public ElGamalSecretKey elgamal() {
        return elgamal;
    }

    public NOfNKeyContext context() {
        return NOfNKeyContext.singleKey(elgamal);
    }

    public NoteViewingKey viewing() {
        return viewing;
    }
}
