package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.UnaryOperator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Registry admission (ADR-0007 N5; ZeroJ ADR-0055 M3 criterion (b)): an entry is admitted only
 * with both possession proofs verifying for exactly its keys under this registry, this auditor and
 * each key's own type, and with coordinates equal to each key's encoding.
 */
class RegistryAdmissionTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] AUDITOR = filled(28, (byte) 0xa1);
    private static final byte[] POLICY = filled(28, (byte) 0x3e);
    private static KeyPossession possession;
    private static AuditorKeys keys;
    private static RegistryEntry entry;
    private static RegistryEntry other;

    @BeforeAll
    static void setup() {
        possession = new KeyPossession();
        keys = AuditorKeys.generate(RANDOM);
        entry = keys.entry(POLICY, AUDITOR, 0, possession);
        other = AuditorKeys.generate(RANDOM).entry(POLICY, AUDITOR, 0, possession);
    }

    @Test
    @DisplayName("An honest entry is admitted, and survives a round trip through its datum")
    void honest() throws Exception {
        AdmittedAuditor admitted = AdmittedAuditor.admit(POLICY, entry, possession);
        assertEquals(keys.elgamal().publicKey().affineU(), admitted.pkU());
        assertEquals(keys.viewing().readerKey(), admitted.viewKey());
        RegistryEntry back = RegistryEntry.fromPlutusData(PlutusData.deserialize(entry.toPlutusData().serializeToBytes()));
        assertArrayEquals(entry.pkProof(), back.pkProof());
        assertEquals(entry.viewU(), back.viewU());
        AdmittedAuditor.admit(POLICY, back, possession);
        // The possession statements' base is the generator the registry script is built with.
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR.normalized();
        assertEquals(g.affineU(), keys.elgamal().possessionStatement().publicInputs().get(0));
        assertEquals(g.affineV(), keys.elgamal().possessionStatement().publicInputs().get(1));
    }

    @Test
    @DisplayName("Refused: swapped or foreign proofs, the wrong key type, mismatched coordinates, equal keys, replay")
    void refusals() {
        refused(e -> with(e, 8, e.viewProof()), "the viewing key's proof for the ElGamal key");
        refused(e -> with(e, 9, e.pkProof()), "the ElGamal key's proof for the viewing key");
        refused(e -> with(e, 8, other.pkProof()), "another key's ElGamal proof");
        refused(e -> with(e, 9, other.viewProof()), "another key's viewing-key proof");
        byte[] corrupt = entry.pkProof().clone();
        corrupt[10] ^= 1;
        refused(e -> with(e, 8, corrupt), "a corrupted proof");
        refused(e -> with(e, 8, Arrays.copyOf(e.pkProof(), 191)), "a short proof");
        refused(e -> new RegistryEntry(e.auditor(), 0, e.pkU().add(BigInteger.ONE), e.pkV(), e.pkEnc(), e.viewU(),
                e.viewV(), e.viewKey(), e.pkProof(), e.viewProof()), "ElGamal coordinates that are not its encoding");
        refused(e -> new RegistryEntry(e.auditor(), 0, e.pkU(), e.pkV(), e.pkEnc(), e.viewU().add(BigInteger.ONE),
                e.viewV(), e.viewKey(), e.pkProof(), e.viewProof()), "viewing coordinates that are not its encoding");
        refused(e -> new RegistryEntry(e.auditor(), 0, other.pkU(), other.pkV(), other.pkEnc(), e.viewU(), e.viewV(),
                e.viewKey(), e.pkProof(), e.viewProof()), "another key with this entry's proof");
        refused(e -> new RegistryEntry(e.auditor(), 0, e.pkU(), e.pkV(), e.pkEnc(), e.pkU(), e.pkV(), e.pkEnc(),
                e.pkProof(), e.pkProof()), "the same key as both");

        // Key-type binding in isolation: each key's own statement, proved under the other type.
        byte[] pkUnderView = possession.prove(KeyPossession.ctx(KeyPossession.KeyType.VIEWING, POLICY, AUDITOR),
                keys.elgamal().possessionStatement(), keys.elgamal().secretScalar());
        refused(e -> with(e, 8, pkUnderView), "the ElGamal key proved under the viewing type");
        byte[] viewUnderPk = keys.viewing().provePossession((s, x) -> possession.prove(
                KeyPossession.ctx(KeyPossession.KeyType.ELGAMAL, POLICY, AUDITOR), s, x));
        refused(e -> with(e, 9, viewUnderPk), "the viewing key proved under the ElGamal type");

        // Replay: this entry's keys and proofs, claimed in another registry or by another registrant.
        assertThrows(IllegalArgumentException.class, () -> AdmittedAuditor.admit(filled(28, (byte) 0x3f), entry, possession),
                "proofs bound to another registry");
        refused(e -> new RegistryEntry(filled(28, (byte) 1), 0, e.pkU(), e.pkV(), e.pkEnc(), e.viewU(), e.viewV(),
                e.viewKey(), e.pkProof(), e.viewProof()), "proofs bound to another registrant");
    }

    private static void refused(UnaryOperator<RegistryEntry> mutate, String what) {
        RegistryEntry mutated = mutate.apply(entry);
        assertThrows(IllegalArgumentException.class, () -> AdmittedAuditor.admit(POLICY, mutated, possession), what);
    }

    /** {@code e} with proof field 8 ({@code pkProof}) or 9 ({@code viewProof}) replaced. */
    private static RegistryEntry with(RegistryEntry e, int field, byte[] proof) {
        return field == 8
                ? new RegistryEntry(e.auditor(), e.generation(), e.pkU(), e.pkV(), e.pkEnc(), e.viewU(), e.viewV(),
                        e.viewKey(), proof, e.viewProof())
                : new RegistryEntry(e.auditor(), e.generation(), e.pkU(), e.pkV(), e.pkEnc(), e.viewU(), e.viewV(),
                        e.viewKey(), e.pkProof(), proof);
    }

    static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }
}
