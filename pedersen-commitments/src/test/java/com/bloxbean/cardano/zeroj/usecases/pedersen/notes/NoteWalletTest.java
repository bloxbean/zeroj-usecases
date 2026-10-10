package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import com.bloxbean.cardano.client.api.model.Utxo;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The wallet's view (ADR-0007 N5, N-I7): a note counts as the wallet's only if its delivery opens
 * <b>and</b> it names the wallet as owner. A note whose delivery opens but which someone else owns
 * (a copied commitment, or a sender's mistake) is "readable, not mine"; an owned note that does not
 * open is reported as unopenable.
 */
class NoteWalletTest {

    static final SecureRandom RANDOM = new SecureRandom();
    static final byte[] ALICE = filled(28, (byte) 0x0a);
    static final byte[] MALLORY = filled(28, (byte) 0x0e);
    static AdmittedAuditor auditor;

    @BeforeAll
    static void setup() {
        KeyPossession possession = new KeyPossession();
        byte[] registry = filled(28, (byte) 0x3e);
        auditor = AdmittedAuditor.admit(registry, AuditorKeys.generate(RANDOM).entry(registry, filled(28, (byte) 0xa1), 0, possession),
                possession);
    }

    static ChainNote chain(AuditedNote n, int index) {
        Utxo u = new Utxo();
        u.setTxHash("00".repeat(32));
        u.setOutputIndex(index);
        return new ChainNote(u, n.owner(), n.u(), n.v(), n.generation(), n.audit(), n.deliveries());
    }

    @Test
    @DisplayName("Owned and opening: counted. Opening but owned by another: not counted. Owned but garbage: unopenable.")
    void ownershipIsNotDecryptability() {
        NoteViewingKey alice = NoteViewingKey.generate(RANDOM);
        AuditedNote mine = AuditedNote.create(ALICE, 500, alice.readerKey(), auditor, RANDOM);
        // Mallory's note whose delivery opens with Alice's key: readable by Alice, spendable only by Mallory.
        AuditedNote notMine = AuditedNote.create(MALLORY, 9_000, alice.readerKey(), auditor, RANDOM);
        byte[] garbage = new byte[89];
        RANDOM.nextBytes(garbage);
        AuditedNote garbled = AuditedNote.create(ALICE, 70, alice.readerKey(), auditor, RANDOM);
        garbled = garbled.withDeliveries(List.of(garbage, garbled.deliveries().get(1)));
        AuditedNote someoneElses = AuditedNote.create(MALLORY, 1, NoteViewingKey.generate(RANDOM).readerKey(), auditor, RANDOM);

        var scan = NoteWallet.scan(List.of(chain(mine, 0), chain(notMine, 1), chain(garbled, 2), chain(someoneElses, 3)), ALICE, alice);
        assertEquals(BigInteger.valueOf(500), scan.balance(), "only the owned, opening note counts");
        assertEquals(1, scan.owned().size());
        assertEquals(1, scan.readableNotMine().size(), "the readable note owned by Mallory is reported, not counted");
        assertEquals(1, scan.unopenable().size(), "the owned garbage note is reported as unopenable");
        assertTrue(Arrays.equals(MALLORY, scan.readableNotMine().getFirst().owner()));
    }

    static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }
}
