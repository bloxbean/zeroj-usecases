package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import org.zeroj.circuit.lib.jubjub.NoteOpening;
import org.zeroj.circuit.lib.jubjub.NoteScanner;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A wallet's view of a ledger, recovered from chain data alone (ADR-0007 N5; ZeroJ ADR-0055 D6,
 * I9): its viewing key opens the owner deliveries of the authenticated notes.
 *
 * <ul>
 *   <li><b>owned</b>: the note names this wallet's key hash as owner <i>and</i> its delivery opens
 *       to the commitment (spec §5 steps 1–7). Only these are spendable.</li>
 *   <li><b>unopenable</b>: owned by this wallet, but the delivery does not open. Value the user
 *       owns and cannot spend: evidence of a misbehaving sender.</li>
 *   <li><b>readable, not mine</b>: the delivery opens, but another key hash owns the note (for
 *       example a copied commitment). Never counted or spent.</li>
 * </ul>
 *
 * <p>Scanning decrypts attacker-chosen ephemeral keys with the viewing key. It belongs in the
 * user's own wallet process (ADR-0055 D9); this demo's server scans on its wallets' behalf.
 */
public final class NoteWallet {

    /** A spendable note: on-chain location plus its opening. */
    public record Owned(ChainNote note, NoteOpening opening) {
        public NoteProofs.Spent spent() {
            return new NoteProofs.Spent(opening, note.u(), note.v());
        }
    }

    public record Scan(List<Owned> owned, List<ChainNote> unopenable, List<ChainNote> readableNotMine) {
        public long balance() {
            return owned.stream().mapToLong(o -> o.opening().value().longValueExact()).sum();
        }
    }

    private NoteWallet() {}

    public static Scan scan(List<ChainNote> notes, byte[] myPkh, NoteViewingKey key) {
        List<NoteScanner.Candidate> candidates = new ArrayList<>();
        for (ChainNote n : notes) {
            candidates.add(NoteScanner.Candidate.of(n.deliveries().get(0), n.u(), n.v(), Arrays.equals(n.owner(), myPkh)));
        }
        NoteScanner.Scan scan = NoteScanner.of(key).scan(candidates);
        List<Owned> owned = new ArrayList<>();
        List<ChainNote> notMine = new ArrayList<>();
        for (NoteScanner.Opened o : scan.opened()) {
            ChainNote n = notes.get(o.index());
            if (Arrays.equals(n.owner(), myPkh)) {
                owned.add(new Owned(n, o.opening()));
            } else {
                notMine.add(n);
            }
        }
        List<ChainNote> unopenable = new ArrayList<>();
        for (int i : scan.unopenableOwned()) unopenable.add(notes.get(i));
        return new Scan(owned, unopenable, notMine);
    }
}
