package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.JubjubDiscreteLog;
import org.zeroj.circuit.lib.jubjub.NoteOpening;
import org.zeroj.circuit.lib.jubjub.NoteScanner;
import org.zeroj.circuit.lib.jubjub.RawElGamalCiphertext;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The auditor's view of a ledger, from chain data alone (ADR-0007 N5; ZeroJ ADR-0055 D3a, D5).
 *
 * <p>For each authenticated note it reads the <b>amount</b> from the two D3a limb ciphertexts with
 * the ElGamal secret of the note's generation, and independently opens its own D5 delivery with
 * that generation's viewing key, then compares the two. A note's <b>origin</b> says whether the
 * amount is enforced: a note created by a transfer or redemption (whose transaction spent a note)
 * or by a proved issuance is <i>proof-enforced</i>; a note from a trusted issuance is
 * <i>issuer-claimed</i>.
 */
public final class AuditorView {

    public enum Origin { PROOF_ENFORCED, ISSUER_CLAIMED }

    /**
     * One audited note. {@code amount} is from the limbs; {@code delivered} is the auditor's own
     * delivery's opening, if it opened; {@code consistent} says the two agree.
     */
    public record Audited(ChainNote note, Origin origin, long amount, Optional<NoteOpening> delivered) {
        public boolean consistent() {
            return delivered.isPresent() && delivered.get().value().longValueExact() == amount;
        }
    }

    private static final long MAX_LIMB = (1L << 32) - 1;
    private static volatile JubjubDiscreteLog table;
    private static final ObjectMapper JSON = new ObjectMapper();

    private final Map<Long, AuditorKeys> keysByGeneration;
    private final String ledgerAddress;
    private final boolean provedIssuance;
    private final Map<String, Boolean> spentNote = new ConcurrentHashMap<>();

    /**
     * @param keysByGeneration every generation's keys the auditor holds (ADR-0055 D2: old keys are
     *                         kept for as long as the notes delivered to them matter)
     */
    public AuditorView(Map<Long, AuditorKeys> keysByGeneration, NoteLedgerScript ledger) {
        this.keysByGeneration = keysByGeneration;
        this.ledgerAddress = ledger.address();
        this.provedIssuance = ledger.provedIssuance();
    }

    public Audited audit(ChainNote note) {
        AuditorKeys keys = keysByGeneration.get(note.generation());
        if (keys == null) throw new IllegalStateException("no auditor keys for generation " + note.generation());
        Origin origin = provedIssuance || createdBySpend(note.utxo().getTxHash())
                ? Origin.PROOF_ENFORCED : Origin.ISSUER_CLAIMED;
        long amount = 0;
        for (int j = 1; j >= 0; j--) {
            var a = note.audit();
            RawElGamalCiphertext raw = RawElGamalCiphertext.fromAffine(
                    a.get(4 * j), a.get(4 * j + 1), a.get(4 * j + 2), a.get(4 * j + 3));
            // Delegated admission (elgamal-jubjub-v1 §10.1): an authenticated proof-enforced note's
            // limbs were proved when the ledger accepted it. An issuer-claimed note's were not; its
            // amount is reported as claimed, never enforced.
            ElGamalCiphertext ct = ElGamal.admit(raw, keys.context(), 32, statement -> true);
            amount = (amount << 32) | ElGamal.decryptWithSecret(ct, keys.elgamal(), MAX_LIMB, table());
        }
        Optional<NoteOpening> delivered = NoteScanner.of(keys.viewing()).open(note.deliveries().get(1), note.u(), note.v());
        return new Audited(note, origin, amount, delivered);
    }

    /** Whether the transaction that created a note spent an input at the ledger's address. */
    private boolean createdBySpend(String txHash) {
        return spentNote.computeIfAbsent(txHash, h -> {
            try {
                var request = HttpRequest.newBuilder(URI.create(DevKit.STORE_URL + "txs/" + h + "/utxos")).GET().build();
                var body = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString()).body();
                JsonNode inputs = JSON.readTree(body).path("inputs");
                for (JsonNode in : inputs) {
                    if (ledgerAddress.equals(in.path("address").asText())) return true;
                }
                return false;
            } catch (Exception e) {
                throw new IllegalStateException("could not read transaction " + h + ": " + e.getMessage(), e);
            }
        });
    }

    private static JubjubDiscreteLog table() {
        JubjubDiscreteLog t = table;
        if (t == null) {
            synchronized (AuditorView.class) {
                if (table == null) table = JubjubDiscreteLog.forBound(MAX_LIMB);
                t = table;
            }
        }
        return t;
    }

    /** The sum of the limb amounts of {@code notes}, for totals per owner. */
    public static long total(Iterable<Audited> notes) {
        long sum = 0;
        for (Audited a : notes) sum = Math.addExact(sum, a.amount());
        return sum;
    }
}
