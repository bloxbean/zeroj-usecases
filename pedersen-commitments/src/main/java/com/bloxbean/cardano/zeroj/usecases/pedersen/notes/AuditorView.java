package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalDecryptionException;
import org.zeroj.circuit.lib.jubjub.JubjubDiscreteLog;
import org.zeroj.circuit.lib.jubjub.NoteOpening;
import org.zeroj.circuit.lib.jubjub.NoteScanner;
import org.zeroj.circuit.lib.jubjub.RawElGamalCiphertext;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The auditor's view of a ledger, from chain data alone (ADR-0007 N5; ZeroJ ADR-0055 D3a, D5).
 *
 * <p>For each authenticated note it reads the <b>amount</b> from the two D3a limb ciphertexts with
 * the ElGamal secret of the note's generation, and independently opens its own D5 delivery with
 * that generation's viewing key, then compares the two. A note's <b>origin</b> says whether the
 * amount is enforced: a note created by a proved issuance, or by a transaction that consumed one
 * of this ledger's notes (a transfer or redemption), is <i>proof-enforced</i>; a note from a
 * trusted issuance is <i>issuer-claimed</i>. Malformed issuer-claimed audit data is reported on
 * that note, never as a failure of the whole view.
 */
public final class AuditorView {

    public enum Origin { PROOF_ENFORCED, ISSUER_CLAIMED }

    /**
     * One audited note. {@code amount} is from the limbs (empty if they could not be read, with
     * {@code problem} saying why); {@code delivered} is the auditor's own delivery's opening.
     */
    public record Audited(ChainNote note, Origin origin, Optional<BigInteger> amount, Optional<NoteOpening> delivered,
                          String problem) {
        public boolean consistent() {
            return amount.isPresent() && delivered.isPresent() && delivered.get().value().equals(amount.get());
        }
    }

    private static final long MAX_LIMB = (1L << 32) - 1;
    private static volatile JubjubDiscreteLog table;
    private static final ObjectMapper JSON = new ObjectMapper();

    private final Map<Long, AuditorKeys> keysByGeneration;
    private final String ledgerAddress;
    private final String noteUnit;
    private final boolean provedIssuance;
    private final Map<String, Boolean> spentNote = new ConcurrentHashMap<>();

    /**
     * @param keysByGeneration every generation's keys the auditor holds (ADR-0055 D2: old keys are
     *                         kept for as long as the notes delivered to them matter)
     */
    public AuditorView(Map<Long, AuditorKeys> keysByGeneration, NoteLedgerScript ledger) {
        this.keysByGeneration = keysByGeneration;
        this.ledgerAddress = ledger.address();
        this.noteUnit = ledger.unit();
        this.provedIssuance = ledger.provedIssuance();
    }

    public Audited audit(ChainNote note) {
        Origin origin = provedIssuance || createdBySpend(note.utxo().getTxHash()) ? Origin.PROOF_ENFORCED : Origin.ISSUER_CLAIMED;
        AuditorKeys keys = keysByGeneration.get(note.generation());
        if (keys == null) {
            return new Audited(note, origin, Optional.empty(), Optional.empty(),
                    "no auditor keys for generation " + note.generation());
        }
        Optional<NoteOpening> delivered = NoteScanner.of(keys.viewing()).open(note.deliveries().get(1), note.u(), note.v());
        try {
            BigInteger amount = BigInteger.ZERO;
            for (int j = 1; j >= 0; j--) {
                var a = note.audit();
                RawElGamalCiphertext raw = RawElGamalCiphertext.fromAffine(
                        a.get(4 * j), a.get(4 * j + 1), a.get(4 * j + 2), a.get(4 * j + 3));
                // Delegated admission (elgamal-jubjub-v1 §10.1): an authenticated proof-enforced note's
                // limbs were proved when the ledger accepted it. An issuer-claimed note's were not; its
                // amount is reported as claimed, never enforced.
                ElGamalCiphertext ct = ElGamal.admit(raw, keys.context(), 32, statement -> true);
                amount = amount.shiftLeft(32).or(BigInteger.valueOf(ElGamal.decryptWithSecret(ct, keys.elgamal(), MAX_LIMB, table())));
            }
            return new Audited(note, origin, Optional.of(amount), delivered, null);
        } catch (IllegalArgumentException | ElGamalDecryptionException e) {
            // Only possible for issuer-claimed data: a proved note's limbs are valid ciphertexts of 32-bit values.
            return new Audited(note, origin, Optional.empty(), delivered, "limb ciphertexts do not decrypt: " + e.getMessage());
        }
    }

    /**
     * Whether the transaction that created a note consumed (not merely referenced) a note of this
     * ledger: only a transfer or redemption does. A failed lookup is an error and is not cached.
     */
    private boolean createdBySpend(String txHash) {
        Boolean known = spentNote.get(txHash);
        if (known != null) return known;
        JsonNode inputs = getJson("txs/" + txHash + "/utxos").path("inputs");
        if (!inputs.isArray()) throw new IllegalStateException("transaction " + txHash + " has no input list");
        boolean spent = false;
        for (JsonNode in : inputs) {
            if (!ledgerAddress.equals(in.path("address").asText())) continue;
            for (JsonNode a : in.path("amount")) {
                if (noteUnit.equals(a.path("unit").asText()) && "1".equals(a.path("quantity").asText())) spent = true;
            }
        }
        spentNote.put(txHash, spent);
        return spent;
    }

    /**
     * Every note this ledger ever issued (its token's mint history, mints that consumed no note),
     * read from the chain: the payroll's payslips. Spent notes are included, so salary history
     * survives transfers and cash-outs.
     */
    public List<ChainNote> issuedNotes(NoteLedgerScript ledger) {
        List<ChainNote> out = new ArrayList<>();
        for (JsonNode event : getJson("assets/" + noteUnit + "/history")) {
            if (!"MINT".equals(event.path("mint_type").asText())) continue;
            String tx = event.path("tx_hash").asText();
            if (createdBySpend(tx)) continue;
            for (JsonNode o : getJson("txs/" + tx + "/utxos").path("outputs")) {
                Utxo u = new Utxo();
                u.setTxHash(tx);
                u.setOutputIndex(o.path("output_index").asInt());
                u.setAddress(o.path("address").asText());
                u.setInlineDatum(o.path("inline_datum").asText(null));
                List<Amount> amounts = new ArrayList<>();
                for (JsonNode a : o.path("amount")) {
                    amounts.add(new Amount(a.path("unit").asText(), new BigInteger(a.path("quantity").asText())));
                }
                u.setAmount(amounts);
                ChainNote.parse(u, ledger).ifPresent(out::add);
            }
        }
        return out;
    }

    private static JsonNode getJson(String path) {
        try {
            var request = HttpRequest.newBuilder(URI.create(DevKit.STORE_URL + path)).GET().build();
            var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                throw new IllegalStateException("Yaci Store " + path + " returned " + response.statusCode());
            }
            return JSON.readTree(response.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted reading " + path, e);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("could not read " + path + ": " + e.getMessage(), e);
        }
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
}
