package com.bloxbean.cardano.zeroj.usecases.pedersen.web;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusScript;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Plutus;
import com.bloxbean.cardano.zeroj.usecases.pedersen.points.ConfidentialPoints;
import com.bloxbean.cardano.zeroj.usecases.pedersen.points.ConfidentialPoints.Note;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Demo A, confidential points, for the UI. The retailer, Alice and Bob are wallets this server
 * creates; the server also keeps each wallet's note <b>openings</b> (amount and blinding) on its
 * behalf, which in a real deployment only the owner would hold. On-chain there are only
 * commitments.
 */
@Service
public class PointsService {

    private static final Logger log = LoggerFactory.getLogger(PointsService.class);
    static final List<String> WALLETS = List.of("retailer", "alice", "bob");

    private final BackendService backend;
    private final Funding funding;

    private ConfidentialPoints points;
    private PlutusScript script;
    private String ledger;
    private String policyId;
    private final Map<String, Account> wallets = new LinkedHashMap<>();
    private final Map<String, List<HeldNote>> notes = new LinkedHashMap<>();
    private final List<Map<String, Object>> history = new ArrayList<>();

    /** A note this server holds the opening of, and where it sits on-chain. */
    record HeldNote(Note note, String txHash, int index) {}

    public PointsService(BackendService backend, Funding funding) {
        this.backend = backend;
        this.funding = funding;
    }

    /** Compiles the circuits (cached dev keys) and creates the funded wallets, once. */
    synchronized void ensureReady() {
        if (points != null) return;
        var p = new ConfidentialPoints();
        for (String label : WALLETS) {
            wallets.put(label, funding.newWallet("points/" + label, 200));
            notes.put(label, new ArrayList<>());
        }
        script = p.script(pkh(wallets.get("retailer")));
        ledger = ConfidentialPoints.address(script);
        policyId = Plutus.policyId(script);
        points = p;
        log.info("Points ledger {} (policy {})", ledger, policyId);
    }

    // ------------------------------------------------------------------
    //  Actions
    // ------------------------------------------------------------------

    /** The retailer issues {@code amount} points to {@code to}. */
    public synchronized Map<String, Object> issue(String to, long amount) throws Exception {
        ensureReady();
        requireHolder(to);
        requireAmount(amount);
        Note note = Note.of(pkh(wallets.get(to)), amount);
        String tx = DemoErrors.require(ConfidentialPoints.issue(backend, script, wallets.get("retailer"), List.of(note)), "Issue");
        DevKit.waitForTx(backend, tx);
        notes.get(to).add(locate(tx, note));
        return record("issue", "Retailer issued " + amount + " points to " + to, tx);
    }

    /**
     * {@code from} sends {@code amount} to {@code to}, splitting one of its notes. Asking for more
     * than the note holds is the "cheat": the prover cannot produce a proof that
     * {@code in = out1 + out2}.
     */
    public synchronized Map<String, Object> transfer(String from, String to, long amount) throws Exception {
        ensureReady();
        requireHolder(from);
        requireHolder(to);
        requireAmount(amount);
        HeldNote source = largest(from);
        Note out1 = Note.of(pkh(wallets.get(to)), amount);
        Note out2 = Note.of(pkh(wallets.get(from)), Math.max(0, source.note().amount() - amount));
        var proof = prove(() -> points.proveTransfer(source.note(), out1, out2),
                from + "'s note holds " + source.note().amount() + " points; no proof exists that it splits into "
                        + amount + " + " + out2.amount());
        String tx = DemoErrors.require(ConfidentialPoints.transfer(backend, script, wallets.get(from),
                utxo(source), out1, out2, proof), "Transfer");
        DevKit.waitForTx(backend, tx);
        notes.get(from).remove(source);
        notes.get(to).add(locate(tx, out1));
        notes.get(from).add(locate(tx, out2));
        return record("transfer", from + " sent " + amount + " points to " + to + " (amounts hidden on-chain)", tx);
    }

    /** {@code from} pays a public {@code price} at the retailer and keeps the hidden change. */
    public synchronized Map<String, Object> redeem(String from, long price) throws Exception {
        ensureReady();
        requireHolder(from);
        requireAmount(price);
        if (price >= 1L << 32) throw new IllegalArgumentException("price must be below 2^32");
        HeldNote source = largest(from);
        Note change = Note.of(pkh(wallets.get(from)), Math.max(0, source.note().amount() - price));
        var proof = prove(() -> points.proveRedeem(source.note(), change, price),
                from + "'s note holds " + source.note().amount() + " points; no proof exists that it pays "
                        + price + " and keeps " + change.amount());
        String tx = DemoErrors.require(ConfidentialPoints.redeem(backend, script, wallets.get(from),
                wallets.get("retailer").baseAddress(), utxo(source), change, price, proof), "Redeem");
        DevKit.waitForTx(backend, tx);
        notes.get(from).remove(source);
        notes.get(from).add(locate(tx, change));
        return record("redeem", from + " paid " + price + " points at the retailer (price public, balance hidden)", tx);
    }

    /**
     * The other "cheat": {@code thief} spends one of {@code victim}'s notes. The server even holds
     * the victim's opening, so the proof is valid; the validator still rejects the transaction
     * because the note's owner did not sign it.
     */
    public synchronized Map<String, Object> steal(String thief, String victim) throws Exception {
        ensureReady();
        requireHolder(thief);
        requireHolder(victim);
        if (thief.equals(victim)) throw new IllegalArgumentException("pick two different wallets");
        HeldNote target = largest(victim);
        Note toThief = Note.of(pkh(wallets.get(thief)), target.note().amount());
        Note zero = Note.of(pkh(wallets.get(thief)), 0);
        var proof = points.proveTransfer(target.note(), toThief, zero);
        DemoErrors.require(ConfidentialPoints.transfer(backend, script, wallets.get(thief), utxo(target),
                toThief, zero, proof), thief + " spending " + victim + "'s note");
        throw new IllegalStateException("unexpected: the ledger accepted a spend without the owner's signature");
    }

    // ------------------------------------------------------------------
    //  State for the UI
    // ------------------------------------------------------------------

    public synchronized Map<String, Object> state() throws Exception {
        ensureReady();
        Map<String, Object> privateView = new LinkedHashMap<>();
        for (String label : WALLETS) {
            List<Map<String, Object>> held = new ArrayList<>();
            long total = 0;
            for (HeldNote h : notes.get(label)) {
                total += h.note().amount();
                held.add(Map.of("amount", h.note().amount(),
                        "commitment", shortHex(h.note().commitment().affineU()),
                        "utxo", h.txHash().substring(0, 12) + "…#" + h.index()));
            }
            privateView.put(label, Map.of("address", wallets.get(label).baseAddress(),
                    "balance", total, "notes", held));
        }

        List<Map<String, Object>> onChain = new ArrayList<>();
        for (Utxo u : utxosAt(ledger)) {
            ConstrPlutusData d = datum(u);
            if (d == null || !holdsNoteToken(u)) continue;
            var f = d.getData().getPlutusDataList();
            onChain.add(Map.of(
                    "utxo", u.getTxHash().substring(0, 12) + "…#" + u.getOutputIndex(),
                    "owner", labelOf(((BytesPlutusData) f.get(0)).getValue()),
                    "u", shortHex(((BigIntPlutusData) f.get(1)).getValue()),
                    "v", shortHex(((BigIntPlutusData) f.get(2)).getValue())));
        }
        List<Map<String, Object>> receipts = new ArrayList<>();
        for (Utxo u : utxosAt(wallets.get("retailer").baseAddress())) {
            boolean receipt = u.getAmount().stream().anyMatch(a -> a.getUnit().startsWith(policyId)
                    && a.getUnit().length() == policyId.length() + 64);
            ConstrPlutusData d = datum(u);
            if (!receipt || d == null) continue;
            var f = d.getData().getPlutusDataList();
            receipts.add(Map.of("utxo", u.getTxHash().substring(0, 12) + "…#" + u.getOutputIndex(),
                    "spender", labelOf(((BytesPlutusData) f.get(0)).getValue()),
                    "price", ((BigIntPlutusData) f.get(1)).getValue()));
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("policyId", policyId);
        body.put("ledgerAddress", ledger);
        body.put("private", privateView);
        body.put("onChain", onChain);
        body.put("receipts", receipts);
        body.put("history", List.copyOf(history));
        body.put("constraints", Map.of("transfer", points.transferCircuit().numConstraints(),
                "redeem", points.redeemCircuit().numConstraints()));
        return body;
    }

    // ------------------------------------------------------------------

    private interface Prover<T> {
        T prove();
    }

    private static <T> T prove(Prover<T> prover, String noProofMessage) {
        try {
            return prover.prove();
        } catch (RuntimeException e) {
            throw new DemoErrors.NoProof(noProofMessage, e);
        }
    }

    private HeldNote largest(String label) {
        return notes.get(label).stream().max(Comparator.comparingLong(h -> h.note().amount()))
                .orElseThrow(() -> new IllegalStateException(label + " holds no notes yet; issue some points first"));
    }

    /** The output of {@code tx} at the ledger whose datum commits to {@code note}. */
    private HeldNote locate(String tx, Note note) throws Exception {
        for (Utxo u : DevKit.utxosOf(backend, ledger, tx)) {
            ConstrPlutusData d = datum(u);
            if (d == null) continue;
            var f = d.getData().getPlutusDataList();
            if (((BigIntPlutusData) f.get(1)).getValue().equals(note.commitment().affineU())
                    && ((BigIntPlutusData) f.get(2)).getValue().equals(note.commitment().affineV())) {
                return new HeldNote(note, tx, u.getOutputIndex());
            }
        }
        throw new IllegalStateException("note output of " + tx + " not found");
    }

    private Utxo utxo(HeldNote h) throws Exception {
        return DevKit.utxosOf(backend, ledger, h.txHash()).stream()
                .filter(u -> u.getOutputIndex() == h.index()).findFirst()
                .orElseThrow(() -> new IllegalStateException("note " + h.txHash() + "#" + h.index() + " is spent"));
    }

    private boolean holdsNoteToken(Utxo u) {
        String unit = policyId + HexUtil.encodeHexString(ConfidentialPoints.NOTE_TOKEN);
        return u.getAmount().stream().anyMatch(a -> a.getUnit().equals(unit));
    }

    private List<Utxo> utxosAt(String address) throws Exception {
        List<Utxo> all = new ArrayList<>();
        for (int page = 1; ; page++) {
            var r = backend.getUtxoService().getUtxos(address, 100, page);
            if (!r.isSuccessful() || r.getValue() == null || r.getValue().isEmpty()) break;
            all.addAll(r.getValue());
            if (r.getValue().size() < 100) break;
        }
        return all;
    }

    private static ConstrPlutusData datum(Utxo u) {
        try {
            if (u.getInlineDatum() == null || u.getInlineDatum().isEmpty()) return null;
            var d = PlutusData.deserialize(HexUtil.decodeHexString(u.getInlineDatum()));
            return d instanceof ConstrPlutusData c ? c : null;
        } catch (Exception e) {
            return null;
        }
    }

    private String labelOf(byte[] pkh) {
        for (var e : wallets.entrySet()) {
            if (Arrays.equals(pkh(e.getValue()), pkh)) return e.getKey();
        }
        return HexUtil.encodeHexString(pkh).substring(0, 10) + "…";
    }

    private Map<String, Object> record(String action, String summary, String tx) {
        var entry = Map.<String, Object>of("action", action, "summary", summary, "txHash", tx);
        history.add(0, entry);
        return entry;
    }

    private void requireHolder(String label) {
        if (!wallets.containsKey(label)) throw new IllegalArgumentException("unknown wallet: " + label);
    }

    private static void requireAmount(long amount) {
        if (amount <= 0) throw new IllegalArgumentException("amount must be positive");
    }

    static byte[] pkh(Account account) {
        return account.hdKeyPair().getPublicKey().getKeyHash();
    }

    static String shortHex(BigInteger value) {
        String hex = value.toString(16);
        return hex.substring(0, Math.min(14, hex.length())) + "…";
    }
}
