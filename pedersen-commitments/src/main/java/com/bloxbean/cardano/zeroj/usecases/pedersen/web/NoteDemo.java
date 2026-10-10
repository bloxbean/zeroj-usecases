package com.bloxbean.cardano.zeroj.usecases.pedersen.web;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.AdmittedAuditor;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.AuditedNote;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.AuditorKeys;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.AuditorView;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.ChainNote;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.KeyPossession;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.NoteLedgerScript;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.NoteProofs;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.NoteWallet;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.Registry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * One confidential-note demo (ADR-0007): an issuer, holders, an auditor with a registry, and a
 * {@code NoteLedger}. Points uses trusted issuance; payroll uses proved issuance. The server holds
 * every wallet's viewing key and the auditor's keys on their behalf (demo custody); every balance
 * and every audited amount is recovered from the chain, never from server memory.
 */
final class NoteDemo {

    private static final Logger log = LoggerFactory.getLogger(NoteDemo.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String name;
    private final BackendService backend;
    private final Funding funding;
    private final List<String> holders;
    private final String issuerLabel;
    private final String auditorLabel;
    private final byte[] token;
    private final boolean provedIssuance;

    private final Map<String, Account> wallets = new LinkedHashMap<>();
    private final Map<String, NoteViewingKey> views = new LinkedHashMap<>();
    private final Map<Long, AuditorKeys> auditorKeys = new ConcurrentHashMap<>();
    private final List<Map<String, Object>> history = new ArrayList<>();
    private Account auditorAccount;
    private KeyPossession possession;
    private Registry registry;
    private NoteLedgerScript ledger;
    private AuditorView auditorView;
    private AdmittedAuditor retired;

    NoteDemo(String name, BackendService backend, Funding funding, String issuerLabel, List<String> holders,
             String auditorLabel, String token, boolean provedIssuance) {
        this.name = name;
        this.backend = backend;
        this.funding = funding;
        this.issuerLabel = issuerLabel;
        this.holders = holders;
        this.auditorLabel = auditorLabel;
        this.token = token.getBytes(StandardCharsets.UTF_8);
        this.provedIssuance = provedIssuance;
    }

    /** Compiles circuits (cached dev keys), funds wallets, registers the auditor and deploys the ledger, once. */
    synchronized void ensureReady() throws Exception {
        if (ledger != null) return;
        NoteProofs proofs = provedIssuance ? NoteProofs.withIssuance() : NoteProofs.spendOnly();
        possession = new KeyPossession();
        wallets.put(issuerLabel, funding.newWallet(name + "/" + issuerLabel, 300));
        for (String h : holders) {
            wallets.put(h, funding.newWallet(name + "/" + h, 200));
            views.put(h, NoteViewingKey.generate(RANDOM));
        }
        auditorAccount = funding.newWallet(name + "/" + auditorLabel, 100);
        Utxo seed = backend.getUtxoService().getUtxos(auditorAccount.baseAddress(), 10, 1).getValue().getFirst();
        Registry reg = Registry.forSeed(seed.getTxHash(), seed.getOutputIndex(), possession);
        AuditorKeys gen0 = AuditorKeys.generate(RANDOM);
        String init = DemoErrors.require(reg.init(backend, auditorAccount, seed,
                gen0.entry(reg.policy(), pkh(auditorAccount), 0, possession)), "Registering the " + auditorLabel);
        DevKit.waitForTx(backend, init);
        auditorKeys.put(0L, gen0);
        NoteLedgerScript l = new NoteLedgerScript(pkh(wallets.get(issuerLabel)), token, proofs, reg);
        String deployed = DemoErrors.require(l.deploy(backend, wallets.get(issuerLabel)), "Deploying the ledger");
        registry = reg;
        auditorView = new AuditorView(auditorKeys, l);
        ledger = l;
        record("setup", auditorLabel + " registered its keys (generation 0); ledger deployed", deployed, null);
        log.info("{} ledger {} (policy {}), registry {}", name, l.address(), l.policyId(), reg.address());
    }

    NoteLedgerScript ledger() { return ledger; }

    // ------------------------------------------------------------------ actions

    /** The issuer creates a note of {@code amount} for {@code to}. With {@code reported}, the trusted issuer lies to the auditor. */
    Map<String, Object> issue(String to, long amount, Long reported) throws Exception {
        requireHolder(to);
        requireAmount(amount);
        AdmittedAuditor auditor = registry.admitted(backend);
        AuditedNote note = AuditedNote.create(pkh(wallets.get(to)), amount, views.get(to).readerKey(), auditor, RANDOM);
        if (reported != null) {
            note = note.withLimbs(AuditedNote.limbsOf(BigInteger.valueOf(reported), auditor, RANDOM));
        }
        Result<String> result;
        if (provedIssuance) {
            AuditedNote proved = note;
            var proof = DemoErrors.prove(() -> ledger.proofs().proveIssue(List.of(proved), auditor),
                    reported == null ? "no issuance proof"
                            : "the " + issuerLabel + "'s limbs encrypt " + reported + ", not " + amount + ": no issuance proof exists");
            result = ledger.provedIssue(backend, wallets.get(issuerLabel), List.of(note), proof);
        } else {
            result = ledger.issue(backend, wallets.get(issuerLabel), List.of(note));
        }
        String tx = DemoErrors.require(result, "Issue");
        DevKit.waitForTx(backend, tx);
        String summary = issuerLabel + " issued " + amount + " to " + to
                + (reported == null ? "" : " but told the " + auditorLabel + " " + reported);
        return record("issue", summary, tx, DevKit.lastBudget());
    }

    /** {@code from} sends {@code amount} to {@code to}, splitting its largest note. */
    Map<String, Object> transfer(String from, String to, long amount, Cheat cheat) throws Exception {
        requireHolder(from);
        requireHolder(to);
        requireAmount(amount);
        NoteWallet.Owned source = largest(from);
        AdmittedAuditor auditor = cheat == Cheat.RETIRED_KEY ? requireRetired() : registry.admitted(backend);
        long have = source.opening().value().longValueExact();
        AuditedNote out1 = AuditedNote.create(pkh(wallets.get(to)), amount, views.get(to).readerKey(), auditor, RANDOM);
        AuditedNote out2 = AuditedNote.create(pkh(wallets.get(from)), Math.max(0, have - amount),
                views.get(from).readerKey(), auditor, RANDOM);
        if (cheat == Cheat.GARBAGE_DELIVERY) {
            byte[] garbage = new byte[89];
            RANDOM.nextBytes(garbage);
            out1 = out1.withDeliveries(List.of(garbage, out1.deliveries().get(1)));
        }
        AuditedNote o1 = out1;
        var proof = DemoErrors.prove(() -> ledger.proofs().proveTransfer(source.spent(), o1, out2, auditor),
                from + "'s note holds " + have + "; no proof exists that it splits into " + amount + " + " + out2.amount());
        Result<String> result = cheat == Cheat.STAKE_VARIANT_OUTPUT
                ? ledger.transferWithStakeVariantCopy(backend, wallets.get(from), source.note().utxo(), out1, out2, proof)
                : ledger.transfer(backend, wallets.get(from), source.note().utxo(), out1, out2, proof);
        String what = switch (cheat) {
            case RETIRED_KEY -> "Transfer with limbs to the " + auditorLabel + "'s retired key";
            case STAKE_VARIANT_OUTPUT -> "Transfer with an extra note at the ledger's script under another stake key";
            default -> "Transfer";
        };
        String tx = DemoErrors.require(result, what);
        DevKit.waitForTx(backend, tx);
        String summary = from + " sent " + amount + " to " + to
                + (cheat == Cheat.GARBAGE_DELIVERY ? " with a garbage delivery (the amount is still enforced for the "
                + auditorLabel + ")" : " (amounts hidden on-chain)");
        return record("transfer", summary, tx, DevKit.lastBudget());
    }

    /** {@code from} pays a public {@code price} at the issuer and keeps the hidden change. */
    Map<String, Object> redeem(String from, long price) throws Exception {
        requireHolder(from);
        requireAmount(price);
        if (price >= 1L << 32) throw new IllegalArgumentException("price must be below 2^32");
        NoteWallet.Owned source = largest(from);
        AdmittedAuditor auditor = registry.admitted(backend);
        long have = source.opening().value().longValueExact();
        AuditedNote change = AuditedNote.create(pkh(wallets.get(from)), Math.max(0, have - price),
                views.get(from).readerKey(), auditor, RANDOM);
        var proof = DemoErrors.prove(() -> ledger.proofs().proveRedeem(source.spent(), change, price, auditor),
                from + "'s note holds " + have + "; no proof exists that it pays " + price + " and keeps " + change.amount());
        String tx = DemoErrors.require(ledger.redeem(backend, wallets.get(from), wallets.get(issuerLabel).baseAddress(),
                source.note().utxo(), change, price, proof), "Redeem");
        DevKit.waitForTx(backend, tx);
        return record("redeem", from + " redeemed " + price + " at the " + issuerLabel + " (price public, balance hidden)",
                tx, DevKit.lastBudget());
    }

    /** {@code thief} spends one of {@code victim}'s notes: the validator requires the owner's signature. */
    Map<String, Object> steal(String thief, String victim) throws Exception {
        requireHolder(thief);
        requireHolder(victim);
        if (thief.equals(victim)) throw new IllegalArgumentException("pick two different wallets");
        NoteWallet.Owned target = largest(victim);
        AdmittedAuditor auditor = registry.admitted(backend);
        AuditedNote toThief = AuditedNote.create(pkh(wallets.get(thief)), target.opening().value().longValueExact(),
                views.get(thief).readerKey(), auditor, RANDOM);
        AuditedNote zero = AuditedNote.create(pkh(wallets.get(thief)), 0, views.get(thief).readerKey(), auditor, RANDOM);
        var proof = ledger.proofs().proveTransfer(target.spent(), toThief, zero, auditor);
        DemoErrors.require(ledger.transfer(backend, wallets.get(thief), target.note().utxo(), toThief, zero, proof),
                thief + " spending " + victim + "'s note");
        throw new IllegalStateException("unexpected: the ledger accepted a spend without the owner's signature");
    }

    /** The auditor rotates to a new generation of keys; the old keys are kept to read old notes. */
    Map<String, Object> rotate() throws Exception {
        retired = registry.admitted(backend);
        long next = retired.generation() + 1;
        AuditorKeys keys = AuditorKeys.generate(RANDOM);
        String tx = DemoErrors.require(registry.rotate(backend, auditorAccount, auditorAccount,
                keys.entry(registry.policy(), pkh(auditorAccount), next, possession)), "Rotating the " + auditorLabel + "'s keys");
        DevKit.waitForTx(backend, tx);
        auditorKeys.put(next, keys);
        return record("rotate", auditorLabel + " rotated to key generation " + next, tx, DevKit.lastBudget());
    }

    enum Cheat { NONE, GARBAGE_DELIVERY, RETIRED_KEY, STAKE_VARIANT_OUTPUT }

    // ------------------------------------------------------------------ state

    Map<String, Object> state() throws Exception {
        List<ChainNote> notes = ChainNote.all(backend, ledger);
        Map<String, Object> wallet = new LinkedHashMap<>();
        for (String h : holders) {
            NoteWallet.Scan scan = NoteWallet.scan(notes, pkh(wallets.get(h)), views.get(h));
            List<Map<String, Object>> owned = new ArrayList<>();
            for (NoteWallet.Owned o : scan.owned()) {
                owned.add(Map.of("amount", o.opening().value().longValueExact(), "utxo", shortRef(o.note()),
                        "commitment", shortHex(o.note().u()), "generation", o.note().generation()));
            }
            List<String> unopenable = scan.unopenable().stream().map(NoteDemo::shortRef).toList();
            wallet.put(h, Map.of("address", wallets.get(h).baseAddress(), "balance", scan.balance(),
                    "notes", owned, "unopenable", unopenable, "readableNotMine", scan.readableNotMine().size()));
        }

        List<Map<String, Object>> onChain = new ArrayList<>();
        List<Map<String, Object>> audited = new ArrayList<>();
        Map<String, Long> totals = new LinkedHashMap<>();
        for (ChainNote n : notes) {
            onChain.add(Map.of("utxo", shortRef(n), "owner", labelOf(n.owner()), "u", shortHex(n.u()),
                    "v", shortHex(n.v()), "generation", n.generation(),
                    "limbHandle", shortHex(n.audit().getFirst()), "deliveries", n.deliveries().size()));
            AuditorView.Audited a = auditorView.audit(n);
            String status = a.consistent() ? "matches its delivery"
                    : a.delivered().isEmpty() ? "its delivery does not open" : "its delivery says " + a.delivered().get().value();
            audited.add(Map.of("utxo", shortRef(n), "owner", labelOf(n.owner()), "amount", a.amount(),
                    "origin", a.origin() == AuditorView.Origin.PROOF_ENFORCED ? "proof-enforced" : "issuer-claimed",
                    "consistent", a.consistent(), "status", status, "generation", n.generation()));
            totals.merge(labelOf(n.owner()), a.amount(), Long::sum);
        }
        var entry = registry.current(backend);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ledgerAddress", ledger.address());
        body.put("policyId", ledger.policyId());
        body.put("registry", Map.of("address", registry.address(), "generation", entry.generation(),
                "elgamalKey", HexUtil.encodeHexString(entry.pkEnc()).substring(0, 16) + "…",
                "viewingKey", HexUtil.encodeHexString(entry.viewKey()).substring(0, 16) + "…",
                "auditor", auditorLabel));
        body.put("wallets", wallet);
        body.put("onChain", onChain);
        body.put("auditor", Map.of("notes", audited, "totals", totals, "label", auditorLabel));
        body.put("receipts", receipts());
        body.put("history", List.copyOf(history));
        body.put("constraints", constraints());
        body.put("issuance", provedIssuance ? "proved" : "trusted");
        body.put("canUseRetiredKey", retired != null);
        return body;
    }

    private Map<String, Object> constraints() {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("transfer", ledger.proofs().transfer().numConstraints());
        c.put("redeem", ledger.proofs().redeem().numConstraints());
        if (provedIssuance) c.put("issue", ledger.proofs().issue(1).numConstraints());
        return c;
    }

    private List<Map<String, Object>> receipts() throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        String policy = ledger.policyId();
        for (int page = 1; ; page++) {
            var r = backend.getUtxoService().getUtxos(wallets.get(issuerLabel).baseAddress(), 100, page);
            if (!r.isSuccessful() || r.getValue() == null || r.getValue().isEmpty()) break;
            for (Utxo u : r.getValue()) {
                boolean receipt = u.getAmount().stream().anyMatch(a -> a.getUnit().startsWith(policy)
                        && a.getUnit().length() == policy.length() + 64);
                if (!receipt || u.getInlineDatum() == null) continue;
                var d = PlutusData.deserialize(HexUtil.decodeHexString(u.getInlineDatum()));
                if (!(d instanceof ConstrPlutusData c)) continue;
                var f = c.getData().getPlutusDataList();
                out.add(Map.of("utxo", u.getTxHash().substring(0, 12) + "…#" + u.getOutputIndex(),
                        "spender", labelOf(((BytesPlutusData) f.get(0)).getValue()),
                        "price", ((BigIntPlutusData) f.get(1)).getValue()));
            }
            if (r.getValue().size() < 100) break;
        }
        return out;
    }

    // ------------------------------------------------------------------ helpers

    private NoteWallet.Owned largest(String label) throws Exception {
        List<ChainNote> notes = ChainNote.all(backend, ledger);
        return NoteWallet.scan(notes, pkh(wallets.get(label)), views.get(label)).owned().stream()
                .max(Comparator.comparingLong(o -> o.opening().value().longValueExact()))
                .orElseThrow(() -> new IllegalStateException(label + " holds no notes yet; issue some first"));
    }

    private AdmittedAuditor requireRetired() {
        if (retired == null) throw new IllegalStateException("rotate the " + auditorLabel + "'s keys first");
        return retired;
    }

    private Map<String, Object> record(String action, String summary, String tx, DevKit.Budget budget) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("action", action);
        entry.put("summary", summary);
        entry.put("txHash", tx);
        if (budget != null && budget.steps() > 0) {
            entry.put("cost", String.format("%.1f%% of the step limit, %.1f%% of memory", budget.stepsPercent(), budget.memoryPercent()));
        }
        history.add(0, entry);
        return entry;
    }

    private void requireHolder(String label) {
        if (!views.containsKey(label)) throw new IllegalArgumentException("unknown wallet: " + label);
    }

    private static void requireAmount(long amount) {
        if (amount <= 0) throw new IllegalArgumentException("amount must be positive");
    }

    private String labelOf(byte[] pkh) {
        for (var e : wallets.entrySet()) {
            if (Arrays.equals(pkh(e.getValue()), pkh)) return e.getKey();
        }
        return HexUtil.encodeHexString(pkh).substring(0, 10) + "…";
    }

    static byte[] pkh(Account account) {
        return account.hdKeyPair().getPublicKey().getKeyHash();
    }

    static String shortRef(ChainNote n) {
        return n.utxo().getTxHash().substring(0, 12) + "…#" + n.utxo().getOutputIndex();
    }

    static String shortHex(BigInteger value) {
        String hex = value.toString(16);
        return hex.substring(0, Math.min(14, hex.length())) + "…";
    }
}
