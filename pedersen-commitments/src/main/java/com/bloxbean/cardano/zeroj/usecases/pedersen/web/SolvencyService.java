package com.bloxbean.cardano.zeroj.usecases.pedersen.web;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.plutus.spec.PlutusScript;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Plutus;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.RoleWallet;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Customer;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Period;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.AuditorKeys;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.KeyPossession;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.Registry;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Demo C, solvency with hidden liabilities, for the UI (ADR-0006 C, ADR-0007 N6). Each customer's
 * opening is delivered on-chain to the customer's viewing key, and the aggregate opening to the
 * auditor's registered viewing key, so customers and the auditor check from chain data. The server
 * holds the customers' and the auditor's keys on their behalf (demo custody), and its API is the
 * exchange operator's view.
 *
 * <p>The exchange's signature makes an attestation the exchange's, so its wallet has a random key
 * persisted in the demo data directory ({@link RoleWallet}, ADR-0009 D11), loaded before the app
 * starts serving; its key hash is the vault's parameter. Every attestation draws fresh salts and
 * blindings and a shuffled entry order ({@link SolvencyAttestation#forAttestation}, ADR-0009 D7).
 */
@Service
public class SolvencyService {

    static final int CUSTOMERS = 4;
    /** The exchange's role name for {@link RoleWallet}: its key and deployment state files. */
    static final String EXCHANGE_ROLE = "solvency-exchange";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final long LOVELACE = 1_000_000L;

    @Value("${solvency.period-lead-seconds:45}")
    private long leadSeconds = 45;

    @Value("${solvency.period-length-seconds:180}")
    private long lengthSeconds = 180;

    @Value("${demo.data-dir:./data}")
    private String dataDir = "./data";

    private final BackendService backend;
    private final Funding funding;

    private SolvencyAttestation solvency;
    private Account exchange;
    private List<Customer> book = List.of();
    private final Map<String, NoteViewingKey> customerKeys = new LinkedHashMap<>();
    private Account auditorAccount;
    private Registry auditorRegistry;
    private AuditorKeys auditorKeys;

    private Period period;
    private PlutusScript vault;
    private String attestTx;
    private long attestedReserves;
    private String releaseTx;
    private final Map<String, Object> lastChecks = new LinkedHashMap<>();

    public SolvencyService(BackendService backend, Funding funding) {
        this.backend = backend;
        this.funding = funding;
    }

    /**
     * Loads the exchange's wallet, or creates it on first start. A missing, damaged or mismatched
     * key with existing deployment state stops the app (fail closed, ADR-0009 D11).
     */
    @PostConstruct
    synchronized void loadExchangeKey() {
        exchange = RoleWallet.loadOrCreate(Path.of(dataDir), EXCHANGE_ROLE, RANDOM).account();
    }

    /** The exchange's payment key hash: the vault's parameter. */
    synchronized byte[] exchangeKeyHash() {
        return RoleWallet.keyHash(exchange);
    }

    synchronized void ensureReady() throws Exception {
        if (solvency != null) return;
        var s = new SolvencyAttestation(CUSTOMERS);
        funding.topUpIfBelow("solvency/exchange", exchange, 5_000);
        book = List.of(customer("alice", 500 * LOVELACE), customer("bob", 1_200 * LOVELACE),
                customer("carol", 300 * LOVELACE), customer("dave", 0));
        // The auditor registers its keys (possession proved on-chain); the exchange admits the entry.
        var possession = new KeyPossession();
        auditorAccount = funding.newWallet("solvency/auditor", 100);
        Utxo seed = backend.getUtxoService().getUtxos(auditorAccount.baseAddress(), 10, 1).getValue().getFirst();
        auditorRegistry = Registry.forSeed(seed.getTxHash(), seed.getOutputIndex(), possession);
        auditorKeys = AuditorKeys.generate(RANDOM);
        String tx = DemoErrors.require(auditorRegistry.init(backend, auditorAccount, seed,
                auditorKeys.entry(auditorRegistry.policy(), PointsService.pkh(auditorAccount), 0, possession)),
                "Registering the solvency auditor");
        DevKit.waitForTx(backend, tx);
        solvency = s;
    }

    /** A customer of the book; the viewing key stays the same across books for the same id. */
    private Customer customer(String id, long balance) {
        NoteViewingKey key = customerKeys.computeIfAbsent(id, k -> NoteViewingKey.generate(RANDOM));
        return Customer.of(id, balance, key.readerKey());
    }

    /** Replaces the book (four customers, balances in ADA) while no attestation is live. */
    public synchronized Map<String, Object> setBook(List<Map<String, Object>> rows) throws Exception {
        ensureReady();
        if (live()) throw new IllegalStateException("an attestation is live; release it after its period first");
        if (rows == null || rows.size() != CUSTOMERS) {
            throw new IllegalArgumentException("the circuit takes exactly " + CUSTOMERS + " customers (pad with 0 balances)");
        }
        List<Customer> next = new ArrayList<>();
        var ids = new HashSet<String>();
        for (var row : rows) {
            String id = String.valueOf(row.get("id")).trim();
            long ada = ((Number) row.get("balance")).longValue();
            if (id.isEmpty() || !ids.add(id)) throw new IllegalArgumentException("customer ids must be unique and non-empty");
            if (ada < 0 || ada > 1_000_000_000L) throw new IllegalArgumentException("balance out of range");
            next.add(customer(id, ada * LOVELACE));
        }
        book = List.copyOf(next);
        period = null;
        vault = null;
        attestTx = null;
        releaseTx = null;
        lastChecks.clear();
        return Map.of("summary", "Book updated with fresh salts and blindings");
    }

    /**
     * Locks {@code reservesAda} for a new period that starts {@code leadSeconds} from now. An
     * insolvent book has no proof.
     */
    public synchronized Map<String, Object> attest(long reservesAda, String garbageFor) throws Exception {
        ensureReady();
        if (live()) throw new IllegalStateException("an attestation is already live; release it after its period");
        if (reservesAda <= 0) throw new IllegalArgumentException("reserves must be positive");
        long reserves = reservesAda * LOVELACE;
        long now = DevKit.chainTimeMillis(backend);
        Period next = new Period(now + leadSeconds * 1000, now + (leadSeconds + lengthSeconds) * 1000);
        // Fresh salts and blindings in a shuffled order: the proof, the entries and the deliveries
        // all follow this list, so nothing links this attestation's entries to an earlier one's.
        List<Customer> attested = SolvencyAttestation.forAttestation(book);
        var proof = proveSolvent(reserves, attested);
        PlutusScript v = solvency.vault(PointsService.pkh(exchange), next);
        var entries = SolvencyAttestation.entries(attested);
        if (garbageFor != null && !garbageFor.isBlank()) entries = SolvencyAttestation.withGarbageFor(entries, attested, garbageFor);
        var auditor = auditorRegistry.admitted(backend);
        String tx = DemoErrors.require(SolvencyAttestation.attest(backend, v, exchange, reserves, entries,
                SolvencyAttestation.auditorDelivery(attested, auditor.viewKey()), proof, DevKit.slotAt(backend, next.start())),
                "Attestation");
        DevKit.waitForTx(backend, tx);
        // Each customer's record now carries this period's salt and blinding (sent with their
        // statement); the book keeps its own order.
        book = book.stream().map(c -> attested.stream().filter(a -> a.id().equals(c.id())).findFirst().orElseThrow())
                .toList();
        period = next;
        vault = v;
        attestTx = tx;
        attestedReserves = reserves;
        releaseTx = null;
        lastChecks.clear();
        String summary = "Exchange locked " + reservesAda + " ADA and attested for the period"
                + (garbageFor == null || garbageFor.isBlank() ? "" : ", delivering garbage to " + garbageFor);
        return Map.of("summary", summary, "txHash", tx);
    }

    /**
     * The "cheat": add a second attestation for the same period once it has begun (here, the same
     * book again, freshly salted and shuffled like any attestation). The vault refuses anything
     * whose validity range ends after the period start.
     */
    public synchronized Map<String, Object> attestAgain() throws Exception {
        ensureReady();
        if (vault == null) throw new IllegalStateException("attest first");
        List<Customer> again = SolvencyAttestation.forAttestation(book);
        var proof = proveSolvent(attestedReserves, again);
        long until = DevKit.chainTimeMillis(backend) + 60_000;
        DemoErrors.require(SolvencyAttestation.attest(backend, vault, exchange, attestedReserves,
                SolvencyAttestation.entries(again), SolvencyAttestation.auditorDelivery(again,
                        auditorRegistry.admitted(backend).viewKey()), proof, DevKit.slotAt(backend, until)),
                "A second attestation inside the period");
        throw new IllegalStateException("unexpected: the vault accepted an attestation after the period start");
    }

    /**
     * A customer's check from chain data: listed exactly once across the period's attestations,
     * and the delivered opening (decrypted with the customer's own viewing key) is the balance the
     * account shows.
     */
    public synchronized Map<String, Object> check(String id) throws Exception {
        ensureReady();
        if (vault == null) throw new IllegalStateException("attest first");
        Customer customer = book.stream().filter(c -> c.id().equals(id)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("unknown customer: " + id));
        var result = SolvencyAttestation.customerCheck(SolvencyAttestation.liveEntries(backend, vault), customer,
                customerKeys.get(id));
        boolean ok = result == SolvencyAttestation.Check.LISTED_ONCE_CORRECT;
        String verdict = switch (result) {
            case LISTED_ONCE_CORRECT -> "listed exactly once; the on-chain opening decrypts to the account balance";
            case MISSING -> "MISSING from the period's attestations";
            case LISTED_TWICE -> "LISTED TWICE";
            case UNOPENABLE -> "UNOPENABLE: the exchange's on-chain delivery does not open to the entry (evidence)";
            case WRONG_BALANCE -> "WRONG BALANCE: the on-chain opening differs from the account";
        };
        lastChecks.put(id, verdict);
        return Map.of("customer", id, "ok", ok, "verdict", verdict, "phase", phase());
    }

    /**
     * The auditor sums the on-chain commitments and opens its own on-chain delivery against the
     * sum: it learns L (per attestation) and nothing about any single balance.
     */
    public synchronized Map<String, Object> audit() throws Exception {
        ensureReady();
        if (vault == null) throw new IllegalStateException("attest first");
        var live = SolvencyAttestation.liveAttestations(backend, vault);
        if (live.isEmpty()) throw new IllegalStateException("no live attestation to audit (released, or not yet indexed)");
        BigInteger total = BigInteger.ZERO;
        boolean ok = true;
        for (var attestation : live) {
            var opened = SolvencyAttestation.auditorCheck(attestation, auditorKeys.viewing());
            ok = ok && opened.isPresent();
            total = total.add(opened.orElse(BigInteger.ZERO));
        }
        return Map.of("ok", ok,
                "summary", ok ? "Auditor opened its on-chain delivery against the sum of all on-chain commitments"
                        : "The aggregate delivery did not open to the sum of the commitments",
                "liabilitiesAda", total.divide(BigInteger.valueOf(LOVELACE)),
                "reservesAda", attestedReserves / LOVELACE);
    }

    /** Releases the reserve; before the period ends the vault rejects it. */
    public synchronized Map<String, Object> release() throws Exception {
        ensureReady();
        if (vault == null || attestTx == null || releaseTx != null) throw new IllegalStateException("nothing to release");
        Utxo live = liveUtxo();
        long now = DevKit.chainTimeMillis(backend);
        long from = now < period.end() ? DevKit.slotAt(backend, now) : DevKit.slotAt(backend, period.end()) + 1;
        String tx = DemoErrors.require(SolvencyAttestation.release(backend, vault, exchange, live, from),
                now < period.end() ? "A release inside the period" : "Release");
        DevKit.waitForTx(backend, tx);
        releaseTx = tx;
        return Map.of("summary", "Reserve released after the period; attestation token burned", "txHash", tx);
    }

    /**
     * The public view (ADR-0009 D10): what a chain observer can read about the period, and the
     * vault's entries as they are on-chain. It names no customer and no balance, so nothing in it
     * pairs a customer with an id hash, a commitment or a position. The book is in
     * {@link #operatorView()}.
     */
    public synchronized Map<String, Object> state() throws Exception {
        ensureReady();
        PublicPeriod live = null;
        if (period != null) {
            live = new PublicPeriod(period, SolvencyAttestation.address(vault), Plutus.policyId(vault), attestTx,
                    attestedReserves, releaseTx, SolvencyAttestation.liveEntries(backend, vault));
        }
        return publicView(DevKit.chainTimeMillis(backend), phase(), solvency.circuit().numConstraints(),
                exchange.baseAddress(), book.size(), live);
    }

    /**
     * The exchange operator's view, which the demo shows because the server holds everyone's keys
     * (demo custody): the book with customer ids, balances, this period's salts and blindings, id
     * hashes, the last check results and the total liabilities. Never part of the public view.
     */
    public synchronized Map<String, Object> operatorView() throws Exception {
        ensureReady();
        return operatorView(book, lastChecks);
    }

    /** A live or past attestation as anyone reads it: the vault, its transactions and its on-chain entries. */
    record PublicPeriod(Period period, String vaultAddress, String vaultPolicy, String attestTx,
                        long reservesLovelace, String releaseTx, List<SolvencyAttestation.Entry> onChain) {}

    static Map<String, Object> publicView(long chainTime, String phase, int constraints, String exchangeAddress,
                                          int customers, PublicPeriod live) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("view", "public");
        body.put("chainTime", chainTime);
        body.put("phase", phase);
        body.put("constraints", constraints);
        body.put("exchangeAddress", exchangeAddress);
        body.put("customers", customers);
        if (live != null) {
            body.put("period", Map.of("start", live.period().start(), "end", live.period().end()));
            body.put("vaultAddress", live.vaultAddress());
            body.put("vaultPolicy", live.vaultPolicy());
            body.put("attestTx", live.attestTx());
            body.put("reservesAda", live.reservesLovelace() / LOVELACE);
            if (live.releaseTx() != null) body.put("releaseTx", live.releaseTx());
            List<Map<String, Object>> entries = new ArrayList<>();
            for (var e : live.onChain()) {
                entries.add(Map.of("idHash", HexUtil.encodeHexString(e.idHash()).substring(0, 12) + "…",
                        "u", PointsService.shortHex(e.commitment().affineU()),
                        "delivery", HexUtil.encodeHexString(e.delivery()).substring(0, 16) + "… (89 B)"));
            }
            body.put("onChain", entries);
        }
        return body;
    }

    static Map<String, Object> operatorView(List<Customer> book, Map<String, Object> checks) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("view", "operator (the exchange's private book; shown by this demo server only because it holds every key)");
        List<Map<String, Object>> privateBook = new ArrayList<>();
        long total = 0;
        for (Customer c : book) {
            total += c.balance();
            privateBook.add(Map.of("id", c.id(), "balance", c.balance() / LOVELACE,
                    "salt", HexUtil.encodeHexString(c.salt()).substring(0, 12) + "…",
                    "blinding", PointsService.shortHex(c.blinding()),
                    "idHash", HexUtil.encodeHexString(c.idHash()).substring(0, 12) + "…",
                    "check", checks.getOrDefault(c.id(), "")));
        }
        body.put("book", privateBook);
        body.put("liabilitiesAda", total / LOVELACE);
        return body;
    }

    // ------------------------------------------------------------------

    private Groth16ProofBLS381 proveSolvent(long reserves, List<Customer> customers) {
        try {
            return solvency.prove(reserves, customers);
        } catch (RuntimeException e) {
            long liabilities = customers.stream().mapToLong(Customer::balance).sum();
            throw new DemoErrors.NoProof("Liabilities (" + liabilities / LOVELACE + " ADA) exceed the reserves ("
                    + reserves / LOVELACE + " ADA), so no proof of solvency exists.", e);
        }
    }

    private boolean live() {
        return attestTx != null && releaseTx == null;
    }

    private String phase() throws Exception {
        if (period == null) return "none";
        if (releaseTx != null) return "released";
        long now = DevKit.chainTimeMillis(backend);
        if (now < period.start()) return "before";
        if (now <= period.end()) return "during";
        return "after";
    }

    private Utxo liveUtxo() throws Exception {
        String unit = Plutus.policyId(vault) + HexUtil.encodeHexString(SolvencyAttestation.ATTEST_TOKEN);
        return DevKit.utxosOf(backend, SolvencyAttestation.address(vault), attestTx).stream()
                .filter(u -> u.getAmount().stream().anyMatch(a -> a.getUnit().equals(unit)))
                .findFirst().orElseThrow(() -> new IllegalStateException("the attestation output is not live"));
    }
}
