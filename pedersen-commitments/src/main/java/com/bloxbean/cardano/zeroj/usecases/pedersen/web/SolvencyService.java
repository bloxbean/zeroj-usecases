package com.bloxbean.cardano.zeroj.usecases.pedersen.web;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.plutus.spec.PlutusScript;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Plutus;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Customer;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Period;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Demo C, solvency with hidden liabilities, for the UI. The exchange is a wallet this server
 * creates; the server keeps every customer's balance, salt and blinding (their openings) on their
 * behalf. On-chain there is one commitment per customer and the locked reserve.
 */
@Service
public class SolvencyService {

    static final int CUSTOMERS = 4;
    private static final long LOVELACE = 1_000_000L;

    @Value("${solvency.period-lead-seconds:45}")
    private long leadSeconds = 45;

    @Value("${solvency.period-length-seconds:180}")
    private long lengthSeconds = 180;

    private final BackendService backend;
    private final Funding funding;

    private SolvencyAttestation solvency;
    private Account exchange;
    private List<Customer> book = List.of();

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

    synchronized void ensureReady() {
        if (solvency != null) return;
        var s = new SolvencyAttestation(CUSTOMERS);
        exchange = funding.newWallet("solvency/exchange", 5_000);
        book = List.of(Customer.of("alice", 500 * LOVELACE), Customer.of("bob", 1_200 * LOVELACE),
                Customer.of("carol", 300 * LOVELACE), Customer.of("dave", 0));
        solvency = s;
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
            next.add(Customer.of(id, ada * LOVELACE));
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
    public synchronized Map<String, Object> attest(long reservesAda) throws Exception {
        ensureReady();
        if (live()) throw new IllegalStateException("an attestation is already live; release it after its period");
        if (reservesAda <= 0) throw new IllegalArgumentException("reserves must be positive");
        long reserves = reservesAda * LOVELACE;
        long now = DevKit.chainTimeMillis(backend);
        Period next = new Period(now + leadSeconds * 1000, now + (leadSeconds + lengthSeconds) * 1000);
        var proof = proveSolvent(reserves);
        PlutusScript v = solvency.vault(PointsService.pkh(exchange), next);
        String tx = DemoErrors.require(SolvencyAttestation.attest(backend, v, exchange, reserves,
                SolvencyAttestation.entries(book), proof, DevKit.slotAt(backend, next.start())), "Attestation");
        DevKit.waitForTx(backend, tx);
        period = next;
        vault = v;
        attestTx = tx;
        attestedReserves = reserves;
        releaseTx = null;
        lastChecks.clear();
        return Map.of("summary", "Exchange locked " + reservesAda + " ADA and attested for the period", "txHash", tx);
    }

    /**
     * The "cheat": add a second attestation for the same period once it has begun (here, the same
     * book again). The vault refuses anything whose validity range ends after the period start.
     */
    public synchronized Map<String, Object> attestAgain() throws Exception {
        ensureReady();
        if (vault == null) throw new IllegalStateException("attest first");
        var proof = proveSolvent(attestedReserves);
        long until = DevKit.chainTimeMillis(backend) + 60_000;
        DemoErrors.require(SolvencyAttestation.attest(backend, vault, exchange, attestedReserves,
                SolvencyAttestation.entries(book), proof, DevKit.slotAt(backend, until)),
                "A second attestation inside the period");
        throw new IllegalStateException("unexpected: the vault accepted an attestation after the period start");
    }

    /** A customer's check: listed exactly once across the period's attestations, entry opens. */
    public synchronized Map<String, Object> check(String id) throws Exception {
        ensureReady();
        if (vault == null) throw new IllegalStateException("attest first");
        Customer customer = book.stream().filter(c -> c.id().equals(id)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("unknown customer: " + id));
        boolean ok = SolvencyAttestation.customerCheck(SolvencyAttestation.liveEntries(backend, vault), customer);
        String verdict = ok ? "listed exactly once, and the entry opens to the balance" : "MISSING OR WRONG";
        lastChecks.put(id, verdict);
        return Map.of("customer", id, "ok", ok, "verdict", verdict, "phase", phase());
    }

    /** The auditor opens the sum of all commitments with (L, Σr) and learns L, nothing else. */
    public synchronized Map<String, Object> audit() throws Exception {
        ensureReady();
        if (vault == null) throw new IllegalStateException("attest first");
        var opening = SolvencyAttestation.auditOpening(book);
        boolean ok = SolvencyAttestation.auditorCheck(SolvencyAttestation.liveEntries(backend, vault), opening);
        return Map.of("ok", ok,
                "summary", ok ? "Auditor opened the sum of all on-chain commitments" : "The aggregate opening did not verify",
                "liabilitiesAda", opening.liabilities().divide(BigInteger.valueOf(LOVELACE)),
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

    public synchronized Map<String, Object> state() throws Exception {
        ensureReady();
        Map<String, Object> body = new LinkedHashMap<>();
        long now = DevKit.chainTimeMillis(backend);
        body.put("chainTime", now);
        body.put("phase", phase());
        body.put("constraints", solvency.circuit().numConstraints());
        body.put("exchangeAddress", exchange.baseAddress());
        List<Map<String, Object>> privateBook = new ArrayList<>();
        long total = 0;
        for (Customer c : book) {
            total += c.balance();
            privateBook.add(Map.of("id", c.id(), "balance", c.balance() / LOVELACE,
                    "salt", HexUtil.encodeHexString(c.salt()).substring(0, 12) + "…",
                    "blinding", PointsService.shortHex(c.blinding()),
                    "idHash", HexUtil.encodeHexString(c.idHash()).substring(0, 12) + "…",
                    "check", lastChecks.getOrDefault(c.id(), "")));
        }
        body.put("book", privateBook);
        body.put("liabilitiesAda", total / LOVELACE);
        if (period != null) {
            body.put("period", Map.of("start", period.start(), "end", period.end()));
            body.put("vaultAddress", SolvencyAttestation.address(vault));
            body.put("vaultPolicy", Plutus.policyId(vault));
            body.put("attestTx", attestTx);
            body.put("reservesAda", attestedReserves / LOVELACE);
            if (releaseTx != null) body.put("releaseTx", releaseTx);
            List<Map<String, Object>> entries = new ArrayList<>();
            for (var e : SolvencyAttestation.liveEntries(backend, vault)) {
                entries.add(Map.of("idHash", HexUtil.encodeHexString(e.idHash()).substring(0, 12) + "…",
                        "u", PointsService.shortHex(e.commitment().affineU())));
            }
            body.put("onChain", entries);
        }
        return body;
    }

    // ------------------------------------------------------------------

    private Groth16ProofBLS381 proveSolvent(long reserves) {
        try {
            return solvency.prove(reserves, book);
        } catch (RuntimeException e) {
            long liabilities = book.stream().mapToLong(Customer::balance).sum();
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
