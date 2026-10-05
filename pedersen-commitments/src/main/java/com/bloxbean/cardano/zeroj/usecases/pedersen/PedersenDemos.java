package com.bloxbean.cardano.zeroj.usecases.pedersen;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Plutus;
import com.bloxbean.cardano.zeroj.usecases.pedersen.credential.CreditGate;
import com.bloxbean.cardano.zeroj.usecases.pedersen.points.ConfidentialPoints;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation;

import java.time.Instant;
import java.util.List;

/**
 * A walkthrough of the three Pedersen commitment demos on a running Yaci DevKit:
 * {@code ./gradlew run}. Each step prints what goes on-chain and what stays private.
 */
public final class PedersenDemos {

    private PedersenDemos() {}

    public static void main(String[] args) throws Exception {
        if (!DevKit.reachable()) {
            System.err.println("Yaci DevKit is not reachable at " + DevKit.STORE_URL
                    + " (set ZEROJ_YACI_STORE_URL / ZEROJ_YACI_ADMIN_URL)");
            System.exit(1);
        }
        BackendService backend = DevKit.backend();
        confidentialPoints(backend);
        creditGate(backend);
        solvency(backend);
        System.out.println("\nAll three demos completed on DevKit.");
    }

    private static void confidentialPoints(BackendService backend) throws Exception {
        header("A. Confidential points — hidden balances that still add up");
        var retailer = funded();
        var alice = funded();
        var bob = funded();
        var points = new ConfidentialPoints();
        var script = points.script(pkh(retailer));
        String ledger = ConfidentialPoints.address(script);

        var aliceNote = ConfidentialPoints.Note.of(pkh(alice), 1_000);
        String issued = ok(ConfidentialPoints.issue(backend, script, retailer, List.of(aliceNote)), "issue");
        DevKit.waitForTx(backend, issued);
        step("Retailer issued Alice a note. On-chain: owner + commitment (u = %s…). Amount: hidden.",
                aliceNote.commitment().affineU().toString(16).substring(0, 12));

        var toBob = ConfidentialPoints.Note.of(pkh(bob), 700);
        var change = ConfidentialPoints.Note.of(pkh(alice), 300);
        Utxo note = DevKit.utxosOf(backend, ledger, issued).getFirst();
        String sent = ok(ConfidentialPoints.transfer(backend, script, alice, note, toBob, change,
                points.proveTransfer(aliceNote, toBob, change)), "transfer");
        DevKit.waitForTx(backend, sent);
        step("Alice split her note for Bob. The proof shows in = out1 + out2 over 64-bit amounts; nobody else"
                + " learns 1,000 / 700 / 300.");

        var bobChange = ConfidentialPoints.Note.of(pkh(bob), 580);
        Utxo bobNote = DevKit.utxosOf(backend, ledger, sent).stream().filter(u -> u.getOutputIndex() == 0).findFirst().orElseThrow();
        String redeemed = ok(ConfidentialPoints.redeem(backend, script, bob, retailer.baseAddress(), bobNote, bobChange,
                120, points.proveRedeem(toBob, bobChange, 120)), "redeem");
        DevKit.waitForTx(backend, redeemed);
        step("Bob paid a public price of 120 from a hidden balance and kept hidden change; the retailer"
                + " received a receipt token only a valid redemption can mint. tx %s", redeemed);
    }

    private static void creditGate(BackendService backend) throws Exception {
        header("B. Committed credential — prove a predicate, reveal nothing else");
        var bureau = funded();
        var alice = funded();
        var credit = new CreditGate();
        byte[] bureauPolicy = HexUtil.decodeHexString(CreditGate.bureauPolicy(bureau).getPolicyId());
        var gate = credit.gate(bureauPolicy, 50_000, 650);

        var profile = CreditGate.Profile.of(85_000, 720, 1990, 356);
        var commitment = profile.commitment();
        String issued = ok(CreditGate.issueRecord(backend, bureau, alice.baseAddress(), pkh(alice), commitment), "record");
        DevKit.waitForTx(backend, issued);
        step("Bureau committed to Alice's income, credit score, birth year and country in ONE commitment,"
                + " and recorded the issuance on-chain (schema-bound, holder-bound).");

        Utxo record = DevKit.utxosOf(backend, alice.baseAddress(), issued).stream()
                .filter(u -> u.getAmount().stream().anyMatch(a -> a.getUnit().startsWith(HexUtil.encodeHexString(bureauPolicy))))
                .findFirst().orElseThrow();
        String claimed = ok(CreditGate.claim(backend, gate, alice, commitment, record,
                credit.prove(profile, 50_000, 650)), "claim");
        DevKit.waitForTx(backend, claimed);
        step("Alice proved income ≥ 50,000 and score ≥ 650 and received the lender's badge. The lender"
                + " never saw 85,000, 720, her birth year or country. tx %s", claimed);
    }

    private static void solvency(BackendService backend) throws Exception {
        header("C. Solvency — liabilities stay hidden, reserves are locked");
        var exchange = funded(5_000);
        var solvency = new SolvencyAttestation(4);
        long now = DevKit.chainTimeMillis(backend);
        var period = new SolvencyAttestation.Period(now + 40_000, now + 100_000);
        var vault = solvency.vault(pkh(exchange), period);
        var book = List.of(SolvencyAttestation.Customer.of("alice", 500_000_000L),
                SolvencyAttestation.Customer.of("bob", 1_200_000_000L),
                SolvencyAttestation.Customer.of("carol", 300_000_000L),
                SolvencyAttestation.Customer.of("dave", 0));
        long reserves = 2_000_000_000L;
        String attested = ok(SolvencyAttestation.attest(backend, vault, exchange, reserves,
                SolvencyAttestation.entries(book), solvency.prove(reserves, book),
                DevKit.slotAt(backend, period.start())), "attest");
        DevKit.waitForTx(backend, attested);
        step("Before the period starts, the exchange locked 2,000 ADA and proved its hidden liabilities are"
                + " covered. On-chain: one commitment per customer, never a balance or the total.");

        while (DevKit.chainTimeMillis(backend) < period.start()) Thread.sleep(2_000);
        step("The period %s – %s has begun: no attestation can be added or released until it ends.",
                Instant.ofEpochMilli(period.start()), Instant.ofEpochMilli(period.end()));
        var entries = SolvencyAttestation.liveEntries(backend, vault);
        for (var c : book) {
            step("%s checks the period's attestations from chain data: %s", c.id(),
                    SolvencyAttestation.customerCheck(entries, c) ? "listed once, balance correct" : "MISSING OR WRONG");
        }
        step("Auditor opens the sum of all commitments: total liabilities %s (no single balance revealed)",
                SolvencyAttestation.auditorCheck(entries, SolvencyAttestation.auditOpening(book)) ? "verified" : "FAILED");
    }

    // ------------------------------------------------------------------

    private static Account funded() throws Exception {
        return funded(200);
    }

    private static Account funded(int ada) throws Exception {
        var account = new Account(Networks.testnet());
        DevKit.topUp(account.baseAddress(), ada);
        return account;
    }

    private static byte[] pkh(Account account) {
        return account.hdKeyPair().getPublicKey().getKeyHash();
    }

    private static String ok(Result<String> result, String what) {
        if (!result.isSuccessful()) throw new IllegalStateException(what + " failed: " + result.getResponse());
        return result.getValue();
    }

    private static void header(String title) {
        System.out.println("\n=== " + title + " ===");
    }

    private static void step(String format, Object... args) {
        System.out.println("  • " + String.format(format, args));
    }
}
