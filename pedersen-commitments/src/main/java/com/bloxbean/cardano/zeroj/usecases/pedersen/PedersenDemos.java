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
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.AuditedNote;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.AuditorKeys;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.AuditorView;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.ChainNote;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.KeyPossession;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.NoteLedgerScript;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.NoteProofs;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.NoteWallet;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.Registry;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation;

import org.zeroj.circuit.lib.jubjub.NoteViewingKey;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
        header("A. Confidential points — hidden balances that still add up, readable from the chain");
        var retailer = funded();
        var alice = funded();
        var bob = funded();
        var auditorAccount = funded(100);
        var random = new SecureRandom();
        var aliceView = NoteViewingKey.generate(random);
        var bobView = NoteViewingKey.generate(random);

        var possession = new KeyPossession();
        Utxo seed = backend.getUtxoService().getUtxos(auditorAccount.baseAddress(), 10, 1).getValue().getFirst();
        var registry = Registry.forSeed(seed.getTxHash(), seed.getOutputIndex(), possession);
        var auditorKeys = AuditorKeys.generate(random);
        DevKit.waitForTx(backend, ok(registry.init(backend, auditorAccount, seed,
                auditorKeys.entry(registry.policy(), pkh(auditorAccount), 0, possession)), "registry"));
        step("The auditor registered its ElGamal and viewing keys; the registry verified both possession proofs on-chain.");
        var ledger = new NoteLedgerScript(pkh(retailer), "PTS".getBytes(), NoteProofs.spendOnly(), registry);
        ok(ledger.deploy(backend, retailer), "deploy");
        var auditor = registry.admitted(backend);
        var auditorView = new AuditorView(Map.of(0L, auditorKeys), ledger);

        var issued = AuditedNote.create(pkh(alice), 1_000, aliceView.readerKey(), auditor, random);
        DevKit.waitForTx(backend, ok(ledger.issue(backend, retailer, List.of(issued)), "issue"));
        var aliceScan = NoteWallet.scan(ChainNote.all(backend, ledger), pkh(alice), aliceView);
        step("Retailer issued Alice a note: owner, commitment, two limb ciphertexts for the auditor, and an"
                + " encrypted opening for Alice and the auditor. Alice recovers %d points from the chain alone.", aliceScan.balance());

        var source = aliceScan.owned().getFirst();
        var toBob = AuditedNote.create(pkh(bob), 700, bobView.readerKey(), auditor, random);
        var change = AuditedNote.create(pkh(alice), 300, aliceView.readerKey(), auditor, random);
        DevKit.waitForTx(backend, ok(ledger.transfer(backend, alice, source.note().utxo(), toBob, change,
                ledger.proofs().proveTransfer(source.spent(), toBob, change, auditor)), "transfer"));
        var bobScan = NoteWallet.scan(ChainNote.all(backend, ledger), pkh(bob), bobView);
        step("Alice split her note for Bob. The proof shows in = out1 + out2 and that each new note's limbs encrypt"
                + " its amount to the auditor. Bob recovers %d from the chain (cost %.1f%% of the step limit).",
                bobScan.balance(), DevKit.lastBudget().stepsPercent());
        for (var n : ChainNote.all(backend, ledger)) {
            var a = auditorView.audit(n);
            step("Auditor reads a note of %d points (%s)", a.amount(), a.origin());
        }

        var bobNote = bobScan.owned().getFirst();
        var bobChange = AuditedNote.create(pkh(bob), 580, bobView.readerKey(), auditor, random);
        String redeemed = ok(ledger.redeem(backend, bob, retailer.baseAddress(), bobNote.note().utxo(), bobChange, 120,
                ledger.proofs().proveRedeem(bobNote.spent(), bobChange, 120, auditor)), "redeem");
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
        header("C. Solvency — liabilities stay hidden, reserves are locked, openings delivered on-chain");
        var exchange = funded(5_000);
        var auditorAccount = funded(100);
        var random = new SecureRandom();
        var possession = new KeyPossession();
        Utxo seed = backend.getUtxoService().getUtxos(auditorAccount.baseAddress(), 10, 1).getValue().getFirst();
        var registry = Registry.forSeed(seed.getTxHash(), seed.getOutputIndex(), possession);
        var auditorKeys = AuditorKeys.generate(random);
        DevKit.waitForTx(backend, ok(registry.init(backend, auditorAccount, seed,
                auditorKeys.entry(registry.policy(), pkh(auditorAccount), 0, possession)), "auditor registry"));

        var solvency = new SolvencyAttestation(4);
        long now = DevKit.chainTimeMillis(backend);
        var period = new SolvencyAttestation.Period(now + 40_000, now + 100_000);
        var vault = solvency.vault(pkh(exchange), period);
        Map<String, NoteViewingKey> keys = new LinkedHashMap<>();
        for (String id : List.of("alice", "bob", "carol", "dave")) keys.put(id, NoteViewingKey.generate(random));
        var book = List.of(SolvencyAttestation.Customer.of("alice", 500_000_000L, keys.get("alice").readerKey()),
                SolvencyAttestation.Customer.of("bob", 1_200_000_000L, keys.get("bob").readerKey()),
                SolvencyAttestation.Customer.of("carol", 300_000_000L, keys.get("carol").readerKey()),
                SolvencyAttestation.Customer.of("dave", 0, keys.get("dave").readerKey()));
        long reserves = 2_000_000_000L;
        String attested = ok(SolvencyAttestation.attest(backend, vault, exchange, reserves,
                SolvencyAttestation.entries(book), SolvencyAttestation.auditorDelivery(book, registry.admitted(backend).viewKey()),
                solvency.prove(reserves, book), DevKit.slotAt(backend, period.start())), "attest");
        DevKit.waitForTx(backend, attested);
        step("Before the period starts, the exchange locked 2,000 ADA and proved its hidden liabilities are"
                + " covered. On-chain: one commitment per customer, each with its opening encrypted to the customer,"
                + " and the total's opening encrypted to the auditor — never a balance or the total in the clear.");

        while (DevKit.chainTimeMillis(backend) < period.start()) Thread.sleep(2_000);
        step("The period %s – %s has begun: no attestation can be added or released until it ends.",
                Instant.ofEpochMilli(period.start()), Instant.ofEpochMilli(period.end()));
        var entries = SolvencyAttestation.liveEntries(backend, vault);
        for (var c : book) {
            step("%s decrypts their entry from chain data with their own key: %s", c.id(),
                    SolvencyAttestation.customerCheck(entries, c, keys.get(c.id())));
        }
        for (var attestation : SolvencyAttestation.liveAttestations(backend, vault)) {
            step("Auditor opens its delivery against the sum of the commitments: total liabilities %s lovelace"
                    + " (no single balance revealed)", SolvencyAttestation.auditorCheck(attestation, auditorKeys.viewing())
                    .map(Object::toString).orElse("NOT OPENABLE"));
        }
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
