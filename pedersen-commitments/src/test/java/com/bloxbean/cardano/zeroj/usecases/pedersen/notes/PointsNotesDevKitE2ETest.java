package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.E2E;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * ZeroJ ADR-0055 M3 on Yaci DevKit (ADR-0007): confidential points as notes with on-chain
 * deliveries and an enforced auditor amount.
 *
 * <ol>
 *   <li>An auditor registers its keys (on-chain possession proofs); the retailer deploys the ledger.</li>
 *   <li>The retailer issues Alice 1,000 points; Alice recovers her note from the chain.</li>
 *   <li>Alice sends Bob 700. A tampered proof and a spend by Bob are refused. Bob and Alice recover
 *       their notes; the auditor reads 700 and 300 from the limbs, proof-enforced.</li>
 *   <li>Alice sends Bob 100 with a garbage delivery: Bob's wallet reports it unopenable, while the
 *       auditor still reads the amount.</li>
 *   <li>Bob redeems 120 at the retailer and keeps the change.</li>
 *   <li>The auditor rotates its keys: a transfer whose limbs go to the retired key is refused; one
 *       to the new key is accepted, and the auditor reads both generations.</li>
 * </ol>
 * Each accepted transaction's complete script cost is printed against the 80% gate.
 *
 * <p>Runs only with {@code ZEROJ_YACI_E2E=true}.
 */
class PointsNotesDevKitE2ETest {

    static final SecureRandom RANDOM = new SecureRandom();

    @Test
    void confidentialPointsWithNotesOnDevKit() throws Exception {
        assumeTrue(E2E.enabled(), "Set ZEROJ_YACI_E2E=true with DevKit running");
        BackendService backend = DevKit.backend();
        Account retailer = new Account(Networks.testnet());
        Account alice = new Account(Networks.testnet());
        Account bob = new Account(Networks.testnet());
        Account auditorAccount = new Account(Networks.testnet());
        for (Account a : List.of(retailer, alice, bob, auditorAccount)) DevKit.topUp(a.baseAddress(), 300);
        NoteViewingKey aliceView = NoteViewingKey.generate(RANDOM);
        NoteViewingKey bobView = NoteViewingKey.generate(RANDOM);

        // 1. Registry and ledger.
        KeyPossession possession = new KeyPossession();
        Utxo seed = backend.getUtxoService().getUtxos(auditorAccount.baseAddress(), 10, 1).getValue().getFirst();
        Registry registry = Registry.forSeed(seed.getTxHash(), seed.getOutputIndex(), possession);
        AuditorKeys gen0 = AuditorKeys.generate(RANDOM);
        ok(registry.init(backend, auditorAccount, seed, gen0.entry(registry.policy(), pkh(auditorAccount), 0, possession)),
                "registry init", backend);
        NoteLedgerScript ledger = new NoteLedgerScript(pkh(retailer), "PTS".getBytes(StandardCharsets.UTF_8),
                NoteProofs.spendOnly(), registry);
        assertTrue(ledger.deploy(backend, retailer).isSuccessful(), "deploy the ledger's reference script");
        AdmittedAuditor auditor = registry.admitted(backend);
        AuditorView auditorView = new AuditorView(new HashMap<>(Map.of(0L, gen0)), ledger);

        // 2. Issue 1,000 to Alice; she recovers it from the chain.
        AuditedNote issued = AuditedNote.create(pkh(alice), 1_000, aliceView.readerKey(), auditor, RANDOM);
        ok(ledger.issue(backend, retailer, List.of(issued)), "issue", backend);
        var aliceScan = NoteWallet.scan(ChainNote.all(backend, ledger), pkh(alice), aliceView);
        assertEquals(BigInteger.valueOf(1_000), aliceScan.balance(), "Alice recovers her issued note from the chain");
        var auditIssued = auditorView.audit(aliceScan.owned().getFirst().note());
        assertEquals(BigInteger.valueOf(1_000), auditIssued.amount().orElseThrow());
        assertEquals(AuditorView.Origin.ISSUER_CLAIMED, auditIssued.origin());
        assertTrue(auditIssued.consistent());

        // 3. Alice sends Bob 700.
        var source = aliceScan.owned().getFirst();
        AuditedNote toBob = AuditedNote.create(pkh(bob), 700, bobView.readerKey(), auditor, RANDOM);
        AuditedNote aliceChange = AuditedNote.create(pkh(alice), 300, aliceView.readerKey(), auditor, RANDOM);
        var proof = ledger.proofs().proveTransfer(source.spent(), toBob, aliceChange, auditor);
        var other = ledger.proofs().proveTransfer(source.spent(),
                AuditedNote.create(pkh(bob), 700, bobView.readerKey(), auditor, RANDOM), aliceChange, auditor);
        E2E.assertScriptRejected(ledger.transfer(backend, alice, source.note().utxo(), toBob, aliceChange, other),
                "a proof for other commitments");
        E2E.assertScriptRejected(ledger.transfer(backend, bob, source.note().utxo(), toBob, aliceChange, proof),
                "a spend not signed by the owner");
        ok(ledger.transfer(backend, alice, source.note().utxo(), toBob, aliceChange, proof), "transfer", backend);
        var bobScan = NoteWallet.scan(ChainNote.all(backend, ledger), pkh(bob), bobView);
        assertEquals(BigInteger.valueOf(700), bobScan.balance(), "Bob recovers 700 from the chain");
        aliceScan = NoteWallet.scan(ChainNote.all(backend, ledger), pkh(alice), aliceView);
        assertEquals(BigInteger.valueOf(300), aliceScan.balance());
        for (var owned : List.of(bobScan.owned().getFirst(), aliceScan.owned().getFirst())) {
            var audited = auditorView.audit(owned.note());
            assertEquals(owned.opening().value(), audited.amount().orElseThrow(), "the auditor reads the amount (sender, owner and auditor agree)");
            assertEquals(AuditorView.Origin.PROOF_ENFORCED, audited.origin());
            assertTrue(audited.consistent());
        }

        // 4. A garbage delivery to Bob: unopenable for Bob, the auditor still reads the amount.
        var aliceNote = aliceScan.owned().getFirst();
        byte[] garbage = new byte[89];
        RANDOM.nextBytes(garbage);
        AuditedNote garbled = AuditedNote.create(pkh(bob), 100, bobView.readerKey(), auditor, RANDOM);
        garbled = garbled.withDeliveries(List.of(garbage, garbled.deliveries().get(1)));
        AuditedNote aliceRest = AuditedNote.create(pkh(alice), 200, aliceView.readerKey(), auditor, RANDOM);
        ok(ledger.transfer(backend, alice, aliceNote.note().utxo(), garbled, aliceRest,
                ledger.proofs().proveTransfer(aliceNote.spent(), garbled, aliceRest, auditor)), "transfer with a garbage delivery", backend);
        bobScan = NoteWallet.scan(ChainNote.all(backend, ledger), pkh(bob), bobView);
        assertEquals(BigInteger.valueOf(700), bobScan.balance(), "the garbled note is not spendable");
        assertEquals(1, bobScan.unopenable().size(), "Bob's wallet reports the owned note it cannot open");
        var garbledAudit = auditorView.audit(bobScan.unopenable().getFirst());
        assertEquals(BigInteger.valueOf(100), garbledAudit.amount().orElseThrow(), "the auditor reads the amount anyway (D3a)");

        // 5. Bob redeems 120 of his 700.
        var bobNote = bobScan.owned().getFirst();
        AuditedNote bobChange = AuditedNote.create(pkh(bob), 580, bobView.readerKey(), auditor, RANDOM);
        ok(ledger.redeem(backend, bob, retailer.baseAddress(), bobNote.note().utxo(), bobChange, 120,
                ledger.proofs().proveRedeem(bobNote.spent(), bobChange, 120, auditor)), "redeem", backend);
        bobScan = NoteWallet.scan(ChainNote.all(backend, ledger), pkh(bob), bobView);
        assertEquals(BigInteger.valueOf(580), bobScan.balance());

        // 6. Rotation: the auditor moves to generation 1.
        AuditorKeys gen1 = AuditorKeys.generate(RANDOM);
        ok(registry.rotate(backend, auditorAccount, auditorAccount, gen1.entry(registry.policy(), pkh(auditorAccount), 1, possession)),
                "registry rotate", backend);
        AdmittedAuditor rotated = registry.admitted(backend);
        assertEquals(1, rotated.generation());
        aliceScan = NoteWallet.scan(ChainNote.all(backend, ledger), pkh(alice), aliceView);
        var aliceNote2 = aliceScan.owned().getFirst();
        // Limbs to the retired key, but with the current generation number: only the key binding refuses them.
        AuditedNote stale1 = AuditedNote.create(pkh(bob), 50, bobView.readerKey(), auditor, RANDOM).atGeneration(1);
        AuditedNote stale2 = AuditedNote.create(pkh(alice), 150, aliceView.readerKey(), auditor, RANDOM).atGeneration(1);
        E2E.assertScriptRejected(ledger.transfer(backend, alice, aliceNote2.note().utxo(), stale1, stale2,
                ledger.proofs().proveTransfer(aliceNote2.spent(), stale1, stale2, auditor)), "limbs to the retired key");
        AuditedNote fresh1 = AuditedNote.create(pkh(bob), 50, bobView.readerKey(), rotated, RANDOM);
        AuditedNote fresh2 = AuditedNote.create(pkh(alice), 150, aliceView.readerKey(), rotated, RANDOM);
        ok(ledger.transfer(backend, alice, aliceNote2.note().utxo(), fresh1, fresh2,
                ledger.proofs().proveTransfer(aliceNote2.spent(), fresh1, fresh2, rotated)), "transfer after rotation", backend);
        auditorView = new AuditorView(Map.of(0L, gen0, 1L, gen1), ledger);
        BigInteger audited = BigInteger.ZERO;
        for (ChainNote n : ChainNote.all(backend, ledger)) audited = audited.add(auditorView.audit(n).amount().orElseThrow());
        // Live notes: Bob's change 580, the garbled 100, Bob's 50 (generation 1), Alice's 150 (generation 1).
        assertEquals(BigInteger.valueOf(880), audited, "the auditor reads every live note, across both generations");
        System.out.println("[DevKit points] auditor total across generations: " + audited);
    }

    private static void ok(Result<String> result, String what, BackendService backend) throws Exception {
        assertTrue(result.isSuccessful(), what + ": " + result.getResponse());
        var budget = DevKit.lastBudget();
        System.out.printf("[DevKit %s] tx %s steps=%d (%.1f%%) mem=%d (%.1f%%)%n", what, result.getValue(),
                budget.steps(), budget.stepsPercent(), budget.memory(), budget.memoryPercent());
        if (!what.startsWith("registry")) {
            // ZeroJ ADR-0055 note 8: the application's complete transaction, measured on DevKit, within 80%.
            assertTrue(budget.stepsPercent() <= 80 && budget.memoryPercent() <= 80, what + " exceeds the 80% gate");
        }
        DevKit.waitForTx(backend, result.getValue());
    }

    private static byte[] pkh(Account a) {
        return a.hdKeyPair().getPublicKey().getKeyHash();
    }
}
