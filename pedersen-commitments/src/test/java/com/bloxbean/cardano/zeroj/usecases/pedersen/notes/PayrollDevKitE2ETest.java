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
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Confidential payroll on Yaci DevKit (ADR-0007 N4, N8; ZeroJ ADR-0055 Q9 (b)): proof-enforced
 * issuance of two salaries in one pay run, payslips recovered from the chain by each employee, the
 * tax authority's view of every salary (proof-enforced), salary history surviving a transfer, and
 * an under-reported salary that has no proof.
 *
 * <p>Runs only with {@code ZEROJ_YACI_E2E=true}.
 */
class PayrollDevKitE2ETest {

    static final SecureRandom RANDOM = new SecureRandom();

    @Test
    void payrollOnDevKit() throws Exception {
        assumeTrue(E2E.enabled(), "Set ZEROJ_YACI_E2E=true with DevKit running");
        BackendService backend = DevKit.backend();
        Account employer = new Account(Networks.testnet());
        Account carol = new Account(Networks.testnet());
        Account dave = new Account(Networks.testnet());
        Account tax = new Account(Networks.testnet());
        for (Account a : List.of(employer, carol, dave, tax)) DevKit.topUp(a.baseAddress(), 300);
        NoteViewingKey carolView = NoteViewingKey.generate(RANDOM);
        NoteViewingKey daveView = NoteViewingKey.generate(RANDOM);

        KeyPossession possession = new KeyPossession();
        Utxo seed = backend.getUtxoService().getUtxos(tax.baseAddress(), 10, 1).getValue().getFirst();
        Registry registry = Registry.forSeed(seed.getTxHash(), seed.getOutputIndex(), possession);
        AuditorKeys taxKeys = AuditorKeys.generate(RANDOM);
        ok(registry.init(backend, tax, seed, taxKeys.entry(registry.policy(), pkh(tax), 0, possession)), "registry init", backend);
        NoteLedgerScript ledger = new NoteLedgerScript(pkh(employer), "SAL".getBytes(StandardCharsets.UTF_8),
                NoteProofs.withIssuance(), registry);
        assertTrue(ledger.deploy(backend, employer).isSuccessful());
        AdmittedAuditor auditor = registry.admitted(backend);
        AuditorView taxView = new AuditorView(Map.of(0L, taxKeys), ledger);

        // An under-reported salary has no issuance proof.
        AuditedNote honest = AuditedNote.create(pkh(carol), 5_000, carolView.readerKey(), auditor, RANDOM);
        AuditedNote understated = honest.withLimbs(AuditedNote.limbsOf(BigInteger.valueOf(3_000), auditor, RANDOM));
        assertThrows(RuntimeException.class, () -> ledger.proofs().proveIssue(List.of(understated), auditor),
                "an employer cannot under-report a salary to the tax authority");

        // A pay run of two salaries, one proof.
        AuditedNote daveSalary = AuditedNote.create(pkh(dave), 4_200, daveView.readerKey(), auditor, RANDOM);
        List<AuditedNote> run = List.of(honest, daveSalary);
        ok(ledger.provedIssue(backend, employer, run, ledger.proofs().proveIssue(run, auditor)), "pay run (2 salaries)", backend);

        assertEquals(BigInteger.valueOf(5_000), NoteWallet.scan(ChainNote.all(backend, ledger), pkh(carol), carolView).balance(),
                "Carol reads her payslip from the chain");
        assertEquals(BigInteger.valueOf(4_200), NoteWallet.scan(ChainNote.all(backend, ledger), pkh(dave), daveView).balance());
        for (ChainNote n : ChainNote.all(backend, ledger)) {
            var a = taxView.audit(n);
            assertEquals(AuditorView.Origin.PROOF_ENFORCED, a.origin(), "every salary is proof-enforced");
            assertTrue(a.consistent());
        }

        // Carol pays Dave 800: salary history is unchanged in the tax view.
        var carolNote = NoteWallet.scan(ChainNote.all(backend, ledger), pkh(carol), carolView).owned().getFirst();
        AuditedNote toDave = AuditedNote.create(pkh(dave), 800, daveView.readerKey(), auditor, RANDOM);
        AuditedNote carolRest = AuditedNote.create(pkh(carol), 4_200, carolView.readerKey(), auditor, RANDOM);
        ok(ledger.transfer(backend, carol, carolNote.note().utxo(), toDave, carolRest,
                ledger.proofs().proveTransfer(carolNote.spent(), toDave, carolRest, auditor)), "transfer", backend);
        BigInteger carolPaid = BigInteger.ZERO;
        BigInteger davePaid = BigInteger.ZERO;
        for (ChainNote n : taxView.issuedNotes(ledger)) {
            BigInteger amount = taxView.audit(n).amount().orElseThrow();
            if (Arrays.equals(n.owner(), pkh(carol))) carolPaid = carolPaid.add(amount);
            else davePaid = davePaid.add(amount);
        }
        assertEquals(BigInteger.valueOf(5_000), carolPaid, "Carol's salary history survives her transfer");
        assertEquals(BigInteger.valueOf(4_200), davePaid);
    }

    private static void ok(Result<String> result, String what, BackendService backend) throws Exception {
        assertTrue(result.isSuccessful(), what + ": " + result.getResponse());
        var budget = DevKit.lastBudget();
        System.out.printf("[DevKit %s] tx %s steps=%d (%.1f%%) mem=%d (%.1f%%)%n", what, result.getValue(),
                budget.steps(), budget.stepsPercent(), budget.memory(), budget.memoryPercent());
        if (!what.startsWith("registry")) {
            assertTrue(budget.stepsPercent() <= 80 && budget.memoryPercent() <= 80, what + " exceeds the 80% gate");
        }
        DevKit.waitForTx(backend, result.getValue());
    }

    private static byte[] pkh(Account a) {
        return a.hdKeyPair().getPublicKey().getKeyHash();
    }
}
