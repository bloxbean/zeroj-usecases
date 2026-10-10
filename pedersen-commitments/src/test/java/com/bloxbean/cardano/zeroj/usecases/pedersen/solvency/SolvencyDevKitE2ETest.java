package com.bloxbean.cardano.zeroj.usecases.pedersen.solvency;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.E2E;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Plutus;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Customer;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Demo C on Yaci DevKit: before an attestation period, an exchange with four customers locks
 * 2,000 ADA and attests that its hidden liabilities are covered. During the period each customer
 * checks every attestation of the period's vault from chain data and finds their entry exactly
 * once; an auditor opens the total by homomorphism; an insolvent book cannot be proved; a second
 * attestation and an early release are rejected by the vault. After the period the release burns
 * the attestation.
 *
 * <p>Runs only with {@code ZEROJ_YACI_E2E=true}.
 */
class SolvencyDevKitE2ETest {

    @Test
    void solvencyOnDevKit() throws Exception {
        assumeTrue(E2E.enabled(), "Set ZEROJ_YACI_E2E=true with DevKit running");
        var backend = DevKit.backend();
        var exchange = new Account(Networks.testnet());
        DevKit.topUp(exchange.baseAddress(), 5_000);

        var solvency = new SolvencyAttestation(SolvencyCircuitTest.N);
        long now = DevKit.chainTimeMillis(backend);
        var period = new SolvencyAttestation.Period(now + 40_000, now + 90_000);
        var vault = solvency.vault(exchange.hdKeyPair().getPublicKey().getKeyHash(), period);
        String vaultAddress = SolvencyAttestation.address(vault);
        List<Customer> book = SolvencyCircuitTest.book();   // 2,000 ADA of liabilities, in lovelace
        long reserves = 2_000_000_000L;

        assertThrows(RuntimeException.class, () -> solvency.prove(reserves - 1, book), "insolvent books have no proof");
        var proof = solvency.prove(reserves, book);

        // Before the period: attest, with a validity range ending at the period start. Each entry's
        // opening is delivered to its customer, and the total's to the auditor (ADR-0007 N6).
        NoteViewingKey auditor = NoteViewingKey.generate(new SecureRandom());
        byte[] auditorDelivery = SolvencyAttestation.auditorDelivery(book, auditor.readerKey());
        var attested = SolvencyAttestation.attest(backend, vault, exchange, reserves,
                SolvencyAttestation.entries(book), auditorDelivery, proof, DevKit.slotAt(backend, period.start()));
        assertTrue(attested.isSuccessful(), "attest: " + attested.getResponse());
        DevKit.waitForTx(backend, attested.getValue());

        // During the period: customers and the auditor check every live attestation of the
        // period's vault, which they derive themselves.
        while (DevKit.chainTimeMillis(backend) < period.start() + 2_000) Thread.sleep(2_000);
        var entries = SolvencyAttestation.liveEntries(backend, vault);
        for (Customer c : book) {
            assertEquals(SolvencyAttestation.Check.LISTED_ONCE_CORRECT,
                    SolvencyAttestation.customerCheck(entries, c, SolvencyCircuitTest.KEYS.get(c.id())),
                    c.id() + " decrypts their entry from the chain");
        }
        NoteViewingKey eve = NoteViewingKey.generate(new SecureRandom());
        assertEquals(SolvencyAttestation.Check.MISSING,
                SolvencyAttestation.customerCheck(entries, Customer.of("eve", 1, eve.readerKey()), eve), "a stranger has no entry");
        var live = SolvencyAttestation.liveAttestations(backend, vault);
        assertEquals(1, live.size());
        assertEquals(BigInteger.valueOf(reserves), SolvencyAttestation.auditorCheck(live.getFirst(), auditor).orElseThrow(),
                "the auditor opens total liabilities from its on-chain delivery");

        // Inside the period nothing changes: a second attestation (here, the same reserves for
        // the same book again, valid until a minute from now) and an early release are rejected.
        E2E.assertScriptRejected(SolvencyAttestation.attest(backend, vault, exchange, reserves,
                SolvencyAttestation.entries(book), auditorDelivery, proof,
                DevKit.slotAt(backend, DevKit.chainTimeMillis(backend) + 60_000)), "an attestation inside the period");
        String tokenUnit = Plutus.policyId(vault) + HexUtil.encodeHexString(SolvencyAttestation.ATTEST_TOKEN);
        Utxo liveUtxo = DevKit.utxosOf(backend, vaultAddress, attested.getValue()).stream()
                .filter(u -> u.getAmount().stream().anyMatch(a -> a.getUnit().equals(tokenUnit)))
                .findFirst().orElseThrow();
        E2E.assertScriptRejected(SolvencyAttestation.release(backend, vault, exchange, liveUtxo,
                DevKit.slotAt(backend, DevKit.chainTimeMillis(backend))), "a release inside the period");

        // After the period: released, attestation token burned.
        while (DevKit.chainTimeMillis(backend) < period.end() + 2_000) Thread.sleep(3_000);
        var released = SolvencyAttestation.release(backend, vault, exchange, liveUtxo, DevKit.slotAt(backend, period.end()) + 1);
        assertTrue(released.isSuccessful(), "release: " + released.getResponse());
        DevKit.waitForTx(backend, released.getValue());
        System.out.println("Solvency on DevKit: attest " + attested.getValue() + ", release " + released.getValue());
    }
}
