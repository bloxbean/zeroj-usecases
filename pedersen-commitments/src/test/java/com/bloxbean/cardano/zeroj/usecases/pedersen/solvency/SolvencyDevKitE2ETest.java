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

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Demo C on Yaci DevKit: an exchange with four customers locks 2,000 ADA and attests that its
 * hidden liabilities are covered. Each customer finds and opens their own entry from chain data;
 * an auditor opens the total by homomorphism; an insolvent book cannot be proved; releasing the
 * reserve before the lock expires is rejected by the vault; after it, the release burns the
 * attestation.
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
        var vault = solvency.vault(exchange.hdKeyPair().getPublicKey().getKeyHash());
        String vaultAddress = SolvencyAttestation.address(vault);
        List<Customer> book = SolvencyCircuitTest.book();   // 2,000 ADA of liabilities, in lovelace
        long reserves = 2_000_000_000L;

        assertThrows(RuntimeException.class, () -> solvency.prove(reserves - 1, book), "insolvent books have no proof");

        long unlockAfter = DevKit.chainTimeMillis(backend) + 60_000;
        var attested = SolvencyAttestation.attest(backend, vault, exchange, reserves, unlockAfter,
                SolvencyAttestation.entries(book), solvency.prove(reserves, book));
        assertTrue(attested.isSuccessful(), "attest: " + attested.getResponse());
        DevKit.waitForTx(backend, attested.getValue());

        // Everyone reads the attestation from the chain: the vault output holding the token.
        String tokenUnit = Plutus.policyId(vault) + HexUtil.encodeHexString(SolvencyAttestation.ATTEST_TOKEN);
        Utxo live = DevKit.utxosOf(backend, vaultAddress, attested.getValue()).stream()
                .filter(u -> u.getAmount().stream().anyMatch(a -> a.getUnit().equals(tokenUnit)))
                .findFirst().orElseThrow();
        var entries = SolvencyAttestation.readEntries(live);
        for (Customer c : book) {
            assertTrue(SolvencyAttestation.customerCheck(entries, c), c.id() + " finds and opens their entry");
        }
        assertFalse(SolvencyAttestation.customerCheck(entries, Customer.of("eve", 1)), "a stranger has no entry");
        assertTrue(SolvencyAttestation.auditorCheck(entries, SolvencyAttestation.auditOpening(book)),
                "the auditor opens total liabilities from the on-chain entries");

        // Too early: the vault refuses to release the reserve.
        E2E.assertScriptRejected(SolvencyAttestation.release(backend, vault, exchange, live,
                DevKit.slotAt(backend, DevKit.chainTimeMillis(backend))), "an early release");

        // After the lock: released, attestation token burned.
        while (DevKit.chainTimeMillis(backend) < unlockAfter + 2_000) Thread.sleep(3_000);
        var released = SolvencyAttestation.release(backend, vault, exchange, live, DevKit.slotAt(backend, unlockAfter) + 1);
        assertTrue(released.isSuccessful(), "release: " + released.getResponse());
        DevKit.waitForTx(backend, released.getValue());
        System.out.println("Solvency on DevKit: attest " + attested.getValue() + ", release " + released.getValue());
    }
}
