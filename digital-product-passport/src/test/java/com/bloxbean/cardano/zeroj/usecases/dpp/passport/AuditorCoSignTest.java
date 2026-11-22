package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.address.Credential;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.transaction.spec.Transaction;
import com.bloxbean.cardano.client.transaction.spec.TransactionInput;
import com.bloxbean.cardano.client.transaction.spec.Withdrawal;
import com.bloxbean.cardano.client.transaction.spec.cert.StakeCredential;
import com.bloxbean.cardano.client.transaction.spec.cert.StakeRegistration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The auditor's co-signing check (ADR-0009 D1): it signs the passport transaction only if the
 * transaction mints exactly {@code {productId: 1}} into the passport address with exactly the
 * datum of its own report, and its signature authorises nothing else.
 */
class AuditorCoSignTest {

    @Test
    @DisplayName("The exact passport transaction passes the auditor's check")
    void exactTransaction() {
        var f = new PassportTxFixture("BAT-SN001");
        assertDoesNotThrow(() -> PassportTransactions.check(f.body().build(), f.script, f.expected, f.addressOf()));
    }

    @Test
    @DisplayName("The auditor refuses another datum, another address, an extra mint or a missing signer slot")
    void refusals() {
        // Another commitment for the same product (a value the auditor did not measure).
        refused(b -> b.datum = PassportDatum.of(b.fixture().productId, RoleKeys.pkh(b.fixture().manufacturer),
                List.of(ClaimOpening.fresh(Claim.CARBON, 7), ClaimOpening.fresh(Claim.ORIGIN, 276))).toPlutusData());
        // Another manufacturer named in the datum.
        refused(b -> b.datum = new PassportDatum(b.fixture().productId, new byte[28], b.fixture().expected.claims()).toPlutusData());
        // A claim dropped.
        refused(b -> b.datum = new PassportDatum(b.fixture().productId, RoleKeys.pkh(b.fixture().manufacturer),
                b.fixture().expected.claims().subList(0, 1)).toPlutusData());
        // The passport paid to the manufacturer instead of the passport address.
        refused(b -> b.address = b.fixture().manufacturer.baseAddress());
        // Two passports, or a second token in the mint.
        refused(b -> b.quantity = 2);
        refused(b -> b.extraMint = true);
        // The auditor is not a required signer.
        refused(b -> b.auditorRequired = false);
    }

    @Test
    @DisplayName("The auditor's signature authorises no spend of its own funds, no withdrawal and no certificate")
    void noOtherAuthority() {
        // An input at the auditor's own address.
        refused(b -> b.inputs.add(b.input("bb", 0, b.fixture().auditor.baseAddress())));
        refused(b -> b.inputs.add(b.input("bb", 1, b.fixture().auditor.enterpriseAddress())));
        // Collateral from the auditor.
        refused(b -> b.collateral.add(b.input("bb", 2, b.fixture().auditor.baseAddress())));
        // An address whose stake credential is the auditor's key hash.
        refused(b -> {
            String staked = AddressProvider.getBaseAddress(Credential.fromKey(new byte[28]),
                    Credential.fromKey(RoleKeys.pkh(b.fixture().auditor)), Networks.testnet()).toBech32();
            b.inputs.add(b.input("bb", 3, staked));
        });
        // An input the auditor cannot resolve.
        refused(b -> b.inputs.add(new TransactionInput("cc".repeat(32), 0)));
        // A withdrawal, or a certificate.
        refused(b -> b.extra.withdrawals(List.of(new Withdrawal(
                AddressProvider.getRewardAddress(Credential.fromKey(RoleKeys.pkh(b.fixture().auditor)), Networks.testnet()).toBech32(),
                BigInteger.ONE))));
        refused(b -> b.extra.certs(List.of(new StakeRegistration(StakeCredential.fromKeyHash(RoleKeys.pkh(b.fixture().auditor))))));
        // Someone else's inputs are fine.
        var f = new PassportTxFixture("BAT-SN001");
        var b = f.body();
        b.inputs.add(b.input("dd", 0, new Account(Networks.testnet()).baseAddress()));
        assertDoesNotThrow(() -> PassportTransactions.check(b.build(), f.script, f.expected, f.addressOf()));
    }

    private static void refused(Consumer<PassportTxFixture.Body> mutation) {
        var f = new PassportTxFixture("BAT-SN001");
        var body = f.body();
        mutation.accept(body);
        Transaction tx = body.build();
        var e = assertThrows(IllegalStateException.class, () -> PassportTransactions.check(tx, f.script, f.expected, f.addressOf()));
        assertTrue(e.getMessage().startsWith("auditor refuses"), e.getMessage());
    }
}
