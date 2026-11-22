package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.plutus.spec.PlutusV3Script;
import com.bloxbean.cardano.client.util.HexUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The faucet pays each nullifier once (ADR-0009 D3.5) and only to key-credential recipients
 * (D3.4).
 */
class PaidNullifierTest {

    private static final BigInteger NULLIFIER = new BigInteger("1f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a7988", 16);

    @Test
    void secondClaimWithTheSameNullifierIsRefusedAlsoAfterRestart(@TempDir Path dir) throws Exception {
        var data = new AirdropDataDir(dir);
        var ledger = new PaidNullifierLedger(data);
        ledger.reserve(NULLIFIER);
        assertThrows(PaidNullifierLedger.AlreadyPaidException.class, () -> ledger.reserve(NULLIFIER));
        ledger.markPaid(NULLIFIER, "ab".repeat(32));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(data.paidNullifiers())));

        var restarted = new PaidNullifierLedger(new AirdropDataDir(dir));
        assertTrue(restarted.isRecorded(NULLIFIER));
        assertThrows(PaidNullifierLedger.AlreadyPaidException.class, () -> restarted.reserve(NULLIFIER));
        restarted.release(NULLIFIER);   // a paid nullifier is never released
        assertTrue(restarted.isRecorded(NULLIFIER));
    }

    @Test
    void reservationIsDurableBeforeSigningAndReleasedOnlyIfNothingLeft(@TempDir Path dir) {
        var data = new AirdropDataDir(dir);
        var ledger = new PaidNullifierLedger(data);
        ledger.reserve(NULLIFIER);
        // A crash after reserving (before or after signing) keeps the nullifier refused.
        assertTrue(new PaidNullifierLedger(new AirdropDataDir(dir)).isRecorded(NULLIFIER));
        ledger.release(NULLIFIER);
        assertFalse(new PaidNullifierLedger(new AirdropDataDir(dir)).isRecorded(NULLIFIER));
    }

    @Test
    void corruptLedgerFailsClosed(@TempDir Path dir) throws Exception {
        var data = new AirdropDataDir(dir);
        new PaidNullifierLedger(data).reserve(NULLIFIER);
        Files.writeString(data.paidNullifiers(), Files.readString(data.paidNullifiers()).replace("reserved", "unpaid"));
        assertThrows(IllegalStateException.class, () -> new PaidNullifierLedger(new AirdropDataDir(dir)));
        Files.writeString(data.paidNullifiers(), "[]");
        assertThrows(IllegalStateException.class, () -> new PaidNullifierLedger(new AirdropDataDir(dir)));
    }

    /**
     * Service level: with a deployment recorded, a claim whose nullifier the ledger holds is
     * refused before any transaction is built (the backend is never touched), also by a freshly
     * started service over the same data directory.
     */
    @Test
    void serviceRefusesARecordedNullifierBeforeBuildingAndAfterRestart(@TempDir Path dir) throws Exception {
        var prover = new AirdropProofService(14, Path.of("build", "airdrop-test-setup").toString());
        prover.init();
        var data = new AirdropDataDir(dir);
        var keys = new AirdropKeys(data);
        var issuer = new PersonhoodIssuerService(keys, data);
        recordDeployment(data, keys, issuer);
        String recipient = new Account(Networks.testnet()).baseAddress();

        var ledger = new PaidNullifierLedger(data);
        var service = new OnChainAirdropService(null, keys, prover, issuer, ledger, data, 1, 2, false, "", 0, null);
        service.initialize();
        assertNotNull(service.getPolicyId());
        ledger.reserve(NULLIFIER);
        ledger.markPaid(NULLIFIER, "cd".repeat(32));
        assertThrows(PaidNullifierLedger.AlreadyPaidException.class,
                () -> service.submitClaim(null, NULLIFIER, recipient));

        var data2 = new AirdropDataDir(dir);
        var keys2 = new AirdropKeys(data2);
        var issuer2 = new PersonhoodIssuerService(keys2, data2);
        var restarted = new OnChainAirdropService(null, keys2, prover, issuer2, new PaidNullifierLedger(data2),
                data2, 1, 2, false, "", 0, null);
        restarted.initialize();
        assertEquals(service.getPolicyId(), restarted.getPolicyId(), "same deployment, same policy");
        assertTrue(restarted.alreadyClaimed(NULLIFIER));
        assertThrows(PaidNullifierLedger.AlreadyPaidException.class,
                () -> restarted.submitClaim(null, NULLIFIER, recipient));
    }

    @Test
    void onlyKeyCredentialRecipientsAreAccepted() {
        var account = new Account(Networks.testnet());
        byte[] pkh = account.hdKeyPair().getPublicKey().getKeyHash();
        assertArrayEquals(pkh, OnChainAirdropService.recipientKeyHash(account.baseAddress()));
        assertArrayEquals(pkh, OnChainAirdropService.recipientKeyHash(account.enterpriseAddress()));

        var script = PlutusV3Script.builder().cborHex("4e4d01000033222220051200120011").build();
        String scriptAddress = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
        assertThrows(IllegalArgumentException.class, () -> OnChainAirdropService.recipientKeyHash(scriptAddress));
        assertThrows(IllegalArgumentException.class, () -> OnChainAirdropService.recipientKeyHash(account.stakeAddress()));
        assertThrows(IllegalArgumentException.class, () -> OnChainAirdropService.recipientKeyHash("not-an-address"));
    }

    private static void recordDeployment(AirdropDataDir data, AirdropKeys keys, PersonhoodIssuer issuer) {
        var d = DemoFiles.object();
        d.put("seedTxHash", "5e".repeat(32));
        d.put("seedIndex", "1");
        d.put("issuerPkU", issuer.publicKey().affineU().toString(16));
        d.put("issuerPkV", issuer.publicKey().affineV().toString(16));
        d.put("adminKeyHash", HexUtil.encodeHexString(keys.adminKeyHash()));
        DemoFiles.writeAtomic(data.deployment(), d);
    }
}
