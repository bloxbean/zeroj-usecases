package com.bloxbean.cardano.zeroj.usecases.pedersen.points;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.E2E;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Plutus;
import com.bloxbean.cardano.zeroj.usecases.pedersen.points.ConfidentialPoints.Note;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Demo A on Yaci DevKit: the retailer issues points to Alice; Alice sends Bob 700 of her 1,000
 * points privately; Bob spends 120 at the retailer and keeps the change. Amounts never appear
 * on-chain except the redeemed price. A tampered proof and a spend without the owner's signature
 * are rejected.
 *
 * <p>Runs only with {@code ZEROJ_YACI_E2E=true}.
 */
class PointsDevKitE2ETest {

    @Test
    void confidentialPointsOnDevKit() throws Exception {
        assumeTrue(E2E.enabled(), "Set ZEROJ_YACI_E2E=true with DevKit running");
        var backend = DevKit.backend();
        var retailer = new Account(Networks.testnet());
        var alice = new Account(Networks.testnet());
        var bob = new Account(Networks.testnet());
        for (Account a : List.of(retailer, alice, bob)) DevKit.topUp(a.baseAddress(), 200);
        byte[] alicePkh = alice.hdKeyPair().getPublicKey().getKeyHash();
        byte[] bobPkh = bob.hdKeyPair().getPublicKey().getKeyHash();

        var points = new ConfidentialPoints();
        var script = points.script(retailer.hdKeyPair().getPublicKey().getKeyHash());
        String ledger = ConfidentialPoints.address(script);
        String policyId = Plutus.policyId(script);

        // 1. The retailer issues 1,000 points to Alice.
        Note aliceNote = Note.of(alicePkh, 1_000);
        var issued = ConfidentialPoints.issue(backend, script, retailer, List.of(aliceNote));
        assertTrue(issued.isSuccessful(), "issue: " + issued.getResponse());
        DevKit.waitForTx(backend, issued.getValue());
        Utxo aliceUtxo = DevKit.utxosOf(backend, ledger, issued.getValue()).getFirst();

        // 2. Alice sends Bob 700 and keeps 300. Rejected first: a tampered proof, and Bob trying to
        //    spend Alice's note.
        Note toBob = Note.of(bobPkh, 700);
        Note aliceChange = Note.of(alicePkh, 300);
        var proof = points.proveTransfer(aliceNote, toBob, aliceChange);
        var tampered = points.proveTransfer(aliceNote, Note.of(bobPkh, 700), Note.of(alicePkh, 300));
        E2E.assertScriptRejected(ConfidentialPoints.transfer(backend, script, alice, aliceUtxo, toBob, aliceChange, tampered),
                "a proof for other commitments");
        E2E.assertScriptRejected(ConfidentialPoints.transfer(backend, script, bob, aliceUtxo, toBob, aliceChange, proof),
                "a spend not signed by the owner");
        var sent = ConfidentialPoints.transfer(backend, script, alice, aliceUtxo, toBob, aliceChange, proof);
        assertTrue(sent.isSuccessful(), "transfer: " + sent.getResponse());
        DevKit.waitForTx(backend, sent.getValue());
        List<Utxo> notes = DevKit.utxosOf(backend, ledger, sent.getValue());
        assertEquals(2, notes.size());
        Utxo bobUtxo = notes.stream().filter(u -> u.getOutputIndex() == 0).findFirst().orElseThrow();

        // 3. Bob spends 120 at the retailer: change note 580, receipt token to the retailer.
        Note bobChange = Note.of(bobPkh, 580);
        var redeemed = ConfidentialPoints.redeem(backend, script, bob, retailer.baseAddress(), bobUtxo,
                bobChange, 120, points.proveRedeem(toBob, bobChange, 120));
        assertTrue(redeemed.isSuccessful(), "redeem: " + redeemed.getResponse());
        DevKit.waitForTx(backend, redeemed.getValue());

        String receiptUnit = policyId + HexUtil.encodeHexString(
                ConfidentialPoints.receiptName(bobUtxo));
        boolean receiptHeld = DevKit.utxosOf(backend, retailer.baseAddress(), redeemed.getValue()).stream()
                .anyMatch(u -> u.getAmount().stream().anyMatch(a -> a.getUnit().equals(receiptUnit)));
        assertTrue(receiptHeld, "the retailer holds the receipt token");
        // 4. The note Bob redeemed is gone: redeeming it again is impossible, so the receipt is unique.
        assertTrue(DevKit.utxosOf(backend, ledger, sent.getValue()).stream().noneMatch(u -> u.getOutputIndex() == 0));
        System.out.println("Points on DevKit: issue " + issued.getValue() + ", transfer " + sent.getValue()
                + ", redeem " + redeemed.getValue());
    }
}
