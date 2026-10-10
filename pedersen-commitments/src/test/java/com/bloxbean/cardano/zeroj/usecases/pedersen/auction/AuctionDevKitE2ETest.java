package com.bloxbean.cardano.zeroj.usecases.pedersen.auction;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.E2E;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.AdmittedAuditor;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.AuditorKeys;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.KeyPossession;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.Registry;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalEncryption;
import org.zeroj.circuit.lib.jubjub.JubjubDiscreteLog;
import org.zeroj.circuit.lib.jubjub.RawElGamalCiphertext;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The sealed-bid auction on Yaci DevKit (ADR-0008): an auctioneer registers its keys; a seller
 * lists an item; Alice, Bob and Carol bid 40, 70 and 70 ADA (sealed); a bid above the deposit has
 * no proof, a copied bid proof and a late bid are refused; the auctioneer decrypts the bids and
 * settles for Bob (the earliest of the two highest) at 70; payouts are checked. A second lot with
 * no settlement is refunded after its deadline.
 *
 * <p>Runs only with {@code ZEROJ_YACI_E2E=true}.
 */
class AuctionDevKitE2ETest {

    static final SecureRandom RANDOM = new SecureRandom();
    static final long BIDDING_MILLIS = 90_000;
    static final long SETTLE_MILLIS = 70_000;

    @Test
    void sealedBidAuctionOnDevKit() throws Exception {
        assumeTrue(E2E.enabled(), "Set ZEROJ_YACI_E2E=true with DevKit running");
        BackendService backend = DevKit.backend();
        Account seller = new Account(Networks.testnet());
        Account auctioneer = new Account(Networks.testnet());
        Account alice = new Account(Networks.testnet());
        Account bob = new Account(Networks.testnet());
        Account carol = new Account(Networks.testnet());
        for (Account a : List.of(seller, auctioneer, alice, bob, carol)) DevKit.topUp(a.baseAddress(), 400);

        KeyPossession possession = new KeyPossession();
        Utxo seed = backend.getUtxoService().getUtxos(auctioneer.baseAddress(), 10, 1).getValue().getFirst();
        Registry registry = Registry.forSeed(seed.getTxHash(), seed.getOutputIndex(), possession);
        AuditorKeys keys = AuditorKeys.generate(RANDOM);
        ok(registry.init(backend, auctioneer, seed, keys.entry(registry.policy(), pkh(auctioneer), 0, possession)), "registry init", backend);
        AuctionScript auction = new AuctionScript(new AuctionProofs(), registry, 60_000, 2_000_000);
        var deployed1 = auction.deploy(backend, auctioneer);
        assertTrue(deployed1.isSuccessful(), "deploy: " + deployed1.getResponse());
        AdmittedAuditor key = registry.admitted(backend);

        // Open.
        Lot lot = open(backend, auction, seller, key, "Painting");
        assertTrue(lot.bids().isEmpty());

        // Bids.
        lot = bid(backend, auction, alice, lot, key, 40);
        assertThrows(RuntimeException.class, () -> auction.proofs().proveBid(pkh(bob), 100, 10, key.pkU(), key.pkV(),
                ElGamal.encryptWithOpening(key.context(), BigInteger.valueOf(101), 32, RANDOM)), "a bid above the deposit has no proof");
        ElGamalEncryption bobBid = ElGamal.encryptWithOpening(key.context(), BigInteger.valueOf(70), 32, RANDOM);
        var bobProof = auction.proofs().proveBid(pkh(bob), lot.deposit(), lot.reserve(), lot.pkU(), lot.pkV(), bobBid);
        E2E.assertScriptRejected(auction.bid(backend, carol, lot, bobBid, bobProof), "Carol submitting Bob's bid proof");
        ok(auction.bid(backend, bob, lot, bobBid, bobProof), "bid (Bob, 70)", backend);
        lot = auction.lots(backend).stream().filter(l -> l.bids().size() == 2).findFirst().orElseThrow();
        lot = bid(backend, auction, carol, lot, key, 70);
        assertEquals(3, lot.bids().size());

        // The bidding window closes; a late bid (valid past the deadline) is refused by the script.
        while (DevKit.chainTimeMillis(backend) < lot.biddingEnds() + 2_000) Thread.sleep(2_000);
        Account late = new Account(Networks.testnet());
        DevKit.topUp(late.baseAddress(), 300);
        ElGamalEncryption lateBid = ElGamal.encryptWithOpening(key.context(), BigInteger.valueOf(90), 32, RANDOM);
        E2E.assertScriptRejected(auction.bid(backend, late, lot, lateBid,
                auction.proofs().proveBid(pkh(late), lot.deposit(), lot.reserve(), lot.pkU(), lot.pkV(), lateBid),
                DevKit.slotAt(backend, DevKit.chainTimeMillis(backend) + 60_000)), "a bid after the window");

        // The auctioneer decrypts and settles: Bob (bid #2), the earliest of the two highest, at 70.
        JubjubDiscreteLog table = JubjubDiscreteLog.forBound((1L << 32) - 1);
        List<Long> amounts = new ArrayList<>();
        for (Lot.Bid b : lot.bids()) {
            ElGamalCiphertext ct = ElGamal.admit(RawElGamalCiphertext.fromAffine(b.aU(), b.aV(), b.bU(), b.bV()),
                    keys.context(), 32, s -> true);
            amounts.add(ElGamal.decryptWithSecret(ct, keys.elgamal(), (1L << 32) - 1, table));
        }
        assertEquals(List.of(40L, 70L, 70L), amounts, "the auctioneer reads every bid");
        Lot settling = lot;
        assertThrows(RuntimeException.class, () -> auction.proofs().proveSettle(settling, 3, 70,
                keys.elgamal().secretScalar(), amounts), "the later equal bid cannot be named the winner");
        ok(auction.settle(backend, auctioneer, lot, 2, 70, auction.proofs().proveSettle(lot, 2, 70,
                keys.elgamal().secretScalar(), amounts)), "settle (3 bids)", backend);
        assertTrue(auction.lots(backend).stream().noneMatch(l -> l.token().equals(settling.token())), "the lot is closed");
        String item = lot.itemUnit();
        boolean bobHasItem = backend.getUtxoService().getUtxos(AuctionScript.enterprise(pkh(bob)), 20, 1).getValue().stream()
                .anyMatch(u -> u.getAmount().stream().anyMatch(a -> a.getUnit().equals(item)));
        assertTrue(bobHasItem, "the winner receives the item");
        assertEquals(BigInteger.valueOf(70_000_000L), lovelaceAt(backend, AuctionScript.enterprise(pkh(seller))), "the seller receives the price");
        assertEquals(BigInteger.valueOf(100_000_000L), lovelaceAt(backend, AuctionScript.enterprise(pkh(alice))), "Alice's deposit is returned");
        assertEquals(BigInteger.valueOf(100_000_000L), lovelaceAt(backend, AuctionScript.enterprise(pkh(carol))), "Carol's deposit is returned");
        assertEquals(BigInteger.valueOf(lot.lotAda() + 30_000_000L), lovelaceAt(backend, AuctionScript.enterprise(pkh(bob))),
                "Bob receives the item with the lot ADA and his change (100 − 70)");

        // A second lot, one bid, never settled: refunded after its deadline.
        Lot second = open(backend, auction, seller, key, "Vase");
        second = bid(backend, auction, alice, second, key, 25);
        while (DevKit.chainTimeMillis(backend) < second.settleBy() + 2_000) Thread.sleep(3_000);
        BigInteger aliceBefore = lovelaceAt(backend, AuctionScript.enterprise(pkh(alice)));
        BigInteger sellerBefore = lovelaceAt(backend, AuctionScript.enterprise(pkh(seller)));
        ok(auction.refund(backend, carol, second), "refund", backend);
        assertEquals(aliceBefore.add(BigInteger.valueOf(100_000_000L)), lovelaceAt(backend, AuctionScript.enterprise(pkh(alice))),
                "the refund returns Alice's deposit");
        assertEquals(sellerBefore.add(BigInteger.valueOf(second.lotAda())), lovelaceAt(backend, AuctionScript.enterprise(pkh(seller))),
                "the refund returns the item with the lot ADA to the seller");
    }

    private static BigInteger lovelaceAt(BackendService backend, String address) throws Exception {
        BigInteger sum = BigInteger.ZERO;
        var r = backend.getUtxoService().getUtxos(address, 100, 1);
        if (!r.isSuccessful() || r.getValue() == null) return sum;
        for (Utxo u : r.getValue()) {
            for (var a : u.getAmount()) if (a.getUnit().equals("lovelace")) sum = sum.add(a.getQuantity());
        }
        return sum;
    }

    private static Lot open(BackendService backend, AuctionScript auction, Account seller, AdmittedAuditor key, String name)
            throws Exception {
        String itemName = name + "#" + RANDOM.nextInt(1_000_000);
        DevKit.waitForTx(backend, AuctionScript.mintItem(backend, seller, itemName).getValue());
        long now = DevKit.chainTimeMillis(backend);
        var opened = auction.open(backend, seller, AuctionScript.itemUnit(seller, itemName), 100, 10,
                now + BIDDING_MILLIS, now + BIDDING_MILLIS + SETTLE_MILLIS, key);
        ok(opened, "open", backend);
        return auction.lots(backend).stream().filter(l -> l.utxo().getTxHash().equals(opened.getValue())).findFirst().orElseThrow();
    }

    private static Lot bid(BackendService backend, AuctionScript auction, Account bidder, Lot lot, AdmittedAuditor key, long amount)
            throws Exception {
        ElGamalEncryption e = ElGamal.encryptWithOpening(key.context(), BigInteger.valueOf(amount), 32, RANDOM);
        var result = auction.bid(backend, bidder, lot, e,
                auction.proofs().proveBid(pkh(bidder), lot.deposit(), lot.reserve(), lot.pkU(), lot.pkV(), e));
        ok(result, "bid (" + amount + ")", backend);
        return auction.lots(backend).stream().filter(l -> l.utxo().getTxHash().equals(result.getValue())).findFirst().orElseThrow();
    }

    private static void ok(Result<String> result, String what, BackendService backend) throws Exception {
        assertTrue(result.isSuccessful(), what + ": " + result.getResponse());
        var budget = DevKit.lastBudget();
        System.out.printf("[DevKit auction %s] tx %s steps=%d (%.1f%%) mem=%d (%.1f%%)%n", what, result.getValue(),
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
