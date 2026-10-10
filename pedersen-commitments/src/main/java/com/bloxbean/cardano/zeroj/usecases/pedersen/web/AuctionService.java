package com.bloxbean.cardano.zeroj.usecases.pedersen.web;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.auction.AuctionProofs;
import com.bloxbean.cardano.zeroj.usecases.pedersen.auction.AuctionScript;
import com.bloxbean.cardano.zeroj.usecases.pedersen.auction.Lot;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.AdmittedAuditor;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.AuditorKeys;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.KeyPossession;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.Registry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalEncryption;
import org.zeroj.circuit.lib.jubjub.JubjubDiscreteLog;
import org.zeroj.circuit.lib.jubjub.RawElGamalCiphertext;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The sealed-bid auction for the UI (ADR-0008). A seller lists an item; bidders encrypt their bids
 * to the auctioneer with a proof that each bid lies between the reserve and the deposit; after the
 * bidding window the auctioneer decrypts every bid and proves who won and at what price, without
 * publishing the losing bids. The server holds every wallet and the auctioneer's keys (demo custody).
 */
@Service
public class AuctionService {

    static final List<String> BIDDERS = List.of("alice", "bob", "carol");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final long MAX_BID = (1L << 32) - 1;

    @Value("${auction.bidding-seconds:120}")
    private long biddingSeconds = 120;

    @Value("${auction.settle-seconds:180}")
    private long settleSeconds = 180;

    private final BackendService backend;
    private final Funding funding;
    private final Map<String, Account> wallets = new LinkedHashMap<>();
    private final Map<Long, AuditorKeys> auctioneerKeys = new LinkedHashMap<>();
    private final List<Map<String, Object>> history = new ArrayList<>();
    private Account auctioneer;
    private AuctionScript auction;
    private JubjubDiscreteLog table;
    private String currentLot;
    private int itemCounter;

    public AuctionService(BackendService backend, Funding funding) {
        this.backend = backend;
        this.funding = funding;
    }

    synchronized void ensureReady() throws Exception {
        if (auction != null) return;
        var proofs = new AuctionProofs();
        var possession = new KeyPossession();
        wallets.put("seller", funding.newWallet("auction/seller", 200));
        for (String b : BIDDERS) wallets.put(b, funding.newWallet("auction/" + b, 2_000));
        auctioneer = funding.newWallet("auction/auctioneer", 300);
        Utxo seed = backend.getUtxoService().getUtxos(auctioneer.baseAddress(), 10, 1).getValue().getFirst();
        Registry registry = Registry.forSeed(seed.getTxHash(), seed.getOutputIndex(), possession);
        AuditorKeys keys = AuditorKeys.generate(RANDOM);
        String init = DemoErrors.require(registry.init(backend, auctioneer, seed,
                keys.entry(registry.policy(), NoteDemo.pkh(auctioneer), 0, possession)), "Registering the auctioneer");
        DevKit.waitForTx(backend, init);
        auctioneerKeys.put(0L, keys);
        var a = new AuctionScript(proofs, registry, 60_000, 2_000_000);
        DemoErrors.require(a.deploy(backend, auctioneer), "Deploying the auction script");
        table = JubjubDiscreteLog.forBound(MAX_BID);
        auction = a;
    }

    // ------------------------------------------------------------------ actions

    /** The seller mints a demo item and opens a lot for it. */
    public synchronized Map<String, Object> open(String item, long deposit, long reserve) throws Exception {
        ensureReady();
        if (deposit < 2 || reserve < 2 || reserve > deposit || deposit > 1_000) {
            throw new IllegalArgumentException("need 2 ≤ reserve ≤ deposit ≤ 1000 ADA");
        }
        if (currentLot != null && auction.lot(backend, currentLot).isPresent()) {
            throw new IllegalStateException("the current lot is still open: settle it, refund it or close it first");
        }
        Account seller = wallets.get("seller");
        sweep(seller);
        String name = (item == null || item.isBlank() ? "Lot" : item.replaceAll("[^A-Za-z0-9]", "")) + "#" + (++itemCounter);
        String minted = DemoErrors.require(AuctionScript.mintItem(backend, seller, name), "Minting the item");
        DevKit.waitForTx(backend, minted);
        long now = DevKit.chainTimeMillis(backend);
        long biddingEnds = now + biddingSeconds * 1000;
        long settleBy = biddingEnds + settleSeconds * 1000;
        AdmittedAuditor key = auction.registry().admitted(backend);
        String tx = DemoErrors.require(auction.open(backend, seller, AuctionScript.itemUnit(seller, name), deposit, reserve,
                biddingEnds, settleBy, key), "Opening the lot");
        DevKit.waitForTx(backend, tx);
        currentLot = auction.lots(backend).stream().filter(l -> l.utxo().getTxHash().equals(tx)).findFirst()
                .orElseThrow(() -> new IllegalStateException("the new lot is not visible")).token();
        return record("open", "Seller listed " + name + " (deposit " + deposit + " ADA, reserve " + reserve
                + " ADA); bidding closes in " + biddingSeconds + " s", tx);
    }

    /**
     * {@code bidder} places a sealed bid of {@code amount} ADA. With {@code copyFrom}, it instead
     * re-submits another bidder's ciphertext and proof (the copy cheat).
     */
    public synchronized Map<String, Object> bid(String bidder, long amount, String copyFrom) throws Exception {
        ensureReady();
        Lot lot = current();
        Account wallet = requireBidder(bidder);
        AdmittedAuditor key = auction.registry().admitted(backend);
        // ADR-0008 D5: the lot's pinned auctioneer, generation and key must be the current entry's.
        if (!Arrays.equals(key.auditor(), lot.auctioneer()) || key.generation() != lot.generation()
                || !key.pkU().equals(lot.pkU()) || !key.pkV().equals(lot.pkV())) {
            throw new IllegalStateException("the auctioneer's registry entry has changed since this lot opened; refusing to bid");
        }
        sweep(wallet);
        if (amount < 0 || amount > MAX_BID) throw new IllegalArgumentException("bid out of range");
        ElGamalEncryption enc = ElGamal.encryptWithOpening(key.context(), BigInteger.valueOf(amount), 32, RANDOM);
        var proof = DemoErrors.prove(() -> auction.proofs().proveBid(NoteDemo.pkh(wallet), lot.deposit(), lot.reserve(),
                lot.pkU(), lot.pkV(), enc), "A bid of " + amount + " ADA is outside [reserve " + lot.reserve()
                + ", deposit " + lot.deposit() + "]: no bid proof exists");
        String what = "Bid";
        if (copyFrom != null && !copyFrom.isBlank()) {
            // The copy cheat: a bid proof made for another bidder (bound to that bidder's key hash),
            // submitted by this one. The lot verifies the proof against the submitter and refuses it.
            if (copyFrom.equals(bidder)) throw new IllegalArgumentException("pick another bidder to copy from");
            what = bidder + " copying " + copyFrom + "'s bid";
            Account original = requireBidder(copyFrom);
            var copied = DemoErrors.prove(() -> auction.proofs().proveBid(NoteDemo.pkh(original), lot.deposit(),
                    lot.reserve(), lot.pkU(), lot.pkV(), enc), "no proof");
            DemoErrors.require(auction.bid(backend, wallet, lot, enc, copied), what);
            throw new IllegalStateException("unexpected: the lot accepted a proof made for another bidder");
        }
        String tx = DemoErrors.require(auction.bid(backend, wallet, lot, enc, proof), what);
        DevKit.waitForTx(backend, tx);
        return record("bid", bidder + " placed a sealed bid (amount encrypted to the auctioneer; deposit "
                + lot.deposit() + " ADA locked)", tx);
    }

    /**
     * The auctioneer decrypts every bid and settles. With {@code claimWinner} (1-based), it tries
     * to name another winner: no proof exists.
     */
    public synchronized Map<String, Object> settle(Integer claimWinner) throws Exception {
        ensureReady();
        Lot lot = current();
        if (lot.bids().isEmpty()) throw new IllegalStateException("no bids; the seller can take the item back after the window");
        List<Long> amounts = decrypt(lot);
        if (claimWinner != null && (claimWinner < 1 || claimWinner > amounts.size())) {
            throw new IllegalArgumentException("the winner must be a bid number from 1 to " + amounts.size());
        }
        int w = 1;
        for (int i = 1; i < amounts.size(); i++) if (amounts.get(i) > amounts.get(w - 1)) w = i + 1;
        long price = amounts.get(w - 1);
        int claimed = claimWinner == null ? w : claimWinner;
        long claimedPrice = claimWinner == null ? price : amounts.get(Math.max(0, Math.min(claimed, amounts.size()) - 1));
        AuditorKeys keys = auctioneerKeys.get(lot.generation());
        int fw = claimed;
        var proof = DemoErrors.prove(() -> auction.proofs().proveSettle(lot, fw, claimedPrice,
                keys.elgamal().secretScalar(), amounts), "Bid " + claimed + " is not the earliest highest bid: no settlement proof exists");
        String tx = DemoErrors.require(auction.settle(backend, auctioneer, lot, claimed, claimedPrice, proof), "Settlement");
        DevKit.waitForTx(backend, tx);
        String winner = labelOf(lot.bids().get(claimed - 1).bidder());
        return record("settle", winner + " won at " + claimedPrice + " ADA; losing bids were never published", tx);
    }

    /** After {@code settleBy}: anyone returns the item and every deposit. */
    public synchronized Map<String, Object> refund() throws Exception {
        ensureReady();
        Lot lot = current();
        String tx = DemoErrors.require(auction.refund(backend, wallets.get("seller"), lot), "Refund");
        DevKit.waitForTx(backend, tx);
        return record("refund", "No settlement in time: item returned to the seller, deposits to the bidders", tx);
    }

    /** After the window with no bids: the seller takes the item back. */
    public synchronized Map<String, Object> noBids() throws Exception {
        ensureReady();
        Lot lot = current();
        String tx = DemoErrors.require(auction.noBids(backend, wallets.get("seller"), lot), "Closing without bids");
        DevKit.waitForTx(backend, tx);
        return record("noBids", "No bids: the seller took the item back", tx);
    }

    // ------------------------------------------------------------------ state

    public synchronized Map<String, Object> state() throws Exception {
        ensureReady();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("chainTime", DevKit.chainTimeMillis(backend));
        body.put("address", auction.address());
        body.put("constraints", Map.of("bid", auction.proofs().bid().numConstraints(),
                "settle3", auction.proofs().settle(3).numConstraints()));
        List<Map<String, Object>> balances = new ArrayList<>();
        for (var e : wallets.entrySet()) balances.add(Map.of("wallet", e.getKey(), "ada", lovelace(e.getValue()) / 1_000_000));
        body.put("wallets", balances);
        if (currentLot != null) {
            var lotOpt = auction.lot(backend, currentLot);
            if (lotOpt.isPresent()) {
                Lot lot = lotOpt.get();
                List<Map<String, Object>> publicBids = new ArrayList<>();
                List<Map<String, Object>> privateBids = new ArrayList<>();
                List<Long> amounts = decrypt(lot);
                for (int i = 0; i < lot.bids().size(); i++) {
                    Lot.Bid b = lot.bids().get(i);
                    publicBids.add(Map.of("bidder", labelOf(b.bidder()), "handle", NoteDemo.shortHex(b.aU()),
                            "ciphertext", NoteDemo.shortHex(b.bU())));
                    privateBids.add(Map.of("bidder", labelOf(b.bidder()), "amount", amounts.get(i)));
                }
                body.put("lot", Map.of("token", lot.token().substring(0, 12) + "…", "item", new String(lot.itemName()),
                        "deposit", lot.deposit(), "reserve", lot.reserve(), "biddingEnds", lot.biddingEnds(),
                        "settleBy", lot.settleBy(), "generation", lot.generation(), "bids", publicBids,
                        "lockedAda", lot.utxo().getAmount().stream().filter(x -> x.getUnit().equals("lovelace"))
                                .findFirst().orElseThrow().getQuantity().longValueExact() / 1_000_000));
                body.put("auctioneerView", privateBids);
            } else {
                body.put("closed", true);
            }
        }
        body.put("history", List.copyOf(history));
        return body;
    }

    // ------------------------------------------------------------------ helpers

    /**
     * The auctioneer decrypts every bid of an authentic lot with the key of the lot's generation.
     * Delegated admission (elgamal-jubjub-v1 §10.1) needs the context's key to be the one the
     * validator verified the bids against, the lot's pinned key.
     */
    private List<Long> decrypt(Lot lot) {
        AuditorKeys keys = auctioneerKeys.get(lot.generation());
        if (keys == null) throw new IllegalStateException("no auctioneer keys for generation " + lot.generation());
        var key = keys.context().jointKey();
        if (!key.affineU().equals(lot.pkU()) || !key.affineV().equals(lot.pkV())) {
            throw new IllegalStateException("the lot's key is not this auctioneer's key for generation " + lot.generation());
        }
        List<Long> out = new ArrayList<>();
        for (Lot.Bid b : lot.bids()) {
            RawElGamalCiphertext raw = RawElGamalCiphertext.fromAffine(b.aU(), b.aV(), b.bU(), b.bV());
            // The lot is authentic, so its validator verified this bid's proof under the lot's key.
            ElGamalCiphertext ct = ElGamal.admit(raw, keys.context(), 32, statement -> true);
            long m = ElGamal.decryptWithSecret(ct, keys.elgamal(), MAX_BID, table);
            if (m < lot.reserve() || m > lot.deposit()) {
                throw new IllegalStateException("a bid decrypted outside [reserve, deposit]: the lot is not authentic");
            }
            out.add(m);
        }
        return out;
    }

    /** Refunds and payouts land at a wallet's enterprise address; move them back so it can spend them. */
    private void sweep(Account wallet) throws Exception {
        var swept = AuctionScript.sweep(backend, wallet);
        if (swept.isSuccessful() && swept.getValue() != null) DevKit.waitForTx(backend, swept.getValue());
    }

    private Lot current() {
        if (currentLot == null) throw new IllegalStateException("open a lot first");
        return auction.lot(backend, currentLot).orElseThrow(() -> new IllegalStateException("the lot is closed; open a new one"));
    }

    private Account requireBidder(String label) {
        if (!BIDDERS.contains(label)) throw new IllegalArgumentException("unknown bidder: " + label);
        return wallets.get(label);
    }

    /** The wallet's lovelace at its base address and its enterprise address (where payouts land). */
    private long lovelace(Account a) throws Exception {
        String enterprise = AddressProvider.getEntAddress(a.hdKeyPair().getPublicKey(), Networks.testnet()).toBech32();
        return lovelaceAt(a.baseAddress()) + lovelaceAt(enterprise);
    }

    private long lovelaceAt(String address) throws Exception {
        long sum = 0;
        for (int page = 1; ; page++) {
            var r = backend.getUtxoService().getUtxos(address, 100, page);
            if (!r.isSuccessful() || r.getValue() == null || r.getValue().isEmpty()) break;
            for (Utxo u : r.getValue()) {
                for (var amt : u.getAmount()) if (amt.getUnit().equals("lovelace")) sum += amt.getQuantity().longValueExact();
            }
            if (r.getValue().size() < 100) break;
        }
        return sum;
    }

    private String labelOf(byte[] pkh) {
        for (var e : wallets.entrySet()) if (Arrays.equals(NoteDemo.pkh(e.getValue()), pkh)) return e.getKey();
        return HexUtil.encodeHexString(pkh).substring(0, 10) + "…";
    }

    private Map<String, Object> record(String action, String summary, String tx) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("action", action);
        entry.put("summary", summary);
        entry.put("txHash", tx);
        var budget = DevKit.lastBudget();
        if (budget.steps() > 0) entry.put("cost", String.format("%.1f%% of the step limit", budget.stepsPercent()));
        history.add(0, entry);
        return entry;
    }
}
