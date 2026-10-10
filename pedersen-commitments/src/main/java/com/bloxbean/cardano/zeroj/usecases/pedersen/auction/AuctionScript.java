package com.bloxbean.cardano.zeroj.usecases.pedersen.auction;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.address.Credential;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.crypto.VerificationKey;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusScript;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.client.transaction.spec.Asset;
import com.bloxbean.cardano.client.transaction.spec.script.ScriptPubkey;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.auction.onchain.SealedBidAuction;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Fields;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Plutus;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.AdmittedAuditor;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.Registry;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.VerificationKeys;
import org.julclang.clientlib.JulcScriptLoader;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalEncryption;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * One {@code SealedBidAuction} instance (ADR-0008) and its transactions. Like the note ledger, it
 * is deployed once as a reference script at its own address, in an output that is not an
 * authentic lot and so can never be spent.
 */
public final class AuctionScript {

    private static final BigInteger LOVELACE = BigInteger.valueOf(1_000_000);

    private final AuctionProofs proofs;
    private final Registry registry;
    private final long minWindow;
    private final long minLotLovelace;
    private final PlutusScript script;
    private final String policyId;
    private final String address;
    private Utxo reference;

    public AuctionScript(AuctionProofs proofs, Registry registry, long minWindowMillis, long minLotLovelace) {
        this.proofs = proofs;
        this.registry = registry;
        this.minWindow = minWindowMillis;
        this.minLotLovelace = minLotLovelace;
        this.script = JulcScriptLoader.load(SealedBidAuction.class,
                new BytesPlutusData(registry.policy()),
                new BytesPlutusData(Registry.TOKEN),
                BigIntPlutusData.of(minWindowMillis),
                BigIntPlutusData.of(minLotLovelace),
                new BytesPlutusData(VerificationKeys.hash(proofs.bid().compressedVk())),
                new BytesPlutusData(VerificationKeys.hash(proofs.settle(1).compressedVk())),
                new BytesPlutusData(VerificationKeys.hash(proofs.settle(2).compressedVk())),
                new BytesPlutusData(VerificationKeys.hash(proofs.settle(3).compressedVk())));
        this.policyId = Plutus.policyId(script);
        try {
            this.address = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public String policyId() { return policyId; }

    public String address() { return address; }

    public AuctionProofs proofs() { return proofs; }

    public Registry registry() { return registry; }

    public long minWindow() { return minWindow; }

    public Result<String> deploy(BackendService backend, Account payer) {
        try {
            var tx = new Tx().payToContract(address, List.of(Amount.ada(30)), PlutusData.unit(), script).from(payer.baseAddress());
            var result = new QuickTxBuilder(backend).compose(tx).withSigner(SignerProviders.signerFrom(payer)).complete();
            if (result.isSuccessful()) {
                DevKit.waitForTx(backend, result.getValue());
                reference = DevKit.utxosOf(backend, address, result.getValue()).getFirst();
            }
            return result;
        } catch (Exception e) {
            return Result.error(e.getMessage());
        }
    }

    // ------------------------------------------------------------------ reading

    /** Every authentic lot at the auction's address. */
    public List<Lot> lots(BackendService backend) {
        List<Lot> out = new ArrayList<>();
        try {
            for (int page = 1; ; page++) {
                var r = backend.getUtxoService().getUtxos(address, 100, page);
                if (!r.isSuccessful() || r.getValue() == null || r.getValue().isEmpty()) break;
                for (Utxo u : r.getValue()) Lot.parse(u, policyId, address).ifPresent(out::add);
                if (r.getValue().size() < 100) break;
            }
        } catch (Exception e) {
            throw new IllegalStateException("could not read lots: " + e.getMessage(), e);
        }
        return out;
    }

    public Optional<Lot> lot(BackendService backend, String token) {
        return lots(backend).stream().filter(l -> l.token().equals(token)).findFirst();
    }

    // ------------------------------------------------------------------ the item

    /** A demo item: one NFT under the seller's own native-script policy. Returns its unit. */
    public static Result<String> mintItem(BackendService backend, Account seller, String name) {
        try {
            ScriptPubkey policy = ScriptPubkey.create(VerificationKey.create(seller.publicKeyBytes()));
            var tx = new Tx()
                    .mintAssets(policy, new Asset("0x" + HexUtil.encodeHexString(name.getBytes(StandardCharsets.UTF_8)), BigInteger.ONE),
                            seller.baseAddress())
                    .from(seller.baseAddress());
            return new QuickTxBuilder(backend).compose(tx).withSigner(SignerProviders.signerFrom(seller)).complete();
        } catch (Exception e) {
            return Result.error(e.getMessage());
        }
    }

    public static String itemUnit(Account seller, String name) {
        try {
            return ScriptPubkey.create(VerificationKey.create(seller.publicKeyBytes())).getPolicyId()
                    + HexUtil.encodeHexString(name.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------ transactions

    /**
     * Opens a lot: mints its one-shot token (named after a seller UTxO this transaction spends),
     * locks the item with {@code lotAda}, copies the auctioneer's current key and generation.
     */
    public Result<String> open(BackendService backend, Account seller, String itemUnit, long deposit, long reserve,
                               long biddingEnds, long settleBy, AdmittedAuditor auctioneer) {
        try {
            List<Utxo> utxos = backend.getUtxoService().getUtxos(seller.baseAddress(), 100, 1).getValue();
            Utxo seed = utxos.stream().filter(u -> u.getAmount().size() == 1).findFirst()
                    .orElseThrow(() -> new IllegalStateException("the seller has no plain ADA UTxO to name the lot"));
            // The fee payer's balancing adds ADA only, so the UTxO holding the item is spent explicitly.
            Utxo holding = utxos.stream().filter(u -> u.getAmount().stream().anyMatch(a -> a.getUnit().equals(itemUnit)))
                    .findFirst().orElseThrow(() -> new IllegalStateException("the seller does not hold " + itemUnit));
            byte[] token = Blake2bUtil.blake2bHash256(Fields.concat(HexUtil.decodeHexString(seed.getTxHash()),
                    Fields.i2osp(BigInteger.valueOf(seed.getOutputIndex()), 2)));
            byte[] itemPolicy = HexUtil.decodeHexString(itemUnit.substring(0, 56));
            byte[] itemName = HexUtil.decodeHexString(itemUnit.substring(56));
            var datumFull = Lot.datum(pkh(seller), auctioneer.auditor(), itemPolicy, itemName, 10_000_000L, deposit, reserve,
                    biddingEnds, settleBy, auctioneer.pkU(), auctioneer.pkV(), auctioneer.generation(), fullBids());
            String tokenUnit = policyId + HexUtil.encodeHexString(token);
            // lotAda covers the lot output at its largest (three bids), and travels with the item.
            BigInteger lotAda = Plutus.minAda(backend, address,
                    List.of(new Amount(itemUnit, BigInteger.ONE), new Amount(tokenUnit, BigInteger.ONE)), datumFull)
                    .max(BigInteger.valueOf(minLotLovelace));
            var datum = Lot.datum(pkh(seller), auctioneer.auditor(), itemPolicy, itemName, lotAda.longValueExact(), deposit,
                    reserve, biddingEnds, settleBy, auctioneer.pkU(), auctioneer.pkV(), auctioneer.generation(), List.of());
            var tx = new ScriptTx()
                    .collectFrom(List.of(seed, holding))
                    .mintAsset(policyId, List.of(new Asset("0x" + HexUtil.encodeHexString(token), BigInteger.ONE)),
                            ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(BigIntPlutusData.of(0))).build())
                    .readFrom(registry.currentUtxo(backend))
                    .payToContract(address, List.of(new Amount("lovelace", lotAda), new Amount(itemUnit, BigInteger.ONE),
                            new Amount(tokenUnit, BigInteger.ONE)), datum);
            return submit(backend, tx, seller, null, DevKit.slotAt(backend, biddingEnds) - 1);
        } catch (Exception e) {
            return Result.error(e.getMessage());
        }
    }

    /** Places a sealed bid: appends it to the lot and adds the deposit. */
    public Result<String> bid(BackendService backend, Account bidder, Lot lot, ElGamalEncryption encryption,
                              Groth16ProofBLS381 proof) {
        return bid(backend, bidder, lot, encryption, proof, DevKit.slotAt(backend, lot.biddingEnds()) - 1);
    }

    /** A bid whose transaction is valid until {@code validToSlot} (a later slot is the late-bid cheat). */
    public Result<String> bid(BackendService backend, Account bidder, Lot lot, ElGamalEncryption encryption,
                              Groth16ProofBLS381 proof, long validToSlot) {
        ElGamalCiphertext ct = encryption.ciphertext();
        var bid = new Lot.Bid(pkh(bidder), ct.handle().affineU(), ct.handle().affineV(), ct.blinded().affineU(),
                ct.blinded().affineV());
        List<Lot.Bid> bids = new ArrayList<>(lot.bids());
        bids.add(bid);
        var p = ProverToCardano.compressProof(proof);
        var redeemer = ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(bid.bidder()), BigIntPlutusData.of(bid.aU()), BigIntPlutusData.of(bid.aV()),
                BigIntPlutusData.of(bid.bU()), BigIntPlutusData.of(bid.bV()),
                new BytesPlutusData(p.piA()), new BytesPlutusData(p.piB()), new BytesPlutusData(p.piC()),
                VerificationKeys.data(proofs.bid().compressedVk()))).build();
        List<Amount> value = new ArrayList<>();
        for (Amount a : lot.utxo().getAmount()) {
            value.add(a.getUnit().equals("lovelace")
                    ? new Amount("lovelace", a.getQuantity().add(BigInteger.valueOf(lot.deposit()).multiply(LOVELACE))) : a);
        }
        var tx = new ScriptTx()
                .collectFrom(lot.utxo(), redeemer)
                .payToContract(address, value, lot.datum(bids));
        return submit(backend, tx, bidder, null, validToSlot);
    }

    /** Settles the lot with the auctioneer's proof: the winner, the seller and every loser are paid. */
    public Result<String> settle(BackendService backend, Account submitter, Lot lot, int w, long price, Groth16ProofBLS381 proof) {
        var p = ProverToCardano.compressProof(proof);
        var redeemer = ConstrPlutusData.builder().alternative(1).data(ListPlutusData.of(
                BigIntPlutusData.of(w), BigIntPlutusData.of(price),
                new BytesPlutusData(p.piA()), new BytesPlutusData(p.piB()), new BytesPlutusData(p.piC()),
                VerificationKeys.data(proofs.settle(lot.bids().size()).compressedVk()))).build();
        var tx = closing(lot, redeemer);
        BigInteger deposit = BigInteger.valueOf(lot.deposit()).multiply(LOVELACE);
        tx = tx.payToContract(enterprise(lot.seller()), List.of(new Amount("lovelace", BigInteger.valueOf(price).multiply(LOVELACE))),
                payout(lot));
        for (int i = 0; i < lot.bids().size(); i++) {
            byte[] bidder = lot.bids().get(i).bidder();
            if (i + 1 == w) {
                tx = tx.payToContract(enterprise(bidder), List.of(
                        new Amount("lovelace", BigInteger.valueOf(lot.lotAda()).add(deposit).subtract(BigInteger.valueOf(price).multiply(LOVELACE))),
                        new Amount(lot.itemUnit(), BigInteger.ONE)), payout(lot));
            } else {
                tx = tx.payToContract(enterprise(bidder), List.of(new Amount("lovelace", deposit)), payout(lot));
            }
        }
        return submit(backend, tx, submitter, DevKit.slotAt(backend, lot.biddingEnds()) + 1,
                DevKit.slotAt(backend, lot.settleBy()) - 1);
    }

    /** After {@code settleBy} without a settlement: anyone returns the item and every deposit. */
    public Result<String> refund(BackendService backend, Account submitter, Lot lot) {
        var tx = closing(lot, ConstrPlutusData.builder().alternative(3).data(ListPlutusData.of(BigIntPlutusData.of(0))).build())
                .payToContract(enterprise(lot.seller()), List.of(new Amount("lovelace", BigInteger.valueOf(lot.lotAda())),
                        new Amount(lot.itemUnit(), BigInteger.ONE)), payout(lot));
        BigInteger deposit = BigInteger.valueOf(lot.deposit()).multiply(LOVELACE);
        for (Lot.Bid b : lot.bids()) tx = tx.payToContract(enterprise(b.bidder()), List.of(new Amount("lovelace", deposit)), payout(lot));
        return submit(backend, tx, submitter, DevKit.slotAt(backend, lot.settleBy()) + 1, null);
    }

    /** After {@code biddingEnds} with no bids: the seller takes the item back. */
    public Result<String> noBids(BackendService backend, Account seller, Lot lot) {
        var tx = closing(lot, ConstrPlutusData.builder().alternative(2).data(ListPlutusData.of(BigIntPlutusData.of(0))).build())
                .payToContract(enterprise(lot.seller()), List.of(new Amount("lovelace", BigInteger.valueOf(lot.lotAda())),
                        new Amount(lot.itemUnit(), BigInteger.ONE)), payout(lot));
        return submit(backend, tx, seller, DevKit.slotAt(backend, lot.biddingEnds()) + 1, null);
    }

    private ScriptTx closing(Lot lot, PlutusData redeemer) {
        return new ScriptTx()
                .collectFrom(lot.utxo(), redeemer)
                .mintAsset(policyId, List.of(new Asset("0x" + lot.token(), BigInteger.ONE.negate())),
                        ConstrPlutusData.builder().alternative(1).data(ListPlutusData.of(BigIntPlutusData.of(0))).build());
    }

    /** {@code Payout(policy, T)}: tags a payout with the lot token's full asset identity. */
    private PlutusData payout(Lot lot) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(HexUtil.decodeHexString(policyId)),
                new BytesPlutusData(HexUtil.decodeHexString(lot.token())))).build();
    }

    /**
     * Moves everything a wallet holds at its enterprise address (payouts and refunds land there)
     * back to its base address, so the wallet can spend it again. Empty result if there is nothing.
     */
    public static Result<String> sweep(BackendService backend, Account wallet) {
        try {
            String ent = enterprise(pkh(wallet));
            var r = backend.getUtxoService().getUtxos(ent, 100, 1);
            if (!r.isSuccessful() || r.getValue() == null || r.getValue().isEmpty()) return Result.success(null);
            // Spend every enterprise UTxO; the change, which is all of it less the fee, goes to the base address.
            var tx = new Tx().collectFrom(r.getValue())
                    .payToAddress(wallet.baseAddress(), Amount.ada(1))
                    .from(ent)
                    .withChangeAddress(wallet.baseAddress());
            return new QuickTxBuilder(backend).compose(tx)
                    .withSigner(SignerProviders.signerFrom(wallet))
                    .complete();
        } catch (Exception e) {
            return Result.error(e.getMessage());
        }
    }

    static String enterprise(byte[] pkh) {
        return AddressProvider.getEntAddress(Credential.fromKey(pkh), Networks.testnet()).toBech32();
    }

    private static List<Lot.Bid> fullBids() {
        BigInteger big = BigInteger.ONE.shiftLeft(254);
        List<Lot.Bid> out = new ArrayList<>();
        for (int i = 0; i < 3; i++) out.add(new Lot.Bid(new byte[28], big, big, big, big));
        return out;
    }

    private Result<String> submit(BackendService backend, ScriptTx tx, Account signer, Long validFrom, Long validTo) {
        try {
            var ctx = new QuickTxBuilder(backend).compose(tx.readFrom(reference))
                    .withReferenceScripts(script)
                    .withTxEvaluator(DevKit.evaluator(backend))
                    .withSigner(SignerProviders.signerFrom(signer))
                    .withRequiredSigners(pkh(signer))
                    .feePayer(signer.baseAddress())
                    .collateralPayer(signer.baseAddress());
            if (validFrom != null) ctx = ctx.validFrom(validFrom);
            if (validTo != null) ctx = ctx.validTo(validTo);
            return ctx.complete();
        } catch (RuntimeException e) {
            return Result.error(e.getMessage());
        }
    }

    static byte[] pkh(Account a) {
        return a.hdKeyPair().getPublicKey().getKeyHash();
    }
}
