package com.bloxbean.cardano.zeroj.usecases.pedersen.auction.onchain;

import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.onchain.ChainLib;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.onchain.RegistryLib;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.onchain.VkLib;
import org.julclang.core.PlutusData;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.PubKeyHash;
import org.julclang.ledger.ScriptContext;
import org.julclang.ledger.ScriptHash;
import org.julclang.ledger.ScriptInfo;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxInfo;
import org.julclang.ledger.TxOut;
import org.julclang.ledger.Value;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.MultiValidator;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.annotation.Purpose;
import org.julclang.stdlib.lib.ContextsLib;
import org.julclang.stdlib.lib.IntervalLib;
import org.julclang.stdlib.lib.ValuesLib;

import java.math.BigInteger;
import java.util.Optional;

/**
 * A sealed-bid auction lot (ADR-0008): one state UTxO per lot, whose bids are
 * {@code elgamal-jubjub-v1} ciphertexts to the auctioneer, each proved to encrypt an amount in
 * {@code [reserve, deposit]}, and settled with a proof that names the earliest highest bid.
 *
 * <p>Datum {@code Lot(seller, auctioneer, itemPolicy, itemName, lotAda, deposit, reserve,
 * biddingEnds, settleBy, pkU, pkV, generation, bids)} with {@code bids = [Bid(bidder, A.u, A.v,
 * B.u, B.v)]}, at most 3. An <b>authentic lot</b> is an output at the script's exact enterprise
 * address holding exactly lovelace, one unit of the item and one lot token {@code T} (quantity 1).
 * Every payout goes to the recipient's exact enterprise address with inline datum
 * {@code Payout(policy, T)}: the lot token's full asset identity, so one output can never satisfy
 * two lots, even of differently parameterized auction scripts in one transaction.
 */
@MultiValidator
public class SealedBidAuction {

    @Param static byte[] registryPolicy;
    @Param static byte[] registryToken;
    @Param static BigInteger minWindow;     // ms
    @Param static BigInteger minLotAda;     // lovelace
    @Param static byte[] bidVkHash;
    @Param static byte[] settle1VkHash;
    @Param static byte[] settle2VkHash;
    @Param static byte[] settle3VkHash;

    sealed interface LotMint permits Open, Burn {}
    record Open(BigInteger unused) implements LotMint {}
    record Burn(BigInteger unused) implements LotMint {}

    sealed interface LotSpend permits PlaceBid, Settle, NoBids, Refund {}
    record PlaceBid(byte[] bidder, BigInteger aU, BigInteger aV, BigInteger bU, BigInteger bV,
                    byte[] piA, byte[] piB, byte[] piC) implements LotSpend {}
    record Settle(BigInteger w, BigInteger p, byte[] piA, byte[] piB, byte[] piC) implements LotSpend {}
    record NoBids(BigInteger unused) implements LotSpend {}
    record Refund(BigInteger unused) implements LotSpend {}

    // ------------------------------------------------------------------
    //  Minting: Open (one-shot lot token) and Burn
    // ------------------------------------------------------------------

    @Entrypoint(purpose = Purpose.MINT)
    public static boolean mint(LotMint redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policy = PlutusData.cast(mintInfo.policyId(), byte[].class);
        Credential own = new Credential.ScriptCredential(PlutusData.cast(policy, ScriptHash.class));
        if (ChainLib.policyEntryCount(txInfo.mint(), policy) != 1) return false;
        return switch (redeemer) {
            case Open open -> open(txInfo, own, policy);
            // The burned lot's spending purpose (Settle, NoBids, Refund) checks everything else.
            case Burn burn -> ChainLib.countInputs(txInfo.inputs(), own) == 1
                    && Builtins.lengthOfByteString(ValuesLib.findTokenName(txInfo.mint(), policy, BigInteger.valueOf(-1))) == 32;
        };
    }

    private static boolean open(TxInfo txInfo, Credential own, byte[] policy) {
        byte[] token = ValuesLib.findTokenName(txInfo.mint(), policy, BigInteger.ONE);
        boolean derived = false;
        for (TxInInfo input : txInfo.inputs()) {
            derived = derived || Builtins.equalsByteString(ValuesLib.uniqueTokenName(input.outRef()), token);
        }
        if (!derived || ChainLib.countInputs(txInfo.inputs(), own) != 0
                || ChainLib.countOutputs(txInfo.outputs(), own) != 1) {
            return false;
        }
        TxOut lot = onlyOwnOutput(txInfo, own);
        PlutusData d = ChainLib.inlineDatum(lot);
        LotFields ld = PlutusData.cast(d, LotFields.class);
        if (!isLot(d) || !Builtins.nullList(Builtins.unListData(ld.bids()))) return false;
        if (!authentic(lot, new Address(own, Optional.empty()), policy, token, d)
                || ValuesLib.lovelaceOf(lot.value()).compareTo(Builtins.unIData(ld.lotAda())) != 0) {
            return false;
        }
        BigInteger lotAda = Builtins.unIData(ld.lotAda());
        BigInteger deposit = Builtins.unIData(ld.deposit());
        BigInteger reserve = Builtins.unIData(ld.reserve());
        BigInteger biddingEnds = Builtins.unIData(ld.biddingEnds());
        BigInteger settleBy = Builtins.unIData(ld.settleBy());
        BigInteger upper = IntervalLib.finiteUpperBound(txInfo.validRange());
        PlutusData entry = RegistryLib.currentEntry(txInfo, registryPolicy, registryToken);
        return ChainLib.signedBy(txInfo, Builtins.unBData(ld.seller()))
                && !Builtins.equalsByteString(Builtins.unBData(ld.itemPolicy()), policy)
                && lotAda.compareTo(minLotAda) >= 0
                && reserve.compareTo(BigInteger.TWO) >= 0 && reserve.compareTo(deposit) <= 0
                && deposit.compareTo(BigInteger.valueOf(4294967296L)) < 0
                && settleBy.subtract(biddingEnds).compareTo(minWindow) >= 0
                && upper.compareTo(BigInteger.ZERO) >= 0 && upper.compareTo(biddingEnds) <= 0
                && Builtins.equalsByteString(RegistryLib.entryAuditor(entry), Builtins.unBData(ld.auctioneer()))
                && RegistryLib.entryPkU(entry).compareTo(Builtins.unIData(ld.pkU())) == 0
                && RegistryLib.entryPkV(entry).compareTo(Builtins.unIData(ld.pkV())) == 0
                && RegistryLib.entryGeneration(entry).compareTo(Builtins.unIData(ld.generation())) == 0;
    }

    // ------------------------------------------------------------------
    //  Spending the lot
    // ------------------------------------------------------------------

    @Entrypoint(purpose = Purpose.SPEND)
    public static boolean spend(PlutusData datum, LotSpend redeemer, ScriptContext ctx) {
        LotFields ld = PlutusData.cast(datum, LotFields.class);
        TxInfo txInfo = ctx.txInfo();
        byte[] policy = ContextsLib.ownHash(ctx);
        Credential own = new Credential.ScriptCredential(PlutusData.cast(policy, ScriptHash.class));
        Address exact = new Address(own, Optional.empty());
        var ownInputOptional = ContextsLib.findOwnInput(ctx);
        if (ownInputOptional.isEmpty()) return false;
        TxOut lotIn = ownInputOptional.get().resolved();
        if (ChainLib.countInputs(txInfo.inputs(), own) != 1 || !isLot(datum)) return false;
        byte[] token = ValuesLib.findTokenName(lotIn.value(), policy, BigInteger.ONE);
        if (!authentic(lotIn, exact, policy, token, datum)) return false;
        return switch (redeemer) {
            case PlaceBid bid -> placeBid(bid, datum, lotIn, txInfo, own, exact, policy, token);
            case Settle settle -> settle(settle, datum, txInfo, own, policy, token);
            case NoBids noBids -> closing(txInfo, own, policy, token, datum)
                    && lowerAtLeast(txInfo, ld.biddingEnds())
                    && Builtins.nullList(Builtins.unListData(ld.bids()))
                    && ChainLib.signedBy(txInfo, Builtins.unBData(ld.seller()))
                    && paid(txInfo, Builtins.unBData(ld.seller()), Builtins.unIData(ld.lotAda()), true, datum, policy, token);
            case Refund refund -> closing(txInfo, own, policy, token, datum)
                    && lowerAtLeast(txInfo, ld.settleBy())
                    && paid(txInfo, Builtins.unBData(ld.seller()), Builtins.unIData(ld.lotAda()), true, datum, policy, token)
                    && refunded(txInfo, Builtins.unListData(ld.bids()), deposit(datum), BigInteger.ZERO, datum, policy, token);
        };
    }

    private static boolean placeBid(PlaceBid b, PlutusData d, TxOut lotIn, TxInfo txInfo, Credential own,
                                    Address exact, byte[] policy, byte[] token) {
        LotFields ld = PlutusData.cast(d, LotFields.class);
        PlutusData bids = Builtins.unListData(ld.bids());
        BigInteger upper = IntervalLib.finiteUpperBound(txInfo.validRange());
        if (upper.compareTo(BigInteger.ZERO) < 0 || upper.compareTo(Builtins.unIData(ld.biddingEnds())) > 0
                || ChainLib.policyEntryCount(txInfo.mint(), policy) != 0
                || Builtins.lengthOfByteString(b.bidder()) != 28
                || !ChainLib.signedBy(txInfo, b.bidder())
                || Builtins.equalsByteString(b.bidder(), Builtins.unBData(ld.seller()))
                || Builtins.equalsByteString(b.bidder(), Builtins.unBData(ld.auctioneer()))
                || ChainLib.countOutputs(txInfo.outputs(), own) != 1
                || !ChainLib.canonicalField(b.aU()) || !ChainLib.canonicalField(b.aV())
                || !ChainLib.canonicalField(b.bU()) || !ChainLib.canonicalField(b.bV())
                || b.aU().compareTo(BigInteger.ZERO) == 0) {
            return false;
        }
        int count = 0;
        boolean fresh = true;
        PlutusData rest = bids;
        while (!Builtins.nullList(rest)) {
            PlutusData earlier = Builtins.headList(rest);
            PlutusData f = Builtins.constrFields(earlier);
            fresh = fresh && !Builtins.equalsByteString(Builtins.unBData(Builtins.headList(f)), b.bidder())
                    && !(Builtins.unIData(Builtins.headList(Builtins.tailList(f))).compareTo(b.aU()) == 0
                        && Builtins.unIData(Builtins.headList(Builtins.tailList(Builtins.tailList(f)))).compareTo(b.aV()) == 0);
            count = count + 1;
            rest = Builtins.tailList(rest);
        }
        if (!fresh || count >= 3) return false;

        TxOut lotOut = onlyOwnOutput(txInfo, own);
        PlutusData newBid = Builtins.constrData(0,
                Builtins.mkCons(Builtins.bData(b.bidder()),
                Builtins.mkCons(Builtins.iData(b.aU()),
                Builtins.mkCons(Builtins.iData(b.aV()),
                Builtins.mkCons(Builtins.iData(b.bU()),
                Builtins.mkCons(Builtins.iData(b.bV()),
                        Builtins.mkNilData()))))));
        if (!Builtins.equalsData(ChainLib.inlineDatum(lotOut), withBids(d, appendBid(bids, newBid)))
                || !authentic(lotOut, exact, policy, token, d)
                || ValuesLib.lovelaceOf(lotOut.value()).compareTo(
                        ValuesLib.lovelaceOf(lotIn.value()).add(deposit(d).multiply(BigInteger.valueOf(1000000)))) != 0) {
            return false;
        }
        PlutusData publicInputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(Builtins.byteStringToInteger(true, b.bidder())),
                Builtins.mkCons(ld.deposit(),
                Builtins.mkCons(ld.reserve(),
                Builtins.mkCons(ld.pkU(),
                Builtins.mkCons(ld.pkV(),
                Builtins.mkCons(Builtins.iData(b.aU()),
                Builtins.mkCons(Builtins.iData(b.aV()),
                Builtins.mkCons(Builtins.iData(b.bU()),
                Builtins.mkCons(Builtins.iData(b.bV()),
                        Builtins.mkNilData()))))))))));
        return VkLib.verify(publicInputs, b.piA(), b.piB(), b.piC(), VkLib.referenceVk(txInfo, own, 0), bidVkHash);
    }

    private static boolean settle(Settle s, PlutusData d, TxInfo txInfo, Credential own, byte[] policy, byte[] token) {
        LotFields ld = PlutusData.cast(d, LotFields.class);
        PlutusData bids = Builtins.unListData(ld.bids());
        int n = 0;
        PlutusData rest = bids;
        while (!Builtins.nullList(rest)) {
            n = n + 1;
            rest = Builtins.tailList(rest);
        }
        BigInteger upper = IntervalLib.finiteUpperBound(txInfo.validRange());
        BigInteger reserve = Builtins.unIData(ld.reserve());
        if (n < 1 || !closing(txInfo, own, policy, token, d)
                || !lowerAtLeast(txInfo, ld.biddingEnds())
                || upper.compareTo(BigInteger.ZERO) < 0 || upper.compareTo(Builtins.unIData(ld.settleBy())) > 0
                || s.w().compareTo(BigInteger.ONE) < 0 || s.w().compareTo(BigInteger.valueOf(n)) > 0
                || s.p().compareTo(reserve) < 0 || s.p().compareTo(deposit(d)) > 0) {
            return false;
        }
        byte[] vkHash = n == 1 ? settle1VkHash : n == 2 ? settle2VkHash : settle3VkHash;
        PlutusData publicInputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(s.w()),
                Builtins.mkCons(Builtins.iData(s.p()),
                Builtins.mkCons(ld.pkU(),
                Builtins.mkCons(ld.pkV(),
                        ciphertexts(bids))))));
        if (!VkLib.verify(publicInputs, s.piA(), s.piB(), s.piC(), VkLib.referenceVk(txInfo, own, n), vkHash)) return false;
        byte[] seller = Builtins.unBData(ld.seller());
        BigInteger lovelace = BigInteger.valueOf(1000000);
        return paid(txInfo, seller, s.p().multiply(lovelace), false, d, policy, token)
                && refunded(txInfo, bids, deposit(d), s.w(), d, policy, token)
                && paid(txInfo, bidder(bids, s.w()),
                        Builtins.unIData(ld.lotAda()).add(deposit(d).subtract(s.p()).multiply(lovelace)), true, d, policy, token);
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    /** Settle, NoBids, Refund: the lot token {@code T} is burned and no output stays at the script. */
    private static boolean closing(TxInfo txInfo, Credential own, byte[] policy, byte[] token, PlutusData d) {
        return ChainLib.policyEntryCount(txInfo.mint(), policy) == 1
                && ValuesLib.assetOf(txInfo.mint(), policy, token).compareTo(BigInteger.valueOf(-1)) == 0
                && ChainLib.countOutputs(txInfo.outputs(), own) == 0;
    }

    /** The transaction's validity range starts at or after {@code bound} (finite). */
    private static boolean lowerAtLeast(TxInfo txInfo, PlutusData bound) {
        BigInteger lower = IntervalLib.finiteLowerBound(txInfo.validRange());
        return lower.compareTo(BigInteger.ZERO) >= 0 && lower.compareTo(Builtins.unIData(bound)) >= 0;
    }

    /**
     * Some output pays {@code pkh} at its exact enterprise address at least {@code lovelace},
     * with the item if {@code withItem}, tagged {@code Payout(policy, T)}.
     */
    private static boolean paid(TxInfo txInfo, byte[] pkh, BigInteger lovelace, boolean withItem, PlutusData d,
                                byte[] policy, byte[] token) {
        LotFields ld = PlutusData.cast(d, LotFields.class);
        Address to = new Address(new Credential.PubKeyCredential(PlutusData.cast(pkh, PubKeyHash.class)), Optional.empty());
        PlutusData tag = Builtins.constrData(0, Builtins.mkCons(Builtins.bData(policy),
                Builtins.mkCons(Builtins.bData(token), Builtins.mkNilData())));
        byte[] itemPolicy = Builtins.unBData(ld.itemPolicy());
        byte[] itemName = Builtins.unBData(ld.itemName());
        boolean found = false;
        for (TxOut output : txInfo.outputs()) {
            found = found || (Builtins.equalsData(output.address(), to)
                    && Builtins.equalsData(ChainLib.inlineDatum(output), tag)
                    && ValuesLib.lovelaceOf(output.value()).compareTo(lovelace) >= 0
                    && (!withItem || ValuesLib.assetOf(output.value(), itemPolicy, itemName).compareTo(BigInteger.ONE) == 0));
        }
        return found;
    }

    /** Every bidder but the winner {@code w} (1-based; 0 for none) is paid at least its deposit. */
    private static boolean refunded(TxInfo txInfo, PlutusData bids, BigInteger deposit, BigInteger w, PlutusData d,
                                    byte[] policy, byte[] token) {
        boolean ok = true;
        int i = 0;
        PlutusData rest = bids;
        while (!Builtins.nullList(rest)) {
            i = i + 1;
            byte[] bidder = Builtins.unBData(Builtins.headList(Builtins.constrFields(Builtins.headList(rest))));
            boolean winner = BigInteger.valueOf(i).compareTo(w) == 0;
            ok = ok && (winner || paid(txInfo, bidder, deposit.multiply(BigInteger.valueOf(1000000)), false, d, policy, token));
            rest = Builtins.tailList(rest);
        }
        return ok;
    }

    /** The bidder of bid {@code w} (1-based). */
    private static byte[] bidder(PlutusData bids, BigInteger w) {
        PlutusData rest = bids;
        BigInteger i = BigInteger.ONE;
        while (i.compareTo(w) < 0) {
            rest = Builtins.tailList(rest);
            i = i.add(BigInteger.ONE);
        }
        return Builtins.unBData(Builtins.headList(Builtins.constrFields(Builtins.headList(rest))));
    }

    /** {@code A_1.u, A_1.v, B_1.u, B_1.v, …} of the bids, in datum order. */
    private static PlutusData ciphertexts(PlutusData bids) {
        if (Builtins.nullList(bids)) return Builtins.mkNilData();
        PlutusData f = Builtins.tailList(Builtins.constrFields(Builtins.headList(bids)));
        PlutusData f2 = Builtins.tailList(f);
        PlutusData f3 = Builtins.tailList(f2);
        PlutusData f4 = Builtins.tailList(f3);
        return Builtins.mkCons(Builtins.headList(f),
                Builtins.mkCons(Builtins.headList(f2),
                Builtins.mkCons(Builtins.headList(f3),
                Builtins.mkCons(Builtins.headList(f4),
                        ciphertexts(Builtins.tailList(bids))))));
    }

    /** {@code list ++ [item]}. */
    private static PlutusData appendBid(PlutusData list, PlutusData item) {
        if (Builtins.nullList(list)) return Builtins.mkCons(item, Builtins.mkNilData());
        return Builtins.mkCons(Builtins.headList(list), appendBid(Builtins.tailList(list), item));
    }

    /** The lot datum {@code d} with its bids replaced by {@code bids}. */
    private static PlutusData withBids(PlutusData d, PlutusData bids) {
        return Builtins.constrData(0, replaceLast(Builtins.constrFields(d), Builtins.listData(bids)));
    }

    private static PlutusData replaceLast(PlutusData fields, PlutusData last) {
        if (Builtins.nullList(Builtins.tailList(fields))) return Builtins.mkCons(last, Builtins.mkNilData());
        return Builtins.mkCons(Builtins.headList(fields), replaceLast(Builtins.tailList(fields), last));
    }

    /**
     * An authentic lot output: at {@code exact}, without a reference script, holding exactly
     * lovelace, one unit of the item and one {@code token} under {@code policy}.
     */
    private static boolean authentic(TxOut out, Address exact, byte[] policy, byte[] token, PlutusData d) {
        LotFields ld = PlutusData.cast(d, LotFields.class);
        Value v = out.value();
        // No reference script on a lot: it would make later spenders pay its reference-script fee.
        return out.referenceScript().isEmpty()
                && Builtins.equalsData(out.address(), exact)
                && Builtins.lengthOfByteString(token) == 32
                && ChainLib.outerEntryCount(v) == 3
                && ChainLib.policyEntryCount(v, policy) == 1
                && ValuesLib.assetOf(v, policy, token).compareTo(BigInteger.ONE) == 0
                && ChainLib.policyEntryCount(v, Builtins.unBData(ld.itemPolicy())) == 1
                && ValuesLib.assetOf(v, Builtins.unBData(ld.itemPolicy()), Builtins.unBData(ld.itemName())).compareTo(BigInteger.ONE) == 0;
    }

    /** The one output under the script's credential. */
    private static TxOut onlyOwnOutput(TxInfo txInfo, Credential own) {
        TxOut found = txInfo.outputs().get(0);
        for (TxOut output : txInfo.outputs()) {
            if (Builtins.equalsData(output.address().credential(), own)) {
                found = output;
            } else {
                found = found;
            }
        }
        return found;
    }

    /**
     * Exactly 13 fields: three 28-byte hashes, an item name of at most 32 bytes, eight integers
     * (coordinates canonical) and a list of well-formed bids. Anything else fails.
     */
    private static boolean isLot(PlutusData d) {
        LotFields ld = PlutusData.cast(d, LotFields.class);
        if (Builtins.constrTag(d) != 0) return false;
        // Exactly 13 fields (unrolled: fewer fails a builtin, more fails the check).
        PlutusData f12 = Builtins.tailList(Builtins.tailList(Builtins.tailList(Builtins.tailList(
                Builtins.tailList(Builtins.tailList(Builtins.tailList(Builtins.tailList(
                Builtins.tailList(Builtins.tailList(Builtins.tailList(Builtins.tailList(
                Builtins.constrFields(d)))))))))))));
        if (!Builtins.nullList(Builtins.tailList(f12))) return false;
        boolean bidsOk = true;
        PlutusData each = Builtins.unListData(ld.bids());
        while (!Builtins.nullList(each)) {
            PlutusData bid = Builtins.headList(each);
            PlutusData bf = Builtins.constrFields(bid);
            bidsOk = bidsOk && Builtins.constrTag(bid) == 0
                    && Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(bf))) == 28
                    && ChainLib.canonicalField(Builtins.unIData(Builtins.headList(Builtins.tailList(bf))));
            each = Builtins.tailList(each);
        }
        return bidsOk
                && Builtins.lengthOfByteString(Builtins.unBData(ld.seller())) == 28
                && Builtins.lengthOfByteString(Builtins.unBData(ld.auctioneer())) == 28
                && Builtins.lengthOfByteString(Builtins.unBData(ld.itemPolicy())) == 28
                && Builtins.lengthOfByteString(Builtins.unBData(ld.itemName())) <= 32
                && Builtins.unIData(ld.lotAda()).compareTo(BigInteger.ZERO) > 0
                && ChainLib.canonicalField(Builtins.unIData(ld.pkU()))
                && ChainLib.canonicalField(Builtins.unIData(ld.pkV()))
                && Builtins.unIData(ld.generation()).compareTo(BigInteger.ZERO) >= 0;
    }

    private static BigInteger deposit(PlutusData d) {
        LotFields ld = PlutusData.cast(d, LotFields.class);
        return Builtins.unIData(ld.deposit());
    }

    /**
     * A typed view of a lot datum, for constant-cost field access (each accessor is a fixed
     * {@code tailList} chain, where a loop over the index cost a call and an iteration per step).
     * Every component stays raw {@code Data}, so callers decode exactly as before, and
     * {@link #isLot} has already checked the shape before any accessor is used.
     */
    record LotFields(PlutusData seller, PlutusData auctioneer, PlutusData itemPolicy, PlutusData itemName,
                     PlutusData lotAda, PlutusData deposit, PlutusData reserve, PlutusData biddingEnds,
                     PlutusData settleBy, PlutusData pkU, PlutusData pkV, PlutusData generation, PlutusData bids) {}
}
