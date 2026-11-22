package com.bloxbean.cardano.zeroj.usecases.pedersen.auction;

import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.util.HexUtil;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * A sealed-bid lot (ADR-0008 D1): {@code Lot(seller, auctioneer, itemPolicy, itemName, lotAda,
 * deposit, reserve, biddingEnds, settleBy, pkU, pkV, generation, bids)}, and the UTxO holding it.
 */
public record Lot(Utxo utxo, String token, byte[] seller, byte[] auctioneer, byte[] itemPolicy, byte[] itemName,
                  long lotAda, long deposit, long reserve, long biddingEnds, long settleBy, BigInteger pkU,
                  BigInteger pkV, long generation, List<Bid> bids) {

    /** One sealed bid: the bidder and the {@code elgamal-jubjub-v1} ciphertext of its amount. */
    public record Bid(byte[] bidder, BigInteger aU, BigInteger aV, BigInteger bU, BigInteger bV) {
        PlutusData data() {
            return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(new BytesPlutusData(bidder),
                    BigIntPlutusData.of(aU), BigIntPlutusData.of(aV), BigIntPlutusData.of(bU), BigIntPlutusData.of(bV))).build();
        }
    }

    public String itemUnit() {
        return HexUtil.encodeHexString(itemPolicy) + HexUtil.encodeHexString(itemName);
    }

    /** The datum with {@code bids}. */
    public ConstrPlutusData datum(List<Bid> withBids) {
        return datum(seller, auctioneer, itemPolicy, itemName, lotAda, deposit, reserve, biddingEnds, settleBy, pkU, pkV,
                generation, withBids);
    }

    public static ConstrPlutusData datum(byte[] seller, byte[] auctioneer, byte[] itemPolicy, byte[] itemName, long lotAda,
                                         long deposit, long reserve, long biddingEnds, long settleBy, BigInteger pkU,
                                         BigInteger pkV, long generation, List<Bid> bids) {
        List<PlutusData> b = new ArrayList<>();
        for (Bid bid : bids) b.add(bid.data());
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(seller), new BytesPlutusData(auctioneer), new BytesPlutusData(itemPolicy),
                new BytesPlutusData(itemName), BigIntPlutusData.of(lotAda), BigIntPlutusData.of(deposit),
                BigIntPlutusData.of(reserve), BigIntPlutusData.of(biddingEnds), BigIntPlutusData.of(settleBy),
                BigIntPlutusData.of(pkU), BigIntPlutusData.of(pkV), BigIntPlutusData.of(generation),
                ListPlutusData.of(b.toArray(new PlutusData[0])))).build();
    }

    /**
     * The lot in {@code utxo} if it is authentic for the auction whose policy is {@code policyId}
     * and address {@code address}: exactly lovelace, the item and one lot token, and a datum of
     * the lot shape. Anything else at the address is ignored.
     */
    public static Optional<Lot> parse(Utxo utxo, String policyId, String address) {
        if (!address.equals(utxo.getAddress()) || utxo.getInlineDatum() == null) return Optional.empty();
        try {
            var d = (ConstrPlutusData) PlutusData.deserialize(HexUtil.decodeHexString(utxo.getInlineDatum()));
            var f = d.getData().getPlutusDataList();
            if (d.getAlternative() != 0 || f.size() != 13) return Optional.empty();
            byte[] itemPolicy = bytes(f.get(2));
            byte[] itemName = bytes(f.get(3));
            String itemUnit = HexUtil.encodeHexString(itemPolicy) + HexUtil.encodeHexString(itemName);
            String token = null;
            int assets = 0;
            boolean item = false;
            for (Amount a : utxo.getAmount()) {
                if (a.getUnit().equals("lovelace")) continue;
                assets++;
                if (a.getUnit().equals(itemUnit) && a.getQuantity().equals(BigInteger.ONE)) item = true;
                else if (a.getUnit().startsWith(policyId) && a.getUnit().length() == policyId.length() + 64
                        && a.getQuantity().equals(BigInteger.ONE)) token = a.getUnit().substring(policyId.length());
            }
            if (token == null || !item || assets != 2) return Optional.empty();
            List<Bid> bids = new ArrayList<>();
            for (PlutusData x : ((ListPlutusData) f.get(12)).getPlutusDataList()) {
                var bf = ((ConstrPlutusData) x).getData().getPlutusDataList();
                bids.add(new Bid(bytes(bf.get(0)), integer(bf.get(1)), integer(bf.get(2)), integer(bf.get(3)), integer(bf.get(4))));
            }
            return Optional.of(new Lot(utxo, token, bytes(f.get(0)), bytes(f.get(1)), itemPolicy, itemName,
                    integer(f.get(4)).longValueExact(), integer(f.get(5)).longValueExact(), integer(f.get(6)).longValueExact(),
                    integer(f.get(7)).longValueExact(), integer(f.get(8)).longValueExact(), integer(f.get(9)), integer(f.get(10)),
                    integer(f.get(11)).longValueExact(), bids));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static byte[] bytes(PlutusData d) {
        return ((BytesPlutusData) d).getValue();
    }

    private static BigInteger integer(PlutusData d) {
        return ((BigIntPlutusData) d).getValue();
    }
}
