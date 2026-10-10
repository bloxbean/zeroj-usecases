package com.bloxbean.cardano.zeroj.usecases.pedersen.auction;

import com.bloxbean.cardano.zeroj.usecases.pedersen.auction.circuit.BidProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.auction.circuit.SettleProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Fields;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.KeyedCircuit;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalEncryption;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * The auction circuits with their keys (ADR-0008 D3, D4): the bid relation and the settlement
 * relation for 1, 2 and 3 bids.
 */
public final class AuctionProofs {

    private final KeyedCircuit bid;
    private final List<KeyedCircuit> settle;

    public AuctionProofs() {
        bid = KeyedCircuit.compile("sealed-bid", BidProofCircuit.build());
        settle = List.of(
                KeyedCircuit.compile("sealed-bid-settle-n1", SettleProofCircuit.build(1, 4)),
                KeyedCircuit.compile("sealed-bid-settle-n2", SettleProofCircuit.build(2, 8)),
                KeyedCircuit.compile("sealed-bid-settle-n3", SettleProofCircuit.build(3, 12)));
    }

    public KeyedCircuit bid() { return bid; }

    public KeyedCircuit settle(int bids) {
        if (bids < 1 || bids > 3) throw new IllegalArgumentException("1 to 3 bids");
        return settle.get(bids - 1);
    }

    /** {@code OS2IP(bidder)}: the 28-byte key hash as the bid proof's first public input. */
    public static BigInteger bidderInt(byte[] bidder) {
        return new BigInteger(1, bidder);
    }

    public static BidProofCircuit.Inputs bidInputs(byte[] bidder, long deposit, long reserve, BigInteger pkU, BigInteger pkV,
                                                   ElGamalEncryption bid) {
        ElGamalCiphertext ct = bid.ciphertext();
        BigInteger b = bidderInt(bidder);
        return BidProofCircuit.inputs()
                .bidderInt(b).deposit(deposit).reserve(reserve)
                .pkU(pkU).pkV(pkV)
                .aU(ct.handle().affineU()).aV(ct.handle().affineV())
                .bU(ct.blinded().affineU()).bV(ct.blinded().affineV())
                .bid(bid.message()).k(bid.randomness())
                .bidderSquared(b.multiply(b).mod(Fields.FR));
    }

    /** Proves the bid; throws if it is above the deposit or below the reserve. */
    public Groth16ProofBLS381 proveBid(byte[] bidder, long deposit, long reserve, BigInteger pkU, BigInteger pkV,
                                       ElGamalEncryption bidEncryption) {
        return bid.prove(bidInputs(bidder, deposit, reserve, pkU, pkV, bidEncryption).toWitnessMap());
    }

    public static SettleProofCircuit.Inputs settleInputs(Lot lot, int w, long p, BigInteger sk, List<Long> bids) {
        int n = lot.bids().size();
        List<BigInteger> cts = new ArrayList<>();
        for (Lot.Bid b : lot.bids()) cts.addAll(List.of(b.aU(), b.aV(), b.bU(), b.bV()));
        return SettleProofCircuit.inputs(n, 4 * n)
                .w(w).p(p).pkU(lot.pkU()).pkV(lot.pkV()).cts(cts)
                .sk(sk).m(bids.stream().map(BigInteger::valueOf).toList());
    }

    /** Proves the settlement with the auctioneer's secret and the decrypted bids; throws if it does not hold. */
    public Groth16ProofBLS381 proveSettle(Lot lot, int w, long p, BigInteger sk, List<Long> bids) {
        return settle(lot.bids().size()).prove(settleInputs(lot, w, p, sk, bids).toWitnessMap());
    }
}
