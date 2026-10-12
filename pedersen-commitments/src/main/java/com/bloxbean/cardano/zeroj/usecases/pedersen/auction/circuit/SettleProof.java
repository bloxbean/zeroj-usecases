package com.bloxbean.cardano.zeroj.usecases.pedersen.auction.circuit;

import org.zeroj.circuit.annotation.CircuitParam;
import org.zeroj.circuit.annotation.FixedSize;
import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.zk.ZkElGamal;
import org.zeroj.circuit.lib.zk.ZkElGamalPublicKey;

/**
 * Settlement of a sealed-bid auction with {@code n} bids (ADR-0008 D4): the auctioneer proves who
 * won and at what price without publishing the losing bids.
 *
 * <p>Public, in order: {@code w, p, PK.u, PK.v}, then for each bid {@code i = 1 … n} in datum
 * order {@code A_i.u, A_i.v, B_i.u, B_i.v} (the {@code cts} array, interleaved per bid).
 *
 * <p>Witness: the auctioneer's secret {@code sk} (252 bits, one decomposition shared by every
 * bid) and the decrypted bids {@code m_i} (32 bits).
 * <ol>
 *   <li><b>Decryption.</b> For each bid, {@code R_enc(32)} with key {@code A_i} and randomness
 *       {@code sk}, asserted equal to {@code (PK, B_i)}: that is {@code [sk]·G = PK} and
 *       {@code [m_i]·G + [sk]·A_i = B_i}, so {@code m_i} is the ElGamal decryption of bid {@code i}
 *       ({@code elgamal-jubjub-v1} §6.1), unique since {@code m_i < 2^32 < l}. {@code A_i ∈ 𝔾}
 *       and {@code A_i ≠ 𝒪} are established by each bid's proof and the validator.</li>
 *   <li><b>Winner.</b> {@code w ∈ {1, …, n}} as a one-hot selection, and {@code m_w = p}.</li>
 *   <li><b>First price, earliest wins ties.</b> {@code m_i < p} for {@code i < w} and
 *       {@code m_i ≤ p} for every {@code i}.</li>
 * </ol>
 */
@ZKCircuit(name = "sealed-bid-settle", nameTemplate = "sealed-bid-settle-n{bids}-c{cts}", version = 1)
public class SettleProof {

    private final int bids;

    /** {@code cts = 4·bids}: the ciphertext coordinates, which must agree. */
    public SettleProof(@CircuitParam("bids") int bids, @CircuitParam("cts") int cts) {
        if (bids < 1 || bids > 3) throw new IllegalArgumentException("bids must be 1, 2 or 3");
        if (cts != 4 * bids) throw new IllegalArgumentException("cts must be 4·bids");
        this.bids = bids;
    }

    @Prove
    void prove(ZkContext zk,
               @Public ZkField w,
               @Public @UInt(bits = 32) ZkUInt p,
               @Public ZkField pkU, @Public ZkField pkV,
               @Public @FixedSize(param = "cts") ZkArray<ZkField> cts,
               @Secret @UInt(bits = 252) ZkUInt sk,
               @Secret @UInt(bits = 32) @FixedSize(param = "bids") ZkArray<ZkUInt> m) {
        ZkField one = zk.constant(1);
        ZkField zero = zk.constant(0);
        ZkField selected = zero;
        ZkField price = zero;
        ZkBool[] isWinner = new ZkBool[bids];
        for (int i = 0; i < bids; i++) {
            // Decryption of bid i under the auctioneer's key.
            var handle = ZkElGamalPublicKey.fromVerifierFixedPublic(zk, cts.get(4 * i), cts.get(4 * i + 1));
            ZkElGamal.encrypt(zk, m.get(i), sk, handle).assertAffineEquals(zk, pkU, pkV, cts.get(4 * i + 2), cts.get(4 * i + 3));
            isWinner[i] = w.isEqual(zk.constant(i + 1));
            selected = selected.add(isWinner[i].asField());
            price = price.add(isWinner[i].asField().mul(m.get(i).asField()));
        }
        selected.assertEqual(one);
        price.assertEqual(p.asField());
        for (int i = 0; i < bids; i++) {
            m.get(i).lte(p).assertTrue();
            // Bid i comes before the winner when some later index is the winner.
            ZkField beforeWinner = zero;
            for (int j = i + 1; j < bids; j++) beforeWinner = beforeWinner.add(isWinner[j].asField());
            beforeWinner.mul(one.sub(m.get(i).lt(p).asField())).assertEqual(zero);
        }
    }
}
