package com.bloxbean.cardano.zeroj.usecases.pedersen.points.circuit;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.zk.ZkPedersen;
import org.zeroj.circuit.lib.zk.ZkPedersenCommitment;

import java.util.List;

/**
 * Spending points at the retailer (ADR-0006 demo A): a hidden balance pays a public price and
 * keeps a hidden change.
 *
 * <p>Public, in order: {@code in.u, in.v, change.u, change.v, price}. The prover knows openings of
 * both commitments, with 64-bit amounts and 252-bit blindings, such that {@code in = change + price}
 * as integers, where {@code price} is a public 32-bit amount. This is the homomorphic balance with
 * a public term: the commitments hide the balance and the change, while the redeemed price is
 * visible to everyone.
 */
@ZKCircuit(name = "points-redeem", version = 1)
public class PointsRedeemProof {

    @Prove
    void prove(ZkContext zk,
               @Public ZkField inU, @Public ZkField inV,
               @Public ZkField changeU, @Public ZkField changeV,
               @Public @UInt(bits = 32) ZkUInt price,
               @Secret @UInt(bits = 64) ZkUInt inAmount, @Secret @UInt(bits = 252) ZkUInt inBlinding,
               @Secret @UInt(bits = 64) ZkUInt changeAmount, @Secret @UInt(bits = 252) ZkUInt changeBlinding) {
        var in = ZkPedersenCommitment.commit(zk, inAmount, inBlinding);
        var change = ZkPedersenCommitment.commit(zk, changeAmount, changeBlinding);
        in.assertAffineEquals(zk, inU, inV);
        change.assertAffineEquals(zk, changeU, changeV);
        ZkPedersen.assertBalanced(zk,
                List.of(ZkPedersen.Term.of(in)),
                List.of(ZkPedersen.Term.of(change), ZkPedersen.Term.amount(price)));
    }
}
