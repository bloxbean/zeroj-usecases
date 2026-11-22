package com.bloxbean.cardano.zeroj.usecases.pedersen.auction.circuit;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.zk.ZkElGamal;
import org.zeroj.circuit.lib.zk.ZkElGamalPublicKey;

/**
 * A sealed bid (ADR-0008 D3): the bid is encrypted to the auctioneer, and the ciphertext is
 * proved to encrypt an amount between the reserve and the deposit.
 *
 * <p>Public, in order: {@code bidderInt, deposit, reserve} (the application's inputs), then
 * {@code PK.u, PK.v} and {@code A.u, A.v, B.u, B.v} ({@code elgamal-jubjub-v1} §8 groups). The
 * prover knows {@code bid} (32 bits) and {@code k} (252 bits) with {@code (A, B) = R_enc(32)} of
 * {@code bid} under {@code PK} and {@code reserve ≤ bid ≤ deposit}.
 *
 * <p>{@code bidderInt² = sq} binds the proof to the bidder: a public input in no constraint would
 * not affect Groth16 verification, so another bidder could copy a ciphertext with its proof.
 */
@ZKCircuit(name = "sealed-bid", version = 1)
public class BidProof {

    @Prove
    void prove(ZkContext zk,
               @Public ZkField bidderInt,
               @Public @UInt(bits = 32) ZkUInt deposit,
               @Public @UInt(bits = 32) ZkUInt reserve,
               @Public ZkField pkU, @Public ZkField pkV,
               @Public ZkField aU, @Public ZkField aV, @Public ZkField bU, @Public ZkField bV,
               @Secret @UInt(bits = 32) ZkUInt bid,
               @Secret @UInt(bits = 252) ZkUInt k,
               @Secret ZkField bidderSquared) {
        bidderInt.mul(bidderInt).assertEqual(bidderSquared);
        var key = ZkElGamalPublicKey.fromVerifierFixedPublic(zk, pkU, pkV);
        ZkElGamal.encrypt(zk, bid, k, key).assertAffineEquals(zk, aU, aV, bU, bV);
        bid.lte(deposit).assertTrue();
        bid.gte(reserve).assertTrue();
    }
}
