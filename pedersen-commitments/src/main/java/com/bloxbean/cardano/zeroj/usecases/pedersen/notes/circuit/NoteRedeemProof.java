package com.bloxbean.cardano.zeroj.usecases.pedersen.notes.circuit;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.zk.ZkElGamalPublicKey;
import org.zeroj.circuit.lib.zk.ZkPedersen;
import org.zeroj.circuit.lib.zk.ZkPedersenCommitment;

import java.util.List;

/**
 * Redeeming from a confidential note with an enforced auditor amount on the change (ADR-0007 N3;
 * ZeroJ ADR-0055 D3a, spec §8.2): a hidden balance pays a public price and keeps a hidden change.
 *
 * <p>Public, in order: {@code in.u, in.v, change.u, change.v, price} (the application's inputs),
 * {@code PK.u, PK.v}, then the change note's limb 0 and limb 1 {@code A.u, A.v, B.u, B.v}: 15
 * inputs. The prover knows both openings with {@code in = change + price} as integers, and the
 * change amount's two 32-bit limbs encrypted to {@code PK}.
 */
@ZKCircuit(name = "note-redeem", version = 1)
public class NoteRedeemProof {

    @Prove
    void prove(ZkContext zk,
               @Public ZkField inU, @Public ZkField inV,
               @Public ZkField changeU, @Public ZkField changeV,
               @Public @UInt(bits = 32) ZkUInt price,
               @Public ZkField pkU, @Public ZkField pkV,
               @Public ZkField a0u, @Public ZkField a0v, @Public ZkField b0u, @Public ZkField b0v,
               @Public ZkField a1u, @Public ZkField a1v, @Public ZkField b1u, @Public ZkField b1v,
               @Secret @UInt(bits = 64) ZkUInt inAmount, @Secret @UInt(bits = 252) ZkUInt inBlinding,
               @Secret @UInt(bits = 64) ZkUInt changeAmount, @Secret @UInt(bits = 252) ZkUInt changeBlinding,
               @Secret @UInt(bits = 32) ZkUInt l0, @Secret @UInt(bits = 252) ZkUInt k0,
               @Secret @UInt(bits = 32) ZkUInt l1, @Secret @UInt(bits = 252) ZkUInt k1) {
        var in = ZkPedersenCommitment.commit(zk, inAmount, inBlinding);
        var change = ZkPedersenCommitment.commit(zk, changeAmount, changeBlinding);
        in.assertAffineEquals(zk, inU, inV);
        change.assertAffineEquals(zk, changeU, changeV);
        ZkPedersen.assertBalanced(zk,
                List.of(ZkPedersen.Term.of(in)),
                List.of(ZkPedersen.Term.of(change), ZkPedersen.Term.amount(price)));
        var key = ZkElGamalPublicKey.fromVerifierFixedPublic(zk, pkU, pkV);
        AuditLimbs.assertAudited(zk, changeAmount, key, l0, k0, l1, k1, a0u, a0v, b0u, b0v, a1u, a1v, b1u, b1v);
    }
}
