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
 * A private points transfer (ADR-0006 demo A): one note is split into two, and the amounts stay
 * hidden.
 *
 * <p>Public, in order: {@code in.u, in.v, out1.u, out1.v, out2.u, out2.v}, the affine
 * {@code pedersen-jubjub-v1} commitments of the spent note and the two new notes. The prover knows
 * an opening of all three, with 64-bit amounts and 252-bit blindings, such that
 * {@code in = out1 + out2} as integers. {@code assertBalanced} rules out wraparound mod {@code l}.
 */
@ZKCircuit(name = "points-transfer", version = 1)
public class PointsTransferProof {

    @Prove
    void prove(ZkContext zk,
               @Public ZkField inU, @Public ZkField inV,
               @Public ZkField out1U, @Public ZkField out1V,
               @Public ZkField out2U, @Public ZkField out2V,
               @Secret @UInt(bits = 64) ZkUInt inAmount, @Secret @UInt(bits = 252) ZkUInt inBlinding,
               @Secret @UInt(bits = 64) ZkUInt out1Amount, @Secret @UInt(bits = 252) ZkUInt out1Blinding,
               @Secret @UInt(bits = 64) ZkUInt out2Amount, @Secret @UInt(bits = 252) ZkUInt out2Blinding) {
        var in = ZkPedersenCommitment.commit(zk, inAmount, inBlinding);
        var out1 = ZkPedersenCommitment.commit(zk, out1Amount, out1Blinding);
        var out2 = ZkPedersenCommitment.commit(zk, out2Amount, out2Blinding);
        in.assertAffineEquals(zk, inU, inV);
        out1.assertAffineEquals(zk, out1U, out1V);
        out2.assertAffineEquals(zk, out2U, out2V);
        ZkPedersen.assertBalanced(zk,
                List.of(ZkPedersen.Term.of(in)),
                List.of(ZkPedersen.Term.of(out1), ZkPedersen.Term.of(out2)));
    }
}
