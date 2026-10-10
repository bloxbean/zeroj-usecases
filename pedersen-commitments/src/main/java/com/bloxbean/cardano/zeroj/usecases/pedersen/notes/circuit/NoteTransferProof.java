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
 * A confidential note transfer with an enforced auditor amount (ADR-0007 N3; ZeroJ ADR-0055 D3a,
 * spec §8.2 direct layout). One note is split into two.
 *
 * <p>Public, in order: {@code in.u, in.v, o1.u, o1.v, o2.u, o2.v} (the application's inputs),
 * {@code PK.u, PK.v} (the auditor's {@code elgamal-jubjub-v1} key, fixed by the verifier from the
 * registry), then for note 1 and then note 2, for limb 0 and then limb 1, {@code A.u, A.v, B.u,
 * B.v}: 24 inputs.
 *
 * <p>The prover knows openings of all three commitments (64-bit amounts, 252-bit blindings) with
 * {@code in = o1 + o2} as integers, and for each created note two 32-bit limbs of its amount, each
 * encrypted to {@code PK} with fresh randomness.
 */
@ZKCircuit(name = "note-transfer", version = 1)
public class NoteTransferProof {

    @Prove
    void prove(ZkContext zk,
               @Public ZkField inU, @Public ZkField inV,
               @Public ZkField o1U, @Public ZkField o1V,
               @Public ZkField o2U, @Public ZkField o2V,
               @Public ZkField pkU, @Public ZkField pkV,
               @Public ZkField o1a0u, @Public ZkField o1a0v, @Public ZkField o1b0u, @Public ZkField o1b0v,
               @Public ZkField o1a1u, @Public ZkField o1a1v, @Public ZkField o1b1u, @Public ZkField o1b1v,
               @Public ZkField o2a0u, @Public ZkField o2a0v, @Public ZkField o2b0u, @Public ZkField o2b0v,
               @Public ZkField o2a1u, @Public ZkField o2a1v, @Public ZkField o2b1u, @Public ZkField o2b1v,
               @Secret @UInt(bits = 64) ZkUInt inAmount, @Secret @UInt(bits = 252) ZkUInt inBlinding,
               @Secret @UInt(bits = 64) ZkUInt o1Amount, @Secret @UInt(bits = 252) ZkUInt o1Blinding,
               @Secret @UInt(bits = 64) ZkUInt o2Amount, @Secret @UInt(bits = 252) ZkUInt o2Blinding,
               @Secret @UInt(bits = 32) ZkUInt o1L0, @Secret @UInt(bits = 252) ZkUInt o1K0,
               @Secret @UInt(bits = 32) ZkUInt o1L1, @Secret @UInt(bits = 252) ZkUInt o1K1,
               @Secret @UInt(bits = 32) ZkUInt o2L0, @Secret @UInt(bits = 252) ZkUInt o2K0,
               @Secret @UInt(bits = 32) ZkUInt o2L1, @Secret @UInt(bits = 252) ZkUInt o2K1) {
        var in = ZkPedersenCommitment.commit(zk, inAmount, inBlinding);
        var out1 = ZkPedersenCommitment.commit(zk, o1Amount, o1Blinding);
        var out2 = ZkPedersenCommitment.commit(zk, o2Amount, o2Blinding);
        in.assertAffineEquals(zk, inU, inV);
        out1.assertAffineEquals(zk, o1U, o1V);
        out2.assertAffineEquals(zk, o2U, o2V);
        ZkPedersen.assertBalanced(zk,
                List.of(ZkPedersen.Term.of(in)),
                List.of(ZkPedersen.Term.of(out1), ZkPedersen.Term.of(out2)));
        var key = ZkElGamalPublicKey.fromVerifierFixedPublic(zk, pkU, pkV);
        AuditLimbs.assertAudited(zk, o1Amount, key, o1L0, o1K0, o1L1, o1K1,
                o1a0u, o1a0v, o1b0u, o1b0v, o1a1u, o1a1v, o1b1u, o1b1v);
        AuditLimbs.assertAudited(zk, o2Amount, key, o2L0, o2K0, o2L1, o2K1,
                o2a0u, o2a0v, o2b0u, o2b0v, o2a1u, o2a1v, o2b1u, o2b1v);
    }
}
