package com.bloxbean.cardano.zeroj.usecases.pedersen.notes.circuit;

import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.zk.ZkElGamal;
import org.zeroj.circuit.lib.zk.ZkElGamalPublicKey;

import java.math.BigInteger;

/**
 * ZeroJ ADR-0055 D3a for one created note and one auditor (spec §8.1), shared by the note
 * circuits: {@code amount = L0 + 2^32·L1} with both limbs 32-bit (their {@code ZkUInt}
 * decompositions), and each limb an {@code elgamal-jubjub-v1} encryption at width 32 under
 * {@code key}, with its own 252-bit randomness, equal to the public coordinates
 * {@code A.u, A.v, B.u, B.v} of limb 0 then limb 1.
 */
final class AuditLimbs {

    private static final BigInteger TWO_32 = BigInteger.ONE.shiftLeft(32);

    private AuditLimbs() {}

    static void assertAudited(ZkContext zk, ZkUInt amount, ZkElGamalPublicKey key,
                              ZkUInt limb0, ZkUInt k0, ZkUInt limb1, ZkUInt k1,
                              ZkField a0u, ZkField a0v, ZkField b0u, ZkField b0v,
                              ZkField a1u, ZkField a1v, ZkField b1u, ZkField b1v) {
        // One amount: the value that opens the note's commitment is the value its limbs recombine to.
        limb0.asField().add(limb1.asField().mul(zk.constant(TWO_32))).assertEqual(amount.asField());
        ZkElGamal.encrypt(zk, limb0, k0, key).assertAffineEquals(zk, a0u, a0v, b0u, b0v);
        ZkElGamal.encrypt(zk, limb1, k1, key).assertAffineEquals(zk, a1u, a1v, b1u, b1v);
    }
}
