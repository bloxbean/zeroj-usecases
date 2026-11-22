package com.bloxbean.cardano.zeroj.usecases.pedersen.notes.circuit;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.zk.ZkElGamal;

/**
 * Proof of possession of a Jubjub key (ADR-0007 N7): ZeroJ's {@code elgamal-jubjub-v1} DLEQ
 * relation {@code R_dleq} (spec §9.2), as ADR-0005's trustee proof uses it.
 *
 * <p>Public, in order: {@code ctx}, then {@code X.u, X.v, P.u, P.v, D.u, D.v}, exactly a
 * {@code DleqStatement}'s public inputs (spec §8 lets an application put its own inputs around
 * the group). The prover knows {@code x} with {@code P = [x]·G} and {@code D = [x]·X}. For a
 * possession statement the library builds {@code X = G} and {@code D = P = key}.
 *
 * <p>{@code ctx} binds the proof to a key type, a registry and a registrant (ADR-0007 N7), so a
 * published proof cannot be replayed to register the same key elsewhere, by someone else or as the
 * other key type. {@code ctx² = sq} puts it into a constraint: a public input in no constraint would
 * not affect verification.
 */
@ZKCircuit(name = "key-possession", version = 2)
public class KeyPossessionProof {

    @Prove
    void prove(ZkContext zk,
               @Public ZkField ctx,
               @Public ZkField baseU, @Public ZkField baseV,
               @Public ZkField keyU, @Public ZkField keyV,
               @Public ZkField shareU, @Public ZkField shareV,
               @Secret @UInt(bits = 252) ZkUInt secret,
               @Secret ZkField ctxSquared) {
        ctx.mul(ctx).assertEqual(ctxSquared);
        ZkElGamal.assertDiscreteLogEquality(zk, secret, baseU, baseV, keyU, keyV, shareU, shareV);
    }
}
