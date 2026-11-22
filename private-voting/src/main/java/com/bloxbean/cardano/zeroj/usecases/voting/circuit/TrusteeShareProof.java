package com.bloxbean.cardano.zeroj.usecases.voting.circuit;

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
 * The discrete-log equality relation {@code R_dleq} of ADR-0005, which is ZeroJ's
 * {@code elgamal-jubjub-v1} DLEQ relation (spec §9.2).
 *
 * <p>Public, in order: {@code X.u, X.v, P.u, P.v, D.u, D.v}, exactly a {@code DleqStatement}'s
 * public inputs. The prover knows {@code x} with {@code P = [x]·G} and {@code D = [x]·X}. A
 * trustee uses it twice:
 * <ul>
 *   <li><b>Key proof</b> ({@code X = G}, {@code D = P = PK_j}): proves knowledge of its key share,
 *       which rules out rogue-key attacks on the joint election key.</li>
 *   <li><b>Decryption share</b> ({@code X = ΣA}, {@code D = D_j}): proves that its share of the
 *       tally decryption used the same secret as its published key.</li>
 * </ul>
 * All six coordinates are public inputs, so the verifier, never the prover, chooses {@code X}:
 * the library builds each statement from {@code G} or from the admitted sum's handle.
 *
 * <p>Version 2 uses the library relation; it has its own setup and verification key.
 */
@ZKCircuit(name = "trustee-dleq", version = 2)
public class TrusteeShareProof {

    @Prove
    void prove(
            ZkContext zk,
            @Public ZkField baseU,
            @Public ZkField baseV,
            @Public ZkField publicKeyU,
            @Public ZkField publicKeyV,
            @Public ZkField shareU,
            @Public ZkField shareV,
            @Secret @UInt(bits = 252) ZkUInt secretShare) {

        ZkElGamal.assertDiscreteLogEquality(zk, secretShare,
                baseU, baseV, publicKeyU, publicKeyV, shareU, shareV);
    }
}
