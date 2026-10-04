package com.bloxbean.cardano.zeroj.usecases.voting.circuit;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;

/**
 * The discrete-log equality relation {@code R_dleq} of ADR-0005.
 *
 * <p>Public, in order: {@code X.u, X.v, P.u, P.v, D.u, D.v}. The prover knows {@code x} with
 * {@code P = [x]·G} and {@code D = [x]·X}. A trustee uses it twice:
 * <ul>
 *   <li><b>Key proof</b> ({@code X = G}, {@code D = P = PK_j}): proves knowledge of its key share,
 *       which rules out rogue-key attacks on the joint election key.</li>
 *   <li><b>Decryption share</b> ({@code X = ΣA}, {@code D = D_j}): proves that its share of the
 *       tally decryption used the same secret as its published key.</li>
 * </ul>
 * The verifier always chooses {@code X} itself: {@code G}, or the sum it recomputed from the
 * ballots on-chain.
 */
@ZKCircuit(name = "trustee-dleq", version = 1)
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

        JubjubElGamalGadget.assertDiscreteLogEquality(zk, secretShare,
                baseU, baseV, publicKeyU, publicKeyV, shareU, shareV);
    }
}
