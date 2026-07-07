package com.bloxbean.cardano.zeroj.usecases.recovery.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.FixedSize;
import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBytes;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkCip1852;

/**
 * Off-chain ownership proof (annotation DSL): proves the claimant's wallet <b>root key</b> derives,
 * via the full CIP-1852 path {@code m/1852'/1815'/0'/0/0}, to the public address payment key hash —
 * i.e. they know the seed (which the SecondFi-style attacker, holding only the leaf key, does not).
 *
 * <p>Concise thanks to {@link ZkCip1852}; the underlying circuit is ~90M constraints (see ADR-0028
 * on the proving envelope). Establishes the ownership statement at the witness level.</p>
 */
@ZKCircuit(name = "account-ownership-proof", version = 1)
public class OwnershipProof {

    @Prove
    void prove(ZkContext zk,
               @Secret @FixedSize(32) ZkBytes rootKL,
               @Secret @FixedSize(32) ZkBytes rootKR,
               @Secret @FixedSize(32) ZkBytes rootChainCode,
               @Public @FixedSize(28) ZkBytes pkh) {
        ZkCip1852.paymentKeyHash(zk, rootKL, rootKR, rootChainCode, 0, 0, 0).assertEqual(pkh);
    }
}
