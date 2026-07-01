package com.bloxbean.cardano.zeroj.usecases.airdrop.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.UInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkEdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkJubjubPoint;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPoseidon;

@ZKCircuit(name = "personhood-airdrop", version = 1)
public class PersonhoodAirdropProof {

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Public ZkField pkU,
            @Public ZkField pkV,
            @Public ZkField epoch,
            @Public ZkField nullifier,
            @Public ZkField recipient,
            @Public ZkBool eligible,
            @Secret ZkField personhoodId,
            @Secret ZkField sigRU,
            @Secret ZkField sigRV,
            @Secret @UInt(bits = 252) ZkUInt sigS,
            @Secret @UInt(bits = 252) ZkUInt kModL,
            @Secret @UInt(bits = 4) ZkUInt kQuotient) {

        var claimsMsg = ZkPoseidon.hash(zk, POSEIDON, personhoodId, zk.constant(0));
        var issuerKey = ZkJubjubPoint.fromTrustedAffine(zk, pkU, pkV);
        var signatureR = ZkJubjubPoint.fromTrustedAffine(zk, sigRU, sigRV);
        ZkEdDSAJubjub.verify(zk, issuerKey, claimsMsg, signatureR, sigS, kModL, kQuotient);

        recipient.mul(zk.constant(1)).assertEqual(recipient);

        var computedNullifier = ZkPoseidon.hash(zk, POSEIDON, personhoodId, epoch);
        return eligible.and(computedNullifier.isEqual(nullifier));
    }
}
