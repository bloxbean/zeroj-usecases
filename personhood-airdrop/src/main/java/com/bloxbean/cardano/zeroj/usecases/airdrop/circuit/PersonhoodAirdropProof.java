package com.bloxbean.cardano.zeroj.usecases.airdrop.circuit;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.lib.zk.ZkEdDSAJubjub;
import org.zeroj.circuit.lib.zk.ZkPoseidon;

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
        ZkEdDSAJubjub.verifyWithRegisteredKey(
                zk, pkU, pkV, claimsMsg, sigRU, sigRV, sigS, kModL, kQuotient);

        // Bind the public recipient into a non-degenerate R1CS row. A constraint
        // such as recipient * 1 == recipient is a tautology and leaves the
        // corresponding Groth16 IC point at infinity, so the proof would not
        // commit to the recipient at all.
        recipient.mul(personhoodId);

        var computedNullifier = ZkPoseidon.hash(zk, POSEIDON, personhoodId, epoch);
        return eligible.and(computedNullifier.isEqual(nullifier));
    }
}
