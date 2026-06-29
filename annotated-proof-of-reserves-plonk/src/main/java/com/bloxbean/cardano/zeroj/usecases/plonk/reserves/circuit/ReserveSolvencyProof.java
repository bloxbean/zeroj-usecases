package com.bloxbean.cardano.zeroj.usecases.plonk.reserves.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.CircuitParam;
import com.bloxbean.cardano.zeroj.circuit.annotation.FixedSize;
import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.UInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;

@ZKCircuit(
        name = "annotated-batch-reserve-solvency-plonk",
        nameTemplate = "annotated-batch-reserve-solvency-plonk-{accounts}-accounts",
        version = 1)
public class ReserveSolvencyProof {
    private static final int BALANCE_BITS = 8;

    private final int accounts;

    public ReserveSolvencyProof(@CircuitParam("accounts") int accounts) {
        this.accounts = accounts;
    }

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Public ZkField liabilityBatchCommitment,
            @Public ZkField assetValue,
            @Public ZkField claimedLiabilities,
            @Secret @UInt(bits = BALANCE_BITS) ZkUInt surplus,
            @Secret @UInt(bits = BALANCE_BITS)
            @FixedSize(param = "accounts") ZkArray<ZkUInt> privateLiabilities) {
        ZkUInt totalLiabilities = privateLiabilities.get(0);
        ZkField commitment = weightedTerm(zk, privateLiabilities.get(0), 0);
        for (int i = 1; i < accounts; i++) {
            totalLiabilities = totalLiabilities.add(privateLiabilities.get(i));
            commitment = commitment.add(weightedTerm(zk, privateLiabilities.get(i), i));
        }

        var committedToBatch = commitment.isEqual(liabilityBatchCommitment);
        var liabilityTotalMatchesClaim = totalLiabilities.asField().isEqual(claimedLiabilities);
        var exchangeIsSolvent = claimedLiabilities.add(surplus.asField()).isEqual(assetValue);

        return committedToBatch
                .and(liabilityTotalMatchesClaim)
                .and(exchangeIsSolvent);
    }

    private ZkField weightedTerm(ZkContext zk, ZkUInt value, int index) {
        return value.asField().mul(zk.constant(17L + index));
    }
}
