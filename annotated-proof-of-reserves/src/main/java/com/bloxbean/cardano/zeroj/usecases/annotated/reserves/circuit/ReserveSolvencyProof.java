package com.bloxbean.cardano.zeroj.usecases.annotated.reserves.circuit;

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
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMerkle;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPoseidonN;

@ZKCircuit(
        name = "annotated-reserve-solvency",
        nameTemplate = "annotated-reserve-solvency-d{depth}-bls-poseidon",
        version = 1)
public class ReserveSolvencyProof {
    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    private final int depth;

    public ReserveSolvencyProof(@CircuitParam("depth") int depth) {
        this.depth = depth;
    }

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Secret ZkField accountId,
            @Secret @UInt(bits = 64) ZkUInt accountBalance,
            @Secret ZkField accountSalt,
            @Public ZkField liabilitiesRoot,
            @Public @UInt(bits = 64) ZkUInt assetValue,
            @Public @UInt(bits = 64) ZkUInt claimedLiabilities,
            @Secret @FixedSize(param = "depth") ZkArray<ZkField> liabilitySiblings,
            @Secret @FixedSize(param = "depth") ZkArray<ZkBool> liabilityPathBits) {
        var liabilityLeaf = ZkPoseidonN.hash(
                zk,
                POSEIDON,
                accountId,
                accountBalance.asField(),
                accountSalt);

        var accountIncluded = ZkMerkle.isMemberPoseidon(
                zk,
                POSEIDON,
                liabilityLeaf,
                liabilitiesRoot,
                liabilitySiblings,
                liabilityPathBits);
        var exchangeIsSolvent = assetValue.gte(claimedLiabilities);
        var accountIsCoveredByClaim = accountBalance.lte(claimedLiabilities);

        return accountIncluded
                .and(exchangeIsSolvent)
                .and(accountIsCoveredByClaim);
    }
}
