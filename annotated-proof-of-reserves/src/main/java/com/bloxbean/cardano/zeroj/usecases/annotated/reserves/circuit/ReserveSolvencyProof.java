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
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMerkle;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMiMC;

import java.util.Objects;

@ZKCircuit(
        name = "annotated-reserve-solvency",
        nameTemplate = "annotated-reserve-solvency-d{depth}-{hashType}",
        version = 1)
public class ReserveSolvencyProof {
    private final int depth;
    private final ZkMerkle.HashType hashType;

    public ReserveSolvencyProof(
            @CircuitParam("depth") int depth,
            @CircuitParam("hashType") ZkMerkle.HashType hashType) {
        this.depth = depth;
        this.hashType = Objects.requireNonNull(hashType, "hashType");
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
        var liabilityLeaf = ZkMiMC.hash(
                zk,
                ZkMiMC.hash(zk, accountId, accountBalance.asField()),
                accountSalt);

        var accountIncluded = ZkMerkle.isMember(
                zk,
                liabilityLeaf,
                liabilitiesRoot,
                liabilitySiblings,
                liabilityPathBits,
                hashType);
        var exchangeIsSolvent = assetValue.gte(claimedLiabilities);
        var accountIsCoveredByClaim = accountBalance.lte(claimedLiabilities);

        return accountIncluded
                .and(exchangeIsSolvent)
                .and(accountIsCoveredByClaim);
    }
}
