package com.bloxbean.cardano.zeroj.usecases.reserves.circuit;

import org.zeroj.circuit.annotation.CircuitParam;
import org.zeroj.circuit.annotation.FixedSize;
import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.lib.zk.ZkPoseidon;

@ZKCircuit(
        name = "solvency-proof",
        nameTemplate = "solvency-proof-d{treeDepth}-n{numLeaves}-bls-poseidon",
        version = 1)
public class SolvencyProof {

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    private final int treeDepth;
    private final int numLeaves;

    public SolvencyProof(
            @CircuitParam("treeDepth") int treeDepth,
            @CircuitParam("numLeaves") int numLeaves) {
        if (treeDepth < 1) {
            throw new IllegalArgumentException("treeDepth must be positive");
        }
        if (numLeaves != (1 << treeDepth)) {
            throw new IllegalArgumentException("numLeaves must equal 1 << treeDepth");
        }
        this.treeDepth = treeDepth;
        this.numLeaves = numLeaves;
    }

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Public @UInt(bits = 64) ZkUInt totalReserves,
            @Public ZkField liabilitiesRoot,
            @Public @UInt(bits = 64) ZkUInt totalLiabilities,
            @Public ZkBool isSolvent,
            @Secret @FixedSize(param = "numLeaves") ZkArray<ZkField> accountIds,
            @Secret @UInt(bits = 64) @FixedSize(param = "numLeaves") ZkArray<ZkUInt> balances) {

        ZkUInt computedSum = balances.get(0);
        ZkField[] currentLevel = new ZkField[numLeaves];

        for (int i = 0; i < numLeaves; i++) {
            currentLevel[i] = ZkPoseidon.hash(zk, POSEIDON, accountIds.get(i), balances.get(i).asField());
            if (i > 0) {
                computedSum = computedSum.add(balances.get(i));
            }
        }

        int levelSize = numLeaves;
        for (int level = 0; level < treeDepth; level++) {
            ZkField[] nextLevel = new ZkField[levelSize / 2];
            for (int i = 0; i < nextLevel.length; i++) {
                nextLevel[i] = ZkPoseidon.hash(zk, POSEIDON, currentLevel[2 * i], currentLevel[2 * i + 1]);
            }
            currentLevel = nextLevel;
            levelSize = nextLevel.length;
        }

        return currentLevel[0].isEqual(liabilitiesRoot)
                .and(computedSum.asField().isEqual(totalLiabilities.asField()))
                .and(isSolvent.isEqual(totalReserves.gte(totalLiabilities)));
    }
}
