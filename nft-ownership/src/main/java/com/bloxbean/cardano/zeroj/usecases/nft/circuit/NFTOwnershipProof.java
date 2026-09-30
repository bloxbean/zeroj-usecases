package com.bloxbean.cardano.zeroj.usecases.nft.circuit;

import org.zeroj.circuit.annotation.CircuitParam;
import org.zeroj.circuit.annotation.FixedSize;
import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.lib.zk.ZkMerkle;
import org.zeroj.circuit.lib.zk.ZkPoseidon;

@ZKCircuit(
        name = "nft-ownership",
        nameTemplate = "nft-ownership-d{treeDepth}-bls-poseidon",
        version = 1)
public class NFTOwnershipProof {

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    private final int treeDepth;

    public NFTOwnershipProof(@CircuitParam("treeDepth") int treeDepth) {
        if (treeDepth < 1 || treeDepth > 32) {
            throw new IllegalArgumentException("treeDepth must be in [1, 32]");
        }
        this.treeDepth = treeDepth;
    }

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Public ZkField snapshotRoot,
            @Public ZkField contextId,
            @Public ZkBool isOwner,
            @Public ZkField nullifier,
            @Secret ZkField secretKey,
            @Secret ZkField tokenName,
            @Secret @FixedSize(param = "treeDepth") ZkArray<ZkField> siblings,
            @Secret @FixedSize(param = "treeDepth") ZkArray<ZkBool> pathBits) {

        var ownerHash = ZkPoseidon.hash(zk, POSEIDON, secretKey, zk.constant(0));
        var leaf = ZkPoseidon.hash(zk, POSEIDON, ownerHash, tokenName);
        ZkMerkle.verifyProofPoseidon(zk, POSEIDON, leaf, snapshotRoot, siblings, pathBits);

        var computedNullifier = ZkPoseidon.hash(zk, POSEIDON, tokenName, contextId);
        return isOwner.and(computedNullifier.isEqual(nullifier));
    }
}
