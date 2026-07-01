package com.bloxbean.cardano.zeroj.usecases.nft.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.CircuitParam;
import com.bloxbean.cardano.zeroj.circuit.annotation.FixedSize;
import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMerkle;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPoseidon;

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
