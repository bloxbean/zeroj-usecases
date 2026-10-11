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

/**
 * NFT ownership proof, version 2 (ADR-0009 D2).
 *
 * <p>Proves knowledge of a holder secret {@code s} and a token {@code t} whose leaf
 * {@code Poseidon(Poseidon(s, 0), t)} is in the snapshot tree, and publishes the nullifier
 * {@code Poseidon(Poseidon(s, t), contextId)}. The nullifier absorbs the holder's secret, so it
 * does not reveal which token was used (version 1 published {@code Poseidon(t, contextId)}, which
 * anyone could recompute for every token). One use per token now rests on the snapshot having one
 * leaf per token.
 */
@ZKCircuit(
        name = "nft-ownership",
        nameTemplate = "nft-ownership-d{treeDepth}-bls-poseidon",
        version = 2)
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

        // Leaf (unchanged from version 1): Poseidon(Poseidon(secretKey, 0), tokenName).
        var ownerHash = ZkPoseidon.hash(zk, POSEIDON, secretKey, zk.constant(0));
        var leaf = ZkPoseidon.hash(zk, POSEIDON, ownerHash, tokenName);
        ZkMerkle.verifyProofPoseidon(zk, POSEIDON, leaf, snapshotRoot, siblings, pathBits);

        // Nullifier: Poseidon(Poseidon(secretKey, tokenName), contextId).
        var holderToken = ZkPoseidon.hash(zk, POSEIDON, secretKey, tokenName);
        var computedNullifier = ZkPoseidon.hash(zk, POSEIDON, holderToken, contextId);
        return isOwner.and(computedNullifier.isEqual(nullifier));
    }
}
