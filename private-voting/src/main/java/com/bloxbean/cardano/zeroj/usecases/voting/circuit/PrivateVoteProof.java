package com.bloxbean.cardano.zeroj.usecases.voting.circuit;

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
        name = "private-vote",
        nameTemplate = "private-vote-d{treeDepth}-bls-poseidon",
        version = 1)
public class PrivateVoteProof {

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    private final int treeDepth;

    public PrivateVoteProof(@CircuitParam("treeDepth") int treeDepth) {
        if (treeDepth < 1) {
            throw new IllegalArgumentException("treeDepth must be positive");
        }
        this.treeDepth = treeDepth;
    }

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Public ZkField electionId,
            @Public ZkField voterRoot,
            @Public ZkField nullifier,
            @Public ZkField commitment,
            @Secret ZkBool vote,
            @Secret ZkField secretKey,
            @Secret @FixedSize(param = "treeDepth") ZkArray<ZkField> siblings,
            @Secret @FixedSize(param = "treeDepth") ZkArray<ZkBool> pathBits) {

        var computedNullifier = ZkPoseidon.hash(zk, POSEIDON, secretKey, electionId);
        var computedCommitment = ZkPoseidon.hash(zk, POSEIDON, vote.asField(), nullifier);
        var publicKey = ZkPoseidon.hash(zk, POSEIDON, secretKey, zk.constant(0));

        ZkMerkle.verifyProofPoseidon(zk, POSEIDON, publicKey, voterRoot, siblings, pathBits);

        return computedNullifier.isEqual(nullifier)
                .and(computedCommitment.isEqual(commitment));
    }
}
