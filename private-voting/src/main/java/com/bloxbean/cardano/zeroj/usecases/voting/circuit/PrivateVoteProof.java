package com.bloxbean.cardano.zeroj.usecases.voting.circuit;

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
