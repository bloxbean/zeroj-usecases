package com.bloxbean.cardano.zeroj.usecases.annotated.voting.circuit;

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
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPoseidonN;

@ZKCircuit(
        name = "annotated-private-vote",
        nameTemplate = "annotated-private-vote-d{depth}-bls-poseidon",
        version = 1)
public class PrivateVoteProof {
    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    private final int depth;

    public PrivateVoteProof(@CircuitParam("depth") int depth) {
        this.depth = depth;
    }

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Secret ZkBool voteChoice,
            @Secret ZkField voterSecret,
            @Secret ZkField nullifier,
            @Public ZkField electionId,
            @Public ZkField registryRoot,
            @Public ZkField voteCommitment,
            @Public ZkField nullifierHash,
            @Secret @FixedSize(param = "depth") ZkArray<ZkField> registrySiblings,
            @Secret @FixedSize(param = "depth") ZkArray<ZkBool> registryPathBits) {
        var voterLeaf = ZkPoseidon.hash(zk, POSEIDON, voterSecret, electionId);
        var registered = ZkMerkle.isMemberPoseidon(
                zk,
                POSEIDON,
                voterLeaf,
                registryRoot,
                registrySiblings,
                registryPathBits);

        var computedVoteCommitment = ZkPoseidonN.hash(
                zk,
                POSEIDON,
                voteChoice.asField(),
                nullifier,
                electionId);
        var computedNullifierHash = ZkPoseidon.hash(zk, POSEIDON, nullifier, electionId);

        return registered
                .and(computedVoteCommitment.isEqual(voteCommitment))
                .and(computedNullifierHash.isEqual(nullifierHash));
    }
}
