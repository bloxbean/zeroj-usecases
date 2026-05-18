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
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMerkle;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMiMC;

import java.util.Objects;

@ZKCircuit(
        name = "annotated-private-vote",
        nameTemplate = "annotated-private-vote-d{depth}-{hashType}",
        version = 1)
public class PrivateVoteProof {
    private final int depth;
    private final ZkMerkle.HashType hashType;

    public PrivateVoteProof(
            @CircuitParam("depth") int depth,
            @CircuitParam("hashType") ZkMerkle.HashType hashType) {
        this.depth = depth;
        this.hashType = Objects.requireNonNull(hashType, "hashType");
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
        var voterLeaf = ZkMiMC.hash(zk, voterSecret, electionId);
        var registered = ZkMerkle.isMember(
                zk,
                voterLeaf,
                registryRoot,
                registrySiblings,
                registryPathBits,
                hashType);

        var computedVoteCommitment = ZkMiMC.hash(
                zk,
                ZkMiMC.hash(zk, voteChoice.asField(), nullifier),
                electionId);
        var computedNullifierHash = ZkMiMC.hash(zk, nullifier, electionId);

        return registered
                .and(computedVoteCommitment.isEqual(voteCommitment))
                .and(computedNullifierHash.isEqual(nullifierHash));
    }
}
