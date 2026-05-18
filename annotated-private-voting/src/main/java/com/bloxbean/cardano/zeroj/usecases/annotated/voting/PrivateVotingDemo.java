package com.bloxbean.cardano.zeroj.usecases.annotated.voting;

import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMerkle;
import com.bloxbean.cardano.zeroj.usecases.annotated.voting.circuit.PrivateVoteProofCircuit;

public final class PrivateVotingDemo {
    private PrivateVotingDemo() {
    }

    public static void main(String[] args) {
        var schema = PrivateVoteProofCircuit.schema(2, ZkMerkle.HashType.MIMC);
        System.out.println("Circuit: " + schema.name());
        System.out.println("Public inputs: " + schema.publicInputs().names());
        System.out.println("Secret inputs: " + schema.secretInputs().names());
    }
}
