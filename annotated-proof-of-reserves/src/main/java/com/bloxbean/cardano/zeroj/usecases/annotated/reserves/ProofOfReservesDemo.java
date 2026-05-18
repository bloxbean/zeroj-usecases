package com.bloxbean.cardano.zeroj.usecases.annotated.reserves;

import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMerkle;
import com.bloxbean.cardano.zeroj.usecases.annotated.reserves.circuit.ReserveSolvencyProofCircuit;

public final class ProofOfReservesDemo {
    private ProofOfReservesDemo() {
    }

    public static void main(String[] args) {
        var schema = ReserveSolvencyProofCircuit.schema(2, ZkMerkle.HashType.MIMC);
        System.out.println("Circuit: " + schema.name());
        System.out.println("Public inputs: " + schema.publicInputs().names());
        System.out.println("Secret inputs: " + schema.secretInputs().names());
    }
}
