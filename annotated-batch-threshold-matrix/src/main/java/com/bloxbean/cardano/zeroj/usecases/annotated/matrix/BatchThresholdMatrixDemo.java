package com.bloxbean.cardano.zeroj.usecases.annotated.matrix;

import com.bloxbean.cardano.zeroj.usecases.annotated.matrix.circuit.BatchThresholdMatrixProofCircuit;

public final class BatchThresholdMatrixDemo {
    private BatchThresholdMatrixDemo() {
    }

    public static void main(String[] args) {
        var schema = BatchThresholdMatrixProofCircuit.schema(2, 3);
        System.out.println("Circuit: " + schema.name());
        System.out.println("Public inputs: " + schema.publicInputs().names());
        System.out.println("Secret inputs: " + schema.secretInputs().names());
        System.out.println("Measurement dimensions: " + schema.input("measurement").dimensions());
    }
}
