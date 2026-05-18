package com.bloxbean.cardano.zeroj.usecases.annotated.credential;

import com.bloxbean.cardano.zeroj.usecases.annotated.credential.circuit.ComplianceCredentialProofCircuit;

public final class ComplianceCredentialDemo {
    private ComplianceCredentialDemo() {
    }

    public static void main(String[] args) {
        var schema = ComplianceCredentialProofCircuit.schema();
        System.out.println("Circuit: " + schema.name());
        System.out.println("Public inputs: " + schema.publicInputs().names());
        System.out.println("Secret inputs: " + schema.secretInputs().names());
    }
}
