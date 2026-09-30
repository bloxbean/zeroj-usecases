package com.bloxbean.cardano.zeroj.usecases.mpf.circuit;

import org.zeroj.circuit.annotation.CircuitParam;
import org.zeroj.circuit.annotation.FixedSize;
import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.merkle.mpf.poseidon.circuit.ZkMpf;
import org.zeroj.merkle.mpf.poseidon.circuit.ZkMpfBranchProof;
import org.zeroj.merkle.mpf.poseidon.circuit.ZkMpfInclusion;

@ZKCircuit(
        name = "zk-mpf-private-registry-membership",
        nameTemplate = "zk-mpf-private-registry-membership-s{maxSteps}",
        version = 1)
public class PrivateRegistryMembership {
    public PrivateRegistryMembership(@CircuitParam("maxSteps") int maxSteps) {
    }

    @Prove
    void prove(
            ZkContext zk,
            @Public ZkField registryRoot,
            @Public ZkField keyPathNullifier,
            @Secret(name = "key_path")
            @FixedSize(64)
            @UInt(bits = 4)
            ZkArray<ZkUInt> keyPath,
            @Secret(name = "value_commitment")
            ZkField valueCommitment,
            @Secret(name = "mpf_branch_skip")
            @FixedSize(param = "maxSteps")
            @UInt(bits = 8)
            ZkArray<ZkUInt> stepSkip,
            @Secret(name = "mpf_branch_sibling")
            @FixedSize(param = "maxSteps", inner = 4)
            ZkArray<ZkArray<ZkField>> siblings,
            @Secret(name = "mpf_branch_valid")
            @FixedSize(param = "maxSteps")
            ZkArray<ZkBool> valid) {
        ZkMpfBranchProof proof = ZkMpfBranchProof.fromArrays(stepSkip, siblings, valid);

        ZkMpfInclusion.verify(
                zk,
                PoseidonParamsBLS12_381T3.INSTANCE,
                keyPath,
                valueCommitment,
                registryRoot,
                proof);
        ZkMpf.keyPathNullifier(zk, PoseidonParamsBLS12_381T3.INSTANCE, keyPath)
                .assertEqual(keyPathNullifier);
    }
}
