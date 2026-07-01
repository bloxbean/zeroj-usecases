package com.bloxbean.cardano.zeroj.usecases.mpf.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.CircuitParam;
import com.bloxbean.cardano.zeroj.circuit.annotation.FixedSize;
import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.UInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMpf;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMpfProof;

@ZKCircuit(
        name = "zk-mpf-private-registry-membership",
        nameTemplate = "zk-mpf-private-registry-membership-s{maxSteps}-f{maxForkPrefixChunks}",
        version = 1)
public class PrivateRegistryMembership {
    public PrivateRegistryMembership(
            @CircuitParam("maxSteps") int maxSteps,
            @CircuitParam("maxForkPrefixChunks") int maxForkPrefixChunks) {
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
            @Secret(name = "mpf_kind")
            @FixedSize(param = "maxSteps")
            @UInt(bits = 2)
            ZkArray<ZkUInt> stepKind,
            @Secret(name = "mpf_skip")
            @FixedSize(param = "maxSteps")
            @UInt(bits = 8)
            ZkArray<ZkUInt> stepSkip,
            @Secret(name = "mpf_neighbor")
            @FixedSize(param = "maxSteps", inner = 4)
            ZkArray<ZkArray<ZkField>> neighbors,
            @Secret(name = "mpf_neighbor_nibble")
            @FixedSize(param = "maxSteps")
            @UInt(bits = 4)
            ZkArray<ZkUInt> neighborNibble,
            @Secret(name = "mpf_fork_prefix_length")
            @FixedSize(param = "maxSteps")
            @UInt(bits = 8)
            ZkArray<ZkUInt> forkPrefixLength,
            @Secret(name = "mpf_fork_prefix")
            @FixedSize(param = "maxSteps", innerParam = "maxForkPrefixChunks")
            ZkArray<ZkArray<ZkField>> forkPrefixChunks,
            @Secret(name = "mpf_fork_root")
            @FixedSize(param = "maxSteps")
            ZkArray<ZkField> forkRoot,
            @Secret(name = "mpf_leaf_key_path")
            @FixedSize(param = "maxSteps", inner = 64)
            @UInt(bits = 4)
            ZkArray<ZkArray<ZkUInt>> leafKeyPath,
            @Secret(name = "mpf_leaf_value_digest")
            @FixedSize(param = "maxSteps")
            ZkArray<ZkField> leafValueDigest,
            @Secret(name = "mpf_valid")
            @FixedSize(param = "maxSteps")
            ZkArray<ZkBool> valid) {
        ZkMpfProof proof = ZkMpfProof.fromArrays(
                stepKind,
                stepSkip,
                neighbors,
                neighborNibble,
                forkPrefixLength,
                forkPrefixChunks,
                forkRoot,
                leafKeyPath,
                leafValueDigest,
                valid);

        ZkMpf.verifyInclusionPoseidon(
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
