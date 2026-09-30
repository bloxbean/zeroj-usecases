package com.bloxbean.cardano.zeroj.usecases.mpf;

import org.zeroj.api.CurveId;
import org.zeroj.circuit.annotation.ZkInputMap;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfTrie;
import org.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfHash;
import org.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfValueCommitment;
import org.zeroj.merkle.mpf.poseidon.witness.PoseidonMpfBranchWitness;
import com.bloxbean.cardano.zeroj.usecases.mpf.circuit.PrivateRegistryMembershipCircuit;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class PrivateRegistryDemo {
    private static final int MAX_STEPS = 8;

    public static void main(String[] args) {
        byte[] memberKey = bytes("member:alice");
        byte[] memberValue = bytes("tier=premium;active=true");

        PoseidonMpfTrie registry = PoseidonMpfTrie.inMemory();
        registry.put(memberKey, memberValue);
        registry.put(bytes("member:bob"), bytes("tier=standard;active=true"));

        byte[] proof = registry.getProofWire(memberKey).orElseThrow();
        PoseidonMpfBranchWitness witness = PoseidonMpfBranchWitness.inclusion(
                registry.getRootHash(), memberKey, memberValue, proof, MAX_STEPS);

        int[] keyPath = witness.keyPath().stream().mapToInt(BigInteger::intValueExact).toArray();
        BigInteger registryRoot = PoseidonMpfHash.fieldFromDigestBytes(registry.getRootHash());
        BigInteger keyPathNullifier = PoseidonMpfHash.keyPathNullifier(
                PoseidonParamsBLS12_381T3.INSTANCE,
                keyPath);

        var inputs = new ZkInputMap()
                .put("registryRoot", registryRoot)
                .put("keyPathNullifier", keyPathNullifier)
                .put("value_commitment", PoseidonMpfValueCommitment.field(memberValue));
        witness.putInto(inputs);

        var circuit = PrivateRegistryMembershipCircuit.build(MAX_STEPS);
        var schema = PrivateRegistryMembershipCircuit.schema(MAX_STEPS);
        var witnessValues = circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381);

        System.out.println("Circuit: " + schema.name());
        System.out.println("Public inputs: " + inputs.publicValues(schema));
        System.out.println("Registry root bytes: " + HexFormat.of().formatHex(registry.getRootHash()));
        System.out.println("Witness values: " + witnessValues.length);
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
