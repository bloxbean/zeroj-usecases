package com.bloxbean.cardano.zeroj.usecases.mpf;

import com.bloxbean.cardano.vds.mpf.MpfTrie;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkInputMap;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfCodec;
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfHash;
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfTrie;
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfValueCommitment;
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfWitness;
import com.bloxbean.cardano.zeroj.usecases.mpf.circuit.PrivateRegistryMembershipCircuit;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class PrivateRegistryDemo {
    private static final int MAX_FORK_PREFIX_CHUNKS = 2;

    public static void main(String[] args) {
        byte[] memberKey = bytes("member:alice");
        byte[] memberValue = bytes("tier=premium;active=true");

        MpfTrie registry = PoseidonMpfTrie.inMemory();
        registry.put(memberKey, memberValue);
        registry.put(bytes("member:bob"), bytes("tier=standard;active=true"));

        byte[] proof = registry.getProofWire(memberKey).orElseThrow();
        int maxSteps = Math.max(1, PoseidonMpfCodec.decode(proof).size());
        PoseidonMpfWitness witness = PoseidonMpfCodec.toWitness(
                memberKey,
                proof,
                maxSteps,
                MAX_FORK_PREFIX_CHUNKS);

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

        var circuit = PrivateRegistryMembershipCircuit.build(maxSteps, MAX_FORK_PREFIX_CHUNKS);
        var schema = PrivateRegistryMembershipCircuit.schema(maxSteps, MAX_FORK_PREFIX_CHUNKS);
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
