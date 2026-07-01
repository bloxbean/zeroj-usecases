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
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PrivateRegistryMembershipCircuitTest {
    private static final int MAX_FORK_PREFIX_CHUNKS = 2;

    @Test
    void provesPrivateMembershipAgainstCclPoseidonMpfRoot() {
        Fixture fixture = fixture();
        var circuit = PrivateRegistryMembershipCircuit.build(fixture.maxSteps(), MAX_FORK_PREFIX_CHUNKS);

        assertDoesNotThrow(() -> circuit.calculateWitness(fixture.inputs().toWitnessMap(), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                withInput(fixture.inputs().toWitnessMap(), "value_commitment", BigInteger.ONE),
                CurveId.BLS12_381));
    }

    @Test
    void generatedSchemaKeepsOnlyRootAndNullifierPublic() {
        Fixture fixture = fixture();
        var schema = PrivateRegistryMembershipCircuit.schema(fixture.maxSteps(), MAX_FORK_PREFIX_CHUNKS);

        assertEquals(List.of("registryRoot", "keyPathNullifier"), schema.publicInputs().names());
        assertTrue(schema.secretInputs().names().contains("key_path_0"));
        assertTrue(schema.secretInputs().names().contains("mpf_neighbor_0_0"));
        assertEquals(2, fixture.inputs().publicValues(schema).size());
    }

    private static Fixture fixture() {
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

        var inputs = new ZkInputMap()
                .put("registryRoot", PoseidonMpfHash.fieldFromDigestBytes(registry.getRootHash()))
                .put("keyPathNullifier", PoseidonMpfHash.keyPathNullifier(
                        PoseidonParamsBLS12_381T3.INSTANCE,
                        keyPath))
                .put("value_commitment", PoseidonMpfValueCommitment.field(memberValue));
        witness.putInto(inputs);
        return new Fixture(maxSteps, inputs);
    }

    private static Map<String, List<BigInteger>> withInput(
            Map<String, List<BigInteger>> inputs,
            String name,
            BigInteger value) {
        var copy = new java.util.LinkedHashMap<>(inputs);
        copy.put(name, List.of(value));
        return Map.copyOf(copy);
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private record Fixture(int maxSteps, ZkInputMap inputs) {}
}
