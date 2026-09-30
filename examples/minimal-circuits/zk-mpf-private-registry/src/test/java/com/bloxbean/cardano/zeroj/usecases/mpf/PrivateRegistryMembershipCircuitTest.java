package com.bloxbean.cardano.zeroj.usecases.mpf;

import org.zeroj.api.CurveId;
import org.zeroj.circuit.annotation.ZkInputMap;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfTrie;
import org.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfHash;
import org.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfValueCommitment;
import org.zeroj.merkle.mpf.poseidon.witness.PoseidonMpfBranchWitness;
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
    private static final int MAX_STEPS = 8;

    @Test
    void provesPrivateMembershipAgainstCclPoseidonMpfRoot() {
        Fixture fixture = fixture();
        var circuit = PrivateRegistryMembershipCircuit.build(MAX_STEPS);

        assertDoesNotThrow(() -> circuit.calculateWitness(fixture.inputs().toWitnessMap(), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                withInput(fixture.inputs().toWitnessMap(), "value_commitment", BigInteger.ONE),
                CurveId.BLS12_381));
    }

    @Test
    void generatedSchemaKeepsOnlyRootAndNullifierPublic() {
        Fixture fixture = fixture();
        var schema = PrivateRegistryMembershipCircuit.schema(MAX_STEPS);

        assertEquals(List.of("registryRoot", "keyPathNullifier"), schema.publicInputs().names());
        assertTrue(schema.secretInputs().names().contains("key_path_0"));
        assertTrue(schema.secretInputs().names().contains("mpf_branch_sibling_0_0"));
        assertEquals(2, fixture.inputs().publicValues(schema).size());
    }

    private static Fixture fixture() {
        byte[] memberKey = bytes("member:alice");
        byte[] memberValue = bytes("tier=premium;active=true");
        PoseidonMpfTrie registry = PoseidonMpfTrie.inMemory();
        registry.put(memberKey, memberValue);
        registry.put(bytes("member:bob"), bytes("tier=standard;active=true"));

        byte[] proof = registry.getProofWire(memberKey).orElseThrow();
        PoseidonMpfBranchWitness witness = PoseidonMpfBranchWitness.inclusion(
                registry.getRootHash(), memberKey, memberValue, proof, MAX_STEPS);
        int[] keyPath = witness.keyPath().stream().mapToInt(BigInteger::intValueExact).toArray();

        var inputs = new ZkInputMap()
                .put("registryRoot", PoseidonMpfHash.fieldFromDigestBytes(registry.getRootHash()))
                .put("keyPathNullifier", PoseidonMpfHash.keyPathNullifier(
                        PoseidonParamsBLS12_381T3.INSTANCE,
                        keyPath))
                .put("value_commitment", PoseidonMpfValueCommitment.field(memberValue));
        witness.putInto(inputs);
        return new Fixture(inputs);
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

    private record Fixture(ZkInputMap inputs) {}
}
