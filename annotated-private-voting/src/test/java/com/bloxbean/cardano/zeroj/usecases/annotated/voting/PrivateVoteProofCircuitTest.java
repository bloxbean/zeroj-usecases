package com.bloxbean.cardano.zeroj.usecases.annotated.voting;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMerkle;
import com.bloxbean.cardano.zeroj.usecases.annotated.voting.circuit.PrivateVoteProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.annotated.voting.support.BinaryMerkle;
import com.bloxbean.cardano.zeroj.usecases.annotated.voting.support.OffchainMiMC;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PrivateVoteProofCircuitTest {
    private static final BigInteger PRIME = FieldConfig.BN254.prime();

    @Test
    void validVoteWitnessPasses() {
        var fixture = fixture(BigInteger.ONE);
        var circuit = PrivateVoteProofCircuit.build(2, ZkMerkle.HashType.MIMC);

        assertTrue(PrivateVoteProofCircuit.schema(2, ZkMerkle.HashType.MIMC).name()
                .startsWith("annotated-private-vote-d2-MIMC"));
        assertDoesNotThrow(() -> PrivateVoteProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BN254));
        assertEquals(
                List.of(fixture.electionId(), fixture.registryRoot(), fixture.voteCommitment(), fixture.nullifierHash()),
                PrivateVoteProofCircuit.publicInputs(fixture.inputs()));
    }

    @Test
    void wrongPublicCommitmentFails() {
        var fixture = fixture(BigInteger.ZERO);
        var inputs = PrivateVoteProofCircuit.inputs(2, ZkMerkle.HashType.MIMC)
                .voteChoice(BigInteger.ZERO)
                .voterSecret(fixture.voterSecret())
                .nullifier(fixture.nullifier())
                .electionId(fixture.electionId())
                .registryRoot(fixture.registryRoot())
                .voteCommitment(fixture.voteCommitment().add(BigInteger.ONE))
                .nullifierHash(fixture.nullifierHash())
                .registrySiblings(fixture.registrySiblings())
                .registryPathBits(fixture.registryPathBits());

        var circuit = PrivateVoteProofCircuit.build(2, ZkMerkle.HashType.MIMC);
        assertThrows(ArithmeticException.class,
                () -> PrivateVoteProofCircuit.calculateWitness(circuit, inputs, CurveId.BN254));
    }

    private static Fixture fixture(BigInteger voteChoice) {
        var voterSecret = BigInteger.valueOf(1001);
        var nullifier = BigInteger.valueOf(20260518);
        var electionId = BigInteger.valueOf(77);
        var voterLeaf = OffchainMiMC.hash(voterSecret, electionId, PRIME);
        var siblings = List.of(BigInteger.valueOf(2222), BigInteger.valueOf(3333));
        var pathBits = List.of(BigInteger.ZERO, BigInteger.ONE);
        var registryRoot = BinaryMerkle.root(voterLeaf, siblings, pathBits, PRIME);
        var voteCommitment = OffchainMiMC.hash(
                OffchainMiMC.hash(voteChoice, nullifier, PRIME),
                electionId,
                PRIME);
        var nullifierHash = OffchainMiMC.hash(nullifier, electionId, PRIME);

        var inputs = PrivateVoteProofCircuit.inputs(2, ZkMerkle.HashType.MIMC)
                .voteChoice(voteChoice)
                .voterSecret(voterSecret)
                .nullifier(nullifier)
                .electionId(electionId)
                .registryRoot(registryRoot)
                .voteCommitment(voteCommitment)
                .nullifierHash(nullifierHash)
                .registrySiblings(siblings)
                .registryPathBits(pathBits);
        return new Fixture(
                inputs,
                voterSecret,
                nullifier,
                electionId,
                registryRoot,
                voteCommitment,
                nullifierHash,
                siblings,
                pathBits);
    }

    private record Fixture(
            PrivateVoteProofCircuit.Inputs inputs,
            BigInteger voterSecret,
            BigInteger nullifier,
            BigInteger electionId,
            BigInteger registryRoot,
            BigInteger voteCommitment,
            BigInteger nullifierHash,
            List<BigInteger> registrySiblings,
            List<BigInteger> registryPathBits) {
    }
}
