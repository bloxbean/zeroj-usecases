package com.bloxbean.cardano.zeroj.usecases.annotated.voting;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.usecases.annotated.voting.circuit.PrivateVoteProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.annotated.voting.support.BinaryMerkle;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PrivateVoteProofCircuitTest {
    @Test
    void validVoteWitnessPasses() {
        var fixture = fixture(BigInteger.ONE);
        var circuit = PrivateVoteProofCircuit.build(2);

        assertTrue(PrivateVoteProofCircuit.schema(2).name()
                .startsWith("annotated-private-vote-d2-bls-poseidon"));
        assertDoesNotThrow(() -> PrivateVoteProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BLS12_381));
        assertEquals(
                List.of(fixture.electionId(), fixture.registryRoot(), fixture.voteCommitment(), fixture.nullifierHash()),
                PrivateVoteProofCircuit.publicInputs(fixture.inputs()));
    }

    @Test
    void bn254CompilationFailsBecauseCircuitUsesBlsPoseidon() {
        var fixture = fixture(BigInteger.ONE);
        var circuit = PrivateVoteProofCircuit.build(2);

        assertThrows(IllegalStateException.class,
                () -> PrivateVoteProofCircuit.calculateWitness(circuit, fixture.inputs(), CurveId.BN254));
    }

    @Test
    void wrongPublicCommitmentFails() {
        var fixture = fixture(BigInteger.ZERO);
        var inputs = PrivateVoteProofCircuit.inputs(2)
                .voteChoice(BigInteger.ZERO)
                .voterSecret(fixture.voterSecret())
                .nullifier(fixture.nullifier())
                .electionId(fixture.electionId())
                .registryRoot(fixture.registryRoot())
                .voteCommitment(fixture.voteCommitment().add(BigInteger.ONE))
                .nullifierHash(fixture.nullifierHash())
                .registrySiblings(fixture.registrySiblings())
                .registryPathBits(fixture.registryPathBits());

        var circuit = PrivateVoteProofCircuit.build(2);
        assertThrows(ArithmeticException.class,
                () -> PrivateVoteProofCircuit.calculateWitness(circuit, inputs, CurveId.BLS12_381));
    }

    private static Fixture fixture(BigInteger voteChoice) {
        var voterSecret = BigInteger.valueOf(1001);
        var nullifier = BigInteger.valueOf(20260518);
        var electionId = BigInteger.valueOf(77);
        var voterLeaf = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, voterSecret, electionId);
        var siblings = List.of(BigInteger.valueOf(2222), BigInteger.valueOf(3333));
        var pathBits = List.of(BigInteger.ZERO, BigInteger.ONE);
        var registryRoot = BinaryMerkle.root(voterLeaf, siblings, pathBits);
        var voteCommitment = PoseidonHash.hashN(
                PoseidonParamsBLS12_381T3.INSTANCE,
                voteChoice,
                nullifier,
                electionId);
        var nullifierHash = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, nullifier, electionId);

        var inputs = PrivateVoteProofCircuit.inputs(2)
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
