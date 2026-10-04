package com.bloxbean.cardano.zeroj.usecases.voting.circuit;

import com.bloxbean.cardano.zeroj.usecases.voting.VotingFixture;
import com.bloxbean.cardano.zeroj.usecases.voting.crypto.JubjubElGamal;
import com.bloxbean.cardano.zeroj.usecases.voting.service.VoteCircuitService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The ballot relation {@code R_ballot} and the trustee relation {@code R_dleq} (ADR-0005).
 *
 * <p>Honest witnesses are accepted and prove with Groth16; every way of cheating the relation
 * listed in the ADR has no witness; a proof does not verify against changed public inputs.
 */
class BallotCircuitTest {

    private static final SecureRandom RANDOM = VotingFixture.RANDOM;
    private static final int DEPTH = VotingFixture.DEPTH;
    private static final BigInteger ELECTION_ID = VotingFixture.ELECTION_ID;
    private static final List<BigInteger> SECRETS = VotingFixture.SECRETS;

    private static VotingFixture fx;
    private static VoteCircuitService circuits;
    private static CircuitBuilder ballot;
    private static CircuitBuilder dleq;
    private static JubjubPoint electionKey;
    private static List<BigInteger> trusteeSecrets;

    @BeforeAll
    static void setup() {
        fx = VotingFixture.get();
        circuits = fx.circuits;
        electionKey = fx.electionKey;
        trusteeSecrets = fx.trusteeSecrets;
        ballot = PrivateBallotProofCircuit.build(DEPTH);
        dleq = TrusteeShareProofCircuit.build();
    }

    // ------------------------------------------------------------------
    //  Ballot
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Honest ballots for YES and NO have witnesses; the proof verifies; changed public inputs do not")
    void honestBallotProves() {
        for (int vote = 0; vote <= 1; vote++) {
            int v = vote;
            assertDoesNotThrow(() -> ballot.calculateWitness(inputs(0, v, b -> {}).toWitnessMap(), CurveId.BLS12_381));
        }
        var proved = fx.prove(1, 1);
        assertTrue(circuits.verifyBallot(proved.proof(), proved.publicInputs()));
        assertTrue(proved.publicInputs().equals(VoteCircuitService.ballotPublicInputs(ELECTION_ID, root(),
                electionKey, proved.nullifier(), proved.ciphertext())), "public-input order is R_ballot's");

        // Every public input is bound: changing any one of them rejects the proof.
        for (int i = 0; i < proved.publicInputs().size(); i++) {
            List<BigInteger> changed = new ArrayList<>(proved.publicInputs());
            changed.set(i, changed.get(i).add(BigInteger.ONE));
            assertFalse(circuits.verifyBallot(proved.proof(), changed), "public input " + i + " not bound");
        }
        // A ballot that decrypts to the other vote, under the same nullifier, is rejected.
        var flipped = JubjubElGamal.encrypt(0, BigInteger.ONE, electionKey);
        assertFalse(circuits.verifyBallot(proved.proof(), VoteCircuitService.ballotPublicInputs(
                ELECTION_ID, root(), electionKey, proved.nullifier(), flipped)));
        System.out.println("[ballot] constraints: " + circuits.ballotConstraints());
    }

    @Test
    @DisplayName("No witness for: vote = 2, mismatched k, another key, identity key, wrong nullifier, non-member")
    void cheatingBallotsHaveNoWitness() {
        // v = 2: ZkBool's booleanity rejects it even with B built for 2.
        rejects(inputs(0, 1, b -> {
            BigInteger k = BigInteger.valueOf(77);
            var c = JubjubElGamal.encrypt(1, k, electionKey);
            JubjubPoint twoG = JubjubElGamal.G.add(c.ballot()).normalized();
            b.vote(2).randomness(k).handleU(c.handle().affineU()).handleV(c.handle().affineV())
                    .ballotU(twoG.affineU()).ballotV(twoG.affineV());
        }));
        // A from k1, B from k2: would add an arbitrary offset to the decrypted sum.
        rejects(inputs(0, 1, b -> {
            JubjubPoint a = JubjubElGamal.G.scalarMul(BigInteger.valueOf(11)).normalized();
            var c = JubjubElGamal.encrypt(1, BigInteger.valueOf(12), electionKey);
            b.randomness(BigInteger.valueOf(12)).handleU(a.affineU()).handleV(a.affineV())
                    .ballotU(c.ballot().affineU()).ballotV(c.ballot().affineV());
        }));
        // B encrypted under a key other than the public election key.
        rejects(inputs(0, 1, b -> {
            JubjubPoint other = JubjubElGamal.G.scalarMul(BigInteger.valueOf(999));
            BigInteger k = BigInteger.valueOf(13);
            var c = JubjubElGamal.encrypt(1, k, other);
            b.randomness(k).handleU(c.handle().affineU()).handleV(c.handle().affineV())
                    .ballotU(c.ballot().affineU()).ballotV(c.ballot().affineV());
        }));
        // The identity as election key: B = [v]·G would be public. Refused in-circuit.
        rejects(inputs(0, 1, b -> {
            BigInteger k = BigInteger.valueOf(14);
            var c = JubjubElGamal.encrypt(1, k, JubjubPoint.IDENTITY);
            b.electionKeyU(BigInteger.ZERO).electionKeyV(BigInteger.ONE).randomness(k)
                    .handleU(c.handle().affineU()).handleV(c.handle().affineV())
                    .ballotU(c.ballot().affineU()).ballotV(c.ballot().affineV());
        }));
        // An off-curve election key.
        rejects(inputs(0, 1, b -> b.electionKeyU(BigInteger.ONE).electionKeyV(BigInteger.ONE)));
        // Another voter's nullifier (or any other value).
        rejects(inputs(0, 1, b -> b.nullifier(circuits.computeNullifier(SECRETS.get(1), ELECTION_ID))));
        // A secret whose key is not in the tree, with a forged path.
        rejects(inputs(0, 1, b -> b.secretKey(BigInteger.valueOf(66666))
                .nullifier(circuits.computeNullifier(BigInteger.valueOf(66666), ELECTION_ID))));
        // The right voter against another root.
        rejects(inputs(0, 1, b -> b.voterRoot(root().add(BigInteger.ONE))));
    }

    // ------------------------------------------------------------------
    //  DLEQ (key proofs and decryption shares)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("DLEQ: key proof and decryption share verify; wrong share, key or base is rejected")
    void dleq() {
        BigInteger x = trusteeSecrets.getFirst();
        JubjubPoint pk = JubjubElGamal.G.scalarMul(x);
        JubjubPoint base = JubjubElGamal.G.scalarMul(BigInteger.valueOf(31337));
        JubjubPoint share = base.scalarMul(x);

        var keyProof = circuits.proveDleq(JubjubElGamal.G, x);
        assertTrue(circuits.verifyDleq(keyProof.proofJson(), JubjubElGamal.G, pk, pk));
        var shareProof = circuits.proveDleq(base, x);
        assertTrue(circuits.verifyDleq(shareProof.proofJson(), base, pk, share));

        // Verifier-chosen inputs: any other share, key or base fails.
        assertFalse(circuits.verifyDleq(shareProof.proofJson(), base, pk, share.add(JubjubElGamal.G)));
        assertFalse(circuits.verifyDleq(shareProof.proofJson(), base,
                JubjubElGamal.G.scalarMul(trusteeSecrets.get(1)), share));
        assertFalse(circuits.verifyDleq(shareProof.proofJson(), base.add(JubjubElGamal.G), pk, share));
        // A decryption-share proof is not a key proof: the verifier sets X = G for key proofs.
        assertFalse(circuits.verifyDleq(shareProof.proofJson(), JubjubElGamal.G, pk, pk));

        // No witness for a share computed with a different secret.
        var wrong = TrusteeShareProofCircuit.inputs()
                .baseU(base.normalized().affineU()).baseV(base.normalized().affineV())
                .publicKeyU(pk.normalized().affineU()).publicKeyV(pk.normalized().affineV())
                .shareU(base.scalarMul(x.add(BigInteger.ONE)).normalized().affineU())
                .shareV(base.scalarMul(x.add(BigInteger.ONE)).normalized().affineV())
                .secretShare(x);
        assertThrows(RuntimeException.class, () -> dleq.calculateWitness(wrong.toWitnessMap(), CurveId.BLS12_381));
        // Nor for an off-curve base.
        var offCurve = TrusteeShareProofCircuit.inputs()
                .baseU(BigInteger.ONE).baseV(BigInteger.ONE)
                .publicKeyU(pk.normalized().affineU()).publicKeyV(pk.normalized().affineV())
                .shareU(BigInteger.ONE).shareV(BigInteger.ONE)
                .secretShare(x);
        assertThrows(RuntimeException.class, () -> dleq.calculateWitness(offCurve.toWitnessMap(), CurveId.BLS12_381));
    }

    // ------------------------------------------------------------------
    //  Harness
    // ------------------------------------------------------------------

    private static void rejects(PrivateBallotProofCircuit.Inputs inputs) {
        assertThrows(RuntimeException.class, () -> ballot.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381));
    }

    private static BigInteger root() {
        return fx.root();
    }

    /** Honest inputs for voter {@code index}, then {@code tweak} applied. */
    private static PrivateBallotProofCircuit.Inputs inputs(int index, int vote,
                                                           Consumer<PrivateBallotProofCircuit.Inputs> tweak) {
        BigInteger s = SECRETS.get(index);
        BigInteger k = JubjubElGamal.randomScalar(RANDOM);
        var c = JubjubElGamal.encrypt(vote, k, electionKey);
        JubjubPoint key = electionKey.normalized();
        var path = fx.path(index);
        var b = PrivateBallotProofCircuit.inputs(DEPTH)
                .electionId(ELECTION_ID).voterRoot(root())
                .electionKeyU(key.affineU()).electionKeyV(key.affineV())
                .nullifier(circuits.computeNullifier(s, ELECTION_ID))
                .handleU(c.handle().affineU()).handleV(c.handle().affineV())
                .ballotU(c.ballot().affineU()).ballotV(c.ballot().affineV())
                .vote(vote).randomness(k).secretKey(s)
                .siblings(Arrays.asList(path[0])).pathBits(Arrays.asList(path[1]));
        tweak.accept(b);
        return b;
    }
}
