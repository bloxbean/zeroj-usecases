package com.bloxbean.cardano.zeroj.usecases.voting.circuit;

import com.bloxbean.cardano.zeroj.usecases.voting.VotingFixture;
import com.bloxbean.cardano.zeroj.usecases.voting.service.VoteCircuitService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.lib.jubjub.DleqStatement;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalPublicKey;
import org.zeroj.circuit.lib.jubjub.ElGamalSecretKey;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.VerifiedDecryptionShare;
import org.zeroj.circuit.lib.jubjub.VerifiedKeyShare;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The ballot relation {@code R_ballot} and the trustee relation {@code R_dleq} (ADR-0005), built
 * on ZeroJ's {@code elgamal-jubjub-v1} relations.
 *
 * <p>Honest witnesses are accepted and prove with Groth16; every way of cheating the relation
 * listed in the ADR has no witness; a proof does not verify against changed public inputs. The
 * cheating ciphertexts are built with raw {@link JubjubPoint} arithmetic: the library's safe
 * layer cannot produce them.
 */
class BallotCircuitTest {

    private static final SecureRandom RANDOM = VotingFixture.RANDOM;
    private static final int DEPTH = VotingFixture.DEPTH;
    private static final BigInteger ELECTION_ID = VotingFixture.ELECTION_ID;
    private static final List<BigInteger> SECRETS = VotingFixture.SECRETS;
    private static final JubjubPoint G = JubjubPoint.SUBGROUP_GENERATOR;

    private static VotingFixture fx;
    private static VoteCircuitService circuits;
    private static CircuitBuilder ballot;
    private static CircuitBuilder dleq;
    private static ElGamalPublicKey electionKey;

    @BeforeAll
    static void setup() {
        fx = VotingFixture.get();
        circuits = fx.circuits;
        electionKey = fx.electionKey;
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
        assertEquals(VoteCircuitService.ballotPublicInputs(ELECTION_ID, root(), electionKey, proved.nullifier(),
                proved.ciphertext().raw()), proved.publicInputs(), "public-input order is R_ballot's");
        assertEquals(electionKey.publicInputs(), proved.publicInputs().subList(2, 4), "key group, spec §8 order");
        assertEquals(proved.ciphertext().publicInputs(), proved.publicInputs().subList(5, 9),
                "ciphertext group, spec §8 order");

        // Every public input is bound: changing any one of them rejects the proof.
        for (int i = 0; i < proved.publicInputs().size(); i++) {
            List<BigInteger> changed = new ArrayList<>(proved.publicInputs());
            changed.set(i, changed.get(i).add(BigInteger.ONE));
            assertFalse(circuits.verifyBallot(proved.proof(), changed), "public input " + i + " not bound");
        }
        // Another encryption, under the same nullifier, is rejected.
        ElGamalCiphertext other = ElGamal.encrypt(fx.context, BigInteger.ZERO, 1, RANDOM);
        assertFalse(circuits.verifyBallot(proved.proof(), VoteCircuitService.ballotPublicInputs(
                ELECTION_ID, root(), electionKey, proved.nullifier(), other.raw())));
        System.out.println("[ballot] constraints (depth " + DEPTH + "): " + circuits.ballotConstraints());
    }

    @Test
    @DisplayName("No witness for: vote = 2, mismatched k, another key, identity key, off-curve key, wrong nullifier, non-member, wrong root")
    void cheatingBallotsHaveNoWitness() {
        JubjubPoint key = electionKey.point();
        // v = 2: the 1-bit vote's range check rejects it even with B built for 2.
        rejects(inputs(0, 1, b -> {
            BigInteger k = BigInteger.valueOf(77);
            JubjubPoint[] c = rawEncrypt(2, k, key);
            b.vote(2).randomness(k).handleU(u(c[0])).handleV(v(c[0])).ballotU(u(c[1])).ballotV(v(c[1]));
        }));
        // A from k1, B from k2: would add an arbitrary offset to the decrypted sum.
        rejects(inputs(0, 1, b -> {
            JubjubPoint a = G.scalarMul(BigInteger.valueOf(11));
            JubjubPoint[] c = rawEncrypt(1, BigInteger.valueOf(12), key);
            b.randomness(BigInteger.valueOf(12)).handleU(u(a)).handleV(v(a)).ballotU(u(c[1])).ballotV(v(c[1]));
        }));
        // B encrypted under a key other than the public election key.
        rejects(inputs(0, 1, b -> {
            BigInteger k = BigInteger.valueOf(13);
            JubjubPoint[] c = rawEncrypt(1, k, G.scalarMul(BigInteger.valueOf(999)));
            b.randomness(k).handleU(u(c[0])).handleV(v(c[0])).ballotU(u(c[1])).ballotV(v(c[1]));
        }));
        // The identity as election key: B = [v]·G would be public. Refused in-circuit (PK ≠ O).
        rejects(inputs(0, 1, b -> {
            BigInteger k = BigInteger.valueOf(14);
            JubjubPoint[] c = rawEncrypt(1, k, JubjubPoint.IDENTITY);
            b.electionKeyU(BigInteger.ZERO).electionKeyV(BigInteger.ONE).randomness(k)
                    .handleU(u(c[0])).handleV(v(c[0])).ballotU(u(c[1])).ballotV(v(c[1]));
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

    @Test
    @DisplayName("A ballot is not a 2-bit or wider encryption: the circuit's message width is 1")
    void ballotWidthIsOne() {
        // The host refuses to prove a ballot at another width (the policy's circuit proves width 1).
        var p = fx.path(0);
        var wide = ElGamal.encryptWithOpening(fx.context, BigInteger.ONE, 2, RANDOM);
        assertThrows(IllegalArgumentException.class, () -> circuits.proveBallot(new VoteCircuitService.BallotWitness(
                ELECTION_ID, root(), SECRETS.getFirst(), wide, p[0], p[1])));
        // And a vote outside the width is refused by the library before any proof.
        assertThrows(IllegalArgumentException.class,
                () -> ElGamal.encryptWithOpening(fx.context, BigInteger.TWO, VoteCircuitService.BALLOT_MESSAGE_BITS, RANDOM));
    }

    // ------------------------------------------------------------------
    //  DLEQ (key proofs and decryption shares)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("DLEQ: key proof and decryption share verify; wrong share, key or base is rejected")
    void dleq() {
        ElGamalSecretKey sk = fx.trustees.getFirst();
        ElGamalSecretKey other = fx.trustees.get(1);

        DleqStatement possession = sk.possessionStatement();
        var keyProof = circuits.proveDleq(possession, sk.secretScalar());
        assertTrue(circuits.verifyDleq(keyProof.proofJson(), possession.publicInputs()));

        ElGamalCiphertext ciphertext = ElGamal.encrypt(fx.context, BigInteger.ONE, 1, RANDOM);
        VerifiedDecryptionShare own = ElGamal.decryptionShare(sk, ciphertext);
        DleqStatement shareStatement = own.statement();
        var shareProof = circuits.proveDleq(shareStatement, sk.secretScalar());
        assertTrue(circuits.verifyDleq(shareProof.proofJson(), shareStatement.publicInputs()));

        // Verifier-chosen inputs: any other share, key or base fails.
        JubjubPoint base = shareStatement.base();
        JubjubPoint share = shareStatement.share();
        JubjubPoint pk = sk.publicKey().point();
        assertFalse(circuits.verifyDleq(shareProof.proofJson(), dleqInputs(base, pk, share.add(G))));
        assertFalse(circuits.verifyDleq(shareProof.proofJson(), dleqInputs(base, other.publicKey().point(), share)));
        assertFalse(circuits.verifyDleq(shareProof.proofJson(), dleqInputs(base.add(G), pk, share)));
        // A decryption-share proof is not a key proof: the library sets X = G for key proofs.
        assertFalse(circuits.verifyDleq(shareProof.proofJson(), possession.publicInputs()));

        // The same checks through the library's verified types.
        assertThrows(IllegalArgumentException.class, () -> VerifiedDecryptionShare.verify(ciphertext, sk.publicKey(),
                share.add(G).normalized().toBytes(), s -> s.kind() == DleqStatement.Kind.DECRYPTION_SHARE
                        && circuits.verifyDleq(shareProof.proofJson(), s.publicInputs())));
        assertThrows(IllegalArgumentException.class, () -> VerifiedKeyShare.verify(sk.publicKey().encode(),
                s -> s.kind() == DleqStatement.Kind.POSSESSION && circuits.verifyDleq(shareProof.proofJson(), s.publicInputs())));
        // Trustee 1's key proof does not register trustee 2's key (no rogue key without its own proof).
        assertThrows(IllegalArgumentException.class, () -> VerifiedKeyShare.verify(other.publicKey().encode(),
                s -> s.kind() == DleqStatement.Kind.POSSESSION && circuits.verifyDleq(keyProof.proofJson(), s.publicInputs())));
        assertEquals(sk.publicKey(), VerifiedKeyShare.verify(sk.publicKey().encode(),
                s -> s.kind() == DleqStatement.Kind.POSSESSION && circuits.verifyDleq(keyProof.proofJson(), s.publicInputs()))
                .publicKey());

        // No witness for a share computed with a different secret.
        JubjubPoint wrongShare = base.scalarMul(sk.secretScalar().add(BigInteger.ONE));
        var wrong = TrusteeShareProofCircuit.inputs()
                .baseU(u(base)).baseV(v(base))
                .publicKeyU(u(pk)).publicKeyV(v(pk))
                .shareU(u(wrongShare)).shareV(v(wrongShare))
                .secretShare(sk.secretScalar());
        assertThrows(RuntimeException.class, () -> dleq.calculateWitness(wrong.toWitnessMap(), CurveId.BLS12_381));
        // Nor for an off-curve base.
        var offCurve = TrusteeShareProofCircuit.inputs()
                .baseU(BigInteger.ONE).baseV(BigInteger.ONE)
                .publicKeyU(u(pk)).publicKeyV(v(pk))
                .shareU(BigInteger.ONE).shareV(BigInteger.ONE)
                .secretShare(sk.secretScalar());
        assertThrows(RuntimeException.class, () -> dleq.calculateWitness(offCurve.toWitnessMap(), CurveId.BLS12_381));
        System.out.println("[dleq] constraints: " + circuits.dleqConstraints());
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

    /** {@code {[k]·G, [v]·G + [k]·key}}: raw arithmetic, for building cheating witnesses only. */
    private static JubjubPoint[] rawEncrypt(int vote, BigInteger k, JubjubPoint key) {
        return new JubjubPoint[] {
                G.scalarMul(k).normalized(),
                G.scalarMul(BigInteger.valueOf(vote)).add(key.scalarMul(k)).normalized()};
    }

    private static List<BigInteger> dleqInputs(JubjubPoint base, JubjubPoint key, JubjubPoint share) {
        return List.of(u(base), v(base), u(key), v(key), u(share), v(share));
    }

    private static BigInteger u(JubjubPoint p) {
        return p.normalized().affineU();
    }

    private static BigInteger v(JubjubPoint p) {
        return p.normalized().affineV();
    }

    /** Honest inputs for voter {@code index} (the library's encryption and opening), then {@code tweak} applied. */
    private static PrivateBallotProofCircuit.Inputs inputs(int index, int vote,
                                                           Consumer<PrivateBallotProofCircuit.Inputs> tweak) {
        BigInteger s = SECRETS.get(index);
        var encryption = fx.encrypt(vote);
        List<BigInteger> c = encryption.ciphertext().publicInputs();
        var path = fx.path(index);
        var b = PrivateBallotProofCircuit.inputs(DEPTH)
                .electionId(ELECTION_ID).voterRoot(root())
                .electionKeyU(electionKey.affineU()).electionKeyV(electionKey.affineV())
                .nullifier(circuits.computeNullifier(s, ELECTION_ID))
                .handleU(c.get(0)).handleV(c.get(1))
                .ballotU(c.get(2)).ballotV(c.get(3))
                .vote(encryption.message()).randomness(encryption.randomness()).secretKey(s)
                .siblings(Arrays.asList(path[0])).pathBits(Arrays.asList(path[1]));
        tweak.accept(b);
        return b;
    }
}
