package com.bloxbean.cardano.zeroj.usecases.voting;

import com.bloxbean.cardano.zeroj.usecases.voting.service.VoteCircuitService;
import org.springframework.test.util.ReflectionTestUtils;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalEncryption;
import org.zeroj.circuit.lib.jubjub.ElGamalPublicKey;
import org.zeroj.circuit.lib.jubjub.ElGamalSecretKey;
import org.zeroj.circuit.lib.jubjub.NOfNKeyContext;
import org.zeroj.circuit.lib.jubjub.VerifiedKeyShare;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

/**
 * A small election shared by the voting tests: a depth-4 voter tree over {@link #SECRETS}, three
 * trustees and their n-of-n {@code elgamal-jubjub-v1} key context, and the compiled circuits with
 * cached dev keys.
 */
public final class VotingFixture {

    public static final int DEPTH = 4;
    public static final BigInteger ELECTION_ID = new BigInteger("1234567890abcdef", 16);
    public static final List<BigInteger> SECRETS = List.of(
            BigInteger.valueOf(10001), BigInteger.valueOf(10002), BigInteger.valueOf(10003));
    public static final SecureRandom RANDOM = new SecureRandom();

    public final VoteCircuitService circuits;
    public final BigInteger[][] tree;
    public final List<ElGamalSecretKey> trustees;
    /** The trustees' context. The fixture holds the secrets, which counts as possession (spec §3.3). */
    public final NOfNKeyContext context;
    public final ElGamalPublicKey electionKey;

    private static VotingFixture instance;

    private VotingFixture() {
        circuits = new VoteCircuitService();
        ReflectionTestUtils.setField(circuits, "treeDepth", DEPTH);
        circuits.init();
        tree = buildTree(circuits, SECRETS.stream().map(circuits::computePublicKey).toList());
        trustees = List.of(ElGamalSecretKey.generate(RANDOM), ElGamalSecretKey.generate(RANDOM),
                ElGamalSecretKey.generate(RANDOM));
        context = ElGamalPublicKey.aggregate(trustees.stream().map(VerifiedKeyShare::fromSecret).toList());
        electionKey = context.jointKey();
    }

    public static synchronized VotingFixture get() {
        if (instance == null) instance = new VotingFixture();
        return instance;
    }

    public BigInteger root() {
        return tree[DEPTH][0];
    }

    /** {siblings, pathBits} for leaf {@code index}. */
    public BigInteger[][] path(int index) {
        return path(tree, index);
    }

    /** A fresh ballot encryption of {@code vote} under the fixture's context, with its opening. */
    public ElGamalEncryption encrypt(int vote) {
        return ElGamal.encryptWithOpening(context, BigInteger.valueOf(vote),
                VoteCircuitService.BALLOT_MESSAGE_BITS, RANDOM);
    }

    public VoteCircuitService.BallotWitness witness(int index, int vote) {
        var p = path(index);
        return new VoteCircuitService.BallotWitness(ELECTION_ID, root(), SECRETS.get(index),
                encrypt(vote), p[0], p[1]);
    }

    public VoteCircuitService.BallotProof prove(int index, int vote) {
        return circuits.proveBallot(witness(index, vote));
    }

    public static BigInteger[][] buildTree(VoteCircuitService circuits, List<BigInteger> leaves) {
        int n = 1 << DEPTH;
        BigInteger[][] t = new BigInteger[DEPTH + 1][];
        t[0] = new BigInteger[n];
        for (int i = 0; i < n; i++) t[0][i] = i < leaves.size() ? leaves.get(i) : BigInteger.ZERO;
        for (int level = 1; level <= DEPTH; level++) {
            t[level] = new BigInteger[t[level - 1].length / 2];
            for (int i = 0; i < t[level].length; i++) {
                t[level][i] = circuits.merkleHash(t[level - 1][2 * i], t[level - 1][2 * i + 1]);
            }
        }
        return t;
    }

    public static BigInteger[][] path(BigInteger[][] tree, int index) {
        BigInteger[] siblings = new BigInteger[DEPTH];
        BigInteger[] bits = new BigInteger[DEPTH];
        int i = index;
        for (int level = 0; level < DEPTH; level++) {
            siblings[level] = tree[level][i % 2 == 0 ? i + 1 : i - 1];
            bits[level] = BigInteger.valueOf(i % 2);
            i /= 2;
        }
        return new BigInteger[][] {siblings, bits};
    }
}
