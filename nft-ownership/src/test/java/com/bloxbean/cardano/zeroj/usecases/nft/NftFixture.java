package com.bloxbean.cardano.zeroj.usecases.nft;

import com.bloxbean.cardano.zeroj.usecases.nft.service.NftScheme;
import com.bloxbean.cardano.zeroj.usecases.nft.service.ProverService;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

/**
 * A small event shared by the NFT tests: a depth-{@value #DEPTH} snapshot over three holders with
 * fresh 252-bit secrets, and the compiled version 2 circuit with a dev setup. Every expected value
 * comes from {@link NftScheme} (ZeroJ's {@code PoseidonHash}), never from the circuit.
 */
public final class NftFixture {

    public static final int DEPTH = 3;
    public static final SecureRandom RANDOM = new SecureRandom();
    public static final BigInteger CONTEXT = NftScheme.contextId("nft-fixture-event");
    public static final List<String> TOKENS = List.of("ZeroJTicket_1", "ZeroJTicket_2", "ZeroJTicket_3");
    public static final List<BigInteger> SECRETS = List.of(
            NftScheme.newSecret(RANDOM), NftScheme.newSecret(RANDOM), NftScheme.newSecret(RANDOM));

    public final ProverService prover;
    public final BigInteger[][] tree;

    private static NftFixture instance;

    private NftFixture() {
        prover = new ProverService();
        ReflectionTestUtils.setField(prover, "treeDepth", DEPTH);
        ReflectionTestUtils.setField(prover, "potPower", 12);
        prover.init();
        BigInteger[] leaves = new BigInteger[TOKENS.size()];
        for (int i = 0; i < leaves.length; i++) leaves[i] = NftScheme.leaf(SECRETS.get(i), token(i));
        tree = buildTree(List.of(leaves));
    }

    public static synchronized NftFixture get() {
        if (instance == null) instance = new NftFixture();
        return instance;
    }

    public static BigInteger token(int index) {
        return NftScheme.tokenField(TOKENS.get(index));
    }

    public BigInteger root() {
        return tree[DEPTH][0];
    }

    /** The honest proof for holder {@code index} in {@link #CONTEXT}. */
    public ProverService.ProofResult prove(int index) {
        var p = path(tree, index);
        return prover.prove(SECRETS.get(index), token(index), root(), CONTEXT, p[0], p[1]);
    }

    public static BigInteger[][] buildTree(List<BigInteger> leaves) {
        int n = 1 << DEPTH;
        BigInteger[][] t = new BigInteger[DEPTH + 1][];
        t[0] = new BigInteger[n];
        for (int i = 0; i < n; i++) t[0][i] = i < leaves.size() ? leaves.get(i) : BigInteger.ZERO;
        for (int level = 1; level <= DEPTH; level++) {
            t[level] = new BigInteger[t[level - 1].length / 2];
            for (int i = 0; i < t[level].length; i++) {
                t[level][i] = NftScheme.poseidon(t[level - 1][2 * i], t[level - 1][2 * i + 1]);
            }
        }
        return t;
    }

    /** {siblings, pathBits} for leaf {@code index}. */
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
