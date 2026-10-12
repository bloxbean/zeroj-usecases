package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/**
 * An approved set (countries, inspectors) as a fixed-depth Poseidon Merkle tree whose leaves are
 * the raw member values, as {@code OriginClaimProof} and {@code InspectionClaimProof} hash them:
 * {@code parent = Poseidon(left, right)} over {@code PoseidonParamsBLS12_381T3}.
 *
 * <p>Unused leaves hold the <b>sentinel {@code 2^k}</b>, where {@code k} is the width of the
 * committed entry (ADR-0009 D1). A committed value is range-constrained to {@code k} bits, so it
 * can never equal a padding leaf. Padding with 0, as the old trees did, made 0 a member of every
 * set.
 */
public final class ApprovedSet {

    private final int depth;
    private final int entryBits;
    private final List<BigInteger> members;
    private final BigInteger[][] tree;
    private final Map<BigInteger, Integer> index = new HashMap<>();

    public ApprovedSet(List<BigInteger> members, int depth, int entryBits) {
        if (depth < 1 || entryBits < 1 || entryBits > 64) throw new IllegalArgumentException("bad tree shape");
        if (members.isEmpty() || members.size() > (1 << depth)) {
            throw new IllegalArgumentException("a depth-" + depth + " tree holds 1 to " + (1 << depth) + " members");
        }
        if (new HashSet<>(members).size() != members.size()) throw new IllegalArgumentException("duplicate member");
        for (BigInteger m : members) {
            if (m.signum() < 0 || m.bitLength() > entryBits) {
                throw new IllegalArgumentException("member " + m + " does not fit " + entryBits + " bits");
            }
        }
        this.depth = depth;
        this.entryBits = entryBits;
        this.members = List.copyOf(members);
        BigInteger[] leaves = new BigInteger[1 << depth];
        for (int i = 0; i < leaves.length; i++) {
            if (i < members.size()) {
                leaves[i] = members.get(i);
                index.put(members.get(i), i);
            } else {
                leaves[i] = sentinel();
            }
        }
        tree = new BigInteger[depth + 1][];
        tree[0] = leaves;
        for (int level = 1; level <= depth; level++) {
            tree[level] = new BigInteger[tree[level - 1].length / 2];
            for (int i = 0; i < tree[level].length; i++) {
                tree[level][i] = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE,
                        tree[level - 1][2 * i], tree[level - 1][2 * i + 1]);
            }
        }
    }

    public static ApprovedSet ofLongs(List<Long> members, int depth, int entryBits) {
        return new ApprovedSet(members.stream().map(BigInteger::valueOf).toList(), depth, entryBits);
    }

    /** The padding leaf {@code 2^k}. */
    public BigInteger sentinel() {
        return BigInteger.ONE.shiftLeft(entryBits);
    }

    public BigInteger root() { return tree[depth][0]; }

    public int depth() { return depth; }

    public List<BigInteger> members() { return members; }

    public boolean contains(BigInteger value) { return index.containsKey(value); }

    /** A membership path, or {@code null} for a non-member. */
    public Path path(BigInteger member) {
        Integer i = index.get(member);
        return i == null ? null : pathAt(i);
    }

    /** The path of leaf {@code leafIndex}, padding leaves included (for negative tests). */
    public Path pathAt(int leafIndex) {
        List<BigInteger> siblings = new ArrayList<>();
        List<BigInteger> bits = new ArrayList<>();
        int i = leafIndex;
        for (int level = 0; level < depth; level++) {
            siblings.add(tree[level][(i % 2 == 0) ? i + 1 : i - 1]);
            bits.add(BigInteger.valueOf(i % 2));
            i /= 2;
        }
        return new Path(List.copyOf(siblings), List.copyOf(bits));
    }

    /** Siblings and path bits from the leaf up; a bit of 1 means the node is the right child. */
    public record Path(List<BigInteger> siblings, List<BigInteger> pathBits) {}
}
