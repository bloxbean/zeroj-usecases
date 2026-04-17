package com.bloxbean.cardano.zeroj.usecases.dpp.mpf;

import com.bloxbean.cardano.vds.core.NibblePath;
import com.bloxbean.cardano.vds.mpf.commitment.CommitmentScheme;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Poseidon-based commitment scheme for Merkle Patricia Forestry.
 * <p>
 * Replaces Blake2b-256 with Poseidon hash in all node commitments.
 * The branch binary Merkle tree uses Poseidon(left, right) for pairing —
 * naturally compatible since Poseidon takes exactly 2 field element inputs.
 * <p>
 * This makes the MPF root ZK-circuit-verifiable: a ZK proof can reconstruct
 * the same root from a proof path using SignalPoseidon inside the circuit.
 */
public class PoseidonCommitmentScheme implements CommitmentScheme {

    private static final int RADIX = 16;
    private static final int DIGEST_LENGTH = 32;

    private final byte[] nullHash = new byte[DIGEST_LENGTH];

    @Override
    public byte[] commitBranch(NibblePath prefix, byte[][] childHashes, byte[] valueHash) {
        if (childHashes.length != RADIX) {
            throw new IllegalArgumentException("branch must have 16 child slots");
        }

        byte[][] level = new byte[RADIX][];
        for (int i = 0; i < RADIX; i++) {
            level[i] = sanitize(childHashes[i]);
        }

        // Binary Merkle tree over 16 children using Poseidon pairs
        byte[] branchRoot = poseidonMerkleRoot(level);

        // Combine prefix + branchRoot
        if (prefix.isEmpty()) {
            return PoseidonHashFunction.digestPair(branchRoot, nullHash);
        }
        byte[] prefixField = nibblePathToBytes(prefix);
        return PoseidonHashFunction.digestPair(
                padToDigest(prefixField), branchRoot);
    }

    @Override
    public byte[] commitLeaf(NibblePath suffix, byte[] valueHash) {
        if (valueHash.length != DIGEST_LENGTH) {
            throw new IllegalArgumentException("valueHash must be " + DIGEST_LENGTH + " bytes");
        }
        byte[] suffixBytes = nibblePathToBytes(suffix);
        return PoseidonHashFunction.digestPair(padToDigest(suffixBytes), valueHash);
    }

    @Override
    public byte[] commitExtension(NibblePath path, byte[] childHash) {
        byte[] sanitized = sanitize(childHash);
        byte[] pathBytes = nibblePathToBytes(path);
        return PoseidonHashFunction.digestPair(padToDigest(pathBytes), sanitized);
    }

    @Override
    public byte[] nullHash() {
        return Arrays.copyOf(nullHash, DIGEST_LENGTH);
    }

    @Override
    public boolean encodesBranchValueInBranchCommitment() {
        return false;
    }

    // --- Internal ---

    /**
     * Build a binary Merkle tree over 16 children using Poseidon pair hashing.
     * 4 levels: 16 → 8 → 4 → 2 → 1. Total: 15 Poseidon hashes.
     */
    private byte[] poseidonMerkleRoot(byte[][] nodes) {
        byte[][] current = new byte[RADIX][];
        for (int i = 0; i < RADIX; i++) {
            current[i] = sanitize(nodes[i]);
        }
        int size = current.length;
        while (size > 1) {
            int parentSize = size / 2;
            byte[][] next = new byte[parentSize][];
            for (int i = 0; i < parentSize; i++) {
                next[i] = PoseidonHashFunction.digestPair(current[2 * i], current[2 * i + 1]);
            }
            current = next;
            size = parentSize;
        }
        return current[0];
    }

    private byte[] sanitize(byte[] child) {
        if (child == null) return nullHash();
        if (child.length != DIGEST_LENGTH) {
            throw new IllegalArgumentException("child must be " + DIGEST_LENGTH + " bytes, got " + child.length);
        }
        return Arrays.copyOf(child, child.length);
    }

    private static byte[] nibblePathToBytes(NibblePath path) {
        int[] nibbles = path.getNibbles();
        if (nibbles.length == 0) return new byte[0];
        byte[] out = new byte[nibbles.length];
        for (int i = 0; i < nibbles.length; i++) {
            out[i] = (byte) (nibbles[i] & 0xFF);
        }
        return out;
    }

    /**
     * Pad bytes to DIGEST_LENGTH for Poseidon field element conversion.
     * Left-pads with zeros if shorter, truncates (mod) if longer.
     */
    private byte[] padToDigest(byte[] in) {
        if (in.length == 0) return nullHash();
        if (in.length == DIGEST_LENGTH) return in;
        if (in.length < DIGEST_LENGTH) {
            byte[] result = new byte[DIGEST_LENGTH];
            System.arraycopy(in, 0, result, DIGEST_LENGTH - in.length, in.length);
            return result;
        }
        // Longer than DIGEST_LENGTH — hash to reduce
        BigInteger val = new BigInteger(1, in).mod(
                com.bloxbean.cardano.zeroj.circuit.FieldConfig.BLS12_381.prime());
        byte[] raw = val.toByteArray();
        byte[] result = new byte[DIGEST_LENGTH];
        int srcStart = Math.max(0, raw.length - DIGEST_LENGTH);
        int count = Math.min(raw.length, DIGEST_LENGTH);
        System.arraycopy(raw, srcStart, result, DIGEST_LENGTH - count, count);
        return result;
    }
}
