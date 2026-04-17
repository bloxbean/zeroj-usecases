package com.bloxbean.cardano.zeroj.usecases.nft.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * Builds and maintains the Merkle tree of NFT holders for ZK ownership proofs.
 *
 * <p>Scans the chain (or receives registrations) to build a Poseidon Merkle tree
 * where each leaf = Poseidon(ownerHash, tokenName). The root is published on-chain
 * or used directly for proof generation.</p>
 */
@Service
public class SnapshotService {

    private static final Logger log = LoggerFactory.getLogger(SnapshotService.class);

    @Value("${zk.tree-depth}")
    private int treeDepth;

    // Current snapshot state
    private BigInteger currentRoot = BigInteger.ZERO;
    private final List<BigInteger> leaves = Collections.synchronizedList(new ArrayList<>());
    private BigInteger[][] tree; // tree[level][index]
    private int snapshotEpoch = 0;

    private final ProverService proverService;

    public SnapshotService(ProverService proverService) {
        this.proverService = proverService;
    }

    /**
     * Register an NFT holder in the snapshot.
     *
     * @param ownerAddressHash hash of the owner's address (or derived from secret key)
     * @param tokenName        NFT asset name as field element
     * @return the leaf hash added to the tree
     */
    public BigInteger registerHolder(BigInteger ownerAddressHash, BigInteger tokenName) {
        BigInteger leaf = proverService.computeLeafHash(ownerAddressHash, tokenName);
        leaves.add(leaf);
        log.info("Registered holder: leaf={} (total holders: {})", leaf.toString(16).substring(0, 8), leaves.size());
        return leaf;
    }

    /**
     * Build the Merkle tree from all registered holders and update the root.
     *
     * @return the new Merkle root
     */
    public BigInteger buildSnapshot() {
        int maxLeaves = 1 << treeDepth;
        if (leaves.size() > maxLeaves) {
            throw new IllegalStateException("Too many holders (" + leaves.size()
                    + ") for tree depth " + treeDepth + " (max " + maxLeaves + ")");
        }

        log.info("Building Merkle snapshot: {} holders, depth {}", leaves.size(), treeDepth);

        // Pad leaves to full tree size with zeros
        BigInteger[] paddedLeaves = new BigInteger[maxLeaves];
        for (int i = 0; i < maxLeaves; i++) {
            paddedLeaves[i] = (i < leaves.size()) ? leaves.get(i) : BigInteger.ZERO;
        }

        // Build tree bottom-up
        tree = new BigInteger[treeDepth + 1][];
        tree[0] = paddedLeaves;

        for (int level = 1; level <= treeDepth; level++) {
            int size = tree[level - 1].length / 2;
            tree[level] = new BigInteger[size];
            for (int i = 0; i < size; i++) {
                tree[level][i] = poseidon(tree[level - 1][2 * i], tree[level - 1][2 * i + 1]);
            }
        }

        currentRoot = tree[treeDepth][0];
        snapshotEpoch++;

        log.info("Snapshot built: root={}, epoch={}", currentRoot.toString(16).substring(0, 8), snapshotEpoch);
        return currentRoot;
    }

    /**
     * Get the Merkle proof (siblings + path bits) for a leaf at a given index.
     *
     * @param leafIndex the position of the leaf in the tree
     * @return MerkleProof containing siblings and path bits
     */
    public MerkleProof getProof(int leafIndex) {
        if (tree == null) throw new IllegalStateException("Snapshot not built yet. Call buildSnapshot() first.");
        if (leafIndex < 0 || leafIndex >= (1 << treeDepth))
            throw new IllegalArgumentException("Leaf index out of range: " + leafIndex);

        BigInteger[] siblings = new BigInteger[treeDepth];
        BigInteger[] pathBits = new BigInteger[treeDepth];

        int index = leafIndex;
        for (int i = 0; i < treeDepth; i++) {
            int siblingIdx = (index % 2 == 0) ? index + 1 : index - 1;
            siblings[i] = tree[i][siblingIdx];
            pathBits[i] = BigInteger.valueOf(index % 2);
            index /= 2;
        }

        return new MerkleProof(siblings, pathBits, leafIndex);
    }

    /**
     * Find the leaf index for a given owner + token combination.
     *
     * @return the index, or -1 if not found
     */
    public int findLeafIndex(BigInteger ownerHash, BigInteger tokenName) {
        BigInteger leaf = proverService.computeLeafHash(ownerHash, tokenName);
        for (int i = 0; i < leaves.size(); i++) {
            if (leaves.get(i).equals(leaf)) return i;
        }
        return -1;
    }

    public BigInteger getCurrentRoot() {
        return currentRoot;
    }

    public int getSnapshotEpoch() {
        return snapshotEpoch;
    }

    public int getHolderCount() {
        return leaves.size();
    }

    // --- Poseidon helper ---

    private BigInteger poseidon(BigInteger a, BigInteger b) {
        return proverService.computeLeafHash(a, b);
        // Note: this reuses ProverService's Poseidon computation.
        // For tree internal nodes, we use the same Poseidon hash.
    }

    /**
     * Merkle proof data for a specific leaf.
     */
    public record MerkleProof(
            BigInteger[] siblings,
            BigInteger[] pathBits,
            int leafIndex
    ) {}
}
