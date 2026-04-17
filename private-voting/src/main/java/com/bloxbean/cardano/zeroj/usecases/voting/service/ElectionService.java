package com.bloxbean.cardano.zeroj.usecases.voting.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages elections: voter registration, Merkle tree building, voter lookup.
 */
@Service
public class ElectionService {

    private static final Logger log = LoggerFactory.getLogger(ElectionService.class);

    private final VoteCircuitService circuitService;

    // Election state
    private String electionName;
    private BigInteger electionId;
    private final List<BigInteger> voterPublicKeys = Collections.synchronizedList(new ArrayList<>());
    private BigInteger voterRoot = BigInteger.ZERO;
    private BigInteger[][] tree;
    private int treeDepth;
    private boolean finalized;

    // Voter secret keys (for demo — in production, voters hold their own keys)
    private final Map<String, BigInteger> voterSecretKeys = new ConcurrentHashMap<>();

    public ElectionService(VoteCircuitService circuitService) {
        this.circuitService = circuitService;
        this.treeDepth = circuitService.getTreeDepth();
    }

    public void createElection(String name) {
        this.electionName = name;
        this.electionId = new BigInteger(1, name.getBytes());
        this.voterPublicKeys.clear();
        this.voterRoot = BigInteger.ZERO;
        this.tree = null;
        this.finalized = false;
        this.voterSecretKeys.clear();
        log.info("Election created: '{}' (id={})", name, electionId.toString(16).substring(0, 16));
    }

    /**
     * Register a voter by their secret key. Returns the voter's public key hash.
     */
    public BigInteger registerVoter(String voterLabel, BigInteger secretKey) {
        if (finalized) throw new IllegalStateException("Election already finalized");
        BigInteger publicKey = circuitService.computePublicKey(secretKey);
        voterPublicKeys.add(publicKey);
        voterSecretKeys.put(voterLabel, secretKey);
        log.info("Voter '{}' registered (pubKey={})", voterLabel, publicKey.toString(16).substring(0, 8));
        return publicKey;
    }

    /**
     * Finalize the election: build the Merkle tree of eligible voters.
     */
    public BigInteger finalizeElection() {
        int maxLeaves = 1 << treeDepth;
        if (voterPublicKeys.size() > maxLeaves) {
            throw new IllegalStateException("Too many voters (" + voterPublicKeys.size()
                    + ") for tree depth " + treeDepth + " (max " + maxLeaves + ")");
        }

        log.info("Finalizing election: {} voters, depth {}", voterPublicKeys.size(), treeDepth);

        BigInteger[] paddedLeaves = new BigInteger[maxLeaves];
        for (int i = 0; i < maxLeaves; i++) {
            paddedLeaves[i] = (i < voterPublicKeys.size()) ? voterPublicKeys.get(i) : BigInteger.ZERO;
        }

        tree = new BigInteger[treeDepth + 1][];
        tree[0] = paddedLeaves;

        for (int level = 1; level <= treeDepth; level++) {
            int size = tree[level - 1].length / 2;
            tree[level] = new BigInteger[size];
            for (int i = 0; i < size; i++) {
                tree[level][i] = poseidon(tree[level - 1][2 * i], tree[level - 1][2 * i + 1]);
            }
        }

        voterRoot = tree[treeDepth][0];
        finalized = true;

        log.info("Election finalized: root={}", voterRoot.toString(16).substring(0, 8));
        return voterRoot;
    }

    /**
     * Get Merkle proof for a voter at a given index.
     */
    public MerkleProof getProof(int leafIndex) {
        if (!finalized) throw new IllegalStateException("Election not finalized");

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
     * Find the leaf index for a given voter public key.
     */
    public int findVoterIndex(BigInteger publicKey) {
        for (int i = 0; i < voterPublicKeys.size(); i++) {
            if (voterPublicKeys.get(i).equals(publicKey)) return i;
        }
        return -1;
    }

    public BigInteger getSecretKey(String voterLabel) {
        return voterSecretKeys.get(voterLabel);
    }

    public BigInteger getElectionId() { return electionId; }
    public String getElectionName() { return electionName; }
    public BigInteger getVoterRoot() { return voterRoot; }
    public int getVoterCount() { return voterPublicKeys.size(); }
    public boolean isFinalized() { return finalized; }
    public Set<String> getVoterLabels() { return voterSecretKeys.keySet(); }

    private BigInteger poseidon(BigInteger a, BigInteger b) {
        // Reuse circuit service's Poseidon (which uses the same cached implementation)
        return circuitService.computeCommitment(a, b);
    }

    public record MerkleProof(BigInteger[] siblings, BigInteger[] pathBits, int leafIndex) {}
}
