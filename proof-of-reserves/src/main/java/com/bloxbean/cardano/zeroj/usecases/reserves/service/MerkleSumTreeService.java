package com.bloxbean.cardano.zeroj.usecases.reserves.service;

import com.bloxbean.cardano.zeroj.usecases.reserves.model.AccountEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.*;

/**
 * Builds and manages the Merkle Sum Tree for proof of reserves.
 * <p>
 * Each leaf = Poseidon(accountId, balance).
 * Each internal node = Poseidon(left_hash, right_hash).
 * The root sum = sum of all leaf balances (enforced by ZK circuit).
 */
@Service
public class MerkleSumTreeService {

    private static final Logger log = LoggerFactory.getLogger(MerkleSumTreeService.class);

    private final AccountService accountService;
    private final ReserveCircuitService circuitService;

    // Tree state
    private BigInteger[][] tree;    // tree[level][index] = hash
    private BigInteger[] leafIds;   // account ID hashes
    private BigInteger[] leafBalances; // account balances
    private BigInteger root = BigInteger.ZERO;
    private BigInteger totalLiabilities = BigInteger.ZERO;
    private int treeDepth;
    private boolean built;

    public MerkleSumTreeService(AccountService accountService, ReserveCircuitService circuitService) {
        this.accountService = accountService;
        this.circuitService = circuitService;
    }

    /**
     * Build the Merkle Sum Tree from all accounts in H2.
     */
    public TreeResult buildTree() {
        treeDepth = circuitService.getTreeDepth();
        int maxLeaves = 1 << treeDepth;
        var accounts = accountService.getAllAccounts();

        if (accounts.size() > maxLeaves) {
            throw new IllegalStateException("Too many accounts (" + accounts.size()
                    + ") for tree depth " + treeDepth + " (max " + maxLeaves + ")");
        }

        log.info("Building Merkle Sum Tree: {} accounts, depth {}", accounts.size(), treeDepth);

        leafIds = new BigInteger[maxLeaves];
        leafBalances = new BigInteger[maxLeaves];
        BigInteger[] leafHashes = new BigInteger[maxLeaves];
        totalLiabilities = BigInteger.ZERO;

        for (int i = 0; i < maxLeaves; i++) {
            if (i < accounts.size()) {
                var acc = accounts.get(i);
                leafIds[i] = accountService.getAccountIdHash(acc.getAccountId());
                leafBalances[i] = BigInteger.valueOf(acc.getBalanceLovelace());
                totalLiabilities = totalLiabilities.add(leafBalances[i]);
            } else {
                leafIds[i] = BigInteger.ZERO;
                leafBalances[i] = BigInteger.ZERO;
            }
            leafHashes[i] = PoseidonCompute.poseidon(leafIds[i], leafBalances[i]);
        }

        // Build tree bottom-up
        tree = new BigInteger[treeDepth + 1][];
        tree[0] = leafHashes;
        for (int level = 1; level <= treeDepth; level++) {
            int size = tree[level - 1].length / 2;
            tree[level] = new BigInteger[size];
            for (int i = 0; i < size; i++) {
                tree[level][i] = PoseidonCompute.poseidon(
                        tree[level - 1][2 * i], tree[level - 1][2 * i + 1]);
            }
        }

        root = tree[treeDepth][0];
        built = true;

        log.info("Tree built: root={}, totalLiabilities={} lovelace ({} ADA)",
                root.toString(16).substring(0, 12),
                totalLiabilities, totalLiabilities.doubleValue() / 1_000_000);

        return new TreeResult(root, totalLiabilities, accounts.size());
    }

    /**
     * Generate inclusion proof for a specific account.
     */
    public InclusionProof getInclusionProof(String accountId) {
        if (!built) throw new IllegalStateException("Tree not built yet");

        BigInteger idHash = accountService.getAccountIdHash(accountId);
        int leafIndex = -1;
        for (int i = 0; i < leafIds.length; i++) {
            if (leafIds[i].equals(idHash)) {
                leafIndex = i;
                break;
            }
        }

        if (leafIndex < 0) return null; // Account not in tree

        BigInteger[] siblings = new BigInteger[treeDepth];
        BigInteger[] pathBits = new BigInteger[treeDepth];
        int index = leafIndex;
        for (int i = 0; i < treeDepth; i++) {
            int sibIdx = (index % 2 == 0) ? index + 1 : index - 1;
            siblings[i] = tree[i][sibIdx];
            pathBits[i] = BigInteger.valueOf(index % 2);
            index /= 2;
        }

        return new InclusionProof(leafIndex, leafBalances[leafIndex], siblings, pathBits, root);
    }

    public BigInteger getRoot() { return root; }
    public BigInteger getTotalLiabilities() { return totalLiabilities; }
    public BigInteger[] getLeafIds() { return leafIds; }
    public BigInteger[] getLeafBalances() { return leafBalances; }
    public boolean isBuilt() { return built; }

    public record TreeResult(BigInteger root, BigInteger totalLiabilities, int accountCount) {}
    public record InclusionProof(int leafIndex, BigInteger balance, BigInteger[] siblings,
                                  BigInteger[] pathBits, BigInteger root) {}
}
