package com.bloxbean.cardano.zeroj.usecases.reserves.service;

import com.bloxbean.cardano.zeroj.usecases.reserves.model.AccountEntity;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds and manages the salted Poseidon Merkle tree for proof of reserves (ADR-0009 D4).
 * <p>
 * Each leaf = Poseidon(Poseidon(idTag, salt), balance), with a fresh 252-bit salt per account per
 * snapshot ({@link ReserveLeaves}). Each internal node = Poseidon(left_hash, right_hash): internal
 * nodes carry no sums. The total of the leaf balances is proved by the ZK circuit, not stored in
 * the tree.
 * <p>
 * Unused leaves get a random 252-bit id and balance 0, so a padding leaf on a customer's path
 * looks like any other leaf.
 */
@Service
public class MerkleSumTreeService {

    private static final Logger log = LoggerFactory.getLogger(MerkleSumTreeService.class);

    private final AccountService accountService;
    private final ReserveCircuitService circuitService;
    private final SecureRandom rng = new SecureRandom();

    private volatile Snapshot snapshot;
    private volatile Snapshot attested;

    private final Path dataDir;

    public MerkleSumTreeService(AccountService accountService, ReserveCircuitService circuitService,
                                @Value("${demo.data-dir:./data}") String dataDir) {
        this.accountService = accountService;
        this.circuitService = circuitService;
        this.dataDir = Path.of(dataDir);
    }

    /** Restores the last attested snapshot, so customers can check the live attestation after a restart. */
    @PostConstruct
    public void restoreAttested() {
        Snapshot restored = AttestedSnapshotStore.read(dataDir, circuitService.getTreeDepth());
        if (restored != null) {
            attested = restored;
            log.info("Restored the attested snapshot (root={})", restored.root().toString(16).substring(0, 12));
        }
    }

    /**
     * Build a fresh snapshot from all accounts in H2. Every build draws new salts.
     */
    public TreeResult buildTree() {
        int treeDepth = circuitService.getTreeDepth();
        var accounts = accountService.getAllAccounts();
        log.info("Building salted Merkle tree: {} accounts, depth {}", accounts.size(), treeDepth);
        Snapshot built = build(accounts, treeDepth, rng);
        snapshot = built;
        log.info("Tree built: root={}, totalLiabilities={} lovelace ({} ADA)",
                built.root().toString(16).substring(0, 12),
                built.totalLiabilities(), built.totalLiabilities().doubleValue() / 1_000_000);
        return new TreeResult(built.root(), built.totalLiabilities(), accounts.size());
    }

    /**
     * A snapshot over {@code accounts} (in list order), with a fresh salt for every account and a
     * random id for every padding leaf.
     */
    public static Snapshot build(List<AccountEntity> accounts, int treeDepth, SecureRandom rng) {
        int maxLeaves = 1 << treeDepth;
        if (accounts.size() > maxLeaves) {
            throw new IllegalStateException("Too many accounts (" + accounts.size()
                    + ") for tree depth " + treeDepth + " (max " + maxLeaves + ")");
        }
        BigInteger[] salts = new BigInteger[maxLeaves];
        BigInteger[] leafIds = new BigInteger[maxLeaves];
        BigInteger[] leafBalances = new BigInteger[maxLeaves];
        Map<String, Integer> index = new HashMap<>();
        BigInteger total = BigInteger.ZERO;
        for (int i = 0; i < maxLeaves; i++) {
            if (i < accounts.size()) {
                var acc = accounts.get(i);
                if (acc.getBalanceLovelace() < 0) {
                    throw new IllegalStateException("negative balance for " + acc.getAccountId());
                }
                salts[i] = ReserveLeaves.randomSalt(rng);
                leafIds[i] = ReserveLeaves.saltedId(acc.getAccountId(), salts[i]);
                leafBalances[i] = BigInteger.valueOf(acc.getBalanceLovelace());
                total = total.add(leafBalances[i]);
                index.put(acc.getAccountId(), i);
            } else {
                salts[i] = null;
                leafIds[i] = ReserveLeaves.randomSalt(rng);
                leafBalances[i] = BigInteger.ZERO;
            }
        }
        return Snapshot.of(treeDepth, salts, leafIds, leafBalances, index, total);
    }

    /**
     * The inclusion data for one account: its salt, balance, leaf index and sibling path. Null
     * if the account is not in the snapshot.
     */
    public InclusionProof getInclusionProof(String accountId) {
        Snapshot s = snapshot;
        if (s == null) throw new IllegalStateException("Tree not built yet");
        return s.inclusionProof(accountId);
    }

    /** The current snapshot, or null before the first build. Read it once per request. */
    public Snapshot snapshot() { return snapshot; }

    /**
     * Records the snapshot whose root the latest attestation token carries, persisting it first
     * (owner-only, atomic). If the write fails the snapshot is kept in memory only and the error is
     * logged: customers can check until the next restart.
     */
    public void markAttested(Snapshot s, long period) {
        try {
            AttestedSnapshotStore.write(dataDir, s, period);
        } catch (Exception e) {
            log.error("Could not persist the attested snapshot; it is kept in memory only", e);
        }
        attested = s;
    }

    /**
     * The snapshot customers check: the last attested one, since a later build (fresh salts) no
     * longer matches the on-chain root. Falls back to the current snapshot before any attestation.
     */
    public Snapshot customerSnapshot() {
        Snapshot a = attested;
        return a != null ? a : snapshot;
    }

    public BigInteger getRoot() { return snapshot.root(); }
    public BigInteger getTotalLiabilities() { return snapshot.totalLiabilities(); }
    public BigInteger[] getLeafIds() { return snapshot.leafIds().clone(); }
    public BigInteger[] getLeafBalances() { return snapshot.leafBalances().clone(); }
    public boolean isBuilt() { return snapshot != null; }

    /** One salted tree. {@code tree[level][index]} is a node hash; level 0 holds the leaves. */
    public record Snapshot(int treeDepth, BigInteger[] salts, BigInteger[] leafIds, BigInteger[] leafBalances,
                           Map<String, Integer> index, BigInteger totalLiabilities, BigInteger[][] tree) {

        static Snapshot of(int treeDepth, BigInteger[] salts, BigInteger[] leafIds, BigInteger[] leafBalances,
                           Map<String, Integer> index, BigInteger totalLiabilities) {
            BigInteger[][] tree = new BigInteger[treeDepth + 1][];
            tree[0] = new BigInteger[leafIds.length];
            for (int i = 0; i < leafIds.length; i++) {
                tree[0][i] = ReserveLeaves.leaf(leafIds[i], leafBalances[i]);
            }
            for (int level = 1; level <= treeDepth; level++) {
                int size = tree[level - 1].length / 2;
                tree[level] = new BigInteger[size];
                for (int i = 0; i < size; i++) {
                    tree[level][i] = ReserveLeaves.node(tree[level - 1][2 * i], tree[level - 1][2 * i + 1]);
                }
            }
            return new Snapshot(treeDepth, salts, leafIds, leafBalances, Map.copyOf(index), totalLiabilities, tree);
        }

        public BigInteger root() {
            return tree[treeDepth][0];
        }

        public InclusionProof inclusionProof(String accountId) {
            Integer leafIndex = index.get(accountId);
            if (leafIndex == null) return null;
            BigInteger[] siblings = new BigInteger[treeDepth];
            int i = leafIndex;
            for (int level = 0; level < treeDepth; level++) {
                siblings[level] = tree[level][i ^ 1];
                i >>= 1;
            }
            return new InclusionProof(leafIndex, salts[leafIndex], leafBalances[leafIndex], siblings);
        }
    }

    public record TreeResult(BigInteger root, BigInteger totalLiabilities, int accountCount) {}

    /** What a customer needs to recompute the root: path bit {@code i} is bit {@code i} of {@code leafIndex}. */
    public record InclusionProof(int leafIndex, BigInteger salt, BigInteger balance, BigInteger[] siblings) {}
}
