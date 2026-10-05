package com.bloxbean.cardano.zeroj.usecases.voting.service;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.util.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.zeroj.circuit.lib.jubjub.DleqStatement;
import org.zeroj.circuit.lib.jubjub.ElGamalPublicKey;
import org.zeroj.circuit.lib.jubjub.ElGamalSecretKey;
import org.zeroj.circuit.lib.jubjub.NOfNKeyContext;
import org.zeroj.circuit.lib.jubjub.VerifiedKeyShare;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Election lifecycle (ADR-0005): voter registration and the eligibility tree, the trustees and
 * their joint ElGamal key, and the voting deadline.
 *
 * <p>The election key is an n-of-n {@code elgamal-jubjub-v1} key context built by ZeroJ
 * ({@link ElGamalPublicKey#aggregate}) from trustee key shares that were each registered through
 * a proof of possession ({@link VerifiedKeyShare#verify}). The manifest keeps every trustee's key
 * encoding and key proof, so anyone rebuilds the same context with {@link #keyContext}.
 *
 * <p><b>Demo shortcut.</b> The trustees' secret keys and the voters' secrets live in this service
 * so the demo can run unattended. In a real election each trustee and each voter holds their own
 * secret, and nobody holds them all.
 */
@Service
public class ElectionService {

    private static final Logger log = LoggerFactory.getLogger(ElectionService.class);
    private static final BigInteger FR = new BigInteger(
            "52435875175126190479447740508185965837690552500527637822603658699938581184513");
    private static final byte[] ELECTION_ID_TAG =
            "zeroj.private-voting.election-id.v2".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final VoteCircuitService circuitService;
    private final int treeDepth;

    @Value("${election.trustee-count:3}")
    private int trusteeCount = 3;

    @Value("${election.voting-window-seconds:600}")
    private long votingWindowSeconds = 600;

    // Election state
    private String electionName;
    private BigInteger electionId;
    private final List<BigInteger> voterPublicKeys = Collections.synchronizedList(new ArrayList<>());
    private BigInteger[][] tree;
    private List<Trustee> trustees = List.of();
    private NOfNKeyContext keyContext;
    private ElectionConfig config;

    // Voter secret keys (demo only — in production, voters hold their own keys)
    private final Map<String, BigInteger> voterSecretKeys = new ConcurrentHashMap<>();

    public ElectionService(VoteCircuitService circuitService) {
        this.circuitService = circuitService;
        this.treeDepth = circuitService.getTreeDepth();
    }

    /** A trustee: label, secret key share and its proof of possession. */
    public record Trustee(String label, ElGamalSecretKey secretKey, VoteCircuitService.DleqProof keyProof) {
        public TrusteeInfo info() {
            return new TrusteeInfo(label, HexUtil.encodeHexString(secretKey.publicKey().encode()), keyProof.proofJson());
        }
    }

    /**
     * What anyone may see of a trustee, as the manifest publishes it: the key share's 32-byte
     * {@code elgamal-jubjub-v1} encoding (spec §7.3), hex, and the proof of possession of it.
     */
    public record TrusteeInfo(String label, String publicKeyHex, String keyProofJson) {}

    /**
     * The fixed parameters of a finalized election. The election id, voter root, election key and
     * deadline become the on-chain script parameters, so they never change once voting starts.
     */
    public record ElectionConfig(String name, BigInteger electionId, BigInteger voterRoot,
                                 NOfNKeyContext keyContext, List<TrusteeInfo> trustees,
                                 long votingDeadlineMillis, int voterCount) {
        /** The joint election key {@code PK = Σ PK_j}: a parameter of the ballot policy. */
        public ElGamalPublicKey electionKey() {
            return keyContext.jointKey();
        }
    }

    public synchronized void createElection(String name) {
        this.electionName = name;
        this.electionId = deriveElectionId(name, System.currentTimeMillis(), RANDOM);
        this.voterPublicKeys.clear();
        this.voterSecretKeys.clear();
        this.tree = null;
        this.config = null;
        this.trustees = generateTrustees();
        // Registered the way any verifier registers them: each key through its proof of possession.
        this.keyContext = keyContext(circuitService, trustees.stream().map(Trustee::info).toList());
        log.info("Election created: '{}' (id={}...), {} trustees, joint key {}", name,
                electionId.toString(16).substring(0, 12), trustees.size(), keyContext.jointKey());
    }

    /** Each trustee samples a key share and proves possession of it (ADR-0005 V9). */
    private List<Trustee> generateTrustees() {
        List<Trustee> out = new ArrayList<>();
        for (int j = 1; j <= trusteeCount; j++) {
            ElGamalSecretKey sk = ElGamalSecretKey.generate(RANDOM);
            // Key proof: R_dleq for the library's possession statement, X = G and D = P = PK_j.
            var proof = circuitService.proveDleq(sk.possessionStatement(), sk.secretScalar());
            out.add(new Trustee("trustee" + j, sk, proof));
        }
        return List.copyOf(out);
    }

    /**
     * Registers one trustee key from the manifest ({@code elgamal-jubjub-v1} §3.3): the encoding
     * must decode to a non-identity subgroup point, and the key proof must verify for exactly the
     * possession statement the library builds for it ({@code X = G}, {@code P = D = PK_j}).
     *
     * @throws IllegalArgumentException if the encoding is invalid or the proof is rejected
     */
    public static VerifiedKeyShare verifiedKeyShare(VoteCircuitService circuits, TrusteeInfo trustee) {
        return VerifiedKeyShare.verify(HexUtil.decodeHexString(trustee.publicKeyHex()), statement ->
                statement.kind() == DleqStatement.Kind.POSSESSION
                        && circuits.verifyDleq(trustee.keyProofJson(), statement.publicInputs()));
    }

    /**
     * The n-of-n key context rebuilt from the manifest's trustee keys and key proofs: every key
     * registered through {@link #verifiedKeyShare}, then {@link ElGamalPublicKey#aggregate}
     * (distinct shares, sum not the identity).
     *
     * @throws IllegalArgumentException if any key or proof is rejected, or aggregation refuses
     */
    public static NOfNKeyContext keyContext(VoteCircuitService circuits, List<TrusteeInfo> trustees) {
        List<VerifiedKeyShare> shares = new ArrayList<>(trustees.size());
        for (TrusteeInfo trustee : trustees) {
            shares.add(verifiedKeyShare(circuits, trustee));
        }
        return ElGamalPublicKey.aggregate(shares);
    }

    /** Register a voter by their secret key. Returns the voter's public key hash. */
    public synchronized BigInteger registerVoter(String voterLabel, BigInteger secretKey) {
        if (config != null) throw new IllegalStateException("Election already finalized");
        BigInteger publicKey = circuitService.computePublicKey(secretKey);
        voterPublicKeys.add(publicKey);
        voterSecretKeys.put(voterLabel, secretKey);
        log.info("Voter '{}' registered (pubKey={})", voterLabel, publicKey.toString(16).substring(0, 8));
        return publicKey;
    }

    /**
     * Finalize the election: build the eligibility tree and fix the voting deadline. From here on
     * the configuration is immutable and can be deployed on-chain.
     */
    public synchronized ElectionConfig finalizeElection() {
        if (config != null) throw new IllegalStateException("Election already finalized");
        int maxLeaves = 1 << treeDepth;
        if (voterPublicKeys.size() > maxLeaves) {
            throw new IllegalStateException("Too many voters (" + voterPublicKeys.size()
                    + ") for tree depth " + treeDepth + " (max " + maxLeaves + ")");
        }

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
                tree[level][i] = circuitService.merkleHash(tree[level - 1][2 * i], tree[level - 1][2 * i + 1]);
            }
        }

        long deadline = System.currentTimeMillis() + votingWindowSeconds * 1000;
        config = new ElectionConfig(electionName, electionId, tree[treeDepth][0], keyContext,
                trustees.stream().map(Trustee::info).toList(), deadline, voterPublicKeys.size());
        log.info("Election finalized: {} voters, root={}..., voting closes at {}",
                voterPublicKeys.size(), config.voterRoot().toString(16).substring(0, 8),
                Instant.ofEpochMilli(deadline));
        return config;
    }

    /** Merkle proof for a voter at a given index. */
    public MerkleProof getProof(int leafIndex) {
        if (tree == null) throw new IllegalStateException("Election not finalized");
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

    public int findVoterIndex(BigInteger publicKey) {
        for (int i = 0; i < voterPublicKeys.size(); i++) {
            if (voterPublicKeys.get(i).equals(publicKey)) return i;
        }
        return -1;
    }

    /**
     * {@code OS2IP(blake2b_256(tag ‖ UTF-8(name) ‖ I2OSP8(createdAt) ‖ nonce)) mod p}: distinct for
     * every election, even two with the same name, so nullifiers never carry over.
     */
    static BigInteger deriveElectionId(String name, long createdAtMillis, SecureRandom random) {
        byte[] nonce = new byte[16];
        random.nextBytes(nonce);
        var buf = new ByteArrayOutputStream();
        buf.writeBytes(ELECTION_ID_TAG);
        buf.writeBytes(name.getBytes(StandardCharsets.UTF_8));
        buf.writeBytes(ByteBuffer.allocate(Long.BYTES).putLong(createdAtMillis).array());
        buf.writeBytes(nonce);
        return new BigInteger(1, Blake2bUtil.blake2bHash256(buf.toByteArray())).mod(FR);
    }

    public BigInteger getSecretKey(String voterLabel) { return voterSecretKeys.get(voterLabel); }
    public BigInteger getElectionId() { return electionId; }
    public String getElectionName() { return electionName; }
    public BigInteger getVoterRoot() { return config == null ? BigInteger.ZERO : config.voterRoot(); }
    public int getVoterCount() { return voterPublicKeys.size(); }
    public boolean isFinalized() { return config != null; }
    public Set<String> getVoterLabels() { return voterSecretKeys.keySet(); }
    /** The joint election key, or {@code null} before {@link #createElection}. */
    public ElGamalPublicKey getElectionKey() { return keyContext == null ? null : keyContext.jointKey(); }
    public List<TrusteeInfo> getTrusteeInfo() { return trustees.stream().map(Trustee::info).toList(); }

    /** The finalized configuration, or {@code null} before {@link #finalizeElection()}. */
    public ElectionConfig getConfig() { return config; }

    /** The trustees with their secret keys; only the in-process trustees of the demo use this. */
    List<Trustee> trustees() { return trustees; }

    public record MerkleProof(BigInteger[] siblings, BigInteger[] pathBits, int leafIndex) {}
}
