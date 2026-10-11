package com.bloxbean.cardano.zeroj.usecases.nft.service;

import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.address.AddressType;
import com.bloxbean.cardano.client.address.Credential;
import com.bloxbean.cardano.client.address.CredentialType;
import com.bloxbean.cardano.client.cip.cip30.CIP30DataSigner;
import com.bloxbean.cardano.client.cip.cip30.DataSignature;
import com.bloxbean.cardano.client.cip.cip8.COSESign1;
import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.util.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The event's indexer: builds the Poseidon Merkle snapshot of NFT holders for one event
 * (ADR-0009 D2).
 *
 * <p>Each leaf is {@code Poseidon(Poseidon(s, 0), t)}. Since circuit version 2 the nullifier
 * depends on the holder's secret, so the number of uses per event is bounded only by the number of
 * leaves. Registration therefore admits at most one leaf per authenticated holding:
 * <ul>
 *   <li>refuses a second leaf for a token already in the snapshot;</li>
 *   <li>requires a CIP-8 {@code COSE_Sign1} signature over
 *       {@code (contextId, t, leaf)} ({@link NftScheme#registrationPayload}) by the payment key of the
 *       address that, according to the chain indexer, holds the token;</li>
 *   <li>freezes when the snapshot is built. One snapshot per event; a new event is a new run.</li>
 * </ul>
 */
@Service
public class SnapshotService {

    private static final Logger log = LoggerFactory.getLogger(SnapshotService.class);

    private final HolderLookup holders;
    private final int treeDepth;
    private final String contextLabel;
    private final BigInteger contextId;

    // Registrations, in order: token field value -> leaf
    private final Map<BigInteger, BigInteger> leavesByToken = new LinkedHashMap<>();
    private final List<BigInteger> leaves = new ArrayList<>();
    private String collectionPolicyId;

    // Snapshot state
    private BigInteger currentRoot = BigInteger.ZERO;
    private BigInteger[][] tree; // tree[level][index]
    private boolean frozen;

    public SnapshotService(HolderLookup holders,
                           @Value("${zk.tree-depth}") int treeDepth,
                           @Value("${zk.default-context}") String contextLabel) {
        this.holders = holders;
        this.treeDepth = treeDepth;
        this.contextLabel = contextLabel;
        this.contextId = NftScheme.contextId(contextLabel);
    }

    /**
     * Registers {@code leaf} for the NFT {@code policyId.assetName}, authenticated by the token's
     * on-chain holder.
     *
     * @param policyId  the collection's policy id (hex); every registration of an event uses one
     * @param assetName the NFT's asset name (1–31 bytes)
     * @param leaf      {@code Poseidon(Poseidon(s, 0), t)}
     * @param signature the holder's CIP-8 signature over {@code (contextId, t, leaf)}
     * @return the number of registered holders
     * @throws IllegalStateException    when the snapshot is frozen
     * @throws IllegalArgumentException when the registration is refused
     */
    public synchronized int registerHolder(String policyId, byte[] assetName, BigInteger leaf,
                                           DataSignature signature) {
        if (frozen) {
            throw new IllegalStateException("registration is closed: the snapshot for this event is built");
        }
        if (policyId == null || !policyId.matches("[0-9a-f]{56}")) {
            throw new IllegalArgumentException("policy id must be 28 bytes of lowercase hex");
        }
        if (collectionPolicyId != null && !collectionPolicyId.equals(policyId)) {
            throw new IllegalArgumentException("the snapshot covers collection " + collectionPolicyId);
        }
        BigInteger token = NftScheme.tokenField(assetName);
        if (leavesByToken.containsKey(token)) {
            throw new IllegalArgumentException("token " + displayName(assetName)
                    + " is already in the snapshot; one registration per token");
        }
        NftScheme.i2osp32(leaf); // canonical field element
        if (leaves.size() >= (1 << treeDepth)) {
            throw new IllegalStateException("the snapshot is full (" + (1 << treeDepth) + " leaves)");
        }
        String unit = policyId + HexUtil.encodeHexString(assetName);
        verifyHolderSignature(signature, NftScheme.registrationPayload(contextId, token, leaf), unit);

        collectionPolicyId = policyId;
        leavesByToken.put(token, leaf);
        leaves.add(leaf);
        log.info("Registered holder of {} (total holders: {})", displayName(assetName), leaves.size());
        return leaves.size();
    }

    /**
     * Checks the CIP-8 registration signature: exact payload, valid Ed25519 signature, a key
     * (not script) payment credential equal to the signing key's hash, and an address that holds
     * exactly one unit of the token on-chain. The leaf hides {@code t}, so this cannot check that
     * the leaf commits to the token it is registered under; it bounds leaves by authenticated
     * holdings.
     */
    private void verifyHolderSignature(DataSignature signature, byte[] expectedPayload, String unit) {
        if (signature == null) {
            throw new IllegalArgumentException("registration is not signed");
        }
        Address signer;
        try {
            COSESign1 sign1 = signature.coseSign1();
            if (!Arrays.equals(sign1.payload(), expectedPayload)) {
                throw new IllegalArgumentException("the signed payload is not (contextId, token, leaf) of this registration");
            }
            if (!CIP30DataSigner.INSTANCE.verify(signature)) {
                throw new IllegalArgumentException("the CIP-8 signature does not verify for its address");
            }
            byte[] addressBytes = sign1.headers()._protected().getAsHeaderMap().otherHeaderAsBytes("address");
            signer = new Address(addressBytes);
            byte[] publicKey = signature.coseKey().otherHeaderAsBytes(-2);
            AddressType type = signer.getAddressType();
            Optional<Credential> payment = signer.getPaymentCredential();
            if ((type != AddressType.Base && type != AddressType.Enterprise) || payment.isEmpty()
                    || payment.get().getType() != CredentialType.Key
                    || !Arrays.equals(payment.get().getBytes(), Blake2bUtil.blake2bHash224(publicKey))) {
                throw new IllegalArgumentException("the signing key is not the payment key of the signed address");
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("malformed CIP-8 signature", e);
        }

        BigInteger held;
        try {
            held = holders.quantityAt(signer.toBech32(), unit);
        } catch (Exception e) {
            throw new IllegalStateException("cannot look up the token's holder; registration refused", e);
        }
        if (held.compareTo(BigInteger.ONE) != 0) {
            throw new IllegalArgumentException("the signing address does not hold the token on-chain");
        }
    }

    /**
     * Builds the Merkle tree from all registered holders and freezes registration.
     *
     * @return the snapshot root
     */
    public synchronized BigInteger buildSnapshot() {
        if (frozen) {
            throw new IllegalStateException("the snapshot for this event is already built");
        }
        if (leaves.isEmpty()) {
            throw new IllegalStateException("no holders registered");
        }
        int maxLeaves = 1 << treeDepth;
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
                tree[level][i] = NftScheme.poseidon(tree[level - 1][2 * i], tree[level - 1][2 * i + 1]);
            }
        }

        currentRoot = tree[treeDepth][0];
        frozen = true;
        log.info("Snapshot built and registration frozen: root={}", currentRoot.toString(16).substring(0, 8));
        return currentRoot;
    }

    /**
     * Get the Merkle proof (siblings + path bits) for a leaf at a given index.
     */
    public synchronized MerkleProof getProof(int leafIndex) {
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
     * The index of {@code leaf} in the snapshot, or -1 if it is not there.
     */
    public synchronized int findLeafIndex(BigInteger leaf) {
        return leaves.indexOf(leaf);
    }

    public synchronized BigInteger getCurrentRoot() {
        return currentRoot;
    }

    public synchronized boolean isFrozen() {
        return frozen;
    }

    public synchronized int getHolderCount() {
        return leaves.size();
    }

    public synchronized String getCollectionPolicyId() {
        return collectionPolicyId;
    }

    /** The event's label, e.g. {@code nft-demo-v1}. */
    public String getContextLabel() {
        return contextLabel;
    }

    /** The event's context as a field element ({@link NftScheme#contextId}). */
    public BigInteger getContextId() {
        return contextId;
    }

    public int getTreeDepth() {
        return treeDepth;
    }

    private static String displayName(byte[] assetName) {
        return new String(assetName, StandardCharsets.UTF_8);
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
