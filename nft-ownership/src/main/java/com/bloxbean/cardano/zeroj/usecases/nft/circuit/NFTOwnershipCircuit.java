package com.bloxbean.cardano.zeroj.usecases.nft.circuit;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMerkle;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalPoseidon;

/**
 * ZK circuit for proving NFT ownership without revealing the holder's wallet.
 *
 * <p>Proves: "I know a secret key and token name such that their hash is in the
 * ownership Merkle tree — meaning I own an NFT from this collection."</p>
 *
 * <p>The proof reveals NOTHING about which wallet, which specific NFT, or any
 * other token holdings. The nullifier prevents reuse (one proof per context).</p>
 *
 * <h3>Signals</h3>
 * <ul>
 *   <li><b>Secret:</b> secretKey (wallet identifier), tokenName (which NFT)</li>
 *   <li><b>Secret:</b> Merkle siblings and path bits (position in tree)</li>
 *   <li><b>Public:</b> snapshotRoot (on-chain Merkle root of all holders)</li>
 *   <li><b>Public:</b> contextId (event/airdrop/vote ID — for nullifier)</li>
 *   <li><b>Output:</b> isOwner (boolean), nullifier (anti-replay token)</li>
 * </ul>
 *
 * @param treeDepth Merkle tree depth (e.g., 10 for 1024 holders, 20 for 1M)
 */
public class NFTOwnershipCircuit implements CircuitSpec {

    private final int treeDepth;

    public NFTOwnershipCircuit(int treeDepth) {
        if (treeDepth < 1 || treeDepth > 32)
            throw new IllegalArgumentException("treeDepth must be in [1, 32]");
        this.treeDepth = treeDepth;
    }

    @Override
    public void define(SignalBuilder c) {
        // Secret inputs — only the NFT holder knows these
        Signal secretKey = c.privateInput("secretKey");
        Signal tokenName = c.privateInput("tokenName");

        // Merkle proof (secret — hides position in tree)
        Signal[] siblings = new Signal[treeDepth];
        Signal[] pathBits = new Signal[treeDepth];
        for (int i = 0; i < treeDepth; i++) {
            siblings[i] = c.privateInput("sibling_" + i);
            pathBits[i] = c.privateInput("pathBit_" + i);
        }

        // Public inputs — visible to the verifier
        Signal snapshotRoot = c.publicInput("snapshotRoot");
        Signal contextId    = c.publicInput("contextId");

        // Public outputs
        Signal isOwner   = c.publicOutput("isOwner");
        Signal nullifier = c.publicOutput("nullifier");

        // 1. Derive owner identifier from secret key
        //    ownerHash = Poseidon(secretKey, 0) — deterministic, one-way
        Signal ownerHash = SignalPoseidon.hash(c, secretKey, c.constant(0));

        // 2. Compute leaf: Poseidon(ownerHash, tokenName)
        //    This is what the snapshot indexer computes for each holder
        Signal leaf = SignalPoseidon.hash(c, ownerHash, tokenName);

        // 3. Verify Merkle inclusion: leaf is in the tree with the published root
        SignalMerkle.verifyProof(c, leaf, c.signal("snapshotRoot"),
                siblings, pathBits, SignalPoseidon::hash);

        // 4. Compute nullifier: Poseidon(tokenName, contextId)
        //    Same NFT + same context = same nullifier (prevents double use)
        //    Different context = different nullifier (allows reuse across events)
        c.assertEqual(nullifier, SignalPoseidon.hash(c, tokenName, c.signal("contextId")));

        // 5. All constraints satisfied = owner proven
        c.assertEqual(isOwner, c.constant(1));
    }

    /**
     * Build the circuit with the given tree depth.
     *
     * @param treeDepth Merkle tree depth (10 = 1024 holders, 20 = 1M holders)
     */
    public static CircuitBuilder build(int treeDepth) {
        var builder = CircuitBuilder.create("nft-ownership")
                .publicVar("snapshotRoot")
                .publicVar("contextId")
                .publicVar("isOwner")
                .publicVar("nullifier")
                .secretVar("secretKey")
                .secretVar("tokenName");

        for (int i = 0; i < treeDepth; i++) {
            builder = builder.secretVar("sibling_" + i).secretVar("pathBit_" + i);
        }

        return builder.defineSignals(new NFTOwnershipCircuit(treeDepth));
    }
}
