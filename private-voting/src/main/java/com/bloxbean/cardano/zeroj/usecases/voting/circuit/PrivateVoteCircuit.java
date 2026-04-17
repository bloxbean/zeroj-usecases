package com.bloxbean.cardano.zeroj.usecases.voting.circuit;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMerkle;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalPoseidon;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * ZK circuit for private voting on Cardano.
 *
 * <p>Proves: "I am an eligible voter AND my vote is valid (0 or 1)"
 * without revealing who I am or how I voted.</p>
 *
 * <h3>Signals</h3>
 * <ul>
 *   <li><b>Secret:</b> vote (0=NO, 1=YES), secretKey, Merkle siblings + pathBits</li>
 *   <li><b>Public:</b> electionId, voterRoot</li>
 *   <li><b>Output:</b> nullifier (anti-double-vote), commitment (vote hash)</li>
 * </ul>
 *
 * @param treeDepth Merkle tree depth (10 = 1024 voters, 14 = 16K)
 */
public class PrivateVoteCircuit implements CircuitSpec {

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    private final int treeDepth;

    public PrivateVoteCircuit(int treeDepth) {
        this.treeDepth = treeDepth;
    }

    @Override
    public void define(SignalBuilder c) {
        // Secret inputs
        Signal vote = c.privateInput("vote");
        Signal secretKey = c.privateInput("secretKey");

        Signal[] siblings = new Signal[treeDepth];
        Signal[] pathBits = new Signal[treeDepth];
        for (int i = 0; i < treeDepth; i++) {
            siblings[i] = c.privateInput("sibling_" + i);
            pathBits[i] = c.privateInput("pathBit_" + i);
        }

        // Public inputs
        Signal electionId = c.publicInput("electionId");
        Signal voterRoot = c.publicInput("voterRoot");

        // Public outputs
        Signal nullifier = c.publicOutput("nullifier");
        Signal commitment = c.publicOutput("commitment");

        // 1. Vote must be 0 or 1
        vote.assertBoolean();

        // 2. Nullifier = Poseidon(secretKey, electionId) — deterministic per voter+election
        c.assertEqual(nullifier, SignalPoseidon.hash(c, POSEIDON, secretKey, c.signal("electionId")));

        // 3. Commitment = Poseidon(vote, nullifier) — binds vote to nullifier
        c.assertEqual(commitment, SignalPoseidon.hash(c, POSEIDON, vote, nullifier));

        // 4. Derive public key from secret key
        Signal publicKey = SignalPoseidon.hash(c, POSEIDON, secretKey, c.constant(0));

        // 5. Verify voter is in the eligible voter Merkle tree
        SignalMerkle.verifyProof(c, publicKey, c.signal("voterRoot"),
                siblings, pathBits, (sb, a, b) -> SignalPoseidon.hash(sb, POSEIDON, a, b));
    }

    public static CircuitBuilder build(int treeDepth) {
        var builder = CircuitBuilder.create("private-vote")
                .publicVar("electionId")
                .publicVar("voterRoot")
                .publicVar("nullifier")
                .publicVar("commitment")
                .secretVar("vote")
                .secretVar("secretKey");

        for (int i = 0; i < treeDepth; i++) {
            builder = builder.secretVar("sibling_" + i).secretVar("pathBit_" + i);
        }

        return builder.defineSignals(new PrivateVoteCircuit(treeDepth));
    }
}
