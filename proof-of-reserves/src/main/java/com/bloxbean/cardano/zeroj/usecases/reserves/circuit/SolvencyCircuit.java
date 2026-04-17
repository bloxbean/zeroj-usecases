package com.bloxbean.cardano.zeroj.usecases.reserves.circuit;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalComparators;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalPoseidon;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * ZK circuit for Proof of Reserves (solvency proof).
 * <p>
 * Proves: "I know account balances [b0..bN] such that:
 * <ol>
 *   <li>Their Poseidon Merkle Sum Tree root matches the published liabilities root</li>
 *   <li>The sum of all balances equals the published total liabilities</li>
 *   <li>All balances are non-negative (64-bit range check)</li>
 *   <li>Declared reserves >= total liabilities</li>
 * </ol>
 * Without revealing any individual account balance."
 *
 * @param treeDepth depth of the Merkle Sum Tree (4 = 16 accounts)
 */
public class SolvencyCircuit implements CircuitSpec {

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    private final int treeDepth;

    public SolvencyCircuit(int treeDepth) {
        this.treeDepth = treeDepth;
    }

    @Override
    public void define(SignalBuilder c) {
        // Public inputs
        Signal totalReserves = c.publicInput("totalReserves");
        Signal liabilitiesRoot = c.publicInput("liabilitiesRoot");
        Signal totalLiabilities = c.publicInput("totalLiabilities");

        // Public output
        Signal isSolvent = c.publicOutput("isSolvent");

        // Build Merkle Sum Tree in-circuit from secret account data
        int numLeaves = 1 << treeDepth;
        Signal computedSum = c.constant(0);
        Signal[] leafHashes = new Signal[numLeaves];

        for (int i = 0; i < numLeaves; i++) {
            Signal accountId = c.privateInput("accountId_" + i);
            Signal balance = c.privateInput("balance_" + i);

            // Range check: balance must fit in 64 bits (non-negative)
            // This prevents the exchange from using negative balances to cheat
            balance.assertInRange(64);

            // Leaf hash = Poseidon(accountId, balance)
            leafHashes[i] = SignalPoseidon.hash(c, POSEIDON, accountId, balance);

            // Accumulate total
            computedSum = computedSum.add(balance);
        }

        // Build Merkle tree bottom-up (standard Poseidon binary tree)
        Signal[] currentLevel = leafHashes;
        for (int level = 0; level < treeDepth; level++) {
            Signal[] nextLevel = new Signal[currentLevel.length / 2];
            for (int i = 0; i < nextLevel.length; i++) {
                nextLevel[i] = SignalPoseidon.hash(c, POSEIDON, currentLevel[2 * i], currentLevel[2 * i + 1]);
            }
            currentLevel = nextLevel;
        }

        // Root must match published root
        c.assertEqual(currentLevel[0], c.signal("liabilitiesRoot"));

        // Computed sum must match published total
        c.assertEqual(computedSum, c.signal("totalLiabilities"));

        // Solvency: reserves >= liabilities (64-bit comparison)
        Signal solvent = SignalComparators.greaterOrEqual(c,
                c.signal("totalReserves"), c.signal("totalLiabilities"), 64);
        c.assertEqual(isSolvent, solvent);
    }

    public static CircuitBuilder build(int treeDepth) {
        var builder = CircuitBuilder.create("solvency-proof")
                .publicVar("totalReserves")
                .publicVar("liabilitiesRoot")
                .publicVar("totalLiabilities")
                .publicVar("isSolvent");

        int numLeaves = 1 << treeDepth;
        for (int i = 0; i < numLeaves; i++) {
            builder = builder
                    .secretVar("accountId_" + i)
                    .secretVar("balance_" + i);
        }

        return builder.defineSignals(new SolvencyCircuit(treeDepth));
    }
}
