package com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.circuit;

import org.zeroj.circuit.annotation.CircuitParam;
import org.zeroj.circuit.annotation.FixedSize;
import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.zk.ZkPedersenCommitment;

/**
 * Solvency with hidden liabilities (ADR-0006 demo C, after Provisions).
 *
 * <p>Public, in order: {@code R, u_1..u_N, v_1..v_N}: the attested reserve and the affine
 * {@code pedersen-jubjub-v1} commitment of each customer's balance. The prover knows every opening,
 * with 64-bit balances and 252-bit blindings, and proves {@code Σ b_i ≤ R}. Neither the balances
 * nor their total are revealed. With {@code N·2^64 ≪ p} the sum cannot wrap.
 */
@ZKCircuit(
        name = "hidden-liability-solvency",
        nameTemplate = "hidden-liability-solvency-n{customers}",
        version = 1)
public class HiddenLiabilitySolvencyProof {

    private final int customers;

    public HiddenLiabilitySolvencyProof(@CircuitParam("customers") int customers) {
        if (customers < 1 || customers > 64) {
            throw new IllegalArgumentException("customers must be in [1, 64]");
        }
        this.customers = customers;
    }

    @Prove
    void prove(ZkContext zk,
               @Public @UInt(bits = 64) ZkUInt reserves,
               @Public @FixedSize(param = "customers") ZkArray<ZkField> liabilityU,
               @Public @FixedSize(param = "customers") ZkArray<ZkField> liabilityV,
               @Secret @UInt(bits = 64) @FixedSize(param = "customers") ZkArray<ZkUInt> balances,
               @Secret @UInt(bits = 252) @FixedSize(param = "customers") ZkArray<ZkUInt> blindings) {
        ZkUInt total = null;
        for (int i = 0; i < customers; i++) {
            ZkPedersenCommitment.commit(zk, balances.get(i), blindings.get(i))
                    .assertAffineEquals(zk, liabilityU.get(i), liabilityV.get(i));
            total = total == null ? balances.get(i) : total.add(balances.get(i));
        }
        total.lte(reserves).assertTrue();
    }
}
