package com.bloxbean.cardano.zeroj.usecases.dpp.circuit;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema.Entry;
import org.zeroj.circuit.lib.zk.ZkPedersenVector;

import java.util.List;

/**
 * The recycled-content claim of a product passport (ADR-0009 D1): the auditor committed to the
 * recycled content in percent under {@link #SCHEMA}; the manufacturer proves
 * {@code recycled_pct ≥ threshold}.
 *
 * <p>Public, in order: {@code σ, u, v, threshold}. Proved and verified off-chain, against the
 * commitment in the passport datum.
 */
@ZKCircuit(name = "dpp-recycled-claim", version = 1)
public class RecycledClaimProof {

    public static final PedersenVectorSchema SCHEMA = PedersenVectorSchema.of("zeroj.demo.dpp.recycled", 1,
            List.of(new Entry("recycled_pct", 16)));

    @Prove
    void prove(ZkContext zk,
               @Public ZkField schemaDigest,
               @Public ZkField u,
               @Public ZkField v,
               @Public @UInt(bits = 16) ZkUInt threshold,
               @Secret @UInt(bits = 16) ZkUInt recycledPct,
               @Secret @UInt(bits = 252) ZkUInt blinding) {
        var binding = ZkPedersenVector.bindSchema(zk, SCHEMA, schemaDigest);
        ZkPedersenVector.commit(zk, binding, List.of(recycledPct), blinding).assertAffineEquals(zk, u, v);
        recycledPct.gte(threshold).assertTrue();
    }
}
