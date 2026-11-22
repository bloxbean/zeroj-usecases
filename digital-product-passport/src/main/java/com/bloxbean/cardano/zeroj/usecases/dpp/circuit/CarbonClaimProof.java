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
 * The carbon claim of a product passport (ADR-0009 D1): the auditor committed to the product's
 * carbon footprint in kg under {@link #SCHEMA}; the manufacturer proves
 * {@code carbon_kg ≤ threshold} and reveals nothing else.
 *
 * <p>Public, in order: {@code σ, u, v, threshold}. {@code σ} is constrained to the schema's digest
 * by {@code bindSchema}, and {@code commit} range-constrains {@code carbon_kg} to 16 bits. This is
 * the claim the {@code DppPassport} policy verifies on-chain.
 */
@ZKCircuit(name = "dpp-carbon-claim", version = 1)
public class CarbonClaimProof {

    public static final PedersenVectorSchema SCHEMA = PedersenVectorSchema.of("zeroj.demo.dpp.carbon", 1,
            List.of(new Entry("carbon_kg", 16)));

    @Prove
    void prove(ZkContext zk,
               @Public ZkField schemaDigest,
               @Public ZkField u,
               @Public ZkField v,
               @Public @UInt(bits = 16) ZkUInt threshold,
               @Secret @UInt(bits = 16) ZkUInt carbonKg,
               @Secret @UInt(bits = 252) ZkUInt blinding) {
        var binding = ZkPedersenVector.bindSchema(zk, SCHEMA, schemaDigest);
        ZkPedersenVector.commit(zk, binding, List.of(carbonKg), blinding).assertAffineEquals(zk, u, v);
        carbonKg.lte(threshold).assertTrue();
    }
}
