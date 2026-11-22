package com.bloxbean.cardano.zeroj.usecases.dpp.circuit;

import org.zeroj.circuit.annotation.FixedSize;
import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema.Entry;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.lib.zk.ZkMerkle;
import org.zeroj.circuit.lib.zk.ZkPedersenVector;

import java.util.List;

/**
 * The origin claim of a product passport (ADR-0009 D1): the auditor committed to the country of
 * manufacture (ISO 3166-1 numeric) under {@link #SCHEMA}; the manufacturer proves that the
 * committed country is a leaf of an approved-set tree, without saying which.
 *
 * <p>Public, in order: {@code σ, u, v, countryRoot}. The tree is a depth-{@value #DEPTH} Poseidon
 * Merkle tree over the raw country codes, padded with the sentinel {@code 2^16}
 * ({@link com.bloxbean.cardano.zeroj.usecases.dpp.passport.ApprovedSet}). {@code commit} bounds the
 * committed country to 16 bits, so it can never equal the padding.
 */
@ZKCircuit(name = "dpp-origin-claim", version = 1)
public class OriginClaimProof {

    public static final int DEPTH = 5;

    public static final PedersenVectorSchema SCHEMA = PedersenVectorSchema.of("zeroj.demo.dpp.origin", 1,
            List.of(new Entry("country", 16)));

    @Prove
    void prove(ZkContext zk,
               @Public ZkField schemaDigest,
               @Public ZkField u,
               @Public ZkField v,
               @Public ZkField countryRoot,
               @Secret @UInt(bits = 16) ZkUInt country,
               @Secret @UInt(bits = 252) ZkUInt blinding,
               @Secret @FixedSize(DEPTH) ZkArray<ZkField> siblings,
               @Secret @FixedSize(DEPTH) ZkArray<ZkBool> pathBits) {
        var binding = ZkPedersenVector.bindSchema(zk, SCHEMA, schemaDigest);
        ZkPedersenVector.commit(zk, binding, List.of(country), blinding).assertAffineEquals(zk, u, v);
        ZkMerkle.verifyProofPoseidon(zk, PoseidonParamsBLS12_381T3.INSTANCE, country.asField(), countryRoot,
                siblings, pathBits);
    }
}
