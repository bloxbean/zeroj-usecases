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

import java.util.ArrayList;
import java.util.List;

/**
 * The inspection claim of a product passport (ADR-0009 D1): the auditor committed to the
 * product's {@value #CHECKPOINTS} passed inspections, each an inspector id and a time, under
 * {@link #SCHEMA}; the manufacturer proves that every inspector is in the approved set and that
 * the times strictly increase, without revealing inspectors or times.
 *
 * <p>Public, in order: {@code σ, u, v, inspectorRoot}. The tree is a depth-{@value #DEPTH}
 * Poseidon Merkle tree over the raw 8-bit inspector ids, padded with the sentinel {@code 2^8}.
 * An inspector may appear at more than one checkpoint. The auditor commits only passed
 * inspections, so the schema has no {@code passed} entry.
 */
@ZKCircuit(name = "dpp-inspection-claim", version = 1)
public class InspectionClaimProof {

    public static final int CHECKPOINTS = 3;
    public static final int DEPTH = 3;

    public static final PedersenVectorSchema SCHEMA = PedersenVectorSchema.of("zeroj.demo.dpp.inspections", 1,
            List.of(new Entry("inspector_0", 8), new Entry("time_0", 32),
                    new Entry("inspector_1", 8), new Entry("time_1", 32),
                    new Entry("inspector_2", 8), new Entry("time_2", 32)));

    @Prove
    void prove(ZkContext zk,
               @Public ZkField schemaDigest,
               @Public ZkField u,
               @Public ZkField v,
               @Public ZkField inspectorRoot,
               @Secret @UInt(bits = 8) @FixedSize(CHECKPOINTS) ZkArray<ZkUInt> inspectors,
               @Secret @UInt(bits = 32) @FixedSize(CHECKPOINTS) ZkArray<ZkUInt> times,
               @Secret @UInt(bits = 252) ZkUInt blinding,
               @Secret @FixedSize(value = CHECKPOINTS, inner = DEPTH) ZkArray<ZkArray<ZkField>> siblings,
               @Secret @FixedSize(value = CHECKPOINTS, inner = DEPTH) ZkArray<ZkArray<ZkBool>> pathBits) {
        var binding = ZkPedersenVector.bindSchema(zk, SCHEMA, schemaDigest);
        List<ZkUInt> entries = new ArrayList<>();
        for (int i = 0; i < CHECKPOINTS; i++) {
            entries.add(inspectors.get(i));
            entries.add(times.get(i));
        }
        ZkPedersenVector.commit(zk, binding, entries, blinding).assertAffineEquals(zk, u, v);
        for (int i = 0; i < CHECKPOINTS; i++) {
            ZkMerkle.verifyProofPoseidon(zk, PoseidonParamsBLS12_381T3.INSTANCE, inspectors.get(i).asField(),
                    inspectorRoot, siblings.get(i), pathBits.get(i));
            if (i > 0) {
                times.get(i - 1).lt(times.get(i)).assertTrue();
            }
        }
    }
}
