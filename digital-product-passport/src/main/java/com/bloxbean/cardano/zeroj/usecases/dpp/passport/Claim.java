package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.zeroj.usecases.dpp.circuit.CarbonClaimProof;
import com.bloxbean.cardano.zeroj.usecases.dpp.circuit.InspectionClaimProof;
import com.bloxbean.cardano.zeroj.usecases.dpp.circuit.OriginClaimProof;
import com.bloxbean.cardano.zeroj.usecases.dpp.circuit.RecycledClaimProof;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema;

/**
 * The claims an auditor can attest in a passport (ADR-0009 D1), each a
 * {@code pedersen-jubjub-vector-v1} commitment under its own schema. The id is the {@code claim}
 * field of a passport datum entry; the schemas (labels and widths) are normative.
 */
public enum Claim {
    CARBON(0, "carbon", CarbonClaimProof.SCHEMA),
    RECYCLED(1, "recycled_content", RecycledClaimProof.SCHEMA),
    ORIGIN(2, "origin", OriginClaimProof.SCHEMA),
    INSPECTIONS(3, "inspections", InspectionClaimProof.SCHEMA);

    private final int id;
    private final String label;
    private final PedersenVectorSchema schema;

    Claim(int id, String label, PedersenVectorSchema schema) {
        this.id = id;
        this.label = label;
        this.schema = schema;
    }

    public int id() { return id; }

    public String label() { return label; }

    public PedersenVectorSchema schema() { return schema; }

    /** {@code σ} as the datum carries it: {@code I2OSP(digest, 32)}. */
    public byte[] sigma() {
        return Fields.i2osp(schema.digest(), 32);
    }

    public static Claim of(int id) {
        for (Claim c : values()) {
            if (c.id == id) return c;
        }
        throw new IllegalArgumentException("unknown claim id " + id);
    }
}
