package com.bloxbean.cardano.zeroj.usecases.pedersen.credential.circuit;

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
 * A credit check against a committed profile (ADR-0006 demo B).
 *
 * <p>The bureau committed to four attributes in one {@code pedersen-jubjub-vector-v1} commitment
 * under {@link #SCHEMA}. The holder proves {@code income ≥ minIncome} and
 * {@code creditScore ≥ minScore} and reveals nothing else: not the income, not the score, and
 * nothing about {@code birthYear} or {@code country}, which are committed but not used.
 *
 * <p>Public, in order: {@code σ, u, v, minIncome, minScore}. {@code σ} is the schema digest,
 * constrained to {@link #SCHEMA} by {@code bindSchema}, so a commitment issued under any other
 * schema cannot be presented as a credit profile.
 */
@ZKCircuit(name = "credit-profile-check", version = 1)
public class CreditProfileProof {

    public static final PedersenVectorSchema SCHEMA = PedersenVectorSchema.of("zeroj.demo.credit-profile", 1,
            List.of(new Entry("income", 64), new Entry("credit_score", 16),
                    new Entry("birth_year", 16), new Entry("country", 16)));

    @Prove
    void prove(ZkContext zk,
               @Public ZkField schemaDigest,
               @Public ZkField u,
               @Public ZkField v,
               @Public @UInt(bits = 64) ZkUInt minIncome,
               @Public @UInt(bits = 16) ZkUInt minScore,
               @Secret @UInt(bits = 64) ZkUInt income,
               @Secret @UInt(bits = 16) ZkUInt creditScore,
               @Secret @UInt(bits = 16) ZkUInt birthYear,
               @Secret @UInt(bits = 16) ZkUInt country,
               @Secret @UInt(bits = 252) ZkUInt blinding) {
        var binding = ZkPedersenVector.bindSchema(zk, SCHEMA, schemaDigest);
        ZkPedersenVector.commit(zk, binding, List.of(income, creditScore, birthYear, country), blinding)
                .assertAffineEquals(zk, u, v);
        income.gte(minIncome).assertTrue();
        creditScore.gte(minScore).assertTrue();
    }
}
