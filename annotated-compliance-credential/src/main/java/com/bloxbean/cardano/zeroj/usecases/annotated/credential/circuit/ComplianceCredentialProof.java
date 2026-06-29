package com.bloxbean.cardano.zeroj.usecases.annotated.credential.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.UInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPoseidonN;

/**
 * Compliance-credential circuit (v1) — demonstrates the commitment + predicate pattern.
 *
 * <p><b>Security note:</b> this circuit is <em>not sound on its own</em>. The
 * {@code credentialCommitment} is a public input chosen by the prover, and nothing forces it
 * to be a commitment a trusted issuer actually created. An attacker can pick any compliant
 * attributes, compute the matching Poseidon commitment themselves, and produce a valid proof.
 * It proves internal consistency, not legitimacy. See {@link ComplianceCredentialProofV2} for
 * the hardened version that roots trust in an in-circuit issuer EdDSA-Jubjub signature.
 */
@ZKCircuit(name = "annotated-compliance-credential", version = 1)
public class ComplianceCredentialProof {
    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Secret @UInt(bits = 8) ZkUInt age,
            @Secret @UInt(bits = 16) ZkUInt countryCode,
            @Secret ZkBool notSanctioned,
            @Secret ZkField credentialSalt,
            @Public @UInt(bits = 8) ZkUInt minimumAge,
            @Public @UInt(bits = 16) ZkUInt requiredCountryCode,
            @Public ZkField credentialCommitment) {
        var computedCommitment = ZkPoseidonN.hash(
                zk,
                POSEIDON,
                age.asField(),
                countryCode.asField(),
                notSanctioned.asField(),
                credentialSalt);

        return age.gte(minimumAge)
                .and(countryCode.isEqual(requiredCountryCode))
                .and(notSanctioned)
                .and(computedCommitment.isEqual(credentialCommitment));
    }
}
