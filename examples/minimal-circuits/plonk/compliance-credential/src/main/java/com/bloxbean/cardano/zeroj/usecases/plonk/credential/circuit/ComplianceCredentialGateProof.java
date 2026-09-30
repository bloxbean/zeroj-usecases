package com.bloxbean.cardano.zeroj.usecases.plonk.credential.circuit;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;

@ZKCircuit(name = "compliance-credential-plonk", version = 1)
public class ComplianceCredentialGateProof {
    private static final int ATTRIBUTE_BITS = 8;

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Public ZkField credentialCommitment,
            @Public ZkField minimumAge,
            @Public ZkField requiredJurisdiction,
            @Secret @UInt(bits = ATTRIBUTE_BITS) ZkUInt age,
            @Secret @UInt(bits = ATTRIBUTE_BITS) ZkUInt ageSurplus,
            @Secret @UInt(bits = ATTRIBUTE_BITS) ZkUInt jurisdiction,
            @Secret ZkBool notSanctioned,
            @Secret ZkField credentialSalt) {
        var computedCommitment = age.asField().mul(zk.constant(17))
                .add(jurisdiction.asField().mul(zk.constant(19)))
                .add(notSanctioned.asField().mul(zk.constant(23)))
                .add(credentialSalt.mul(zk.constant(29)));

        var commitmentMatches = computedCommitment.isEqual(credentialCommitment);
        var ageMeetsPolicy = minimumAge.add(ageSurplus.asField()).isEqual(age.asField());
        var jurisdictionMatches = jurisdiction.asField().isEqual(requiredJurisdiction);

        return commitmentMatches
                .and(ageMeetsPolicy)
                .and(jurisdictionMatches)
                .and(notSanctioned);
    }
}
