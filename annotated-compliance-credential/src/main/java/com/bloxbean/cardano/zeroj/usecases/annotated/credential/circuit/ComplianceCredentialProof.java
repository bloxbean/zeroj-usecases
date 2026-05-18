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
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMiMC;

@ZKCircuit(name = "annotated-compliance-credential", version = 1)
public class ComplianceCredentialProof {

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
        var computedCommitment = ZkMiMC.hash(
                zk,
                ZkMiMC.hash(
                        zk,
                        ZkMiMC.hash(zk, age.asField(), countryCode.asField()),
                        notSanctioned.asField()),
                credentialSalt);

        return age.gte(minimumAge)
                .and(countryCode.isEqual(requiredCountryCode))
                .and(notSanctioned)
                .and(computedCommitment.isEqual(credentialCommitment));
    }
}
