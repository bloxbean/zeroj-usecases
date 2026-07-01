package com.bloxbean.cardano.zeroj.usecases.selective.circuit;

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
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkEdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkJubjubPoint;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPoseidonN;

@ZKCircuit(name = "senior-doctor", version = 1)
public class SeniorDoctorProof {

    public static final int MIN_AGE = 30;
    private static final long DOCTOR_ROLE_ID = 1001L;
    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Public ZkField pkU,
            @Public ZkField pkV,
            @Public @UInt(bits = 16) ZkUInt currentYear,
            @Public ZkBool eligible,
            @Secret @UInt(bits = 16) ZkUInt dobYear,
            @Secret @UInt(bits = 16) ZkUInt country,
            @Secret ZkField roleId,
            @Secret @UInt(bits = 8) ZkUInt salaryBracket,
            @Secret ZkField nameHash,
            @Secret ZkField sigRU,
            @Secret ZkField sigRV,
            @Secret @UInt(bits = 252) ZkUInt sigS,
            @Secret @UInt(bits = 252) ZkUInt kModL,
            @Secret @UInt(bits = 4) ZkUInt kQuotient) {

        var claimsMsg = ZkPoseidonN.hash(
                zk,
                POSEIDON,
                dobYear.asField(),
                country.asField(),
                roleId,
                salaryBracket.asField(),
                nameHash);

        var issuerKey = ZkJubjubPoint.fromTrustedAffine(zk, pkU, pkV);
        var signatureR = ZkJubjubPoint.fromTrustedAffine(zk, sigRU, sigRV);
        ZkEdDSAJubjub.verify(zk, issuerKey, claimsMsg, signatureR, sigS, kModL, kQuotient);

        var maxDobYear = ZkUInt.wrap(
                zk,
                currentYear.asField().sub(zk.constant(MIN_AGE)).signal(),
                16);
        var ageOk = dobYear.lte(maxDobYear);
        var roleOk = roleId.isEqual(zk.constant(DOCTOR_ROLE_ID));

        return roleOk.and(eligible.isEqual(ageOk));
    }
}
