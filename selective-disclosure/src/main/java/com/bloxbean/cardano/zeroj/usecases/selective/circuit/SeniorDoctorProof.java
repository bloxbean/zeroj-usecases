package com.bloxbean.cardano.zeroj.usecases.selective.circuit;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.lib.zk.ZkEdDSAJubjub;
import org.zeroj.circuit.lib.zk.ZkPoseidonN;

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

        ZkEdDSAJubjub.verifyWithRegisteredKey(
                zk, pkU, pkV, claimsMsg, sigRU, sigRV, sigS, kModL, kQuotient);

        var maxDobYear = ZkUInt.wrap(
                zk,
                currentYear.asField().sub(zk.constant(MIN_AGE)).signal(),
                16);
        var ageOk = dobYear.lte(maxDobYear);
        var roleOk = roleId.isEqual(zk.constant(DOCTOR_ROLE_ID));

        return roleOk.and(eligible.isEqual(ageOk));
    }
}
