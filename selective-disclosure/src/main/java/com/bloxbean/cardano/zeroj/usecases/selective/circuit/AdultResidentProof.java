package com.bloxbean.cardano.zeroj.usecases.selective.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.CircuitParam;
import com.bloxbean.cardano.zeroj.circuit.annotation.FixedSize;
import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.UInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkEdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkJubjubPoint;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMerkle;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPoseidonN;

@ZKCircuit(
        name = "adult-resident",
        nameTemplate = "adult-resident-d{countryTreeDepth}-bls-poseidon",
        version = 1)
public class AdultResidentProof {

    public static final int MIN_AGE = 21;

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    private final int countryTreeDepth;

    public AdultResidentProof(@CircuitParam("countryTreeDepth") int countryTreeDepth) {
        if (countryTreeDepth < 1) {
            throw new IllegalArgumentException("countryTreeDepth must be positive");
        }
        this.countryTreeDepth = countryTreeDepth;
    }

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Public ZkField pkU,
            @Public ZkField pkV,
            @Public @UInt(bits = 16) ZkUInt currentYear,
            @Public ZkField countryRoot,
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
            @Secret @UInt(bits = 4) ZkUInt kQuotient,
            @Secret @FixedSize(param = "countryTreeDepth") ZkArray<ZkField> siblings,
            @Secret @FixedSize(param = "countryTreeDepth") ZkArray<ZkBool> pathBits) {

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

        ZkMerkle.verifyProofPoseidon(zk, POSEIDON, country.asField(), countryRoot, siblings, pathBits);

        return eligible.isEqual(ageOk);
    }
}
