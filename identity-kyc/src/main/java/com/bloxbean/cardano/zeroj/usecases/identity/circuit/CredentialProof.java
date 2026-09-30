package com.bloxbean.cardano.zeroj.usecases.identity.circuit;

import org.zeroj.circuit.annotation.CircuitParam;
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
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.lib.zk.ZkEdDSAJubjub;
import org.zeroj.circuit.lib.zk.ZkMerkle;
import org.zeroj.circuit.lib.zk.ZkPoseidon;

@ZKCircuit(
        name = "credential-verify-eddsa",
        nameTemplate = "credential-verify-eddsa-d{countryTreeDepth}-bls-poseidon",
        version = 1)
public class CredentialProof {

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    private final int countryTreeDepth;

    public CredentialProof(@CircuitParam("countryTreeDepth") int countryTreeDepth) {
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
            @Public @UInt(bits = 8) ZkUInt minAge,
            @Public ZkField countryRoot,
            @Public ZkBool eligible,
            @Secret @UInt(bits = 8) ZkUInt age,
            @Secret ZkField country,
            @Secret ZkField sigRU,
            @Secret ZkField sigRV,
            @Secret @UInt(bits = 252) ZkUInt sigS,
            @Secret @UInt(bits = 252) ZkUInt kModL,
            @Secret @UInt(bits = 4) ZkUInt kQuotient,
            @Secret @FixedSize(param = "countryTreeDepth") ZkArray<ZkField> siblings,
            @Secret @FixedSize(param = "countryTreeDepth") ZkArray<ZkBool> pathBits) {

        var claimsMsg = ZkPoseidon.hash(zk, POSEIDON, age.asField(), country);
        ZkEdDSAJubjub.verifyWithRegisteredKey(
                zk, pkU, pkV, claimsMsg, sigRU, sigRV, sigS, kModL, kQuotient);

        var ageOk = age.gte(minAge);
        ZkMerkle.verifyProofPoseidon(zk, POSEIDON, country, countryRoot, siblings, pathBits);

        return eligible.isEqual(ageOk);
    }
}
