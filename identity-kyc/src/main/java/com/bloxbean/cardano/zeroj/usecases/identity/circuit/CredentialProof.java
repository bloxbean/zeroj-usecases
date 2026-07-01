package com.bloxbean.cardano.zeroj.usecases.identity.circuit;

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
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPoseidon;

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
        var issuerKey = ZkJubjubPoint.fromTrustedAffine(zk, pkU, pkV);
        var signatureR = ZkJubjubPoint.fromTrustedAffine(zk, sigRU, sigRV);
        ZkEdDSAJubjub.verify(zk, issuerKey, claimsMsg, signatureR, sigS, kModL, kQuotient);

        var ageOk = age.gte(minAge);
        ZkMerkle.verifyProofPoseidon(zk, POSEIDON, country, countryRoot, siblings, pathBits);

        return eligible.isEqual(ageOk);
    }
}
