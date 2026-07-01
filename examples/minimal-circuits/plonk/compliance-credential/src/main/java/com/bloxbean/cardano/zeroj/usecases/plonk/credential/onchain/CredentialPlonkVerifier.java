package com.bloxbean.cardano.zeroj.usecases.plonk.credential.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.lib.PlonkBLS12381Lib;

import java.math.BigInteger;

@SpendingValidator
public class CredentialPlonkVerifier {
    private static final BigInteger EXPECTED_PUBLIC_INPUTS = BigInteger.valueOf(3);
    private static final BigInteger MINIMUM_ALLOWED_AGE = BigInteger.valueOf(18);
    private static final BigInteger REQUIRED_JURISDICTION = BigInteger.ONE;

    @Param static byte[] vkQm;
    @Param static byte[] vkQl;
    @Param static byte[] vkQr;
    @Param static byte[] vkQo;
    @Param static byte[] vkQc;
    @Param static byte[] vkS1;
    @Param static byte[] vkS2;
    @Param static byte[] vkS3;
    @Param static byte[] vkX2;

    @Param static BigInteger domainSize;
    @Param static BigInteger domainPower;
    @Param static BigInteger omega;
    @Param static BigInteger k1;
    @Param static BigInteger k2;
    @Param static BigInteger k1OverK2;
    @Param static BigInteger fr;
    @Param static BigInteger nInv;
    @Param static byte[] g1Gen;
    @Param static byte[] g2Gen;
    @Param static byte[] profileTag;
    @Param static BigInteger publicInputCount;

    record PlonkProof(
            byte[] cmA, byte[] cmB, byte[] cmC, byte[] cmZ,
            byte[] cmT1, byte[] cmT2, byte[] cmT3,
            byte[] wXi, byte[] wXiw,
            BigInteger evalA, BigInteger evalB, BigInteger evalC,
            BigInteger evalS1, BigInteger evalS2, BigInteger evalZw,
            PlutusData publicInputInverses
    ) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, PlonkProof proof, PlutusData ctx) {
        boolean proofValid = PlonkBLS12381Lib.verifyMultiInputDatum(
                datum, proof.publicInputInverses(),
                proof.cmA(), proof.cmB(), proof.cmC(), proof.cmZ(),
                proof.cmT1(), proof.cmT2(), proof.cmT3(),
                proof.wXi(), proof.wXiw(),
                proof.evalA(), proof.evalB(), proof.evalC(),
                proof.evalS1(), proof.evalS2(), proof.evalZw(),
                vkQm, vkQl, vkQr, vkQo, vkQc, vkS1, vkS2, vkS3, vkX2,
                domainSize, domainPower, omega, k1, k2, k1OverK2, fr, nInv,
                g1Gen, g2Gen, profileTag, publicInputCount);

        return proofValid
                && publicInputCount.compareTo(EXPECTED_PUBLIC_INPUTS) == 0
                && credentialPolicy(datum);
    }

    private static boolean credentialPolicy(PlutusData datum) {
        PlutusData inputs = Builtins.unListData(datum);
        PlutusData rest1 = Builtins.tailList(inputs);
        BigInteger minimumAge = Builtins.asInteger(Builtins.headList(rest1));
        PlutusData rest2 = Builtins.tailList(rest1);
        BigInteger requiredJurisdiction = Builtins.asInteger(Builtins.headList(rest2));

        return minimumAge.compareTo(MINIMUM_ALLOWED_AGE) >= 0
                && requiredJurisdiction.compareTo(REQUIRED_JURISDICTION) == 0;
    }
}
