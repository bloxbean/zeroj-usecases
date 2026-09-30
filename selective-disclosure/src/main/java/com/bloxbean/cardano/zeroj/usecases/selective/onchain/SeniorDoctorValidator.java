package com.bloxbean.cardano.zeroj.usecases.selective.onchain;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcList;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * Senior Doctor DApp Plutus validator. Public inputs (4):
 * pkU, pkV, currentYear, eligible. Releases gated funds when the Groth16
 * proof verifies AND eligible == 1.
 */
@SpendingValidator
public class SeniorDoctorValidator {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;
    @Param static BigInteger issuerPkU;
    @Param static BigInteger issuerPkV;
    @Param static BigInteger policyCurrentYear;

    record SeniorDoctorProof(byte[] piA, byte[] piB, byte[] piC,
                             byte[] pkU, byte[] pkV,
                             byte[] currentYear, byte[] eligible) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, SeniorDoctorProof proof, ScriptContext ctx) {
        BigInteger eligibleVal = Builtins.byteStringToInteger(true, proof.eligible());
        boolean isEligible = eligibleVal.compareTo(BigInteger.ONE) == 0;

        BigInteger pub0 = Builtins.byteStringToInteger(true, proof.pkU());
        BigInteger pub1 = Builtins.byteStringToInteger(true, proof.pkV());
        BigInteger pub2 = Builtins.byteStringToInteger(true, proof.currentYear());
        BigInteger pub3 = Builtins.byteStringToInteger(true, proof.eligible());

        boolean registeredIssuer = isRegisteredIssuer(pub0, pub1);
        boolean registeredPolicy = isRegisteredPolicy(pub2);
        PlutusData publicInputs = JulcList.of(pub0, pub1, pub2, pub3).toPlutusData();
        boolean proofValid = Groth16BLS12381Lib.verify(publicInputs,
                proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
        return registeredIssuer && registeredPolicy && isEligible && proofValid;
    }

    static boolean isRegisteredIssuer(BigInteger publicKeyU, BigInteger publicKeyV) {
        return publicKeyU.equals(issuerPkU) && publicKeyV.equals(issuerPkV);
    }

    static boolean isRegisteredPolicy(BigInteger currentYear) {
        return currentYear.equals(policyCurrentYear);
    }
}
