package com.bloxbean.cardano.zeroj.usecases.selective.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Adult Resident DApp Plutus validator. Public inputs (5):
 * pkU, pkV, currentYear, countryRoot, eligible. Releases gated funds when
 * the Groth16 proof verifies AND eligible == 1.
 */
@SpendingValidator
public class AdultResidentValidator {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record AdultResidentProof(byte[] piA, byte[] piB, byte[] piC,
                              byte[] pkU, byte[] pkV,
                              byte[] currentYear, byte[] countryRoot, byte[] eligible) {}

    @Entrypoint
    public static boolean validate(Optional<PlutusData> datum, AdultResidentProof proof, ScriptContext ctx) {
        BigInteger eligibleVal = Builtins.byteStringToInteger(true, proof.eligible());
        boolean isEligible = eligibleVal.compareTo(BigInteger.ONE) == 0;

        BigInteger pub0 = Builtins.byteStringToInteger(true, proof.pkU());
        BigInteger pub1 = Builtins.byteStringToInteger(true, proof.pkV());
        BigInteger pub2 = Builtins.byteStringToInteger(true, proof.currentYear());
        BigInteger pub3 = Builtins.byteStringToInteger(true, proof.countryRoot());
        BigInteger pub4 = Builtins.byteStringToInteger(true, proof.eligible());

        PlutusData publicInputs = Groth16BLS12381Lib.publicInputs(pub0, pub1, pub2, pub3, pub4);
        boolean proofValid = Groth16BLS12381Lib.verify(publicInputs,
                proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
        return isEligible && proofValid;
    }
}
