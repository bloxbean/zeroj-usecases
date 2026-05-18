package com.bloxbean.cardano.zeroj.usecases.reserves.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.zeroj.onchain.julc.Groth16BLS12381;

import java.math.BigInteger;

/**
 * On-chain Groth16 BLS12-381 verifier for proof of reserves.
 * <p>
 * Datum = [totalReserves, liabilitiesRoot, totalLiabilities, isSolvent].
 * Redeemer = Groth16Proof(piA, piB, piC).
 * Verifies the solvency proof on-chain.
 */
@SpendingValidator
public class ReserveAttestationValidator {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Groth16Proof proof, PlutusData ctx) {
        // Extract public inputs from datum
        PlutusData inputs = Builtins.unListData(datum);
        BigInteger pub0 = Builtins.asInteger(Builtins.headList(inputs));
        PlutusData r1 = Builtins.tailList(inputs);
        BigInteger pub1 = Builtins.asInteger(Builtins.headList(r1));
        PlutusData r2 = Builtins.tailList(r1);
        BigInteger pub2 = Builtins.asInteger(Builtins.headList(r2));
        PlutusData r3 = Builtins.tailList(r2);
        BigInteger pub3 = Builtins.asInteger(Builtins.headList(r3));

        // isSolvent must be 1
        boolean isSolvent = pub3.compareTo(BigInteger.ONE) == 0;

        boolean proofValid = Groth16BLS12381.verify(datum, proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        return isSolvent && proofValid;
    }
}
