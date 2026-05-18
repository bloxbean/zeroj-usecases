package com.bloxbean.cardano.zeroj.usecases.dpp.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.zeroj.onchain.julc.Groth16BLS12381;

import java.math.BigInteger;
/**
 * On-chain Groth16 BLS12-381 verifier for DPP compliance proofs.
 * 4 public values: productId, threshold, auditorHash, isCompliant.
 * Unlocks funds only when ZK proof valid AND isCompliant == 1.
 */
@SpendingValidator
public class DppComplianceValidator {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    /**
     * Groth16 proof — only 3 fields in redeemer (matching zeroj working pattern).
     * Public inputs are in the datum.
     */
    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Groth16Proof proof, PlutusData ctx) {
        // Extract public inputs from datum (list of integers)
        PlutusData inputs = Builtins.unListData(datum);
        PlutusData rest1 = Builtins.tailList(inputs);
        PlutusData rest2 = Builtins.tailList(rest1);
        PlutusData rest3 = Builtins.tailList(rest2);
        BigInteger pub3 = Builtins.asInteger(Builtins.headList(rest3));

        // isCompliant (pub3) must be 1
        boolean isCompliant = pub3.compareTo(BigInteger.ONE) == 0;

        boolean proofValid = Groth16BLS12381.verify(datum, proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        return isCompliant && proofValid;
    }
}
