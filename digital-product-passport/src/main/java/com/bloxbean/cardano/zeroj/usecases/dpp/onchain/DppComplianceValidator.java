package com.bloxbean.cardano.zeroj.usecases.dpp.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.julc.stdlib.lib.BlsLib;

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
    @Param static byte[] vkIc0;
    @Param static byte[] vkIc1;
    @Param static byte[] vkIc2;
    @Param static byte[] vkIc3;
    @Param static byte[] vkIc4;

    /**
     * Groth16 proof — only 3 fields in redeemer (matching zeroj working pattern).
     * Public inputs are in the datum.
     */
    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Groth16Proof proof, PlutusData ctx) {
        // Extract public inputs from datum (list of integers)
        PlutusData inputs = Builtins.unListData(datum);
        BigInteger pub0 = Builtins.asInteger(Builtins.headList(inputs));
        PlutusData rest1 = Builtins.tailList(inputs);
        BigInteger pub1 = Builtins.asInteger(Builtins.headList(rest1));
        PlutusData rest2 = Builtins.tailList(rest1);
        BigInteger pub2 = Builtins.asInteger(Builtins.headList(rest2));
        PlutusData rest3 = Builtins.tailList(rest2);
        BigInteger pub3 = Builtins.asInteger(Builtins.headList(rest3));

        // isCompliant (pub3) must be 1
        boolean isCompliant = pub3.compareTo(BigInteger.ONE) == 0;

        // Uncompress proof
        byte[] a = BlsLib.g1Uncompress(proof.piA());
        byte[] b = BlsLib.g2Uncompress(proof.piB());
        byte[] c = BlsLib.g1Uncompress(proof.piC());

        // Uncompress VK
        byte[] alpha = BlsLib.g1Uncompress(vkAlpha);
        byte[] beta  = BlsLib.g2Uncompress(vkBeta);
        byte[] gamma = BlsLib.g2Uncompress(vkGamma);
        byte[] delta = BlsLib.g2Uncompress(vkDelta);
        byte[] ic0   = BlsLib.g1Uncompress(vkIc0);
        byte[] ic1   = BlsLib.g1Uncompress(vkIc1);
        byte[] ic2   = BlsLib.g1Uncompress(vkIc2);
        byte[] ic3   = BlsLib.g1Uncompress(vkIc3);
        byte[] ic4   = BlsLib.g1Uncompress(vkIc4);

        // vk_x = IC[0] + pub[0]*IC[1] + pub[1]*IC[2] + pub[2]*IC[3] + pub[3]*IC[4]
        byte[] s0 = BlsLib.g1ScalarMul(pub0, ic1);
        byte[] s1 = BlsLib.g1ScalarMul(pub1, ic2);
        byte[] s2 = BlsLib.g1ScalarMul(pub2, ic3);
        byte[] s3 = BlsLib.g1ScalarMul(pub3, ic4);
        byte[] vkX = BlsLib.g1Add(ic0,
                BlsLib.g1Add(s0, BlsLib.g1Add(s1, BlsLib.g1Add(s2, s3))));

        // Groth16 pairing check
        byte[] negAlpha = BlsLib.g1Neg(alpha);
        byte[] lhs = BlsLib.mulMlResult(
                BlsLib.millerLoop(a, b),
                BlsLib.millerLoop(negAlpha, beta));
        byte[] rhs = BlsLib.mulMlResult(
                BlsLib.millerLoop(vkX, gamma),
                BlsLib.millerLoop(c, delta));

        boolean proofValid = BlsLib.finalVerify(lhs, rhs);

        return isCompliant && proofValid;
    }
}
