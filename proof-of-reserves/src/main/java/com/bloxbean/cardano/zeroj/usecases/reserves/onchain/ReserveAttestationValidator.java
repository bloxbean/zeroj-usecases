package com.bloxbean.cardano.zeroj.usecases.reserves.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.julc.stdlib.lib.BlsLib;

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
    @Param static byte[] vkIc0;
    @Param static byte[] vkIc1;
    @Param static byte[] vkIc2;
    @Param static byte[] vkIc3;
    @Param static byte[] vkIc4;

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

        // Groth16 BLS12-381 pairing check
        byte[] a = BlsLib.g1Uncompress(proof.piA());
        byte[] b = BlsLib.g2Uncompress(proof.piB());
        byte[] c = BlsLib.g1Uncompress(proof.piC());

        byte[] alpha = BlsLib.g1Uncompress(vkAlpha);
        byte[] beta  = BlsLib.g2Uncompress(vkBeta);
        byte[] gamma = BlsLib.g2Uncompress(vkGamma);
        byte[] delta = BlsLib.g2Uncompress(vkDelta);
        byte[] ic0   = BlsLib.g1Uncompress(vkIc0);
        byte[] ic1   = BlsLib.g1Uncompress(vkIc1);
        byte[] ic2   = BlsLib.g1Uncompress(vkIc2);
        byte[] ic3   = BlsLib.g1Uncompress(vkIc3);
        byte[] ic4   = BlsLib.g1Uncompress(vkIc4);

        byte[] s0 = BlsLib.g1ScalarMul(pub0, ic1);
        byte[] s1 = BlsLib.g1ScalarMul(pub1, ic2);
        byte[] s2 = BlsLib.g1ScalarMul(pub2, ic3);
        byte[] s3 = BlsLib.g1ScalarMul(pub3, ic4);
        byte[] vkX = BlsLib.g1Add(ic0,
                BlsLib.g1Add(s0, BlsLib.g1Add(s1, BlsLib.g1Add(s2, s3))));

        byte[] negAlpha = BlsLib.g1Neg(alpha);
        byte[] lhs = BlsLib.mulMlResult(
                BlsLib.millerLoop(a, b),
                BlsLib.millerLoop(negAlpha, beta));
        byte[] rhs = BlsLib.mulMlResult(
                BlsLib.millerLoop(vkX, gamma),
                BlsLib.millerLoop(c, delta));

        boolean proofValid = BlsLib.finalVerify(lhs, rhs);

        return isSolvent && proofValid;
    }
}
