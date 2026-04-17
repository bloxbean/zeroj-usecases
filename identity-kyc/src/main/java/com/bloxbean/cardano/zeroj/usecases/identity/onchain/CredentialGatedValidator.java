package com.bloxbean.cardano.zeroj.usecases.identity.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.julc.stdlib.lib.BlsLib;

import java.math.BigInteger;
import java.util.Optional;

/**
 * On-chain Groth16 BLS12-381 verifier for KYC credential proofs.
 * <p>
 * 4 public values: credentialHash, minAge, countryRoot, eligible.
 * Unlocks funds only when the ZK proof is valid AND eligible == 1.
 * <p>
 * Stateless — no nullifiers, proofs can be reused for ongoing access.
 */
@SpendingValidator
public class CredentialGatedValidator {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static byte[] vkIc0;
    @Param static byte[] vkIc1;
    @Param static byte[] vkIc2;
    @Param static byte[] vkIc3;
    @Param static byte[] vkIc4;

    record CredentialProof(byte[] piA, byte[] piB, byte[] piC,
                           byte[] credentialHash, byte[] minAge,
                           byte[] countryRoot, byte[] eligible) {}

    @Entrypoint
    public static boolean validate(Optional<PlutusData> datum, CredentialProof proof, ScriptContext ctx) {
        // Check eligible == 1
        BigInteger eligibleVal = Builtins.byteStringToInteger(true, proof.eligible());
        boolean isEligible = eligibleVal.compareTo(BigInteger.ONE) == 0;

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

        BigInteger pub0 = Builtins.byteStringToInteger(true, proof.credentialHash());
        BigInteger pub1 = Builtins.byteStringToInteger(true, proof.minAge());
        BigInteger pub2 = Builtins.byteStringToInteger(true, proof.countryRoot());
        BigInteger pub3 = Builtins.byteStringToInteger(true, proof.eligible());

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

        return isEligible && proofValid;
    }
}
