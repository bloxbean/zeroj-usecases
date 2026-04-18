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
 * On-chain Groth16 BLS12-381 verifier for KYC credential proofs backed by
 * EdDSA-Jubjub signatures (ADR-0016).
 *
 * <p>Public inputs (5): {@code pkU, pkV, minAge, countryRoot, eligible}.
 * The first two identify the issuer by their Jubjub public key; the next
 * two bind the proof to a specific policy; {@code eligible} is the assertion
 * the caller claims (1 = eligible). The validator accepts only when the
 * Groth16 proof is valid AND {@code eligible == 1}.
 *
 * <p>Stateless — no nullifiers, proofs can be reused for ongoing access.
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
    @Param static byte[] vkIc5;

    record CredentialProof(byte[] piA, byte[] piB, byte[] piC,
                           byte[] pkU, byte[] pkV,
                           byte[] minAge, byte[] countryRoot, byte[] eligible) {}

    @Entrypoint
    public static boolean validate(Optional<PlutusData> datum, CredentialProof proof, ScriptContext ctx) {
        BigInteger eligibleVal = Builtins.byteStringToInteger(true, proof.eligible());
        boolean isEligible = eligibleVal.compareTo(BigInteger.ONE) == 0;

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
        byte[] ic5   = BlsLib.g1Uncompress(vkIc5);

        BigInteger pub0 = Builtins.byteStringToInteger(true, proof.pkU());
        BigInteger pub1 = Builtins.byteStringToInteger(true, proof.pkV());
        BigInteger pub2 = Builtins.byteStringToInteger(true, proof.minAge());
        BigInteger pub3 = Builtins.byteStringToInteger(true, proof.countryRoot());
        BigInteger pub4 = Builtins.byteStringToInteger(true, proof.eligible());

        byte[] s0 = BlsLib.g1ScalarMul(pub0, ic1);
        byte[] s1 = BlsLib.g1ScalarMul(pub1, ic2);
        byte[] s2 = BlsLib.g1ScalarMul(pub2, ic3);
        byte[] s3 = BlsLib.g1ScalarMul(pub3, ic4);
        byte[] s4 = BlsLib.g1ScalarMul(pub4, ic5);
        byte[] vkX = BlsLib.g1Add(ic0,
                BlsLib.g1Add(s0,
                        BlsLib.g1Add(s1,
                                BlsLib.g1Add(s2,
                                        BlsLib.g1Add(s3, s4)))));

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
