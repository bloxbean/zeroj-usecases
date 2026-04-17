package com.bloxbean.cardano.zeroj.usecases.voting.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.ledger.ScriptInfo;
import com.bloxbean.cardano.julc.ledger.TxInfo;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.MintingValidator;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.lib.BlsLib;
import com.bloxbean.cardano.julc.stdlib.lib.ValuesLib;

import java.math.BigInteger;

/**
 * On-chain Groth16 BLS12-381 verifier for private vote proofs.
 * <p>
 * 4 public inputs: electionId, voterRoot, nullifier, commitment.
 * Mints exactly 1 token whose name = nullifier (32 bytes).
 */
@MintingValidator
public class VoteZkMintingPolicy {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static byte[] vkIc0;
    @Param static byte[] vkIc1;
    @Param static byte[] vkIc2;
    @Param static byte[] vkIc3;
    @Param static byte[] vkIc4;

    record ZkRedeemer(byte[] piA, byte[] piB, byte[] piC,
                      byte[] electionId, byte[] voterRoot,
                      byte[] nullifier, byte[] commitment) {}

    @Entrypoint
    public static boolean validate(ZkRedeemer redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();

        // Get own policy ID
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policyBytes = PlutusData.cast(mintInfo.policyId(), byte[].class);

        // Check: minted token name == nullifier
        byte[] mintedName = ValuesLib.findTokenName(txInfo.mint(), policyBytes, BigInteger.ONE);
        boolean nameCorrect = Builtins.equalsByteString(mintedName, redeemer.nullifier());

        // Check: exactly 1 token minted
        BigInteger mintCount = ValuesLib.countTokensWithQty(txInfo.mint(), policyBytes, BigInteger.ONE);
        boolean exactlyOne = mintCount.compareTo(BigInteger.ONE) == 0;

        // Groth16 BLS12-381 pairing check
        byte[] a = BlsLib.g1Uncompress(redeemer.piA());
        byte[] b = BlsLib.g2Uncompress(redeemer.piB());
        byte[] c = BlsLib.g1Uncompress(redeemer.piC());

        byte[] alpha = BlsLib.g1Uncompress(vkAlpha);
        byte[] beta  = BlsLib.g2Uncompress(vkBeta);
        byte[] gamma = BlsLib.g2Uncompress(vkGamma);
        byte[] delta = BlsLib.g2Uncompress(vkDelta);
        byte[] ic0   = BlsLib.g1Uncompress(vkIc0);
        byte[] ic1   = BlsLib.g1Uncompress(vkIc1);
        byte[] ic2   = BlsLib.g1Uncompress(vkIc2);
        byte[] ic3   = BlsLib.g1Uncompress(vkIc3);
        byte[] ic4   = BlsLib.g1Uncompress(vkIc4);

        BigInteger pub0 = Builtins.byteStringToInteger(true, redeemer.electionId());
        BigInteger pub1 = Builtins.byteStringToInteger(true, redeemer.voterRoot());
        BigInteger pub2 = Builtins.byteStringToInteger(true, redeemer.nullifier());
        BigInteger pub3 = Builtins.byteStringToInteger(true, redeemer.commitment());

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

        return nameCorrect && exactlyOne && proofValid;
    }
}
