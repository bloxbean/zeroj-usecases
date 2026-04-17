package com.bloxbean.cardano.zeroj.usecases.dpp.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.ledger.ScriptInfo;
import com.bloxbean.cardano.julc.ledger.TxInfo;
import com.bloxbean.cardano.julc.ledger.TxOut;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.MintingValidator;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.lib.BlsLib;
import com.bloxbean.cardano.julc.stdlib.lib.ContextsLib;
import com.bloxbean.cardano.julc.stdlib.lib.OutputLib;
import com.bloxbean.cardano.julc.stdlib.lib.ValuesLib;

import java.math.BigInteger;

/**
 * DPP minting policy with FULL ON-CHAIN Groth16 BLS12-381 verification.
 * <p>
 * Mint product DPP NFT only if:
 * 1. Manufacturer signed the transaction
 * 2. Exactly 1 token minted
 * 3. Groth16 ZK compliance proof is valid (BLS12-381 pairing check)
 * 4. isCompliant == 1
 * <p>
 * Public inputs (productId, threshold, auditorHash, isCompliant) are in the
 * first output's inline datum. Proof (piA, piB, piC) is in the redeemer.
 */
@MintingValidator
public class DppMintingPolicy {

    @Param static byte[] manufacturerPkh;
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
    public static boolean validate(Groth16Proof proof, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();

        // 1. Manufacturer must sign
        boolean mfgSigned = ContextsLib.signedBy(txInfo, manufacturerPkh);

        // 2. Exactly 1 token minted under own policy
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policyBytes = PlutusData.cast(mintInfo.policyId(), byte[].class);
        BigInteger mintCount = ValuesLib.countTokensWithQty(txInfo.mint(), policyBytes, BigInteger.ONE);
        boolean exactlyOne = mintCount.compareTo(BigInteger.ONE) == 0;

        // 3. Read public inputs from first output's inline datum
        //    Datum = ListData [productId, threshold, auditorHash, isCompliant]
        TxOut firstOutput = txInfo.outputs().get(0);
        PlutusData datumData = OutputLib.getInlineDatum(firstOutput);
        PlutusData inputs = Builtins.unListData(datumData);
        BigInteger pub0 = Builtins.asInteger(Builtins.headList(inputs));
        PlutusData r1 = Builtins.tailList(inputs);
        BigInteger pub1 = Builtins.asInteger(Builtins.headList(r1));
        PlutusData r2 = Builtins.tailList(r1);
        BigInteger pub2 = Builtins.asInteger(Builtins.headList(r2));
        PlutusData r3 = Builtins.tailList(r2);
        BigInteger pub3 = Builtins.asInteger(Builtins.headList(r3));

        // 4. isCompliant must be 1
        boolean isCompliant = pub3.compareTo(BigInteger.ONE) == 0;

        // 5. Groth16 BLS12-381 pairing check
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

        return mfgSigned && exactlyOne && isCompliant && proofValid;
    }
}
