package com.bloxbean.cardano.zeroj.usecases.dpp.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.ledger.ScriptInfo;
import org.julclang.ledger.TxInfo;
import org.julclang.ledger.TxOut;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.MintingValidator;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.lib.ContextsLib;
import org.julclang.stdlib.lib.OutputLib;
import org.julclang.stdlib.lib.ValuesLib;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

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
    @Param static PlutusData vkIc;

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
        PlutusData r1 = Builtins.tailList(inputs);
        PlutusData r2 = Builtins.tailList(r1);
        PlutusData r3 = Builtins.tailList(r2);
        BigInteger pub3 = Builtins.asInteger(Builtins.headList(r3));

        // 4. isCompliant must be 1
        boolean isCompliant = pub3.compareTo(BigInteger.ONE) == 0;

        // 5. Groth16 BLS12-381 pairing check
        boolean proofValid = Groth16BLS12381Lib.verify(datumData, proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        return mfgSigned && exactlyOne && isCompliant && proofValid;
    }
}
