package com.bloxbean.cardano.zeroj.usecases.voting.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.ledger.ScriptInfo;
import org.julclang.ledger.TxInfo;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.MintingValidator;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.lib.ValuesLib;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

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
    @Param static PlutusData vkIc;

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

        BigInteger pub0 = Builtins.byteStringToInteger(true, redeemer.electionId());
        BigInteger pub1 = Builtins.byteStringToInteger(true, redeemer.voterRoot());
        BigInteger pub2 = Builtins.byteStringToInteger(true, redeemer.nullifier());
        BigInteger pub3 = Builtins.byteStringToInteger(true, redeemer.commitment());

        boolean proofValid = Groth16BLS12381Lib.verifyFour(pub0, pub1, pub2, pub3,
                redeemer.piA(), redeemer.piB(), redeemer.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        return nameCorrect && exactlyOne && proofValid;
    }
}
