package com.bloxbean.cardano.zeroj.usecases.nft.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.ledger.ScriptInfo;
import com.bloxbean.cardano.julc.ledger.TxInfo;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.MintingValidator;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.lib.ValuesLib;
import com.bloxbean.cardano.zeroj.onchain.julc.Groth16BLS12381;

import java.math.BigInteger;

/**
 * On-chain Groth16 BLS12-381 verifier as a Plutus V3 minting policy.
 * <p>
 * Validates a ZK proof of NFT ownership and mints exactly 1 nullifier token.
 * The token name equals the nullifier bytes from the proof's public inputs.
 * <p>
 * This validator has 4 public inputs: snapshotRoot, contextId, isOwner, nullifier.
 * VK points are baked in at deploy time via {@link Param}.
 */
@MintingValidator
public class ZkProofMintingPolicy {

    // VK points — compressed bytes baked at compile time
    @Param static byte[] vkAlpha;   // G1 compressed 48 bytes
    @Param static byte[] vkBeta;    // G2 compressed 96 bytes
    @Param static byte[] vkGamma;   // G2 compressed 96 bytes
    @Param static byte[] vkDelta;   // G2 compressed 96 bytes
    @Param static PlutusData vkIc;  // List of G1 compressed IC points

    /**
     * ZK proof + public inputs, passed as redeemer.
     */
    record ZkRedeemer(byte[] piA, byte[] piB, byte[] piC,
                      byte[] snapshotRoot, byte[] contextId,
                      byte[] isOwner, byte[] nullifier) {}

    @Entrypoint
    public static boolean validate(ZkRedeemer redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();

        // Get own policy ID
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policyBytes = PlutusData.cast(mintInfo.policyId(), byte[].class);

        // Check: minted token name must equal nullifier bytes from redeemer
        byte[] mintedName = ValuesLib.findTokenName(txInfo.mint(), policyBytes, BigInteger.ONE);
        boolean nameCorrect = Builtins.equalsByteString(mintedName, redeemer.nullifier());

        // Check: exactly 1 token minted under this policy
        BigInteger mintCount = ValuesLib.countTokensWithQty(txInfo.mint(), policyBytes, BigInteger.ONE);
        boolean exactlyOne = mintCount.compareTo(BigInteger.ONE) == 0;

        // Check: isOwner must be 1
        BigInteger pub2 = Builtins.byteStringToInteger(true, redeemer.isOwner());
        boolean ownerValid = pub2.compareTo(BigInteger.ONE) == 0;

        // Public inputs from redeemer
        BigInteger pub0 = Builtins.byteStringToInteger(true, redeemer.snapshotRoot());
        BigInteger pub1 = Builtins.byteStringToInteger(true, redeemer.contextId());
        BigInteger pub3 = Builtins.byteStringToInteger(true, redeemer.nullifier());

        PlutusData publicInputs = Groth16BLS12381.publicInputs(pub0, pub1, pub2, pub3);
        boolean proofValid = Groth16BLS12381.verify(publicInputs,
                redeemer.piA(), redeemer.piB(), redeemer.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        return nameCorrect && exactlyOne && ownerValid && proofValid;
    }
}
