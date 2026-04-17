package com.bloxbean.cardano.zeroj.usecases.nft.onchain;

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
    @Param static byte[] vkIc0;     // G1 compressed 48 bytes
    @Param static byte[] vkIc1;     // G1 compressed 48 bytes
    @Param static byte[] vkIc2;     // G1 compressed 48 bytes
    @Param static byte[] vkIc3;     // G1 compressed 48 bytes
    @Param static byte[] vkIc4;     // G1 compressed 48 bytes

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

        // --- Groth16 BLS12-381 pairing check (4 public inputs) ---
        // 1. Uncompress proof points
        byte[] a = BlsLib.g1Uncompress(redeemer.piA());
        byte[] b = BlsLib.g2Uncompress(redeemer.piB());
        byte[] c = BlsLib.g1Uncompress(redeemer.piC());

        // 2. Uncompress VK points
        byte[] alpha = BlsLib.g1Uncompress(vkAlpha);
        byte[] beta  = BlsLib.g2Uncompress(vkBeta);
        byte[] gamma = BlsLib.g2Uncompress(vkGamma);
        byte[] delta = BlsLib.g2Uncompress(vkDelta);
        byte[] ic0   = BlsLib.g1Uncompress(vkIc0);
        byte[] ic1   = BlsLib.g1Uncompress(vkIc1);
        byte[] ic2   = BlsLib.g1Uncompress(vkIc2);
        byte[] ic3   = BlsLib.g1Uncompress(vkIc3);
        byte[] ic4   = BlsLib.g1Uncompress(vkIc4);

        // 3. Public inputs from redeemer
        BigInteger pub0 = Builtins.byteStringToInteger(true, redeemer.snapshotRoot());
        BigInteger pub1 = Builtins.byteStringToInteger(true, redeemer.contextId());
        BigInteger pub3 = Builtins.byteStringToInteger(true, redeemer.nullifier());

        // 4. Compute vk_x = IC[0] + pub[0]*IC[1] + pub[1]*IC[2] + pub[2]*IC[3] + pub[3]*IC[4]
        byte[] s0 = BlsLib.g1ScalarMul(pub0, ic1);
        byte[] s1 = BlsLib.g1ScalarMul(pub1, ic2);
        byte[] s2 = BlsLib.g1ScalarMul(pub2, ic3);
        byte[] s3 = BlsLib.g1ScalarMul(pub3, ic4);
        byte[] vkX = BlsLib.g1Add(ic0,
                BlsLib.g1Add(s0, BlsLib.g1Add(s1, BlsLib.g1Add(s2, s3))));

        // 5. Groth16 pairing check
        byte[] negAlpha = BlsLib.g1Neg(alpha);
        byte[] lhs = BlsLib.mulMlResult(
                BlsLib.millerLoop(a, b),
                BlsLib.millerLoop(negAlpha, beta));
        byte[] rhs = BlsLib.mulMlResult(
                BlsLib.millerLoop(vkX, gamma),
                BlsLib.millerLoop(c, delta));

        boolean proofValid = BlsLib.finalVerify(lhs, rhs);

        return nameCorrect && exactlyOne && ownerValid && proofValid;
    }
}
