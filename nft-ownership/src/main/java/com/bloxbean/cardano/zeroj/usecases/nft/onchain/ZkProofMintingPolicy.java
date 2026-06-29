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

        boolean proofValid = verifyFour(pub0, pub1, pub2, pub3,
                redeemer.piA(), redeemer.piB(), redeemer.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        return nameCorrect && exactlyOne && ownerValid && proofValid;
    }

    private static boolean verifyFour(BigInteger pub0, BigInteger pub1,
                                      BigInteger pub2, BigInteger pub3,
                                      byte[] piA, byte[] piB, byte[] piC,
                                      byte[] vkAlpha, byte[] vkBeta,
                                      byte[] vkGamma, byte[] vkDelta,
                                      PlutusData vkIc) {
        PlutusData ic0 = Builtins.unListData(vkIc);
        if (Builtins.nullList(ic0)) return false;

        PlutusData ic1 = Builtins.tailList(ic0);
        if (Builtins.nullList(ic1)) return false;

        PlutusData ic2 = Builtins.tailList(ic1);
        if (Builtins.nullList(ic2)) return false;

        PlutusData ic3 = Builtins.tailList(ic2);
        if (Builtins.nullList(ic3)) return false;

        PlutusData ic4 = Builtins.tailList(ic3);
        if (Builtins.nullList(ic4)) return false;

        if (!Builtins.nullList(Builtins.tailList(ic4))) return false;

        byte[] vkX0 = Builtins.bls12_381_G1_uncompress(Builtins.unBData(Builtins.headList(ic0)));
        byte[] vkX1 = addPublicInput(vkX0, pub0, ic1);
        byte[] vkX2 = addPublicInput(vkX1, pub1, ic2);
        byte[] vkX3 = addPublicInput(vkX2, pub2, ic3);
        byte[] vkX4 = addPublicInput(vkX3, pub3, ic4);

        byte[] a = Builtins.bls12_381_G1_uncompress(piA);
        byte[] b = Builtins.bls12_381_G2_uncompress(piB);
        byte[] c = Builtins.bls12_381_G1_uncompress(piC);

        byte[] alpha = Builtins.bls12_381_G1_uncompress(vkAlpha);
        byte[] beta = Builtins.bls12_381_G2_uncompress(vkBeta);
        byte[] gamma = Builtins.bls12_381_G2_uncompress(vkGamma);
        byte[] delta = Builtins.bls12_381_G2_uncompress(vkDelta);

        byte[] lhs = Builtins.bls12_381_mulMlResult(
                Builtins.bls12_381_millerLoop(a, b),
                Builtins.bls12_381_millerLoop(Builtins.bls12_381_G1_neg(alpha), beta));
        byte[] rhs = Builtins.bls12_381_mulMlResult(
                Builtins.bls12_381_millerLoop(vkX4, gamma),
                Builtins.bls12_381_millerLoop(c, delta));

        return Builtins.bls12_381_finalVerify(lhs, rhs);
    }

    private static byte[] addPublicInput(byte[] vkX, BigInteger publicInput, PlutusData icCursor) {
        byte[] ic = Builtins.bls12_381_G1_uncompress(Builtins.unBData(Builtins.headList(icCursor)));
        byte[] scaled = Builtins.bls12_381_G1_scalarMul(publicInput, ic);
        return Builtins.bls12_381_G1_add(vkX, scaled);
    }
}
