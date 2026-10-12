package com.bloxbean.cardano.zeroj.usecases.nft.onchain;

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
 * On-chain Groth16 BLS12-381 verifier of the NFT ownership proof (circuit version 2), as a
 * Plutus V3 minting policy (ADR-0009 D2).
 *
 * <p>One policy instance per event: {@code snapshotRoot} and {@code contextId} are script
 * parameters, so a proof against another snapshot or another event is rejected. The redeemer
 * carries only the proof and the nullifier. The public inputs are
 * {@code [snapshotRoot, contextId, 1, nullifier]}.
 *
 * <p>The mint map under this policy is exactly {@code {n: 1}}, where {@code n} is the canonical
 * 32-byte big-endian encoding of the nullifier ({@code 0 ≤ nullifier < r}). The nullifier list
 * keys its new node by {@code slice(1, 31, n)} and requires the token in that node; a token
 * minted outside a list insert grants no access.
 */
@MintingValidator
public class ZkProofMintingPolicy {

    @Param static BigInteger snapshotRoot;
    @Param static BigInteger contextId;
    // VK points — compressed bytes baked at deploy time
    @Param static byte[] vkAlpha;   // G1 compressed 48 bytes
    @Param static byte[] vkBeta;    // G2 compressed 96 bytes
    @Param static byte[] vkGamma;   // G2 compressed 96 bytes
    @Param static byte[] vkDelta;   // G2 compressed 96 bytes
    @Param static PlutusData vkIc;  // List of G1 compressed IC points

    /** The Groth16 proof (compressed points) and the nullifier it proves. */
    record ZkRedeemer(byte[] piA, byte[] piB, byte[] piC, BigInteger nullifier) {}

    @Entrypoint
    public static boolean validate(ZkRedeemer redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policy = PlutusData.cast(mintInfo.policyId(), byte[].class);

        if (!NullifierListLib.canonicalField(snapshotRoot) || !NullifierListLib.canonicalField(contextId)) {
            return false;
        }

        // Exactly {n: 1}: one entry, quantity 1, no burns.
        if (!NullifierListLib.mintsExactlyOne(txInfo.mint(), policy)) return false;
        byte[] name = ValuesLib.findTokenName(txInfo.mint(), policy, BigInteger.ONE);
        if (Builtins.lengthOfByteString(name) != 32) return false;

        // The name is the canonical 32-byte encoding of the proved nullifier.
        BigInteger nullifier = redeemer.nullifier();
        if (!NullifierListLib.canonicalField(nullifier)) return false;
        if (!Builtins.equalsByteString(name, Builtins.integerToByteString(true, 32, nullifier))) return false;

        return Groth16BLS12381Lib.verifyFour(snapshotRoot, contextId, BigInteger.ONE, nullifier,
                redeemer.piA(), redeemer.piB(), redeemer.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }
}
