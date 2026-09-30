package com.bloxbean.cardano.zeroj.usecases.airdrop.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.ledger.ScriptInfo;
import org.julclang.ledger.TxInfo;
import org.julclang.ledger.TxOut;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.MintingValidator;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.lib.OutputLib;
import org.julclang.stdlib.lib.ValuesLib;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * On-chain Sybil-resistant airdrop minting policy.
 *
 * <p>Mints exactly one "claim NFT" per (personhood credential, epoch). The
 * NFT's asset name encodes the nullifier; future attempts to claim with the
 * same (credential, epoch) pair would derive the same nullifier and the
 * faucet's off-chain UTxO selection would refuse a transaction whose mint
 * collides with an already-minted NFT.
 *
 * <p>Public inputs (6) are read from the claim output's inline datum:
 * {@code [pkU, pkV, epoch, nullifier, recipient, eligible]}. The validator:
 * <ol>
 *   <li>Mints exactly one token under this policy.</li>
 *   <li>The minted token's asset name equals the nullifier bytes.</li>
 *   <li>{@code eligible == 1}.</li>
 *   <li>The Groth16 BLS12-381 proof verifies under the parameterized vk.</li>
 * </ol>
 *
 * <h2>Why one NFT per nullifier?</h2>
 * The NFT acts as an on-chain receipt: anyone querying chain state can
 * see "this nullifier has been claimed" by looking up the policy ID with
 * that asset name. The faucet service consults this view before accepting
 * a new claim. (Full on-chain double-spend prevention via state-thread
 * tokens is out of scope for this demo; the off-chain check is sufficient
 * to demonstrate the cryptographic gating.)
 */
@MintingValidator
public class FaucetMintingPolicy {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;
    @Param static BigInteger issuerPkU;
    @Param static BigInteger issuerPkV;
    @Param static BigInteger policyEpoch;

    record AirdropProof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(AirdropProof proof, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();

        // 1. Exactly one token minted under own policy.
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policyBytes = PlutusData.cast(mintInfo.policyId(), byte[].class);
        BigInteger mintCount = ValuesLib.countTokensWithQty(txInfo.mint(), policyBytes, BigInteger.ONE);
        boolean exactlyOne = mintCount.compareTo(BigInteger.ONE) == 0;

        byte[] mintedName = ValuesLib.findTokenName(txInfo.mint(), policyBytes, BigInteger.ONE);

        // 2. Read public inputs from the output carrying the freshly minted claim NFT.
        //    Datum = ListData [pkU, pkV, epoch, nullifier, recipient, eligible].
        TxOut claimOutput = OutputLib.findOutputWithToken(txInfo.outputs(), policyBytes, policyBytes, mintedName);
        PlutusData datumData = OutputLib.getInlineDatum(claimOutput);
        PlutusData inputs = Builtins.unListData(datumData);
        PlutusData r1 = Builtins.tailList(inputs);
        PlutusData r2 = Builtins.tailList(r1);
        PlutusData r3 = Builtins.tailList(r2);
        PlutusData r4 = Builtins.tailList(r3);
        PlutusData r5 = Builtins.tailList(r4);
        BigInteger pub0 = Builtins.asInteger(Builtins.headList(inputs));      // pkU
        BigInteger pub1 = Builtins.asInteger(Builtins.headList(r1));          // pkV
        BigInteger pub2 = Builtins.asInteger(Builtins.headList(r2));          // epoch
        BigInteger pub3 = Builtins.asInteger(Builtins.headList(r3));          // nullifier
        BigInteger pub4 = Builtins.asInteger(Builtins.headList(r4));          // recipient
        BigInteger pub5 = Builtins.asInteger(Builtins.headList(r5));          // eligible

        // 3. Bind the registered issuer required by verifyWithRegisteredKey, require
        //    eligibility, and bind the token name to the public nullifier.
        boolean registeredIssuer = isRegisteredIssuer(pub0, pub1);
        boolean registeredEpoch = isRegisteredEpoch(pub2);
        boolean isEligible = pub5.compareTo(BigInteger.ONE) == 0;
        boolean nameCorrect = Builtins.equalsByteString(mintedName, Builtins.integerToByteString(true, 32, pub3));

        // 4. Groth16 BLS12-381 pairing check with 6 public inputs.
        PlutusData publicInputs = Groth16BLS12381Lib.publicInputs6(pub0, pub1, pub2, pub3, pub4, pub5);
        boolean proofValid = Groth16BLS12381Lib.verify(publicInputs,
                proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        return registeredIssuer && registeredEpoch
                && exactlyOne && nameCorrect && isEligible && proofValid;
    }

    static boolean isRegisteredIssuer(BigInteger publicKeyU, BigInteger publicKeyV) {
        return publicKeyU.equals(issuerPkU) && publicKeyV.equals(issuerPkV);
    }

    static boolean isRegisteredEpoch(BigInteger epoch) {
        return epoch.equals(policyEpoch);
    }
}
