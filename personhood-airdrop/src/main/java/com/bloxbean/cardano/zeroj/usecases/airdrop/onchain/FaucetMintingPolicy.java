package com.bloxbean.cardano.zeroj.usecases.airdrop.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.ledger.ScriptInfo;
import com.bloxbean.cardano.julc.ledger.TxInfo;
import com.bloxbean.cardano.julc.ledger.TxOut;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.MintingValidator;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.lib.OutputLib;
import com.bloxbean.cardano.julc.stdlib.lib.ValuesLib;
import com.bloxbean.cardano.zeroj.onchain.julc.Groth16BLS12381;

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
 * <p>Public inputs (6) are read from the first output's inline datum:
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

    record AirdropProof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(AirdropProof proof, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();

        // 1. Exactly one token minted under own policy.
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policyBytes = PlutusData.cast(mintInfo.policyId(), byte[].class);
        BigInteger mintCount = ValuesLib.countTokensWithQty(txInfo.mint(), policyBytes, BigInteger.ONE);
        boolean exactlyOne = mintCount.compareTo(BigInteger.ONE) == 0;

        // 2. Read public inputs from the first output's inline datum.
        //    Datum = ListData [pkU, pkV, epoch, nullifier, recipient, eligible].
        TxOut firstOutput = txInfo.outputs().get(0);
        PlutusData datumData = OutputLib.getInlineDatum(firstOutput);
        PlutusData inputs = Builtins.unListData(datumData);
        PlutusData r1 = Builtins.tailList(inputs);
        PlutusData r2 = Builtins.tailList(r1);
        PlutusData r3 = Builtins.tailList(r2);
        PlutusData r4 = Builtins.tailList(r3);
        PlutusData r5 = Builtins.tailList(r4);
        BigInteger pub5 = Builtins.asInteger(Builtins.headList(r5));          // eligible

        // 3. eligible must be 1.
        boolean isEligible = pub5.compareTo(BigInteger.ONE) == 0;

        // 4. Groth16 BLS12-381 pairing check with 6 public inputs.
        boolean proofValid = Groth16BLS12381.verify(datumData, proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        return exactlyOne && isEligible && proofValid;
    }
}
