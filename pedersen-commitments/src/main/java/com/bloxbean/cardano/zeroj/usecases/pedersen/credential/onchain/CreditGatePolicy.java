package com.bloxbean.cardano.zeroj.usecases.pedersen.credential.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.Credential;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.PubKeyHash;
import org.julclang.ledger.ScriptContext;
import org.julclang.ledger.ScriptInfo;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxInfo;
import org.julclang.ledger.TxOut;
import org.julclang.ledger.Value;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.MintingValidator;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.lib.ValuesLib;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * A lender's credit gate (ADR-0006 demo B): mints an access badge to a holder whose committed
 * credit profile meets the lender's thresholds.
 *
 * <p>Redeemer {@code Claim(holder, u, v, proof)}. The public inputs are
 * {@code [σ, u, v, minIncome, minScore]}: {@code σ} and the thresholds are parameters; {@code (u, v)}
 * must match an <b>issuance record</b> the transaction references, a token under the bureau's
 * policy named {@code blake2b_256(I2OSP32(u) ‖ I2OSP32(v) ‖ I2OSP32(σ) ‖ holder)} at an output
 * whose inline datum is {@code Record(u, v, σ, holder)}. No record, no badge (fail closed); and
 * because the name commits to the datum, a record cannot be relabelled to another commitment,
 * schema or holder.
 *
 * <p>The holder must sign; the gate's mint entry is exactly one badge named after the holder, and
 * it must be paid to an output with the holder's payment credential. Consumers of badges must
 * also check that the badge's name signed their transaction.
 */
@MintingValidator
public class CreditGatePolicy {

    @Param static byte[] schemaDigest;      // σ, I2OSP32
    @Param static byte[] issuerPolicyId;
    @Param static BigInteger minIncome;
    @Param static BigInteger minScore;
    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record Claim(byte[] holder, BigInteger u, BigInteger v, byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(Claim claim, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policy = PlutusData.cast(mintInfo.policyId(), byte[].class);
        BigInteger sigma = Builtins.byteStringToInteger(true, schemaDigest);
        byte[] holder = claim.holder();
        if (Builtins.lengthOfByteString(schemaDigest) != 32
                || Builtins.lengthOfByteString(issuerPolicyId) != 28
                || Builtins.lengthOfByteString(holder) != 28
                || !canonicalField(sigma) || !canonicalField(claim.u()) || !canonicalField(claim.v())
                || !signedBy(txInfo, holder)) {
            return false;
        }

        // Exactly one badge, named after the holder, paid to the holder.
        if (policyEntryCount(txInfo.mint(), policy) != 1
                || ValuesLib.assetOf(txInfo.mint(), policy, holder).compareTo(BigInteger.ONE) != 0) {
            return false;
        }
        Credential holderCredential = new Credential.PubKeyCredential(PlutusData.cast(holder, PubKeyHash.class));
        boolean paidToHolder = false;
        for (TxOut output : txInfo.outputs()) {
            paidToHolder = paidToHolder
                    || (Builtins.equalsData(output.address().credential(), holderCredential)
                        && ValuesLib.assetOf(output.value(), policy, holder).compareTo(BigInteger.ONE) == 0);
        }
        if (!paidToHolder) return false;

        // The issuance record, by its exact token and its exact datum.
        byte[] recordToken = Builtins.blake2b_256(Builtins.appendByteString(
                Builtins.integerToByteString(true, 32, claim.u()),
                Builtins.appendByteString(Builtins.integerToByteString(true, 32, claim.v()),
                        Builtins.appendByteString(schemaDigest, holder))));
        PlutusData expectedRecord = Builtins.constrData(0,
                Builtins.mkCons(Builtins.iData(claim.u()),
                Builtins.mkCons(Builtins.iData(claim.v()),
                Builtins.mkCons(Builtins.iData(sigma),
                Builtins.mkCons(Builtins.bData(holder),
                        Builtins.mkNilData())))));
        boolean recorded = false;
        for (TxInInfo reference : txInfo.referenceInputs()) {
            TxOut record = reference.resolved();
            recorded = recorded
                    || (ValuesLib.assetOf(record.value(), issuerPolicyId, recordToken).compareTo(BigInteger.ZERO) > 0
                        && Builtins.equalsData(inlineDatum(record), expectedRecord));
        }
        if (!recorded) return false;

        PlutusData publicInputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(sigma),
                Builtins.mkCons(Builtins.iData(claim.u()),
                Builtins.mkCons(Builtins.iData(claim.v()),
                Builtins.mkCons(Builtins.iData(minIncome),
                Builtins.mkCons(Builtins.iData(minScore),
                        Builtins.mkNilData()))))));
        return Groth16BLS12381Lib.verify(publicInputs, claim.piA(), claim.piB(), claim.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }

    private static boolean signedBy(TxInfo txInfo, byte[] pkh) {
        boolean found = false;
        for (var signer : txInfo.signatories()) {
            found = found || Builtins.equalsByteString(signer.hash(), pkh);
        }
        return found;
    }

    private static int policyEntryCount(Value value, byte[] policy) {
        var outerPairs = Builtins.unMapData(value);
        PlutusData target = Builtins.bData(policy);
        int count = 0;
        PlutusData current = outerPairs;
        while (!Builtins.nullList(current)) {
            var outerPair = Builtins.headList(current);
            if (Builtins.equalsData(Builtins.fstPair(outerPair), target)) {
                count = innerEntryCount((PlutusData.MapData) Builtins.sndPair(outerPair));
                current = Builtins.mkNilPairData();
            } else {
                current = Builtins.tailList(current);
            }
        }
        return count;
    }

    private static int innerEntryCount(PlutusData.MapData innerPairs) {
        int count = 0;
        PlutusData current = Builtins.unMapData(innerPairs);
        while (!Builtins.nullList(current)) {
            count = count + 1;
            current = Builtins.tailList(current);
        }
        return count;
    }

    private static PlutusData inlineDatum(TxOut output) {
        return switch (output.datum()) {
            case OutputDatum.OutputDatumInline inline -> inline.datum();
            case OutputDatum.OutputDatumHash ignored -> Builtins.iData(BigInteger.ZERO);
            case OutputDatum.NoOutputDatum ignored -> Builtins.iData(BigInteger.ZERO);
        };
    }

    private static boolean canonicalField(BigInteger value) {
        return value.compareTo(BigInteger.ZERO) >= 0 && value.compareTo(fr()) < 0;
    }

    private static BigInteger fr() {
        BigInteger base = BigInteger.valueOf(1000000000000000000L);
        return BigInteger.valueOf(52435L).multiply(base)
                .add(BigInteger.valueOf(875175126190479447L)).multiply(base)
                .add(BigInteger.valueOf(740508185965837690L)).multiply(base)
                .add(BigInteger.valueOf(552500527637822603L)).multiply(base)
                .add(BigInteger.valueOf(658699938581184513L));
    }
}
