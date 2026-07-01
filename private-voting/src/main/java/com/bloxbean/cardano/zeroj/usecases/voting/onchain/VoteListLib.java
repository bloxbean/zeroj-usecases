package com.bloxbean.cardano.zeroj.usecases.voting.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.core.types.JulcList;
import com.bloxbean.cardano.julc.ledger.Address;
import com.bloxbean.cardano.julc.ledger.TxOut;
import com.bloxbean.cardano.julc.ledger.Value;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.OnchainLibrary;
import com.bloxbean.cardano.julc.stdlib.lib.ByteStringLib;
import com.bloxbean.cardano.julc.stdlib.lib.OutputLib;
import com.bloxbean.cardano.julc.stdlib.lib.ValuesLib;

import java.math.BigInteger;

/**
 * On-chain validation logic for the vote nullifier sorted linked list.
 * <p>
 * Each node stores a vote commitment in userData and links to the next node by key.
 * Adapted from LinkedListLib in julc-examples.
 */
@OnchainLibrary
public class VoteListLib {

    static byte[] extractNodeKey(byte[] tokenName, int prefixLen) {
        return ByteStringLib.drop(tokenName, prefixLen);
    }

    static byte[] buildTokenName(byte[] prefix, byte[] key) {
        return ByteStringLib.append(prefix, key);
    }

    static boolean isRootToken(byte[] tokenName, byte[] rootKey) {
        return Builtins.equalsByteString(tokenName, rootKey);
    }

    public static boolean requireListTokensMintedOrBurned(Value mint, byte[] policyId) {
        return ValuesLib.containsPolicy(mint, policyId);
    }

    public static boolean validateInit(TxOut rootOutput, Value mint, byte[] policyId,
                                       byte[] rootKey, Address scriptAddr) {
        boolean atScript = Builtins.equalsData(rootOutput.address(), scriptAddr);

        PlutusData datum = OutputLib.getInlineDatum(rootOutput);
        boolean emptyNext = Builtins.equalsByteString(elementNextKey(datum), Builtins.emptyByteString());

        BigInteger rootQty = ValuesLib.assetOf(mint, policyId, rootKey);
        boolean rootMinted = rootQty.compareTo(BigInteger.ONE) == 0;

        BigInteger mintCount = ValuesLib.countTokensWithQty(mint, policyId, BigInteger.ONE);
        boolean onlyOne = mintCount.compareTo(BigInteger.ONE) == 0;

        return atScript && emptyNext && rootMinted && onlyOne;
    }

    public static boolean validateInsert(TxOut anchorInputResolved, JulcList<TxOut> outputs,
                                         Value mint, byte[] policyId,
                                         byte[] rootKey, byte[] prefix, int prefixLen,
                                         Address scriptAddr, byte[] zkPolicyId) {
        byte[] anchorTokenName = ValuesLib.findTokenName(
                anchorInputResolved.value(), policyId, BigInteger.ONE);
        boolean anchorIsRoot = isRootToken(anchorTokenName, rootKey);

        byte[] newTokenName = ValuesLib.findTokenName(mint, policyId, BigInteger.ONE);
        byte[] newKey = extractNodeKey(newTokenName, prefixLen);

        byte[] expectedName = buildTokenName(prefix, newKey);
        boolean nameCorrect = Builtins.equalsByteString(newTokenName, expectedName);

        TxOut contAnchorOutput = OutputLib.findOutputWithToken(
                outputs, policyId, policyId, anchorTokenName);
        TxOut newElementOutput = OutputLib.findOutputWithToken(
                outputs, policyId, policyId, newTokenName);

        BigInteger contQty = ValuesLib.assetOf(contAnchorOutput.value(), policyId, anchorTokenName);
        boolean anchorPreserved = contQty.compareTo(BigInteger.ONE) == 0;
        boolean anchorZkPreserved = anchorIsRoot ||
                ValuesLib.assetOf(contAnchorOutput.value(), zkPolicyId,
                        ValuesLib.findTokenName(anchorInputResolved.value(), zkPolicyId, BigInteger.ONE))
                        .compareTo(BigInteger.ONE) == 0;

        boolean contAtScript = Builtins.equalsData(contAnchorOutput.address(), scriptAddr);
        boolean newAtScript = Builtins.equalsData(newElementOutput.address(), scriptAddr);

        PlutusData anchorOld = OutputLib.getInlineDatum(anchorInputResolved);
        PlutusData contAnchor = OutputLib.getInlineDatum(contAnchorOutput);
        PlutusData newElement = OutputLib.getInlineDatum(newElementOutput);

        // Anchor userData unchanged (root has unit data, stays unit)
        boolean dataUnchanged = Builtins.equalsData(elementUserData(anchorOld), elementUserData(contAnchor));

        byte[] anchorOldNextKey = elementNextKey(anchorOld);
        boolean contNextOk = Builtins.equalsByteString(elementNextKey(contAnchor), newKey);
        boolean newNextOk = Builtins.equalsByteString(elementNextKey(newElement), anchorOldNextKey);

        boolean insertAtEnd = Builtins.equalsByteString(anchorOldNextKey, Builtins.emptyByteString());
        byte[] anchorKey = extractNodeKey(anchorTokenName, prefixLen);
        boolean orderOk = (anchorIsRoot || ByteStringLib.lessThan(anchorKey, newKey))
                && (insertAtEnd || ByteStringLib.lessThan(newKey, anchorOldNextKey));

        BigInteger mintCount = ValuesLib.countTokensWithQty(mint, policyId, BigInteger.ONE);
        boolean exactlyOne = mintCount.compareTo(BigInteger.ONE) == 0;

        boolean zkProofVerified = ValuesLib.containsPolicy(mint, zkPolicyId);

        return nameCorrect && anchorPreserved && anchorZkPreserved && contAtScript && newAtScript
                && dataUnchanged && contNextOk && newNextOk && orderOk
                && exactlyOne && zkProofVerified;
    }

    private static PlutusData elementUserData(PlutusData elementDatum) {
        PlutusData fields = Builtins.constrFields(elementDatum);
        return Builtins.headList(fields);
    }

    private static byte[] elementNextKey(PlutusData elementDatum) {
        PlutusData fields = Builtins.constrFields(elementDatum);
        PlutusData afterUserData = Builtins.tailList(fields);
        return Builtins.unBData(Builtins.headList(afterUserData));
    }
}
