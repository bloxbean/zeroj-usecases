package com.bloxbean.cardano.zeroj.usecases.voting.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
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

    public record ListElement(PlutusData userData, byte[] nextKey) {}

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

        ListElement datum = PlutusData.cast(OutputLib.getInlineDatum(rootOutput), ListElement.class);
        boolean emptyNext = Builtins.equalsByteString(datum.nextKey(), Builtins.emptyByteString());

        BigInteger rootQty = ValuesLib.assetOf(mint, policyId, rootKey);
        boolean rootMinted = rootQty.compareTo(BigInteger.ONE) == 0;

        BigInteger mintCount = ValuesLib.countTokensWithQty(mint, policyId, BigInteger.ONE);
        boolean onlyOne = mintCount.compareTo(BigInteger.ONE) == 0;

        return atScript && emptyNext && rootMinted && onlyOne;
    }

    public static boolean validateInsert(TxOut anchorInputResolved, TxOut contAnchorOutput,
                                         TxOut newElementOutput, Value mint, byte[] policyId,
                                         byte[] rootKey, byte[] prefix, int prefixLen,
                                         Address scriptAddr, byte[] zkPolicyId) {
        byte[] anchorTokenName = ValuesLib.findTokenName(
                anchorInputResolved.value(), policyId, BigInteger.ONE);
        boolean anchorIsRoot = isRootToken(anchorTokenName, rootKey);

        byte[] newTokenName = ValuesLib.findTokenName(mint, policyId, BigInteger.ONE);
        byte[] newKey = extractNodeKey(newTokenName, prefixLen);

        byte[] expectedName = buildTokenName(prefix, newKey);
        boolean nameCorrect = Builtins.equalsByteString(newTokenName, expectedName);

        BigInteger contQty = ValuesLib.assetOf(contAnchorOutput.value(), policyId, anchorTokenName);
        boolean anchorPreserved = contQty.compareTo(BigInteger.ONE) == 0;

        boolean contAtScript = Builtins.equalsData(contAnchorOutput.address(), scriptAddr);
        boolean newAtScript = Builtins.equalsData(newElementOutput.address(), scriptAddr);

        ListElement anchorOld = PlutusData.cast(OutputLib.getInlineDatum(anchorInputResolved), ListElement.class);
        ListElement contAnchor = PlutusData.cast(OutputLib.getInlineDatum(contAnchorOutput), ListElement.class);
        ListElement newElement = PlutusData.cast(OutputLib.getInlineDatum(newElementOutput), ListElement.class);

        // Anchor userData unchanged (root has unit data, stays unit)
        boolean dataUnchanged = Builtins.equalsData(anchorOld.userData(), contAnchor.userData());

        boolean contNextOk = Builtins.equalsByteString(contAnchor.nextKey(), newKey);
        boolean newNextOk = Builtins.equalsByteString(newElement.nextKey(), anchorOld.nextKey());

        byte[] oldNextKey = anchorOld.nextKey();
        boolean insertAtEnd = Builtins.equalsByteString(oldNextKey, Builtins.emptyByteString());
        byte[] anchorKey = extractNodeKey(anchorTokenName, prefixLen);
        boolean orderOk = (anchorIsRoot || ByteStringLib.lessThan(anchorKey, newKey))
                && (insertAtEnd || ByteStringLib.lessThan(newKey, oldNextKey));

        BigInteger mintCount = ValuesLib.countTokensWithQty(mint, policyId, BigInteger.ONE);
        boolean exactlyOne = mintCount.compareTo(BigInteger.ONE) == 0;

        boolean zkProofVerified = ValuesLib.containsPolicy(mint, zkPolicyId);

        return nameCorrect && anchorPreserved && contAtScript && newAtScript
                && dataUnchanged && contNextOk && newNextOk && orderOk
                && exactlyOne && zkProofVerified;
    }
}
