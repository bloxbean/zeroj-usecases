package com.bloxbean.cardano.zeroj.usecases.nft.onchain;

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
 * On-chain validation logic for the nullifier sorted linked list.
 * <p>
 * Adapted from LinkedListLib in julc-examples. Each node is a UTXO holding
 * a unique NFT (policyId, PREFIX + key). Nodes link via datum nextKey fields.
 * <p>
 * Supports: init (create empty list) and insert (add new nullifier in sorted order).
 * Nullifiers are permanent — no remove or deinit operations.
 */
@OnchainLibrary
public class NullifierListLib {

    // === Helpers ===

    static byte[] extractNodeKey(byte[] tokenName, int prefixLen) {
        return ByteStringLib.drop(tokenName, prefixLen);
    }

    static byte[] buildTokenName(byte[] prefix, byte[] key) {
        return ByteStringLib.append(prefix, key);
    }

    static boolean isRootToken(byte[] tokenName, byte[] rootKey) {
        return Builtins.equalsByteString(tokenName, rootKey);
    }

    /**
     * Spending validator check: own policy must appear in the mint field.
     * This couples the spend to the mint, ensuring the minting policy ran.
     */
    public static boolean requireListTokensMintedOrBurned(Value mint, byte[] policyId) {
        return ValuesLib.containsPolicy(mint, policyId);
    }

    // === Init validation ===

    /**
     * Validate list initialization: create root node with empty nextKey.
     */
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

    // === Insert validation ===

    /**
     * Validate sorted insertion of a new nullifier node.
     * <p>
     * Checks: sorted order, anchor updated, new node correct, outputs at script address,
     * exactly 1 new NFT minted, and ZK proof minting policy also minted in the tx.
     */
    public static boolean validateInsert(TxOut anchorInputResolved, JulcList<TxOut> outputs,
                                         Value mint, byte[] policyId,
                                         byte[] rootKey, byte[] prefix, int prefixLen,
                                         Address scriptAddr, byte[] zkPolicyId) {
        // Discover anchor's NFT token name
        byte[] anchorTokenName = ValuesLib.findTokenName(
                anchorInputResolved.value(), policyId, BigInteger.ONE);
        boolean anchorIsRoot = isRootToken(anchorTokenName, rootKey);

        // Discover newly minted NFT token name and extract key
        byte[] newTokenName = ValuesLib.findTokenName(mint, policyId, BigInteger.ONE);
        byte[] newKey = extractNodeKey(newTokenName, prefixLen);

        // Token name must be prefix + key
        byte[] expectedName = buildTokenName(prefix, newKey);
        boolean nameCorrect = Builtins.equalsByteString(newTokenName, expectedName);

        TxOut contAnchorOutput = OutputLib.findOutputWithToken(
                outputs, policyId, policyId, anchorTokenName);
        TxOut newElementOutput = OutputLib.findOutputWithToken(
                outputs, policyId, policyId, newTokenName);

        // Anchor NFT preserved in continuing output
        BigInteger contQty = ValuesLib.assetOf(contAnchorOutput.value(), policyId, anchorTokenName);
        boolean anchorPreserved = contQty.compareTo(BigInteger.ONE) == 0;

        // Continuing anchor and new element must be at script address
        boolean contAtScript = Builtins.equalsData(contAnchorOutput.address(), scriptAddr);
        boolean newAtScript = Builtins.equalsData(newElementOutput.address(), scriptAddr);

        // Extract datums
        PlutusData anchorOld = OutputLib.getInlineDatum(anchorInputResolved);
        PlutusData contAnchor = OutputLib.getInlineDatum(contAnchorOutput);
        PlutusData newElement = OutputLib.getInlineDatum(newElementOutput);

        // Anchor userData unchanged
        boolean dataUnchanged = Builtins.equalsData(elementUserData(anchorOld), elementUserData(contAnchor));

        // Continuing anchor's nextKey = new node's key
        byte[] anchorOldNextKey = elementNextKey(anchorOld);
        boolean contNextOk = Builtins.equalsByteString(elementNextKey(contAnchor), newKey);

        // New element's nextKey = anchor's old nextKey
        boolean newNextOk = Builtins.equalsByteString(elementNextKey(newElement), anchorOldNextKey);

        // Ordering: anchorKey < newKey (skip if root), newKey < oldNextKey (skip if end)
        boolean insertAtEnd = Builtins.equalsByteString(anchorOldNextKey, Builtins.emptyByteString());
        byte[] anchorKey = extractNodeKey(anchorTokenName, prefixLen);
        boolean orderOk = (anchorIsRoot || ByteStringLib.lessThan(anchorKey, newKey))
                && (insertAtEnd || ByteStringLib.lessThan(newKey, anchorOldNextKey));

        // Exactly 1 new NFT minted under list policy
        BigInteger mintCount = ValuesLib.countTokensWithQty(mint, policyId, BigInteger.ONE);
        boolean exactlyOne = mintCount.compareTo(BigInteger.ONE) == 0;

        // ZK proof minting policy also minted in this tx
        boolean zkProofVerified = ValuesLib.containsPolicy(mint, zkPolicyId);

        return nameCorrect && anchorPreserved && contAtScript && newAtScript
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
