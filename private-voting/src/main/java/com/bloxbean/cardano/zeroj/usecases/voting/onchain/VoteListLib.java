package com.bloxbean.cardano.zeroj.usecases.voting.onchain;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcList;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxOut;
import org.julclang.ledger.Value;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.OnchainLibrary;
import org.julclang.stdlib.lib.ByteStringLib;
import org.julclang.stdlib.lib.OutputLib;
import org.julclang.stdlib.lib.ValuesLib;

import java.math.BigInteger;

/**
 * On-chain validation logic for the vote list: a sorted linked list keyed by nullifier, each
 * node holding one ballot (ADR-0005). Adapted from LinkedListLib in julc-examples.
 *
 * <p>Node token names are {@code prefix ‖ key}. A vote node's key is the low 31 bytes of its
 * nullifier token's 32-byte name, so the sorted list admits each nullifier once.
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

    /**
     * Creates the root once (G5): the transaction must consume the seed output fixed in the
     * script parameters, which can be spent only once.
     */
    public static boolean validateInit(TxOut rootOutput, Value mint, byte[] policyId,
                                       byte[] rootKey, Address scriptAddr,
                                       JulcList<TxInInfo> inputs, byte[] seedRef) {
        boolean seedConsumed = false;
        for (TxInInfo input : inputs) {
            seedConsumed = seedConsumed
                    || Builtins.equalsByteString(ValuesLib.refBytes(input.outRef()), seedRef);
        }

        boolean atScript = Builtins.equalsData(rootOutput.address(), scriptAddr);

        // The root output is exact: lovelace plus the root token, datum Constr 0 [Constr 0 [], B ""].
        PlutusData expectedRoot = Builtins.constrData(0,
                Builtins.mkCons(Builtins.constrData(0, Builtins.mkNilData()),
                Builtins.mkCons(Builtins.bData(Builtins.emptyByteString()),
                        Builtins.mkNilData())));
        boolean emptyNext = Builtins.equalsData(OutputLib.getInlineDatum(rootOutput), expectedRoot);
        boolean rootHeld = ValuesLib.assetOf(rootOutput.value(), policyId, rootKey).compareTo(BigInteger.ONE) == 0
                && outerEntryCount(rootOutput.value()) == 2
                && policyEntryCount(rootOutput.value(), policyId) == 1;

        BigInteger rootQty = ValuesLib.assetOf(mint, policyId, rootKey);
        boolean rootMinted = rootQty.compareTo(BigInteger.ONE) == 0 && rootHeld;
        boolean onlyRoot = policyEntryCount(mint, policyId) == 1;

        return seedConsumed && atScript && emptyNext && rootMinted && onlyRoot;
    }

    public static boolean validateInsert(TxOut anchorInputResolved, JulcList<TxInInfo> inputs,
                                         JulcList<TxOut> outputs,
                                         Value mint, byte[] policyId,
                                         byte[] rootKey, byte[] prefix, int prefixLen,
                                         Address scriptAddr, byte[] zkPolicyId) {
        // G3: the anchor is the only input locked by the list script (by payment credential), so
        // an insert cannot also spend, drop or rewrite another voter's node.
        Credential listCredential = scriptAddr.credential();
        int listInputs = 0;
        for (TxInInfo input : inputs) {
            if (Builtins.equalsData(input.resolved().address().credential(), listCredential)) {
                listInputs = listInputs + 1;
            } else {
                listInputs = listInputs;
            }
        }
        boolean singleListInput = listInputs == 1
                && Builtins.equalsData(anchorInputResolved.address().credential(), listCredential);

        byte[] anchorTokenName = ValuesLib.findTokenName(
                anchorInputResolved.value(), policyId, BigInteger.ONE);
        boolean anchorIsRoot = isRootToken(anchorTokenName, rootKey);

        // Exactly one list token minted, nothing else under this policy: no stray nodes.
        byte[] newTokenName = ValuesLib.findTokenName(mint, policyId, BigInteger.ONE);
        boolean exactlyOne = policyEntryCount(mint, policyId) == 1
                && Builtins.lengthOfByteString(newTokenName) > 0;
        byte[] newKey = extractNodeKey(newTokenName, prefixLen);
        boolean nameCorrect = Builtins.equalsByteString(newTokenName, buildTokenName(prefix, newKey));

        // G2: the new key is the nullifier. Exactly one nullifier token is minted (the ballot
        // policy checks its proof); the key is its low 31 bytes; the new node holds it.
        byte[] zkName = ValuesLib.findTokenName(mint, zkPolicyId, BigInteger.ONE);
        boolean zkMinted = policyEntryCount(mint, zkPolicyId) == 1
                && Builtins.lengthOfByteString(zkName) == 32;
        boolean keyIsNullifier = Builtins.lengthOfByteString(newKey) == 31
                && Builtins.equalsByteString(newKey, ByteStringLib.drop(zkName, 1));

        TxOut contAnchorOutput = OutputLib.findOutputWithToken(
                outputs, policyId, policyId, anchorTokenName);
        TxOut newElementOutput = OutputLib.findOutputWithToken(
                outputs, policyId, policyId, newTokenName);

        boolean nodeHoldsNullifier = ValuesLib.assetOf(newElementOutput.value(), zkPolicyId, zkName)
                .compareTo(BigInteger.ONE) == 0;

        BigInteger contQty = ValuesLib.assetOf(contAnchorOutput.value(), policyId, anchorTokenName);
        boolean anchorPreserved = contQty.compareTo(BigInteger.ONE) == 0;
        boolean anchorZkPreserved = anchorIsRoot ||
                ValuesLib.assetOf(contAnchorOutput.value(), zkPolicyId,
                        ValuesLib.findTokenName(anchorInputResolved.value(), zkPolicyId, BigInteger.ONE))
                        .compareTo(BigInteger.ONE) == 0;

        // Exact values: the new node holds lovelace, its list token and its nullifier token; the
        // continuing anchor holds lovelace and exactly the anchor's own tokens. No dust, no
        // foreign nullifier tokens, so every node stays unambiguous and spendable.
        boolean newNodeExact = outerEntryCount(newElementOutput.value()) == 3
                && policyEntryCount(newElementOutput.value(), policyId) == 1
                && policyEntryCount(newElementOutput.value(), zkPolicyId) == 1;
        int contPolicies = outerEntryCount(contAnchorOutput.value());
        boolean contAnchorExact = policyEntryCount(contAnchorOutput.value(), policyId) == 1
                && ((anchorIsRoot && contPolicies == 2)
                    || (!anchorIsRoot && contPolicies == 3
                        && policyEntryCount(contAnchorOutput.value(), zkPolicyId) == 1));

        boolean contAtScript = Builtins.equalsData(contAnchorOutput.address(), scriptAddr);
        boolean newAtScript = Builtins.equalsData(newElementOutput.address(), scriptAddr);

        PlutusData anchorOld = OutputLib.getInlineDatum(anchorInputResolved);
        PlutusData contAnchor = OutputLib.getInlineDatum(contAnchorOutput);
        PlutusData newElement = OutputLib.getInlineDatum(newElementOutput);

        // The continuing anchor's datum is exactly ListElement(old userData, newKey): same ballot
        // (or the root's unit), next pointer moved to the new node, no extra fields. A datum the
        // off-chain walk cannot parse would make the election untallyable.
        boolean dataUnchanged = Builtins.equalsData(contAnchor, Builtins.constrData(0,
                Builtins.mkCons(elementUserData(anchorOld),
                Builtins.mkCons(Builtins.bData(newKey),
                        Builtins.mkNilData()))));

        byte[] anchorOldNextKey = elementNextKey(anchorOld);
        boolean contNextOk = dataUnchanged;
        boolean newNextOk = Builtins.equalsByteString(elementNextKey(newElement), anchorOldNextKey);

        boolean insertAtEnd = Builtins.equalsByteString(anchorOldNextKey, Builtins.emptyByteString());
        byte[] anchorKey = extractNodeKey(anchorTokenName, prefixLen);
        boolean orderOk = (anchorIsRoot || ByteStringLib.lessThan(anchorKey, newKey))
                && (insertAtEnd || ByteStringLib.lessThan(newKey, anchorOldNextKey));

        return singleListInput && exactlyOne && nameCorrect && zkMinted && keyIsNullifier
                && nodeHoldsNullifier && anchorPreserved && anchorZkPreserved
                && newNodeExact && contAnchorExact && contAtScript
                && newAtScript && dataUnchanged && contNextOk && newNextOk && orderOk;
    }

    /** The number of token names (any quantity, minted or burned) under {@code policyId}. */
    public static int policyEntryCount(Value mint, byte[] policyId) {
        var outerPairs = Builtins.unMapData(mint);
        PlutusData target = Builtins.bData(policyId);
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

    /** The number of entries in one policy's token map. */
    public static int innerEntryCount(PlutusData.MapData innerPairs) {
        int count = 0;
        PlutusData current = Builtins.unMapData(innerPairs);
        while (!Builtins.nullList(current)) {
            count = count + 1;
            current = Builtins.tailList(current);
        }
        return count;
    }

    /** The number of policies (lovelace included) in {@code value}. */
    public static int outerEntryCount(Value value) {
        var outerPairs = Builtins.unMapData(value);
        int count = 0;
        PlutusData current = outerPairs;
        while (!Builtins.nullList(current)) {
            count = count + 1;
            current = Builtins.tailList(current);
        }
        return count;
    }

    /** Whether {@code value} is a canonical BLS12-381 scalar-field element, {@code 0 ≤ value < p}. */
    public static boolean canonicalField(BigInteger value) {
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
