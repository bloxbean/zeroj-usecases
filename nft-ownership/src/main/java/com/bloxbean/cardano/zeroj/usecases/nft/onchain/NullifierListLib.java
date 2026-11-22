package com.bloxbean.cardano.zeroj.usecases.nft.onchain;

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
 * On-chain validation logic for the nullifier list: a sorted linked list keyed by nullifier
 * (ADR-0009 D2). Adapted from LinkedListLib in julc-examples and from the vote list.
 *
 * <p>Each node is a UTXO at the list address holding one list token ({@code prefix ‖ key}) and
 * one ZK token (the 32-byte nullifier). A node's key is the low 31 bytes of its ZK token's name,
 * so the sorted list admits each nullifier once. The list is created once (the root consumes a
 * seed output) and only grows: nodes are never burned or removed.
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
     * Spending check: the list policy mints exactly one token in this transaction, and burns
     * nothing. The minting purpose then decides whether that mint is the root or an insert.
     */
    public static boolean requireSingleListMint(Value mint, byte[] policyId) {
        return mintsExactlyOne(mint, policyId);
    }

    /** The mint map under {@code policyId} is exactly one entry, with quantity 1. */
    public static boolean mintsExactlyOne(Value mint, byte[] policyId) {
        return policyEntryCount(mint, policyId) == 1
                && ValuesLib.countTokensWithQty(mint, policyId, BigInteger.ONE).compareTo(BigInteger.ONE) == 0;
    }

    /** The number of inputs whose payment credential is {@code credential}. */
    public static int inputsAt(JulcList<TxInInfo> inputs, Credential credential) {
        int count = 0;
        for (TxInInfo input : inputs) {
            if (Builtins.equalsData(input.resolved().address().credential(), credential)) {
                count = count + 1;
            } else {
                count = count;
            }
        }
        return count;
    }

    // === Init validation ===

    /**
     * Creates the root once: the transaction consumes the seed output named in the script
     * parameters, which can be spent only once. It spends no list input, mints only the root
     * token, and the root token lands in the root output, at the list address, with datum
     * {@code ListElement((), "")} and no reference script.
     */
    public static boolean validateInit(TxOut rootOutput, Value mint, byte[] policyId,
                                       byte[] rootKey, Address scriptAddr,
                                       JulcList<TxInInfo> inputs, byte[] seedRef) {
        boolean seedConsumed = false;
        for (TxInInfo input : inputs) {
            seedConsumed = seedConsumed
                    || Builtins.equalsByteString(ValuesLib.refBytes(input.outRef()), seedRef);
        }
        boolean noListInput = inputsAt(inputs, scriptAddr.credential()) == 0;

        boolean atScript = Builtins.equalsData(rootOutput.address(), scriptAddr)
                && rootOutput.referenceScript().isEmpty();

        // The root output is exact: lovelace plus the root token, datum Constr 0 [Constr 0 [], B ""].
        PlutusData expectedRoot = Builtins.constrData(0,
                Builtins.mkCons(Builtins.constrData(0, Builtins.mkNilData()),
                Builtins.mkCons(Builtins.bData(Builtins.emptyByteString()),
                        Builtins.mkNilData())));
        boolean emptyNext = Builtins.equalsData(OutputLib.getInlineDatum(rootOutput), expectedRoot);
        boolean rootHeld = ValuesLib.assetOf(rootOutput.value(), policyId, rootKey).compareTo(BigInteger.ONE) == 0
                && outerEntryCount(rootOutput.value()) == 2
                && policyEntryCount(rootOutput.value(), policyId) == 1;

        boolean rootMinted = mintsExactlyOne(mint, policyId)
                && ValuesLib.assetOf(mint, policyId, rootKey).compareTo(BigInteger.ONE) == 0;

        return seedConsumed && noListInput && atScript && emptyNext && rootHeld && rootMinted;
    }

    // === Insert validation ===

    /**
     * Validates the sorted insertion of a new nullifier node.
     *
     * <ul>
     *   <li>The anchor is the only input at the list's payment credential, so an insert cannot
     *       also spend, drop or rewrite another node.</li>
     *   <li>The list policy mints exactly one token, {@code prefix ‖ key}; nothing is burned.</li>
     *   <li>The ZK policy mints exactly {@code {n: 1}} with {@code |n| = 32}, and
     *       {@code key = slice(1, 31, n)}: the new key is the proved nullifier.</li>
     *   <li>The new node holds exactly lovelace, its list token and the ZK token, at the list
     *       address, with datum {@code ListElement((), anchor.oldNext)}.</li>
     *   <li>The continuing anchor holds exactly the anchor's tokens and at least its lovelace, at
     *       the list address, with datum {@code ListElement(anchor.userData, key)}; the keys stay
     *       sorted.</li>
     *   <li>Neither output carries a reference script.</li>
     * </ul>
     */
    public static boolean validateInsert(TxOut anchorInputResolved, JulcList<TxInInfo> inputs,
                                         JulcList<TxOut> outputs,
                                         Value mint, byte[] policyId,
                                         byte[] rootKey, byte[] prefix, int prefixLen,
                                         Address scriptAddr, byte[] zkPolicyId) {
        Credential listCredential = scriptAddr.credential();
        boolean singleListInput = inputsAt(inputs, listCredential) == 1
                && Builtins.equalsData(anchorInputResolved.address().credential(), listCredential);

        byte[] anchorTokenName = ValuesLib.findTokenName(
                anchorInputResolved.value(), policyId, BigInteger.ONE);
        boolean anchorIsRoot = isRootToken(anchorTokenName, rootKey);

        // Exactly one list token minted, nothing else under this policy: no stray nodes, no burns.
        boolean exactlyOne = mintsExactlyOne(mint, policyId);
        byte[] newTokenName = ValuesLib.findTokenName(mint, policyId, BigInteger.ONE);
        byte[] newKey = extractNodeKey(newTokenName, prefixLen);
        boolean nameCorrect = Builtins.equalsByteString(newTokenName, buildTokenName(prefix, newKey));

        // The new key is the nullifier: exactly one 32-byte ZK token minted (the ZK policy checks
        // its proof), the key is its low 31 bytes, and the new node holds it.
        byte[] zkName = ValuesLib.findTokenName(mint, zkPolicyId, BigInteger.ONE);
        boolean zkMinted = mintsExactlyOne(mint, zkPolicyId)
                && Builtins.lengthOfByteString(zkName) == 32;
        boolean keyIsNullifier = Builtins.lengthOfByteString(newKey) == 31
                && Builtins.equalsByteString(newKey, ByteStringLib.slice(zkName, 1, 31));

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

        // Exact values: the new node holds lovelace, its list token and its ZK token; the
        // continuing anchor holds lovelace and exactly the anchor's own tokens.
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

        // No reference script on either output (it would make every later spender of the node pay
        // the per-byte reference-script fee), and the anchor keeps at least its lovelace.
        boolean noRefScripts = contAnchorOutput.referenceScript().isEmpty()
                && newElementOutput.referenceScript().isEmpty();
        boolean anchorLovelaceKept = ValuesLib.lovelaceOf(contAnchorOutput.value())
                .compareTo(ValuesLib.lovelaceOf(anchorInputResolved.value())) >= 0;

        PlutusData anchorOld = OutputLib.getInlineDatum(anchorInputResolved);
        PlutusData contAnchor = OutputLib.getInlineDatum(contAnchorOutput);
        PlutusData newElement = OutputLib.getInlineDatum(newElementOutput);
        byte[] anchorOldNextKey = elementNextKey(anchorOld);

        // Exact datums: the anchor keeps its userData and points at the new key; the new node
        // carries the unit userData and the anchor's old next pointer.
        boolean contDatumOk = Builtins.equalsData(contAnchor, Builtins.constrData(0,
                Builtins.mkCons(elementUserData(anchorOld),
                Builtins.mkCons(Builtins.bData(newKey),
                        Builtins.mkNilData()))));
        boolean newDatumOk = Builtins.equalsData(newElement, Builtins.constrData(0,
                Builtins.mkCons(Builtins.constrData(0, Builtins.mkNilData()),
                Builtins.mkCons(Builtins.bData(anchorOldNextKey),
                        Builtins.mkNilData()))));

        boolean insertAtEnd = Builtins.equalsByteString(anchorOldNextKey, Builtins.emptyByteString());
        byte[] anchorKey = extractNodeKey(anchorTokenName, prefixLen);
        boolean orderOk = (anchorIsRoot || ByteStringLib.lessThan(anchorKey, newKey))
                && (insertAtEnd || ByteStringLib.lessThan(newKey, anchorOldNextKey));

        return singleListInput && exactlyOne && nameCorrect && zkMinted && keyIsNullifier
                && nodeHoldsNullifier && anchorPreserved && anchorZkPreserved
                && newNodeExact && contAnchorExact && contAtScript && newAtScript
                && noRefScripts && anchorLovelaceKept
                && contDatumOk && newDatumOk && orderOk;
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

    /** Whether {@code value} is a canonical BLS12-381 scalar-field element, {@code 0 ≤ value < r}. */
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
