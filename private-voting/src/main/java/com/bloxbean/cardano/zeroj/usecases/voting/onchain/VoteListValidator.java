package com.bloxbean.cardano.zeroj.usecases.voting.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.*;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.MultiValidator;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.Purpose;
import com.bloxbean.cardano.julc.stdlib.lib.ContextsLib;
import com.bloxbean.cardano.julc.stdlib.lib.OutputLib;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Sorted linked list validator for vote nullifiers.
 * Adapted from LinkedListValidator in julc-examples.
 */
@MultiValidator
public class VoteListValidator {

    @Param static byte[] rootKey;
    @Param static byte[] prefix;
    @Param static BigInteger prefixLen;
    @Param static byte[] zkPolicyId;

    sealed interface ListAction permits InitList, InsertNode {}
    record InitList(BigInteger rootOutputIndex) implements ListAction {}
    record InsertNode(byte[] anchorTokenName,
                      BigInteger contAnchorOutputIndex,
                      BigInteger newElementOutputIndex) implements ListAction {}

    @Entrypoint(purpose = Purpose.MINT)
    public static boolean mint(ListAction redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policyBytes = PlutusData.cast(mintInfo.policyId(), byte[].class);

        return switch (redeemer) {
            case InitList init -> {
                Address scriptAddr = new Address(
                        new Credential.ScriptCredential(PlutusData.cast(policyBytes, ScriptHash.class)),
                        Optional.empty());
                TxOut rootOutput = txInfo.outputs().get(init.rootOutputIndex().intValue());
                yield VoteListLib.validateInit(
                        rootOutput, txInfo.mint(), policyBytes, rootKey, scriptAddr);
            }
            case InsertNode insert -> {
                Address scriptAddr = new Address(
                        new Credential.ScriptCredential(PlutusData.cast(policyBytes, ScriptHash.class)),
                        Optional.empty());
                TxInInfo anchorInput = OutputLib.findInputWithToken(
                        txInfo.inputs(), policyBytes, policyBytes, insert.anchorTokenName());
                yield VoteListLib.validateInsert(
                        anchorInput.resolved(), txInfo.outputs(),
                        txInfo.mint(), policyBytes, rootKey, prefix, prefixLen.intValue(),
                        scriptAddr, zkPolicyId);
            }
        };
    }

    @Entrypoint(purpose = Purpose.SPEND)
    public static boolean spend(PlutusData datum, PlutusData redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        byte[] ownHash = ContextsLib.ownHash(ctx);
        return VoteListLib.requireListTokensMintedOrBurned(txInfo.mint(), ownHash);
    }
}
