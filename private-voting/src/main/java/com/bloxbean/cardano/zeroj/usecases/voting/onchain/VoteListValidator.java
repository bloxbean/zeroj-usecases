package com.bloxbean.cardano.zeroj.usecases.voting.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.*;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.MultiValidator;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.annotation.Purpose;
import org.julclang.stdlib.lib.ContextsLib;
import org.julclang.stdlib.lib.OutputLib;

import java.math.BigInteger;
import java.util.Optional;

/**
 * The vote list: a sorted linked list of ballots keyed by nullifier (ADR-0005). Adapted from
 * LinkedListValidator in julc-examples.
 *
 * <p>The minting purpose validates every change to the list; the spending purpose only requires
 * that it runs. {@code seedRef} ({@code txId ‖ I2OSP2(index)}) names an output that
 * {@code InitList} must consume, so the root can be created only once.
 */
@MultiValidator
public class VoteListValidator {

    @Param static byte[] rootKey;
    @Param static byte[] prefix;
    @Param static BigInteger prefixLen;
    @Param static byte[] zkPolicyId;
    @Param static byte[] seedRef;

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
                        rootOutput, txInfo.mint(), policyBytes, rootKey, scriptAddr,
                        txInfo.inputs(), seedRef);
            }
            case InsertNode insert -> {
                Address scriptAddr = new Address(
                        new Credential.ScriptCredential(PlutusData.cast(policyBytes, ScriptHash.class)),
                        Optional.empty());
                TxInInfo anchorInput = OutputLib.findInputWithToken(
                        txInfo.inputs(), policyBytes, policyBytes, insert.anchorTokenName());
                yield VoteListLib.validateInsert(
                        anchorInput.resolved(), txInfo.inputs(), txInfo.outputs(),
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
