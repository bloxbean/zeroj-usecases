package com.bloxbean.cardano.zeroj.usecases.nft.onchain;

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
 * On-chain sorted linked list of nullifiers (ADR-0009 D2). Adapted from LinkedListValidator in
 * julc-examples.
 *
 * <p>The minting purpose validates every change to the list; the spending purpose requires that
 * the list policy mints exactly one token in the same transaction. {@code seedRef}
 * ({@code txId ‖ I2OSP2(index)}) names an output that {@code InitList} must consume, so the root
 * is created once and every later list mint is an {@code InsertNode}. An insert may spend exactly
 * one input at the list address, its anchor, found by its token; so a node can be spent only as
 * an insert's anchor, and is never removed.
 *
 * <p>An insert also requires the ZK policy ({@code zkPolicyId}) to mint exactly the nullifier
 * whose low 31 bytes are the new key, which the ZK policy mints only for a verified proof.
 */
@MultiValidator
public class NullifierListValidator {

    @Param static byte[] rootKey;       // e.g. "NROOT" — token name for the root NFT
    @Param static byte[] prefix;        // e.g. "N" — prefix for node token names (1 byte)
    @Param static BigInteger prefixLen; // e.g. 1 — byte length of prefix
    @Param static byte[] zkPolicyId;    // ZkProofMintingPolicy script hash (one per event)
    @Param static byte[] seedRef;       // the output InitList must consume

    // --- Redeemer variants ---

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
                yield NullifierListLib.validateInit(
                        rootOutput, txInfo.mint(), policyBytes, rootKey, scriptAddr,
                        txInfo.inputs(), seedRef);
            }
            case InsertNode insert -> {
                Address scriptAddr = new Address(
                        new Credential.ScriptCredential(PlutusData.cast(policyBytes, ScriptHash.class)),
                        Optional.empty());
                TxInInfo anchorInput = OutputLib.findInputWithToken(
                        txInfo.inputs(), policyBytes, policyBytes, insert.anchorTokenName());
                yield NullifierListLib.validateInsert(
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
        return NullifierListLib.requireSingleListMint(txInfo.mint(), ownHash);
    }
}
