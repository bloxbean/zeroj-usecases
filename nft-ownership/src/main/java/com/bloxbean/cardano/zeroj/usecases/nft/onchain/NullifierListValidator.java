package com.bloxbean.cardano.zeroj.usecases.nft.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.*;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.MultiValidator;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.Purpose;
import com.bloxbean.cardano.julc.stdlib.lib.ContextsLib;

import java.math.BigInteger;
import java.util.Optional;

/**
 * On-chain sorted linked list validator for nullifier storage.
 * <p>
 * Adapted from LinkedListValidator in julc-examples. Each nullifier is a UTXO
 * holding a unique NFT. Nodes link via datum nextKey fields in sorted order.
 * <p>
 * The MINT policy validates structural mutations (init/insert).
 * The SPEND validator delegates to the MINT policy via the coupling pattern.
 * <p>
 * Insert additionally requires that the ZK proof minting policy ({@code zkPolicyId})
 * also minted in the same transaction, ensuring the Groth16 proof was verified.
 */
@MultiValidator
public class NullifierListValidator {

    @Param static byte[] rootKey;       // e.g. "NROOT" — token name for the root NFT
    @Param static byte[] prefix;        // e.g. "N" — prefix for node token names (1 byte)
    @Param static BigInteger prefixLen; // e.g. 1 — byte length of prefix
    @Param static byte[] zkPolicyId;    // ZkProofMintingPolicy script hash

    // --- Redeemer variants ---

    sealed interface ListAction permits InitList, InsertNode {}
    record InitList(BigInteger rootOutputIndex) implements ListAction {}
    record InsertNode(BigInteger anchorInputIndex,
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
                        rootOutput, txInfo.mint(), policyBytes, rootKey, scriptAddr);
            }
            case InsertNode insert -> {
                Address scriptAddr = new Address(
                        new Credential.ScriptCredential(PlutusData.cast(policyBytes, ScriptHash.class)),
                        Optional.empty());
                TxInInfo anchorInput = txInfo.inputs().get(insert.anchorInputIndex().intValue());
                yield NullifierListLib.validateInsert(
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
        return NullifierListLib.requireListTokensMintedOrBurned(txInfo.mint(), ownHash);
    }
}
