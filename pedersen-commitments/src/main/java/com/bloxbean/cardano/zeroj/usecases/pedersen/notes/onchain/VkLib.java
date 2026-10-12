package com.bloxbean.cardano.zeroj.usecases.pedersen.notes.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.Credential;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxInfo;
import org.julclang.ledger.TxOut;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.OnchainLibrary;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * Groth16 verification against a verification key pinned by hash (ADR-0007 N2): the script
 * parameter is {@code blake2b_256(serialiseData(vk))} with
 * {@code vk = Constr 0 [B alpha, B beta, B gamma, B delta, [B ic_0, …]]}. A key whose hash differs
 * is refused before any pairing. This keeps the verification keys out of the script, so the ledger
 * fits a reference script.
 *
 * <p>The keys themselves travel in the inline datum (a list of keys) of a <b>key carrier</b>: an
 * output at the script's own address without a reference script, deployed once and referenced by
 * every transaction. A reference input's datum is not part of the transaction, so it costs no size
 * fee, where a key in the redeemer cost about a kilobyte per transaction. Where the key comes from
 * does not matter for soundness: only a key whose hash is the pinned parameter is ever used.
 */
@OnchainLibrary
public class VkLib {

    public static boolean verify(PlutusData publicInputs, byte[] piA, byte[] piB, byte[] piC,
                                 PlutusData vk, byte[] vkHash) {
        if (!Builtins.equalsByteString(Builtins.blake2b_256(Builtins.serialiseData(vk)), vkHash)) return false;
        PlutusData f0 = Builtins.constrFields(vk);
        PlutusData f1 = Builtins.tailList(f0);
        PlutusData f2 = Builtins.tailList(f1);
        PlutusData f3 = Builtins.tailList(f2);
        PlutusData f4 = Builtins.tailList(f3);
        return Groth16BLS12381Lib.verify(publicInputs, piA, piB, piC,
                Builtins.unBData(Builtins.headList(f0)),
                Builtins.unBData(Builtins.headList(f1)),
                Builtins.unBData(Builtins.headList(f2)),
                Builtins.unBData(Builtins.headList(f3)),
                Builtins.headList(f4));
    }

    /**
     * Key {@code index} (0 to 3) of the key list in the inline datum of a reference input at the
     * script's own payment credential {@code own} that carries no reference script (the key
     * carrier). No such input, a datum that is not a list, or a shorter list makes a builtin fail
     * (fail closed); the caller's hash check decides whether the key is the right one.
     */
    public static PlutusData referenceVk(TxInfo txInfo, Credential own, int index) {
        PlutusData found = Builtins.iData(BigInteger.ZERO);
        for (TxInInfo reference : txInfo.referenceInputs()) {
            TxOut out = reference.resolved();
            if (out.referenceScript().isEmpty() && Builtins.equalsData(out.address().credential(), own)) {
                found = ChainLib.inlineDatum(out);
            } else {
                found = found;
            }
        }
        PlutusData k0 = Builtins.unListData(found);
        if (index == 0) return Builtins.headList(k0);
        PlutusData k1 = Builtins.tailList(k0);
        if (index == 1) return Builtins.headList(k1);
        PlutusData k2 = Builtins.tailList(k1);
        if (index == 2) return Builtins.headList(k2);
        return Builtins.headList(Builtins.tailList(k2));
    }
}
