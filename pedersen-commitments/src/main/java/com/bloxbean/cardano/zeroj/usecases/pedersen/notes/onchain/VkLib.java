package com.bloxbean.cardano.zeroj.usecases.pedersen.notes.onchain;

import org.julclang.core.PlutusData;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.OnchainLibrary;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

/**
 * Groth16 verification against a verification key pinned by hash (ADR-0007 N2): the script
 * parameter is {@code blake2b_256(serialiseData(vk))}, and the redeemer carries
 * {@code vk = Constr 0 [B alpha, B beta, B gamma, B delta, [B ic_0, …]]}. A key whose hash differs
 * is refused before any pairing. This keeps the verification keys out of the script, so the ledger
 * fits a reference script.
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
}
