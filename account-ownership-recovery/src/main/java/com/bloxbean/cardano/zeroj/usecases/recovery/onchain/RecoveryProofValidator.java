package com.bloxbean.cardano.zeroj.usecases.recovery.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

/**
 * On-chain Groth16 BLS12-381 verifier for the account-ownership recovery gate.
 *
 * <p>Datum = [{@code commitment}, {@code addressKeyHashField}] — the recovery commitment and the
 * address's payment key hash (as a field element) that the ZK proof is bound to. Redeemer =
 * {@code Groth16Proof(piA, piB, piC)}. The transaction unlocks only if the Groth16 proof verifies
 * against these public inputs — i.e. the spender knows the recovery secret behind {@code commitment}
 * for {@code addressKeyHashField}.</p>
 */
@SpendingValidator
public class RecoveryProofValidator {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Groth16Proof proof, PlutusData ctx) {
        // datum is the list of public inputs [commitment, addressKeyHashField], in circuit order.
        return Groth16BLS12381Lib.verify(datum, proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }
}
