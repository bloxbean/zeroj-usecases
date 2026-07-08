package com.bloxbean.cardano.zeroj.usecases.recovery.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

/**
 * On-chain Groth16 BLS12-381 verifier for the <b>real</b> account-ownership statement (ADR-0029 M5):
 * the spender's wallet <em>root key</em> derives, via the full CIP-1852 path
 * {@code m/1852'/1815'/0'/0/0}, to the address's payment key hash.
 *
 * <p>Unlike {@link RecoveryProofValidator} (which gates on knowledge of a registered
 * Poseidon-commitment secret), this validator is parameterized with the verification key of the
 * ~19M-constraint {@code OwnershipProof} derivation circuit — so a passing proof <em>is</em> proof
 * of seed ownership; there is no auxiliary secret to register. On-chain cost is independent of the
 * circuit's size (Groth16 verification is O(#public inputs)).</p>
 *
 * <p>Datum = the circuit's public inputs in order: the 28 bytes of the address payment key hash,
 * each as a field element. Redeemer = {@code Groth16Proof(piA, piB, piC)}. (Demo parity with
 * {@code RecoveryProofValidator}: production validators must additionally bind
 * {@code ScriptContext} — see {@code Groth16BLS12381TxOutRefBindingVerifier}.)</p>
 */
@SpendingValidator
public class OwnershipProofValidator {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Groth16Proof proof, PlutusData ctx) {
        // datum = [pkh_0 .. pkh_27] — the payment-key-hash bytes, in circuit public-input order.
        return Groth16BLS12381Lib.verify(datum, proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }
}
