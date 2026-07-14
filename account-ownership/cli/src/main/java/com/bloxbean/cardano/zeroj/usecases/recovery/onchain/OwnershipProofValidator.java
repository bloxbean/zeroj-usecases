package com.bloxbean.cardano.zeroj.usecases.recovery.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.Credential;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.ledger.TxOut;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * On-chain gate for the <b>recipient-bound</b> account-ownership statement (circuit v3): the spender's
 * wallet <em>root key</em> derives, via the full CIP-1852 path {@code m/1852'/account'/role/index},
 * to the datum's payment key hash <em>and</em> the proof is bound to a specific refund
 * {@code recipient}. Both the pkh and the recipient are the circuit's public inputs, so a passing
 * proof <em>is</em> proof of seed ownership tied to that one payout target — there is no auxiliary
 * secret to register.
 *
 * <p><b>Datum</b> {@code (pkh, refundAmount)} — the 28-byte address payment key hash the proof must
 * attest, and the minimum lovelace the recipient must receive. Written by whoever locks the voucher
 * (they know the compromised address and the amount owed); they do <em>not</em> choose the
 * recipient.</p>
 *
 * <p><b>Redeemer</b> {@code (piA, piB, piC, recipient)} — the compressed Groth16 proof and the
 * 28-byte recipient payment key hash the claimer chose at proving time. The recipient is bound into
 * the proof (public inputs 28..55), so a mismatched recipient fails verification.</p>
 *
 * <p>The validator enforces two things: (1) the proof verifies for public inputs
 * {@code [pack(pkh), pack(recipient)]} — each 28-byte hash packed big-endian into one field element,
 * matching the circuit; and (2) some transaction output pays that recipient's payment credential at
 * least {@code refundAmount}. Without (2) a tx submitter could relay the claim and keep the funds,
 * paying the recipient a token amount — so the payout check, not a recipient signature, is what makes
 * the refund safe. There is no deadline: the owner can claim whenever they wish.</p>
 *
 * <p>On-chain cost is O(#public inputs) at ~0.195e9 CPU steps each. The <b>packed v4</b> form has 2
 * public inputs → <b>~2.8e9 CPU steps</b> (measured in {@code OwnershipProofValidatorVmTest}), well
 * under the ~10e9 per-tx {@code maxTxExUnits} limit. (The earlier byte-per-input encoding used 56
 * public inputs → ~13.4e9, which exceeded the limit; packing moved the byte→scalar work in-circuit,
 * so here it is two {@code byteStringToInteger} calls.)</p>
 */
@SpendingValidator
public class OwnershipProofValidator {

    @Param static byte[] vkAlpha;   // G1 compressed 48 bytes
    @Param static byte[] vkBeta;    // G2 compressed 96 bytes
    @Param static byte[] vkGamma;   // G2 compressed 96 bytes
    @Param static byte[] vkDelta;   // G2 compressed 96 bytes
    @Param static PlutusData vkIc;  // List of G1 compressed 48-byte IC points

    /** Locked by the operator: the pkh to attest and the minimum refund the recipient is owed. */
    record OwnershipDatum(byte[] pkh, BigInteger refundAmount) {}

    /** Supplied by the claimer: the proof, and the recipient it was bound to. */
    record OwnershipRedeemer(byte[] piA, byte[] piB, byte[] piC, byte[] recipient) {}

    @Entrypoint
    public static boolean validate(OwnershipDatum datum, OwnershipRedeemer redeemer, ScriptContext ctx) {
        byte[] recipient = redeemer.recipient();

        // The circuit's 2 public inputs (v4): each 28-byte hash packed big-endian into one field
        // element — pkh then recipient. Matches the circuit's in-circuit packing.
        PlutusData publicInputs = twoInputs(
                Builtins.byteStringToInteger(true, datum.pkh()),
                Builtins.byteStringToInteger(true, recipient));

        boolean proofValid = Groth16BLS12381Lib.verify(publicInputs,
                redeemer.piA(), redeemer.piB(), redeemer.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        // Some output must pay the bound recipient at least the refund amount — otherwise the tx
        // submitter could redirect or short-change the funds while still presenting a valid proof.
        BigInteger minAmount = datum.refundAmount();
        boolean paid = ctx.txInfo().outputs().any(o -> paysAtLeast(o, recipient, minAmount));

        return proofValid && paid;
    }

    /** True if the output goes to {@code recipient}'s payment key credential with lovelace >= {@code min}. */
    private static boolean paysAtLeast(TxOut out, byte[] recipient, BigInteger min) {
        return credentialIs(out.address().credential(), recipient)
                && out.value().lovelaceOf().compareTo(min) >= 0;
    }

    /** True if {@code cred} is a payment key credential whose 28-byte hash equals {@code recipient}. */
    private static boolean credentialIs(Credential cred, byte[] recipient) {
        if (cred instanceof Credential.PubKeyCredential pk) {
            return Builtins.equalsByteString(Builtins.toByteString(pk.hash()), recipient);
        }
        return false;
    }

    /** The two packed public inputs as a {@code Data} list, in circuit order (pkh, recipient). */
    private static PlutusData twoInputs(BigInteger pkh, BigInteger recipient) {
        return Builtins.listData(
                Builtins.mkCons(Builtins.iData(pkh),
                        Builtins.mkCons(Builtins.iData(recipient), Builtins.mkNilData())));
    }
}
