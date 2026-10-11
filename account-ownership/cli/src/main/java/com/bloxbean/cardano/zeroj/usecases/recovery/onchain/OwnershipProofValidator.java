package com.bloxbean.cardano.zeroj.usecases.recovery.onchain;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcList;
import org.julclang.ledger.Credential;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.ScriptContext;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxOut;
import org.julclang.ledger.TxOutRef;
import org.julclang.ledger.Value;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.julclang.stdlib.lib.ContextsLib;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;
import java.util.Optional;

/**
 * On-chain gate for the <b>recipient-bound</b> account-ownership statement (circuit v4, packed
 * public inputs): the spender's wallet <em>root key</em> derives, via the full CIP-1852 path
 * {@code m/1852'/account'/role/index}, to the datum's payment key hash <em>and</em> the proof is
 * bound to a specific refund {@code recipient}. Both the pkh and the recipient are the circuit's
 * public inputs, so a passing proof <em>is</em> proof of seed ownership tied to that one payout
 * target — there is no auxiliary secret to register.
 *
 * <p><b>Datum</b> {@code (pkh, refundAmount, funderPkh, maxFee)} — the 28-byte address payment key
 * hash the proof must attest, the minimum lovelace the recipient must receive, the funder's 28-byte
 * payment key hash that gets the remainder back, and the fee slack. Written by whoever locks the
 * voucher (they know the compromised address and the amount owed); they do <em>not</em> choose the
 * recipient.</p>
 *
 * <p><b>Redeemer</b> {@code (piA, piB, piC, recipient)} — the compressed Groth16 proof and the
 * 28-byte recipient payment key hash the claimer chose at proving time. The recipient is the proof's
 * second public input, so a mismatched recipient fails verification.</p>
 *
 * <p>The validator enforces two things: (1) the proof verifies for the 2 public inputs
 * {@code [pack(pkh), pack(recipient)]} — each 28-byte hash packed big-endian into one field element,
 * matching the circuit; and (2) the voucher pays exactly what it owes (ADR-0009 D6). Without (2) a
 * tx submitter could relay the claim and keep the funds, so the payout check, not a recipient
 * signature, is what makes the refund safe. There is no deadline: the owner can claim whenever they
 * wish.</p>
 *
 * <p><b>Payout rule (D6).</b> Only outputs whose inline datum is exactly the spent voucher's
 * {@code TxOutRef} count as its payments, so no output can pay two vouchers of tag-enforcing
 * validators (this one and {@code BbsKycClaimValidator}), whatever their stake credentials. The
 * voucher's value must be ADA-only. Tagged outputs to the recipient's key credential sum to at least
 * {@code refundAmount}, and tagged outputs to the funder's key credential to at least the remainder
 * {@code voucherLovelace − refundAmount − maxFee} (none needed when it is 0). If funder and recipient
 * are the same key, their combined tagged sum covers both. {@code refundAmount ≥ 0},
 * {@code maxFee ≥ 0} and {@code refundAmount + maxFee ≤ voucherLovelace}. Whoever submits the claim
 * can keep {@code maxFee} minus the actual fee. Composing a voucher spend with a script that ignores
 * tags is unsafe: that script may count the same outputs.</p>
 *
 * <p>On-chain cost is dominated by the Groth16 verify, which is O(#public inputs): with 2 public
 * inputs it measures about 2.3×10⁹ CPU steps in {@code OwnershipProofValidatorVmTest}, well under the
 * per-tx limit. (The earlier byte-per-input encoding used 56 public inputs, ~13.4×10⁹, which exceeded
 * it; packing moved the byte→scalar work in-circuit, so here it is two {@code byteStringToInteger}
 * calls.)</p>
 */
@SpendingValidator
public class OwnershipProofValidator {

    @Param static byte[] vkAlpha;   // G1 compressed 48 bytes
    @Param static byte[] vkBeta;    // G2 compressed 96 bytes
    @Param static byte[] vkGamma;   // G2 compressed 96 bytes
    @Param static byte[] vkDelta;   // G2 compressed 96 bytes
    @Param static PlutusData vkIc;  // List of G1 compressed 48-byte IC points

    /** Locked by the funder: the pkh to attest, the refund owed, who gets the remainder, the fee slack. */
    record OwnershipDatum(byte[] pkh, BigInteger refundAmount, byte[] funderPkh, BigInteger maxFee) {}

    /** Supplied by the claimer: the proof, and the recipient it was bound to. */
    record OwnershipRedeemer(byte[] piA, byte[] piB, byte[] piC, byte[] recipient) {}

    @Entrypoint
    public static boolean validate(OwnershipDatum datum, OwnershipRedeemer redeemer, ScriptContext ctx) {
        byte[] recipient = redeemer.recipient();

        // Packing drops leading zero bytes, so a 27-byte pkh and the same bytes behind a 0x00 pack
        // to the same scalar. Only a 28-byte pkh names an address (the recipient is checked in
        // voucherPaid).
        if (Builtins.lengthOfByteString(datum.pkh()) != 28) return false;

        // The circuit's 2 public inputs (v4): each 28-byte hash packed big-endian into one field
        // element — pkh then recipient. Matches the circuit's in-circuit packing.
        PlutusData publicInputs = twoInputs(
                Builtins.byteStringToInteger(true, datum.pkh()),
                Builtins.byteStringToInteger(true, recipient));

        boolean proofValid = Groth16BLS12381Lib.verify(publicInputs,
                redeemer.piA(), redeemer.piB(), redeemer.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        // The voucher pays exactly what it owes, through outputs tagged with its own outref: the
        // refund to the bound recipient and the remainder (less at most maxFee) back to the funder.
        // Otherwise the tx submitter could redirect or keep the funds while presenting a valid proof.
        boolean paid = voucherPaid(ctx, recipient, datum.funderPkh(), datum.refundAmount(), datum.maxFee());

        return paid && proofValid;
    }

    /**
     * The D6 payout rule for the voucher this script spends (see the class javadoc). Fails closed
     * if the own input can't be found.
     */
    private static boolean voucherPaid(ScriptContext ctx, byte[] recipient, byte[] funder,
                                       BigInteger refund, BigInteger maxFee) {
        Optional<TxInInfo> ownInput = ContextsLib.findOwnInput(ctx);
        if (ownInput.isEmpty()) return false;
        TxInInfo voucher = ownInput.get();
        Value value = voucher.resolved().value();
        BigInteger lovelace = value.lovelaceOf();
        if (outerEntryCount(value) != 1
                || Builtins.lengthOfByteString(recipient) != 28
                || Builtins.lengthOfByteString(funder) != 28
                || refund.compareTo(BigInteger.ZERO) < 0
                || maxFee.compareTo(BigInteger.ZERO) < 0
                || refund.add(maxFee).compareTo(lovelace) > 0) {
            return false;
        }
        BigInteger remainder = lovelace.subtract(refund).subtract(maxFee);
        TxOutRef tag = voucher.outRef();
        JulcList<TxOut> outputs = ctx.txInfo().outputs();
        BigInteger toRecipient = taggedSum(outputs, recipient, tag);
        if (Builtins.equalsByteString(recipient, funder)) {
            return toRecipient.compareTo(refund.add(remainder)) >= 0;
        }
        return toRecipient.compareTo(refund) >= 0
                && taggedSum(outputs, funder, tag).compareTo(remainder) >= 0;
    }

    /** Lovelace on outputs to {@code pkh}'s payment key credential whose inline datum is {@code tag}. */
    private static BigInteger taggedSum(JulcList<TxOut> outputs, byte[] pkh, TxOutRef tag) {
        BigInteger sum = BigInteger.ZERO;
        for (TxOut output : outputs) {
            if (credentialIs(output.address().credential(), pkh)
                    && Builtins.equalsData(inlineDatum(output), tag)) {
                sum = sum.add(output.value().lovelaceOf());
            } else {
                sum = sum;
            }
        }
        return sum;
    }

    /** The inline datum; a missing or hashed datum yields an integer, which no outref tag equals. */
    private static PlutusData inlineDatum(TxOut output) {
        return switch (output.datum()) {
            case OutputDatum.OutputDatumInline inline -> inline.datum();
            case OutputDatum.OutputDatumHash ignored -> Builtins.iData(BigInteger.ZERO);
            case OutputDatum.NoOutputDatum ignored -> Builtins.iData(BigInteger.ZERO);
        };
    }

    /** The number of policies (lovelace included) in a value; 1 means ADA-only. */
    private static int outerEntryCount(Value value) {
        int count = 0;
        PlutusData current = Builtins.unMapData(value);
        while (!Builtins.nullList(current)) {
            count = count + 1;
            current = Builtins.tailList(current);
        }
        return count;
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
