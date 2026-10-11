package com.bloxbean.cardano.zeroj.usecases.reusablekyc.onchain;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcList;
import org.julclang.ledger.Credential;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.ScriptContext;
import org.julclang.ledger.ScriptInfo;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxOut;
import org.julclang.ledger.TxOutRef;
import org.julclang.ledger.Value;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.julclang.stdlib.lib.ContextsLib;
import org.zeroj.onchain.julc.bbs.lib.BbsProofVerify;

import java.math.BigInteger;
import java.util.Optional;

/**
 * The reusable-KYC on-chain claim gate (ADR-0003). A voucher UTxO locked at this validator is spent
 * only by a holder who presents a valid <b>BBS selective-disclosure</b> proof of an issuer-signed KYC
 * credential — verified <b>natively on-chain</b> — that discloses exactly the attributes this voucher
 * requires, and only if the payout goes to the voucher's recipient.
 *
 * <p><b>Params</b> — the issuer's BBS verification material, baked at deploy: public key {@code W}
 * (G2), the G2 generator, the ciphersuite {@code P1}, the BBS generators {@code Q1, H1..H5}, the
 * precomputed {@code domain} scalar, and the two DSTs. These are deterministic for a given
 * issuer/schema/header.</p>
 *
 * <p><b>Datum</b> {@code (requiredCountry, requiredKycLevel, recipientPkh, refundAmount, funderPkh,
 * maxFee)} — the claim policy written by whoever funds the voucher. <b>Redeemer</b> — the BBS proof +
 * the two disclosed messages + the presentation header.</p>
 *
 * <p>Checks: (1) the presentation is bound to <b>this</b> voucher — the expected header is recomputed
 * here, not taken on trust; (2) the disclosed values match the voucher's policy; (3) the BBS
 * presentation verifies under the issuer's key (so the values really are issuer-signed and the
 * undisclosed attributes stay hidden); (4) the voucher pays exactly what it owes (ADR-0009 D6).
 * Spending the voucher UTxO is itself the nullifier — the eUTxO model allows it exactly once, which is
 * also what makes the derived header unique per claim.</p>
 *
 * <p><b>Payout rule (D6).</b> Only outputs whose inline datum is exactly the spent voucher's
 * {@code TxOutRef} count as its payments, so no output can pay two vouchers of tag-enforcing
 * validators (this one and {@code OwnershipProofValidator}), whatever their stake credentials. The
 * voucher's value must be ADA-only. Tagged outputs to the recipient's key credential sum to at least
 * {@code refundAmount}, and tagged outputs to the funder's key credential to at least the remainder
 * {@code voucherLovelace − refundAmount − maxFee} (none needed when it is 0). If funder and recipient
 * are the same key, their combined tagged sum covers both. {@code refundAmount ≥ 0},
 * {@code maxFee ≥ 0} and {@code refundAmount + maxFee ≤ voucherLovelace}. Whoever submits the claim
 * can keep {@code maxFee} minus the actual fee (the fee slack), so the funder sets it close to the
 * expected fee. Composing a voucher spend with a script that ignores tags is unsafe: that script may
 * count the same outputs.</p>
 */
@SpendingValidator
public class BbsKycClaimValidator {

    @Param static byte[] w;
    @Param static byte[] bp2;
    @Param static byte[] p1;
    @Param static byte[] q1;
    @Param static byte[] h0;
    @Param static byte[] h1;
    @Param static byte[] h2;
    @Param static byte[] h3;
    @Param static byte[] h4;
    @Param static byte[] domainBytes;
    @Param static byte[] dstH2S;
    @Param static byte[] dstMap;

    /** What this voucher requires and pays. */
    record ClaimDatum(byte[] requiredCountry, byte[] requiredKycLevel,
                      byte[] recipientPkh, BigInteger refundAmount,
                      byte[] funderPkh, BigInteger maxFee) {}

    /** One claim: the BBS proof, the disclosed messages (country, kycLevel), and the presentation header. */
    record ClaimRedeemer(byte[] abar, byte[] bbar, byte[] d,
                         BigInteger eHat, BigInteger r1Hat, BigInteger r3Hat,
                         BigInteger mHat0, BigInteger mHat1, BigInteger mHat2, BigInteger c,
                         byte[] msg2, byte[] msg3, byte[] ph) {}

    @Entrypoint
    public static boolean validate(ClaimDatum datum, ClaimRedeemer r, ScriptContext ctx) {
        // 0. The presentation must be bound to THIS voucher and recipient. We don't trust a nonce
        //    supplied by the claimer — we recompute the expected presentation header from the voucher
        //    being spent + the datum's recipient. A presentation captured from another claim simply
        //    won't match, and the voucher itself can only ever be spent once (eUTxO = nullifier).
        boolean boundToThisClaim = Builtins.equalsByteString(
                r.ph(), expectedPresentationHeader(ctx, datum.recipientPkh()));

        // 1. Policy: the disclosed attributes are the ones this voucher is for.
        boolean policyOk = Builtins.equalsByteString(r.msg2(), datum.requiredCountry())
                && Builtins.equalsByteString(r.msg3(), datum.requiredKycLevel());

        // 2. The BBS presentation verifies natively on-chain — the disclosed values are issuer-signed
        //    and the remaining attributes stay hidden. The proof is bound to `ph`, checked above.
        boolean proofOk = BbsProofVerify.verify(
                w, bp2, p1, q1, h0, h1, h2, h3, h4,
                Builtins.byteStringToInteger(true, domainBytes), dstH2S, dstMap,
                r.abar(), r.bbar(), r.d(),
                r.eHat(), r.r1Hat(), r.r3Hat(), r.mHat0(), r.mHat1(), r.mHat2(), r.c(),
                r.msg2(), r.msg3(), r.ph());

        // 3. The voucher pays exactly what it owes, through outputs tagged with its own outref: the
        //    refund to the recipient and the remainder (less at most maxFee) back to the funder. A
        //    relayer can neither redirect nor keep the funds, nor reuse one output for two vouchers.
        boolean paid = voucherPaid(ctx, datum.recipientPkh(), datum.funderPkh(),
                datum.refundAmount(), datum.maxFee());

        return boundToThisClaim && policyOk && paid && proofOk;
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

    /**
     * The presentation header this claim must use: {@code blake2b_256(voucherTxId ‖ I2OSP(index,8) ‖
     * recipientPkh)}. Derived from the voucher being spent, so it is unique per claim by construction
     * — no random nonce needed, and nothing the claimer can choose.
     */
    private static byte[] expectedPresentationHeader(ScriptContext ctx, byte[] recipientPkh) {
        if (ctx.scriptInfo() instanceof ScriptInfo.SpendingScript spending) {
            TxOutRef ref = spending.txOutRef();
            return Builtins.blake2b_256(
                    Builtins.concat(
                            ref.txId().hash(),
                            Builtins.integerToByteString(true, 8L, ref.index()),
                            recipientPkh));
        }
        return Builtins.emptyByteString();   // not a spending script — cannot match a real header
    }

    /** True if {@code cred} is a payment key credential whose 28-byte hash equals {@code recipient}. */
    private static boolean credentialIs(Credential cred, byte[] recipient) {
        if (cred instanceof Credential.PubKeyCredential pk) {
            return Builtins.equalsByteString(Builtins.toByteString(pk.hash()), recipient);
        }
        return false;
    }
}
