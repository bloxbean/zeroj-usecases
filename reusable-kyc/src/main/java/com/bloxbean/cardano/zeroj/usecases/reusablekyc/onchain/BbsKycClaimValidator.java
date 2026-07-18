package com.bloxbean.cardano.zeroj.usecases.reusablekyc.onchain;

import com.bloxbean.cardano.julc.ledger.Credential;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.ledger.ScriptInfo;
import com.bloxbean.cardano.julc.ledger.TxOut;
import com.bloxbean.cardano.julc.ledger.TxOutRef;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.zeroj.onchain.julc.bbs.lib.BbsProofVerify;

import java.math.BigInteger;

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
 * <p><b>Datum</b> {@code (requiredCountry, requiredKycLevel, recipientPkh, refundAmount)} — the claim
 * policy written by whoever funds the voucher. <b>Redeemer</b> — the BBS proof + the two disclosed
 * messages + the presentation header.</p>
 *
 * <p>Checks: (1) the presentation is bound to <b>this</b> voucher — the expected header is recomputed
 * here, not taken on trust; (2) the disclosed values match the voucher's policy; (3) the BBS
 * presentation verifies under the issuer's key (so the values really are issuer-signed and the
 * undisclosed attributes stay hidden); (4) an output pays {@code recipientPkh} at least
 * {@code refundAmount}. Spending the voucher UTxO is itself the nullifier — the eUTxO model allows it
 * exactly once, which is also what makes the derived header unique per claim.</p>
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
                      byte[] recipientPkh, BigInteger refundAmount) {}

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

        // 3. The payout must go to the voucher's recipient — a relayer can't redirect or short-change it.
        byte[] recipient = datum.recipientPkh();
        BigInteger minAmount = datum.refundAmount();
        boolean paid = ctx.txInfo().outputs().any(o -> paysAtLeast(o, recipient, minAmount));

        return boundToThisClaim && policyOk && proofOk && paid;
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
                    Builtins.appendByteString(
                            Builtins.appendByteString(
                                    ref.txId().hash(),
                                    Builtins.integerToByteString(true, 8L, ref.index())),
                            recipientPkh));
        }
        return Builtins.emptyByteString();   // not a spending script — cannot match a real header
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
}
