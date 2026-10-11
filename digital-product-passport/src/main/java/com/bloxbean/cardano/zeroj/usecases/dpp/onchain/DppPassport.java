package com.bloxbean.cardano.zeroj.usecases.dpp.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.ScriptContext;
import org.julclang.ledger.ScriptHash;
import org.julclang.ledger.ScriptInfo;
import org.julclang.ledger.TxInfo;
import org.julclang.ledger.TxOut;
import org.julclang.ledger.Value;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.MultiValidator;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.annotation.Purpose;
import org.julclang.stdlib.lib.ContextsLib;
import org.julclang.stdlib.lib.ValuesLib;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Product passports (ADR-0009 D1). The script's hash is both the passport policy and the
 * passport address, so a passport is a public record that stays where it was minted.
 *
 * <p><b>Mint ({@code Issue(piA, piB, piC)}).</b> The redeemer carries only the proof.
 * <ul>
 *   <li>(a) the manufacturer and the auditor both sign;</li>
 *   <li>(b) the mint map under this policy is exactly {@code {productId: 1}}, with a 1–32 byte
 *       {@code productId};</li>
 *   <li>(c) exactly one output holds the token: at the script's enterprise address (no stake
 *       credential), with no reference script, holding only lovelace and the one token, and with
 *       the inline datum {@code Passport(productId, manufacturerPkh, claims)} in exactly this shape:
 *       {@code productId} the token name, {@code manufacturerPkh} the parameter, and 1 to 4
 *       {@code Claim(claim, σ, u, v)} entries with distinct claim ids in {@code [0, 4)}, a 32-byte
 *       {@code σ} and canonical {@code u, v}; the gated claim present with the parameter {@code σ};</li>
 *   <li>(d) the Groth16 proof verifies against {@code [σ, u, v, threshold]}, with {@code u, v}
 *       taken from the gated claim's entry and {@code σ}, {@code threshold} the parameters.</li>
 * </ul>
 *
 * <p><b>Spend ({@code Revoke}).</b> The only spend: the auditor signs and the transaction burns
 * exactly that passport's token, {@code {productId: −1}}, so a passport is never moved and its
 * datum never changes. The burn's mint purpose ({@code Burn}) requires the auditor's signature and
 * a mint map of exactly one entry with quantity −1.
 */
@MultiValidator
public class DppPassport {

    @Param static byte[] manufacturerPkh;
    @Param static byte[] auditorPkh;
    @Param static BigInteger gatedClaim;
    @Param static byte[] gatedSigma;      // σ of the gated claim's schema, I2OSP32
    @Param static BigInteger threshold;
    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    sealed interface PassportMint permits Issue, Burn {}
    record Issue(byte[] piA, byte[] piB, byte[] piC) implements PassportMint {}
    record Burn(BigInteger unused) implements PassportMint {}

    record Revoke(BigInteger unused) {}

    // ------------------------------------------------------------------
    //  Minting: Issue and Burn
    // ------------------------------------------------------------------

    @Entrypoint(purpose = Purpose.MINT)
    public static boolean mint(PassportMint redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policy = PlutusData.cast(mintInfo.policyId(), byte[].class);
        if (policyEntryCount(txInfo.mint(), policy) != 1) return false;
        return switch (redeemer) {
            case Issue issue -> issue(issue, txInfo, policy);
            case Burn burn -> signedBy(txInfo, auditorPkh)
                    && Builtins.lengthOfByteString(ValuesLib.findTokenName(txInfo.mint(), policy, BigInteger.valueOf(-1))) > 0;
        };
    }

    private static boolean issue(Issue issue, TxInfo txInfo, byte[] policy) {
        if (Builtins.lengthOfByteString(manufacturerPkh) != 28 || Builtins.lengthOfByteString(auditorPkh) != 28
                || Builtins.lengthOfByteString(gatedSigma) != 32) {
            return false;
        }
        // (a) both signatures
        if (!signedBy(txInfo, manufacturerPkh) || !signedBy(txInfo, auditorPkh)) return false;
        // (b) the one mint entry is {productId: 1}
        byte[] productId = ValuesLib.findTokenName(txInfo.mint(), policy, BigInteger.ONE);
        if (Builtins.lengthOfByteString(productId) < 1 || Builtins.lengthOfByteString(productId) > 32) return false;
        // (c) exactly one output holds the token, and it is an authentic passport
        int holders = 0;
        TxOut passport = txInfo.outputs().get(0);
        for (TxOut output : txInfo.outputs()) {
            if (ValuesLib.assetOf(output.value(), policy, productId).compareTo(BigInteger.ZERO) > 0) {
                holders = holders + 1;
                passport = output;
            } else {
                holders = holders;
            }
        }
        if (holders != 1) return false;
        Address exact = new Address(new Credential.ScriptCredential(PlutusData.cast(policy, ScriptHash.class)), Optional.empty());
        Value value = passport.value();
        if (!Builtins.equalsData(passport.address(), exact)
                || !passport.referenceScript().isEmpty()
                || outerEntryCount(value) != 2
                || ValuesLib.assetOf(value, policy, productId).compareTo(BigInteger.ONE) != 0) {
            return false;
        }
        PlutusData datum = inlineDatum(passport);
        if (!isPassport(datum, productId)) return false;
        PassportFields pf = PlutusData.cast(datum, PassportFields.class);
        PlutusData gated = gatedEntry(Builtins.unListData(pf.claims()));
        if (Builtins.constrTag(gated) != 0) return false;
        PlutusData gf = Builtins.constrFields(gated);
        if (!Builtins.equalsByteString(Builtins.unBData(Builtins.headList(Builtins.tailList(gf))), gatedSigma)) return false;
        // (d) the proof, against [σ, u, v, threshold] of the gated entry
        PlutusData publicInputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(Builtins.byteStringToInteger(true, gatedSigma)),
                Builtins.mkCons(Builtins.headList(Builtins.tailList(Builtins.tailList(gf))),
                Builtins.mkCons(Builtins.headList(Builtins.tailList(Builtins.tailList(Builtins.tailList(gf)))),
                Builtins.mkCons(Builtins.iData(threshold),
                        Builtins.mkNilData())))));
        return Groth16BLS12381Lib.verify(publicInputs, issue.piA(), issue.piB(), issue.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }

    // ------------------------------------------------------------------
    //  Spending: Revoke only
    // ------------------------------------------------------------------

    @Entrypoint(purpose = Purpose.SPEND)
    public static boolean spend(PlutusData datum, Revoke redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        byte[] policy = ContextsLib.ownHash(ctx);
        var ownInput = ContextsLib.findOwnInput(ctx);
        if (ownInput.isEmpty()) return false;
        byte[] token = ValuesLib.findTokenName(ownInput.get().resolved().value(), policy, BigInteger.ONE);
        return Builtins.lengthOfByteString(token) > 0
                && signedBy(txInfo, auditorPkh)
                && policyEntryCount(txInfo.mint(), policy) == 1
                && ValuesLib.assetOf(txInfo.mint(), policy, token).compareTo(BigInteger.valueOf(-1)) == 0;
    }

    // ------------------------------------------------------------------
    //  The passport datum
    // ------------------------------------------------------------------

    /**
     * {@code Constr 0 [B productId, B manufacturerPkh, List claims]}, exactly three fields, the
     * product id equal to the token name, the manufacturer the parameter, and 1 to 4 well-formed,
     * distinct claim entries. Anything else fails (a builtin failure fails closed).
     */
    private static boolean isPassport(PlutusData d, byte[] productId) {
        if (Builtins.constrTag(d) != 0) return false;
        PlutusData f = Builtins.constrFields(d);
        if (!Builtins.nullList(Builtins.tailList(Builtins.tailList(Builtins.tailList(f))))) return false;
        PassportFields pf = PlutusData.cast(d, PassportFields.class);
        PlutusData claims = Builtins.unListData(pf.claims());
        int n = entryCount(claims);
        return Builtins.equalsByteString(Builtins.unBData(pf.productId()), productId)
                && Builtins.equalsByteString(Builtins.unBData(pf.manufacturerPkh()), manufacturerPkh)
                && n >= 1 && n <= 4
                && entriesWellFormed(claims)
                && entriesDistinct(claims, claims);
    }

    private static int entryCount(PlutusData list) {
        int n = 0;
        PlutusData rest = list;
        while (!Builtins.nullList(rest)) {
            n = n + 1;
            rest = Builtins.tailList(rest);
        }
        return n;
    }

    /** Every entry is {@code Constr 0 [I claim, B σ, I u, I v]}: claim in [0, 4), |σ| = 32, u and v canonical. */
    private static boolean entriesWellFormed(PlutusData list) {
        boolean ok = true;
        PlutusData rest = list;
        while (!Builtins.nullList(rest)) {
            PlutusData entry = Builtins.headList(rest);
            PlutusData ef = Builtins.constrFields(entry);
            PlutusData f1 = Builtins.tailList(ef);
            PlutusData f2 = Builtins.tailList(f1);
            PlutusData f3 = Builtins.tailList(f2);
            BigInteger claim = Builtins.unIData(Builtins.headList(ef));
            ok = ok && Builtins.constrTag(entry) == 0
                    && Builtins.nullList(Builtins.tailList(f3))
                    && claim.compareTo(BigInteger.ZERO) >= 0 && claim.compareTo(BigInteger.valueOf(4)) < 0
                    && Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(f1))) == 32
                    && canonicalField(Builtins.unIData(Builtins.headList(f2)))
                    && canonicalField(Builtins.unIData(Builtins.headList(f3)));
            rest = Builtins.tailList(rest);
        }
        return ok;
    }

    /** Each entry's claim id occurs exactly once in {@code all}. */
    private static boolean entriesDistinct(PlutusData rest, PlutusData all) {
        boolean ok = true;
        PlutusData current = rest;
        while (!Builtins.nullList(current)) {
            BigInteger claim = Builtins.unIData(Builtins.headList(Builtins.constrFields(Builtins.headList(current))));
            ok = ok && occurrences(all, claim) == 1;
            current = Builtins.tailList(current);
        }
        return ok;
    }

    private static int occurrences(PlutusData list, BigInteger claim) {
        int n = 0;
        PlutusData rest = list;
        while (!Builtins.nullList(rest)) {
            BigInteger c = Builtins.unIData(Builtins.headList(Builtins.constrFields(Builtins.headList(rest))));
            if (c.compareTo(claim) == 0) {
                n = n + 1;
            } else {
                n = n;
            }
            rest = Builtins.tailList(rest);
        }
        return n;
    }

    /** The entry of the gated claim, or {@code I 0} (which no constr check accepts) if absent. */
    private static PlutusData gatedEntry(PlutusData list) {
        PlutusData found = Builtins.iData(BigInteger.ZERO);
        PlutusData rest = list;
        while (!Builtins.nullList(rest)) {
            PlutusData entry = Builtins.headList(rest);
            if (Builtins.unIData(Builtins.headList(Builtins.constrFields(entry))).compareTo(gatedClaim) == 0) {
                found = entry;
            } else {
                found = found;
            }
            rest = Builtins.tailList(rest);
        }
        return found;
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    private static boolean signedBy(TxInfo txInfo, byte[] pkh) {
        boolean found = false;
        for (var signer : txInfo.signatories()) {
            found = found || Builtins.equalsByteString(signer.hash(), pkh);
        }
        return found;
    }

    /** The number of policies (lovelace included) in a value. */
    private static int outerEntryCount(Value value) {
        int count = 0;
        PlutusData current = Builtins.unMapData(value);
        while (!Builtins.nullList(current)) {
            count = count + 1;
            current = Builtins.tailList(current);
        }
        return count;
    }

    /** The number of token names (any quantity) under {@code policy}. */
    private static int policyEntryCount(Value value, byte[] policy) {
        PlutusData target = Builtins.bData(policy);
        int count = 0;
        PlutusData current = Builtins.unMapData(value);
        while (!Builtins.nullList(current)) {
            var pair = Builtins.headList(current);
            if (Builtins.equalsData(Builtins.fstPair(pair), target)) {
                count = innerEntryCount((PlutusData.MapData) Builtins.sndPair(pair));
                current = Builtins.mkNilPairData();
            } else {
                current = Builtins.tailList(current);
            }
        }
        return count;
    }

    private static int innerEntryCount(PlutusData.MapData innerPairs) {
        int count = 0;
        PlutusData current = Builtins.unMapData(innerPairs);
        while (!Builtins.nullList(current)) {
            count = count + 1;
            current = Builtins.tailList(current);
        }
        return count;
    }

    /** The inline datum; a missing or hashed datum yields an integer, which no shape check accepts. */
    private static PlutusData inlineDatum(TxOut output) {
        return switch (output.datum()) {
            case OutputDatum.OutputDatumInline inline -> inline.datum();
            case OutputDatum.OutputDatumHash ignored -> Builtins.iData(BigInteger.ZERO);
            case OutputDatum.NoOutputDatum ignored -> Builtins.iData(BigInteger.ZERO);
        };
    }

    /** {@code 0 ≤ value < p}, the BLS12-381 scalar field. */
    private static boolean canonicalField(BigInteger value) {
        return value.compareTo(BigInteger.ZERO) >= 0 && value.compareTo(fr()) < 0;
    }

    private static BigInteger fr() {
        BigInteger base = BigInteger.valueOf(1000000000000000000L);
        return BigInteger.valueOf(52435L).multiply(base)
                .add(BigInteger.valueOf(875175126190479447L)).multiply(base)
                .add(BigInteger.valueOf(740508185965837690L)).multiply(base)
                .add(BigInteger.valueOf(552500527637822603L)).multiply(base)
                .add(BigInteger.valueOf(658699938581184513L));
    }

    /** A typed view of a passport datum; {@link #isPassport} checks the shape before it is used. */
    record PassportFields(PlutusData productId, PlutusData manufacturerPkh, PlutusData claims) {}
}
