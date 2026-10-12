package com.bloxbean.cardano.zeroj.usecases.pedersen.points.onchain;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcList;
import org.julclang.ledger.Credential;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.PubKeyHash;
import org.julclang.ledger.ScriptContext;
import org.julclang.ledger.ScriptHash;
import org.julclang.ledger.ScriptInfo;
import org.julclang.ledger.TxInInfo;
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

/**
 * Confidential loyalty points (ADR-0006 demo A). One script is both the points policy and the
 * note address, so its hash is the policy id and the notes' payment credential.
 *
 * <p>A <b>note</b> is an output at the script credential holding exactly one {@code noteToken} and
 * nothing else under the policy, with inline datum {@code Note(owner, u, v)}: the owner's key hash
 * and the affine {@code pedersen-jubjub-v1} commitment to its amount.
 *
 * <ul>
 *   <li><b>Issue</b> (mint): the issuer signs and mints {@code n} note tokens into exactly {@code n}
 *       new notes; no note is spent. The issuer is trusted for supply.</li>
 *   <li><b>Transfer</b> (spend + {@code Split} mint): the owner splits one note into two, proving
 *       {@code in = out1 + out2} over hidden 64-bit amounts. One note token is minted for the
 *       second output.</li>
 *   <li><b>Redeem</b> (spend + {@code Receipt} mint): the owner pays a public {@code price} from a
 *       note and keeps a hidden change note, proving {@code in = change + price}. A receipt token,
 *       named after the redeemed note's output reference, is minted to the issuer with datum
 *       {@code Receipt(owner, price)}. Only a valid redemption can mint one, and each note can be
 *       redeemed once, so receipts cannot be forged or replayed.</li>
 * </ul>
 *
 * <p>Every public input comes from datums and outputs; the price comes from the redeemer and is
 * bound by the proof and recorded in the receipt. Script inputs are counted by payment credential,
 * so two notes can never be spent in one transaction. Every coordinate is checked canonical.
 */
@MultiValidator
public class PointsLedger {

    @Param static byte[] issuerPkh;
    @Param static byte[] noteToken;
    @Param static byte[] transferAlpha;
    @Param static byte[] transferBeta;
    @Param static byte[] transferGamma;
    @Param static byte[] transferDelta;
    @Param static PlutusData transferIc;
    @Param static byte[] redeemAlpha;
    @Param static byte[] redeemBeta;
    @Param static byte[] redeemGamma;
    @Param static byte[] redeemDelta;
    @Param static PlutusData redeemIc;

    record Note(byte[] owner, BigInteger u, BigInteger v) {}

    sealed interface PointsMint permits Issue, Split, Receipt {}
    record Issue(BigInteger count) implements PointsMint {}
    record Split(BigInteger count) implements PointsMint {}
    record Receipt(BigInteger count) implements PointsMint {}

    sealed interface NoteSpend permits Transfer, Redeem {}
    record Transfer(byte[] piA, byte[] piB, byte[] piC) implements NoteSpend {}
    record Redeem(BigInteger price, byte[] piA, byte[] piB, byte[] piC) implements NoteSpend {}

    // ------------------------------------------------------------------
    //  Minting
    // ------------------------------------------------------------------

    @Entrypoint(purpose = Purpose.MINT)
    public static boolean mint(PointsMint redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policy = PlutusData.cast(mintInfo.policyId(), byte[].class);
        Credential own = new Credential.ScriptCredential(PlutusData.cast(policy, ScriptHash.class));
        int ownInputs = countInputs(txInfo.inputs(), own);
        // Every action mints exactly one token name under this policy.
        if (policyEntryCount(txInfo.mint(), policy) != 1) return false;

        return switch (redeemer) {
            case Issue issue -> {
                BigInteger n = ValuesLib.assetOf(txInfo.mint(), policy, noteToken);
                yield signedBy(txInfo, issuerPkh) && ownInputs == 0
                        && n.compareTo(BigInteger.ONE) >= 0
                        && BigInteger.valueOf(countOutputs(txInfo.outputs(), own)).compareTo(n) == 0
                        && allNotes(txInfo.outputs(), own, policy);
            }
            // The spent note's spending purpose proves the transfer; here only the count.
            case Split split -> ownInputs == 1
                    && ValuesLib.assetOf(txInfo.mint(), policy, noteToken).compareTo(BigInteger.ONE) == 0;
            // The spent note's spending purpose proves the redemption and pins the receipt name.
            case Receipt receipt -> {
                byte[] name = ValuesLib.findTokenName(txInfo.mint(), policy, BigInteger.ONE);
                yield ownInputs == 1 && Builtins.lengthOfByteString(name) == 32;
            }
        };
    }

    // ------------------------------------------------------------------
    //  Spending a note
    // ------------------------------------------------------------------

    @Entrypoint(purpose = Purpose.SPEND)
    public static boolean spend(Note datum, NoteSpend redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        byte[] policy = ContextsLib.ownHash(ctx);
        Credential own = new Credential.ScriptCredential(PlutusData.cast(policy, ScriptHash.class));
        if (Builtins.lengthOfByteString(datum.owner()) != 28
                || !canonicalField(datum.u()) || !canonicalField(datum.v())
                || !signedBy(txInfo, datum.owner())) {
            return false;
        }
        var ownInputOptional = ContextsLib.findOwnInput(ctx);
        if (ownInputOptional.isEmpty()) return false;
        TxInInfo ownInput = ownInputOptional.get();
        if (countInputs(txInfo.inputs(), own) != 1
                || ValuesLib.assetOf(ownInput.resolved().value(), policy, noteToken).compareTo(BigInteger.ONE) != 0
                || policyEntryCount(txInfo.mint(), policy) != 1) {
            return false;
        }
        return switch (redeemer) {
            case Transfer transfer -> transfer(transfer, datum, txInfo, own, policy);
            case Redeem redeem -> redeem(redeem, datum, ownInput, txInfo, own, policy);
        };
    }

    private static boolean transfer(Transfer t, Note in, TxInfo txInfo, Credential own, byte[] policy) {
        if (ValuesLib.assetOf(txInfo.mint(), policy, noteToken).compareTo(BigInteger.ONE) != 0) return false;
        int notes = 0;
        boolean wellFormed = true;
        BigInteger o1u = BigInteger.ZERO;
        BigInteger o1v = BigInteger.ZERO;
        BigInteger o2u = BigInteger.ZERO;
        BigInteger o2v = BigInteger.ZERO;
        for (TxOut output : txInfo.outputs()) {
            if (Builtins.equalsData(output.address().credential(), own)) {
                boolean ok = isNote(output, policy);
                wellFormed = wellFormed && ok;
                PlutusData d = inlineDatum(output);
                if (ok && notes == 0) {
                    o1u = noteU(d);
                    o1v = noteV(d);
                } else {
                    o1u = o1u;
                    o1v = o1v;
                }
                if (ok && notes == 1) {
                    o2u = noteU(d);
                    o2v = noteV(d);
                } else {
                    o2u = o2u;
                    o2v = o2v;
                }
                notes = notes + 1;
            } else {
                notes = notes;
            }
        }
        if (notes != 2 || !wellFormed) return false;
        PlutusData publicInputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(in.u()),
                Builtins.mkCons(Builtins.iData(in.v()),
                Builtins.mkCons(Builtins.iData(o1u),
                Builtins.mkCons(Builtins.iData(o1v),
                Builtins.mkCons(Builtins.iData(o2u),
                Builtins.mkCons(Builtins.iData(o2v),
                        Builtins.mkNilData())))))));
        return Groth16BLS12381Lib.verify(publicInputs, t.piA(), t.piB(), t.piC(),
                transferAlpha, transferBeta, transferGamma, transferDelta, transferIc);
    }

    private static boolean redeem(Redeem r, Note in, TxInInfo ownInput, TxInfo txInfo,
                                  Credential own, byte[] policy) {
        BigInteger price = r.price();
        if (price.compareTo(BigInteger.ONE) < 0 || price.compareTo(BigInteger.valueOf(4294967296L)) >= 0) {
            return false;
        }
        // The receipt token is named after the redeemed note's output reference: one per note.
        byte[] receiptName = ValuesLib.uniqueTokenName(ownInput.outRef());
        if (ValuesLib.assetOf(txInfo.mint(), policy, receiptName).compareTo(BigInteger.ONE) != 0) return false;

        Credential issuer = new Credential.PubKeyCredential(PlutusData.cast(issuerPkh, PubKeyHash.class));
        PlutusData expectedReceipt = Builtins.constrData(0,
                Builtins.mkCons(Builtins.bData(in.owner()),
                Builtins.mkCons(Builtins.iData(price),
                        Builtins.mkNilData())));
        int notes = 0;
        boolean wellFormed = true;
        boolean receipted = false;
        BigInteger cu = BigInteger.ZERO;
        BigInteger cv = BigInteger.ZERO;
        for (TxOut output : txInfo.outputs()) {
            if (Builtins.equalsData(output.address().credential(), own)) {
                boolean ok = isNote(output, policy);
                wellFormed = wellFormed && ok;
                PlutusData d = inlineDatum(output);
                if (ok && notes == 0) {
                    cu = noteU(d);
                    cv = noteV(d);
                } else {
                    cu = cu;
                    cv = cv;
                }
                notes = notes + 1;
            } else {
                notes = notes;
            }
            boolean receipt = Builtins.equalsData(output.address().credential(), issuer)
                    && ValuesLib.assetOf(output.value(), policy, receiptName).compareTo(BigInteger.ONE) == 0
                    && Builtins.equalsData(inlineDatum(output), expectedReceipt);
            receipted = receipted || receipt;
        }
        if (notes != 1 || !wellFormed || !receipted) return false;
        PlutusData publicInputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(in.u()),
                Builtins.mkCons(Builtins.iData(in.v()),
                Builtins.mkCons(Builtins.iData(cu),
                Builtins.mkCons(Builtins.iData(cv),
                Builtins.mkCons(Builtins.iData(price),
                        Builtins.mkNilData()))))));
        return Groth16BLS12381Lib.verify(publicInputs, r.piA(), r.piB(), r.piC(),
                redeemAlpha, redeemBeta, redeemGamma, redeemDelta, redeemIc);
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    /**
     * A note: exactly one note token and nothing else under the policy, and an inline
     * {@code Note(owner: 28 bytes, u, v)} datum with canonical coordinates.
     */
    private static boolean isNote(TxOut output, byte[] policy) {
        if (ValuesLib.assetOf(output.value(), policy, noteToken).compareTo(BigInteger.ONE) != 0
                || policyEntryCount(output.value(), policy) != 1) {
            return false;
        }
        PlutusData d = inlineDatum(output);
        return isNoteDatum(d) && canonicalField(noteU(d)) && canonicalField(noteV(d));
    }

    private static boolean allNotes(JulcList<TxOut> outputs, Credential own, byte[] policy) {
        boolean ok = true;
        for (TxOut output : outputs) {
            if (Builtins.equalsData(output.address().credential(), own)) {
                ok = ok && isNote(output, policy);
            } else {
                ok = ok;
            }
        }
        return ok;
    }

    private static int countInputs(JulcList<TxInInfo> inputs, Credential own) {
        int n = 0;
        for (TxInInfo input : inputs) {
            if (Builtins.equalsData(input.resolved().address().credential(), own)) {
                n = n + 1;
            } else {
                n = n;
            }
        }
        return n;
    }

    private static int countOutputs(JulcList<TxOut> outputs, Credential own) {
        int n = 0;
        for (TxOut output : outputs) {
            if (Builtins.equalsData(output.address().credential(), own)) {
                n = n + 1;
            } else {
                n = n;
            }
        }
        return n;
    }

    private static boolean signedBy(TxInfo txInfo, byte[] pkh) {
        boolean found = false;
        for (var signer : txInfo.signatories()) {
            found = found || Builtins.equalsByteString(signer.hash(), pkh);
        }
        return found;
    }

    /** The number of token names (any quantity) under {@code policy}. */
    private static int policyEntryCount(Value value, byte[] policy) {
        var outerPairs = Builtins.unMapData(value);
        PlutusData target = Builtins.bData(policy);
        int count = 0;
        PlutusData current = outerPairs;
        while (!Builtins.nullList(current)) {
            var outerPair = Builtins.headList(current);
            if (Builtins.equalsData(Builtins.fstPair(outerPair), target)) {
                count = innerEntryCount((PlutusData.MapData) Builtins.sndPair(outerPair));
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

    /** The inline datum; a missing or hashed datum yields an integer, which is never a note. */
    private static PlutusData inlineDatum(TxOut output) {
        return switch (output.datum()) {
            case OutputDatum.OutputDatumInline inline -> inline.datum();
            case OutputDatum.OutputDatumHash ignored -> Builtins.iData(BigInteger.ZERO);
            case OutputDatum.NoOutputDatum ignored -> Builtins.iData(BigInteger.ZERO);
        };
    }

    /** {@code Constr 0 [B(28), I, I]}; any other shape returns false or fails a builtin. */
    private static boolean isNoteDatum(PlutusData value) {
        if (Builtins.constrTag(value) != 0) return false;
        PlutusData fields = Builtins.constrFields(value);
        if (Builtins.nullList(fields)) return false;
        PlutusData rest = Builtins.tailList(fields);
        if (Builtins.nullList(rest)) return false;
        PlutusData rest2 = Builtins.tailList(rest);
        if (Builtins.nullList(rest2)) return false;
        return Builtins.nullList(Builtins.tailList(rest2))
                && Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(fields))) == 28
                && Builtins.unIData(Builtins.headList(rest)).compareTo(BigInteger.ZERO) >= 0
                && Builtins.unIData(Builtins.headList(rest2)).compareTo(BigInteger.ZERO) >= 0;
    }

    private static BigInteger noteU(PlutusData note) {
        return Builtins.unIData(Builtins.headList(Builtins.tailList(Builtins.constrFields(note))));
    }

    private static BigInteger noteV(PlutusData note) {
        return Builtins.unIData(Builtins.headList(Builtins.tailList(Builtins.tailList(Builtins.constrFields(note)))));
    }

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
}
