package com.bloxbean.cardano.zeroj.usecases.reserves.onchain;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcList;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.OutputDatum;
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
import org.julclang.stdlib.lib.IntervalLib;
import org.julclang.stdlib.lib.ValuesLib;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Proof-of-reserves attestations as minted, locked tokens (ADR-0009 D4). One script is the
 * attestation policy and the attestation address.
 *
 * <p><b>Attest</b> (mint): with the custodian's signature, the mint map under this policy is
 * exactly {@code {I2OSP8(period): 1}}, and the token goes to the one output at exactly the
 * script's enterprise address (payment credential, no stake credential), holding lovelace and
 * that token only, with inline datum
 * {@code Attestation(period, liabilitiesRoot, totalLiabilities, totalReserves)}. The Groth16
 * proof (the redeemer) verifies against {@code [totalReserves, liabilitiesRoot, totalLiabilities, 1]}
 * read from that datum, so only a solvent statement attests.
 *
 * <p><b>Release</b> (spend + burn): the only spend is a custodian-signed burn of the spent
 * output's token, {@code {I2OSP8(period): -1}}, in a transaction whose validity range has a
 * finite lower bound at or after the period's end. Period {@code p} is
 * {@code [genesisMs + p·periodMs, genesisMs + (p+1)·periodMs)} (POSIX ms). The datum can never
 * change while the token exists.
 *
 * <p>The script does not stop a second attestation for the same period: that is the
 * custodian's word, and the customer check refuses a period whose token was minted more than
 * once. {@code totalReserves} is declared by the custodian; nothing here checks it against
 * on-chain holdings.
 */
@MultiValidator
public class ReserveAttestation {

    @Param static byte[] custodianPkh;
    @Param static BigInteger genesisMs;     // POSIX ms
    @Param static BigInteger periodMs;      // > 0
    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    sealed interface AttestationMint permits Attest, Burn {}
    record Attest(byte[] piA, byte[] piB, byte[] piC) implements AttestationMint {}
    record Burn(BigInteger unused) implements AttestationMint {}

    @Entrypoint(purpose = Purpose.MINT)
    public static boolean mint(AttestationMint redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policy = PlutusData.cast(mintInfo.policyId(), byte[].class);
        Credential own = new Credential.ScriptCredential(PlutusData.cast(policy, ScriptHash.class));
        if (periodMs.compareTo(BigInteger.ZERO) <= 0 || policyEntryCount(txInfo.mint(), policy) != 1) return false;
        int ownInputs = countInputs(txInfo.inputs(), own);
        return switch (redeemer) {
            case Attest attest -> ownInputs == 0 && attest(attest, txInfo, own, policy);
            // The spent attestation's spending purpose checks the signature, the token and the period end.
            case Burn burn -> ownInputs == 1
                    && Builtins.lengthOfByteString(ValuesLib.findTokenName(txInfo.mint(), policy, BigInteger.valueOf(-1))) == 8;
        };
    }

    private static boolean attest(Attest a, TxInfo txInfo, Credential own, byte[] policy) {
        if (!signedBy(txInfo, custodianPkh)) return false;
        // The one output holding a token of this policy: at the exact address, lovelace plus the token only.
        int holders = 0;
        TxOut locked = txInfo.outputs().get(0);
        for (TxOut output : txInfo.outputs()) {
            if (policyEntryCount(output.value(), policy) > 0) {
                holders = holders + 1;
                locked = output;
            } else {
                holders = holders;
            }
        }
        if (holders != 1
                || !Builtins.equalsData(locked.address(), new Address(own, Optional.empty()))
                || !locked.referenceScript().isEmpty()
                || outerEntryCount(locked.value()) != 2
                || policyEntryCount(locked.value(), policy) != 1) {
            return false;
        }
        PlutusData datum = inlineDatum(locked);
        if (!isAttestation(datum)) return false;
        AttestationFields f = PlutusData.cast(datum, AttestationFields.class);
        byte[] token = Builtins.integerToByteString(true, 8, Builtins.unIData(f.period()));
        return ValuesLib.assetOf(txInfo.mint(), policy, token).compareTo(BigInteger.ONE) == 0
                && ValuesLib.assetOf(locked.value(), policy, token).compareTo(BigInteger.ONE) == 0
                && Groth16BLS12381Lib.verifyFour(
                        Builtins.unIData(f.totalReserves()),
                        Builtins.unIData(f.liabilitiesRoot()),
                        Builtins.unIData(f.totalLiabilities()),
                        BigInteger.ONE,
                        a.piA(), a.piB(), a.piC(), vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }

    @Entrypoint(purpose = Purpose.SPEND)
    public static boolean spend(PlutusData datum, PlutusData redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        byte[] policy = ContextsLib.ownHash(ctx);
        Credential own = new Credential.ScriptCredential(PlutusData.cast(policy, ScriptHash.class));
        var ownInput = ContextsLib.findOwnInput(ctx);
        if (ownInput.isEmpty() || periodMs.compareTo(BigInteger.ZERO) <= 0 || !isAttestation(datum)) return false;
        AttestationFields f = PlutusData.cast(datum, AttestationFields.class);
        BigInteger period = Builtins.unIData(f.period());
        byte[] token = Builtins.integerToByteString(true, 8, period);
        BigInteger periodEnd = genesisMs.add(period.add(BigInteger.ONE).multiply(periodMs));
        // finiteLowerBound is -1 for an unbounded interval.
        BigInteger from = IntervalLib.finiteLowerBound(txInfo.validRange());
        return signedBy(txInfo, custodianPkh)
                && from.compareTo(BigInteger.ZERO) >= 0 && from.compareTo(periodEnd) >= 0
                && countInputs(txInfo.inputs(), own) == 1
                && countOutputs(txInfo.outputs(), own) == 0
                && ValuesLib.assetOf(ownInput.get().resolved().value(), policy, token).compareTo(BigInteger.ONE) == 0
                && policyEntryCount(txInfo.mint(), policy) == 1
                && ValuesLib.assetOf(txInfo.mint(), policy, token).compareTo(BigInteger.valueOf(-1)) == 0;
    }

    // ------------------------------------------------------------------

    /**
     * {@code Constr 0 [I period, I liabilitiesRoot, I totalLiabilities, I totalReserves]}, exactly
     * four fields: {@code 0 ≤ period < 2^64}, a canonical root ({@code < r}), and both totals in
     * the circuit's 64-bit range.
     */
    private static boolean isAttestation(PlutusData d) {
        if (Builtins.constrTag(d) != 0) return false;
        PlutusData f = Builtins.constrFields(d);
        if (Builtins.nullList(f)) return false;
        PlutusData f1 = Builtins.tailList(f);
        if (Builtins.nullList(f1)) return false;
        PlutusData f2 = Builtins.tailList(f1);
        if (Builtins.nullList(f2)) return false;
        PlutusData f3 = Builtins.tailList(f2);
        if (Builtins.nullList(f3) || !Builtins.nullList(Builtins.tailList(f3))) return false;
        return uint64(Builtins.unIData(Builtins.headList(f)))
                && canonicalField(Builtins.unIData(Builtins.headList(f1)))
                && uint64(Builtins.unIData(Builtins.headList(f2)))
                && uint64(Builtins.unIData(Builtins.headList(f3)));
    }

    /** A typed view of the attestation datum; {@link #isAttestation} checks the shape first. */
    record AttestationFields(PlutusData period, PlutusData liabilitiesRoot, PlutusData totalLiabilities,
                             PlutusData totalReserves) {}

    private static boolean uint64(BigInteger value) {
        return value.compareTo(BigInteger.ZERO) >= 0
                && value.compareTo(BigInteger.valueOf(4294967296L).multiply(BigInteger.valueOf(4294967296L))) < 0;
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

    /** The inline datum; a missing or hashed datum yields an integer, which no shape check accepts. */
    private static PlutusData inlineDatum(TxOut output) {
        return switch (output.datum()) {
            case OutputDatum.OutputDatumInline inline -> inline.datum();
            case OutputDatum.OutputDatumHash ignored -> Builtins.iData(BigInteger.ZERO);
            case OutputDatum.NoOutputDatum ignored -> Builtins.iData(BigInteger.ZERO);
        };
    }

    /** {@code 0 ≤ value < r}, the BLS12-381 scalar field. */
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
