package com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.onchain;

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
 * Solvency attestations with hidden liabilities (ADR-0006 demo C). One script is the attestation
 * policy and the vault address, and it is specific to one attestation period
 * {@code [periodStart, periodEnd]}.
 *
 * <p><b>Attest</b> (mint): before the period starts (validity range ending at or before
 * {@code periodStart}), the exchange signs and mints one attestation token into a vault output at
 * exactly the vault's enterprise address, whose inline datum is
 * {@code Attestation([Entry(idHash, u, v, delivery)] × N, auditorDelivery)} (ADR-0007 N6: each
 * customer's opening and the auditor's aggregate opening delivered on-chain, 89 bytes each) and
 * whose value is the attested reserve {@code R}
 * in lovelace plus the token. The proof shows {@code Σ b_i ≤ R} over the hidden balances committed
 * in the entries; its public inputs are {@code [R, u_1..u_N, v_1..v_N]}, read from that output.
 *
 * <p><b>Release</b> (spend + burn): only after the period ends (validity range starting at or after
 * {@code periodEnd}), with the exchange's signature, burning the attestation token.
 *
 * <p>So every attestation of the period is locked for the whole period at once: none can be added
 * or released inside it, and the same reserve cannot back attestations one after another.
 */
@MultiValidator
public class SolvencyVault {

    @Param static byte[] exchangePkh;
    @Param static byte[] attestToken;
    @Param static BigInteger entryCount;
    @Param static BigInteger periodStart;   // POSIX ms
    @Param static BigInteger periodEnd;     // POSIX ms
    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    sealed interface VaultMint permits Attest, Burn {}
    record Attest(byte[] piA, byte[] piB, byte[] piC) implements VaultMint {}
    record Burn(BigInteger count) implements VaultMint {}

    @Entrypoint(purpose = Purpose.MINT)
    public static boolean mint(VaultMint redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policy = PlutusData.cast(mintInfo.policyId(), byte[].class);
        Credential own = new Credential.ScriptCredential(PlutusData.cast(policy, ScriptHash.class));
        if (policyEntryCount(txInfo.mint(), policy) != 1) return false;
        int ownInputs = countInputs(txInfo.inputs(), own);
        return switch (redeemer) {
            case Attest attest -> ownInputs == 0 && attest(attest, txInfo, own, policy);
            // The spent vault output's spending purpose checks the unlock time and signature.
            case Burn burn -> ownInputs == 1
                    && ValuesLib.assetOf(txInfo.mint(), policy, attestToken).compareTo(BigInteger.valueOf(-1)) == 0;
        };
    }

    private static boolean attest(Attest a, TxInfo txInfo, Credential own, byte[] policy) {
        BigInteger upper = IntervalLib.finiteUpperBound(txInfo.validRange());
        if (!signedBy(txInfo, exchangePkh)
                || upper.compareTo(BigInteger.ZERO) < 0 || upper.compareTo(periodStart) > 0
                || ValuesLib.assetOf(txInfo.mint(), policy, attestToken).compareTo(BigInteger.ONE) != 0) {
            return false;
        }
        // The one output holding the token: at the vault, lovelace plus the token only.
        int holders = 0;
        TxOut vault = txInfo.outputs().get(0);
        for (TxOut output : txInfo.outputs()) {
            if (ValuesLib.assetOf(output.value(), policy, attestToken).compareTo(BigInteger.ZERO) > 0) {
                holders = holders + 1;
                vault = output;
            } else {
                holders = holders;
            }
        }
        Address vaultAddress = new Address(own, Optional.empty());
        if (holders != 1
                || !Builtins.equalsData(vault.address(), vaultAddress)
                || outerEntryCount(vault.value()) != 2
                || policyEntryCount(vault.value(), policy) != 1) {
            return false;
        }
        BigInteger reserves = ValuesLib.lovelaceOf(vault.value());
        if (reserves.compareTo(BigInteger.valueOf(4294967296L).multiply(BigInteger.valueOf(4294967296L))) >= 0) return false;

        PlutusData datum = inlineDatum(vault);
        if (Builtins.constrTag(datum) != 0) return false;
        PlutusData fields = Builtins.constrFields(datum);
        PlutusData entries = Builtins.unListData(Builtins.headList(fields));
        // ADR-0007 N6: the attestation also carries the auditor's delivery of the aggregate opening.
        PlutusData rest = Builtins.tailList(fields);
        if (Builtins.nullList(rest) || !Builtins.nullList(Builtins.tailList(rest))
                || Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(rest))) != 89) {
            return false;
        }

        // [R, u_1..u_N, v_1..v_N], with every entry checked: 32-byte idHash, canonical u and v.
        int count = 0;
        boolean wellFormed = true;
        PlutusData reversedV = Builtins.mkNilData();
        PlutusData reversedU = Builtins.mkNilData();
        PlutusData cursor = entries;
        while (!Builtins.nullList(cursor)) {
            PlutusData entry = Builtins.headList(cursor);
            boolean ok = isEntry(entry);
            wellFormed = wellFormed && ok;
            reversedU = Builtins.mkCons(Builtins.iData(entryField(entry, 1)), reversedU);
            reversedV = Builtins.mkCons(Builtins.iData(entryField(entry, 2)), reversedV);
            count = count + 1;
            cursor = Builtins.tailList(cursor);
        }
        if (!wellFormed || BigInteger.valueOf(count).compareTo(entryCount) != 0) return false;
        PlutusData publicInputs = Builtins.mkNilData();
        PlutusData vs = reversedV;
        while (!Builtins.nullList(vs)) {
            publicInputs = Builtins.mkCons(Builtins.headList(vs), publicInputs);
            vs = Builtins.tailList(vs);
        }
        PlutusData us = reversedU;
        while (!Builtins.nullList(us)) {
            publicInputs = Builtins.mkCons(Builtins.headList(us), publicInputs);
            us = Builtins.tailList(us);
        }
        PlutusData withReserves = Builtins.mkCons(Builtins.iData(reserves), publicInputs);
        return Groth16BLS12381Lib.verify(Builtins.listData(withReserves), a.piA(), a.piB(), a.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }

    @Entrypoint(purpose = Purpose.SPEND)
    public static boolean spend(PlutusData datum, PlutusData redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        byte[] policy = ContextsLib.ownHash(ctx);
        Credential own = new Credential.ScriptCredential(PlutusData.cast(policy, ScriptHash.class));
        BigInteger from = IntervalLib.finiteLowerBound(txInfo.validRange());
        return signedBy(txInfo, exchangePkh)
                && from.compareTo(BigInteger.ZERO) >= 0 && from.compareTo(periodEnd) >= 0
                && countInputs(txInfo.inputs(), own) == 1
                && policyEntryCount(txInfo.mint(), policy) == 1
                && ValuesLib.assetOf(txInfo.mint(), policy, attestToken).compareTo(BigInteger.valueOf(-1)) == 0;
    }

    // ------------------------------------------------------------------

    /**
     * {@code Constr 0 [B(32), I, I, B(89)]}: the id hash, canonical coordinates, and the customer's
     * {@code confidential-note-jubjub-v1} delivery of the entry's opening (ADR-0007 N6). A
     * validator can check its length, not that it decrypts.
     */
    private static boolean isEntry(PlutusData entry) {
        if (Builtins.constrTag(entry) != 0) return false;
        PlutusData f = Builtins.constrFields(entry);
        if (Builtins.nullList(f)) return false;
        PlutusData f1 = Builtins.tailList(f);
        if (Builtins.nullList(f1)) return false;
        PlutusData f2 = Builtins.tailList(f1);
        if (Builtins.nullList(f2)) return false;
        PlutusData f3 = Builtins.tailList(f2);
        if (Builtins.nullList(f3) || !Builtins.nullList(Builtins.tailList(f3))) return false;
        return Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(f))) == 32
                && canonicalField(Builtins.unIData(Builtins.headList(f1)))
                && canonicalField(Builtins.unIData(Builtins.headList(f2)))
                && Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(f3))) == 89;
    }

    private static BigInteger entryField(PlutusData entry, int index) {
        PlutusData f = Builtins.constrFields(entry);
        int i = 0;
        while (i < index) {
            f = Builtins.tailList(f);
            i = i + 1;
        }
        return Builtins.unIData(Builtins.headList(f));
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

    private static boolean signedBy(TxInfo txInfo, byte[] pkh) {
        boolean found = false;
        for (var signer : txInfo.signatories()) {
            found = found || Builtins.equalsByteString(signer.hash(), pkh);
        }
        return found;
    }

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

    private static int outerEntryCount(Value value) {
        var outerPairs = Builtins.unMapData(value);
        int count = 0;
        PlutusData current = outerPairs;
        while (!Builtins.nullList(current)) {
            count = count + 1;
            current = Builtins.tailList(current);
        }
        return count;
    }

    private static PlutusData inlineDatum(TxOut output) {
        return switch (output.datum()) {
            case OutputDatum.OutputDatumInline inline -> inline.datum();
            case OutputDatum.OutputDatumHash ignored -> Builtins.iData(BigInteger.ZERO);
            case OutputDatum.NoOutputDatum ignored -> Builtins.iData(BigInteger.ZERO);
        };
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
