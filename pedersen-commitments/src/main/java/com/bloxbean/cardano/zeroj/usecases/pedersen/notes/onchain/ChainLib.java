package com.bloxbean.cardano.zeroj.usecases.pedersen.notes.onchain;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcList;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxInfo;
import org.julclang.ledger.TxOut;
import org.julclang.ledger.Value;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.OnchainLibrary;

import java.math.BigInteger;

/**
 * On-chain helpers shared by the confidential-note validators (ADR-0007, ADR-0008): counting
 * inputs and outputs under a payment credential, exact value shapes, signatures, inline datums
 * and canonical field elements.
 */
@OnchainLibrary
public class ChainLib {

    /** Script inputs counted by payment credential, so every stake variant counts. */
    public static int countInputs(JulcList<TxInInfo> inputs, Credential own) {
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

    /** Outputs counted by payment credential. */
    public static int countOutputs(JulcList<TxOut> outputs, Credential own) {
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

    /**
     * Every output under the payment credential {@code own} is at exactly {@code exact} (the
     * enterprise address, no stake credential). The address policy of ADR-0007 N2.
     */
    public static boolean allAtExactAddress(JulcList<TxOut> outputs, Credential own, Address exact) {
        boolean ok = true;
        for (TxOut output : outputs) {
            if (Builtins.equalsData(output.address().credential(), own)) {
                ok = ok && Builtins.equalsData(output.address(), exact);
            } else {
                ok = ok;
            }
        }
        return ok;
    }

    public static boolean signedBy(TxInfo txInfo, byte[] pkh) {
        boolean found = false;
        for (var signer : txInfo.signatories()) {
            found = found || Builtins.equalsByteString(signer.hash(), pkh);
        }
        return found;
    }

    /** The number of policies (lovelace included) in a value. */
    public static int outerEntryCount(Value value) {
        int count = 0;
        PlutusData current = Builtins.unMapData(value);
        while (!Builtins.nullList(current)) {
            count = count + 1;
            current = Builtins.tailList(current);
        }
        return count;
    }

    /** The number of token names (any quantity) under {@code policy}. */
    public static int policyEntryCount(Value value, byte[] policy) {
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
    public static PlutusData inlineDatum(TxOut output) {
        return switch (output.datum()) {
            case OutputDatum.OutputDatumInline inline -> inline.datum();
            case OutputDatum.OutputDatumHash ignored -> Builtins.iData(BigInteger.ZERO);
            case OutputDatum.NoOutputDatum ignored -> Builtins.iData(BigInteger.ZERO);
        };
    }

    /** The length of a list datum, or -1 for anything else (a builtin failure fails closed). */
    public static int listLength(PlutusData list) {
        int n = 0;
        PlutusData rest = Builtins.unListData(list);
        while (!Builtins.nullList(rest)) {
            n = n + 1;
            rest = Builtins.tailList(rest);
        }
        return n;
    }

    /** {@code 0 ≤ value < p}, the BLS12-381 scalar field. */
    public static boolean canonicalField(BigInteger value) {
        return value.compareTo(BigInteger.ZERO) >= 0 && value.compareTo(fr()) < 0;
    }

    public static BigInteger fr() {
        BigInteger base = BigInteger.valueOf(1000000000000000000L);
        return BigInteger.valueOf(52435L).multiply(base)
                .add(BigInteger.valueOf(875175126190479447L)).multiply(base)
                .add(BigInteger.valueOf(740508185965837690L)).multiply(base)
                .add(BigInteger.valueOf(552500527637822603L)).multiply(base)
                .add(BigInteger.valueOf(658699938581184513L));
    }
}
