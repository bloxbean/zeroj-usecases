package com.bloxbean.cardano.zeroj.usecases.pedersen.common;

import com.bloxbean.cardano.client.api.MinAdaCalculator;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.exception.CborSerializationException;
import com.bloxbean.cardano.client.transaction.spec.Asset;
import com.bloxbean.cardano.client.transaction.spec.MultiAsset;
import com.bloxbean.cardano.client.transaction.spec.TransactionOutput;
import com.bloxbean.cardano.client.transaction.spec.Value;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusScript;
import com.bloxbean.cardano.client.util.HexUtil;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/** Off-chain Plutus data encodings shared by the demos. */
public final class Plutus {

    private Plutus() {}

    /** The script's hash, hex: its policy id and its payment credential. */
    public static String policyId(PlutusScript script) {
        try {
            return HexUtil.encodeHexString(script.getScriptHash());
        } catch (CborSerializationException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The verification key's IC points as a list of compressed G1 byte strings. */
    public static ListPlutusData icData(List<byte[]> ic) {
        PlutusData[] values = new PlutusData[ic.size()];
        for (int i = 0; i < ic.size(); i++) values[i] = new BytesPlutusData(ic.get(i));
        return ListPlutusData.of(values);
    }

    /** {@code Constr 0 [B piA, B piB, B piC]}: a Groth16 proof as a redeemer. */
    public static ConstrPlutusData proofRedeemer(Groth16ProofBLS381 proof) {
        var p = ProverToCardano.compressProof(proof);
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(p.piA()), new BytesPlutusData(p.piB()), new BytesPlutusData(p.piC()))).build();
    }

    /**
     * The lovelace an output needs: the ledger minimum for its serialized size at the current
     * {@code coinsPerUTxOByte}, plus a 10% margin, rounded up to whole ADA. {@code tokens} are
     * {@code policyHex + nameHex} units with quantities (no lovelace).
     */
    public static BigInteger minAda(BackendService backend, String address, List<Amount> tokens, PlutusData inlineDatum) {
        try {
            var params = backend.getEpochService().getProtocolParameters().getValue();
            List<MultiAsset> multiAssets = new ArrayList<>();
            for (Amount a : tokens) {
                String policy = a.getUnit().substring(0, 56);
                String name = "0x" + a.getUnit().substring(56);
                multiAssets.add(MultiAsset.builder().policyId(policy)
                        .assets(List.of(new Asset(name, a.getQuantity()))).build());
            }
            TransactionOutput output = TransactionOutput.builder().address(address)
                    .value(Value.builder().coin(BigInteger.valueOf(10_000_000_000L)).multiAssets(multiAssets).build())
                    .inlineDatum(inlineDatum).build();
            BigInteger min = new MinAdaCalculator(params).calculateMinAda(output);
            BigInteger padded = min.multiply(BigInteger.valueOf(11)).divide(BigInteger.TEN);
            BigInteger ada = BigInteger.valueOf(1_000_000);
            return padded.add(ada.subtract(BigInteger.ONE)).divide(ada).multiply(ada);
        } catch (Exception e) {
            throw new IllegalStateException("could not compute the minimum ADA: " + e.getMessage(), e);
        }
    }
}
