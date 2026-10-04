package com.bloxbean.cardano.zeroj.usecases.pedersen.common;

import com.bloxbean.cardano.client.exception.CborSerializationException;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusScript;
import com.bloxbean.cardano.client.util.HexUtil;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;

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
}
