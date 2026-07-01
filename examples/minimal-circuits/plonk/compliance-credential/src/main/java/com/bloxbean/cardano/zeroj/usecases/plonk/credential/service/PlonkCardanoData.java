package com.bloxbean.cardano.zeroj.usecases.plonk.credential.service;

import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec.PlonKProverToCardano;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec.PlonKProverToCardano.MultiInputProofCompressed;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec.PlonKProverToCardano.VkCompressed;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public final class PlonkCardanoData {
    private PlonkCardanoData() {
    }

    public static PlutusData datum(BigInteger[] publicInputs) {
        PlutusData[] values = new PlutusData[publicInputs.length];
        for (int i = 0; i < publicInputs.length; i++) {
            values[i] = BigIntPlutusData.of(publicInputs[i]);
        }
        return ListPlutusData.of(values);
    }

    public static PlutusData redeemer(MultiInputProofCompressed proof) {
        return ConstrPlutusData.builder()
                .alternative(0)
                .data(ListPlutusData.of(
                        new BytesPlutusData(proof.cmA()),
                        new BytesPlutusData(proof.cmB()),
                        new BytesPlutusData(proof.cmC()),
                        new BytesPlutusData(proof.cmZ()),
                        new BytesPlutusData(proof.cmT1()),
                        new BytesPlutusData(proof.cmT2()),
                        new BytesPlutusData(proof.cmT3()),
                        new BytesPlutusData(proof.wXi()),
                        new BytesPlutusData(proof.wXiw()),
                        BigIntPlutusData.of(proof.evalA()),
                        BigIntPlutusData.of(proof.evalB()),
                        BigIntPlutusData.of(proof.evalC()),
                        BigIntPlutusData.of(proof.evalS1()),
                        BigIntPlutusData.of(proof.evalS2()),
                        BigIntPlutusData.of(proof.evalZw()),
                        scalarList(proof.publicInputInverses())))
                .build();
    }

    public static PlutusData[] verifierParams(VkCompressed vk, int publicInputCount) {
        return new PlutusData[]{
                new BytesPlutusData(vk.qm()),
                new BytesPlutusData(vk.ql()),
                new BytesPlutusData(vk.qr()),
                new BytesPlutusData(vk.qo()),
                new BytesPlutusData(vk.qc()),
                new BytesPlutusData(vk.s1()),
                new BytesPlutusData(vk.s2()),
                new BytesPlutusData(vk.s3()),
                new BytesPlutusData(vk.x2()),
                BigIntPlutusData.of(vk.domainSize()),
                BigIntPlutusData.of(vk.domainPower()),
                BigIntPlutusData.of(vk.omega()),
                BigIntPlutusData.of(vk.k1()),
                BigIntPlutusData.of(vk.k2()),
                BigIntPlutusData.of(vk.k1OverK2()),
                BigIntPlutusData.of(vk.fr()),
                BigIntPlutusData.of(vk.nInv()),
                new BytesPlutusData(vk.g1Gen()),
                new BytesPlutusData(vk.g2Gen()),
                new BytesPlutusData(PlonKProverToCardano.CARDANO_MPI_PROOF_FORMAT.getBytes(StandardCharsets.US_ASCII)),
                BigIntPlutusData.of(BigInteger.valueOf(publicInputCount))
        };
    }

    private static PlutusData scalarList(BigInteger[] scalars) {
        PlutusData[] values = new PlutusData[scalars.length];
        for (int i = 0; i < scalars.length; i++) {
            values[i] = BigIntPlutusData.of(scalars[i]);
        }
        return ListPlutusData.of(values);
    }
}
