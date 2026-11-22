package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Plutus;
import org.julclang.core.PlutusData;
import org.julclang.core.cbor.PlutusDataCborEncoder;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

/**
 * A Groth16 verification key pinned by hash (on-chain {@code VkLib}): the redeemer carries
 * {@code Constr 0 [B alpha, B beta, B gamma, B delta, [B ic_i]]}, and the script parameter is
 * {@code blake2b_256} of that value's Plutus {@code serialiseData} encoding. The hash uses Julc's
 * encoder, which follows Plutus's canonical CBOR (byte strings chunked at 64 bytes), so it equals
 * what the validator recomputes from the decoded redeemer.
 */
public final class VerificationKeys {

    private VerificationKeys() {}

    /** The key as redeemer data (cardano-client-lib). */
    public static ConstrPlutusData data(SnarkjsToCardano.VkCompressed vk) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(vk.alpha()), new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()), new BytesPlutusData(vk.delta()),
                Plutus.icData(vk.ic()))).build();
    }

    /** The same value as Julc data (for VM tests). */
    public static PlutusData julcData(SnarkjsToCardano.VkCompressed vk) {
        PlutusData[] ic = vk.ic().stream().map(PlutusData::bytes).toArray(PlutusData[]::new);
        return PlutusData.constr(0, PlutusData.bytes(vk.alpha()), PlutusData.bytes(vk.beta()),
                PlutusData.bytes(vk.gamma()), PlutusData.bytes(vk.delta()), PlutusData.list(ic));
    }

    /** {@code blake2b_256(serialiseData(vk))}. */
    public static byte[] hash(SnarkjsToCardano.VkCompressed vk) {
        return Blake2bUtil.blake2bHash256(PlutusDataCborEncoder.encode(julcData(vk)));
    }
}
