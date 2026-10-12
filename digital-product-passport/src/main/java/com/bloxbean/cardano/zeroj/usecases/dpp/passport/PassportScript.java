package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.common.model.Network;
import com.bloxbean.cardano.client.exception.CborSerializationException;
import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusScript;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.dpp.onchain.DppPassport;
import org.julclang.clientlib.JulcScriptLoader;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * One {@code DppPassport} instance: the policy (and address) of one manufacturer, audited by one
 * auditor, gating one claim against one threshold. Its hash is the policy id; its enterprise
 * address (no stake credential) is where every passport it mints stays.
 */
public final class PassportScript {

    private final byte[] manufacturerPkh;
    private final byte[] auditorPkh;
    private final Claim gated;
    private final long threshold;
    private final PlutusScript script;
    private final String policyId;
    private final String address;

    public PassportScript(byte[] manufacturerPkh, byte[] auditorPkh, Claim gated, long threshold,
                          SnarkjsToCardano.VkCompressed vk, Network network) {
        this.manufacturerPkh = manufacturerPkh.clone();
        this.auditorPkh = auditorPkh.clone();
        this.gated = gated;
        this.threshold = threshold;
        this.script = JulcScriptLoader.load(DppPassport.class, parameters(manufacturerPkh, auditorPkh, gated, threshold, vk)
                .toArray(PlutusData[]::new));
        try {
            this.policyId = HexUtil.encodeHexString(script.getScriptHash());
            this.address = AddressProvider.getEntAddress(script, network).toBech32();
        } catch (CborSerializationException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The parameters in declaration order: manufacturer, auditor, gated claim, its σ, threshold, VK. */
    public static List<PlutusData> parameters(byte[] manufacturerPkh, byte[] auditorPkh, Claim gated, long threshold,
                                              SnarkjsToCardano.VkCompressed vk) {
        PlutusData[] ic = vk.ic().stream().map(BytesPlutusData::new).toArray(PlutusData[]::new);
        return List.of(new BytesPlutusData(manufacturerPkh), new BytesPlutusData(auditorPkh),
                BigIntPlutusData.of(gated.id()), new BytesPlutusData(gated.sigma()), BigIntPlutusData.of(threshold),
                new BytesPlutusData(vk.alpha()), new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()), new BytesPlutusData(vk.delta()), ListPlutusData.of(ic));
    }

    public PlutusScript script() { return script; }

    public String policyId() { return policyId; }

    public String address() { return address; }

    public Claim gated() { return gated; }

    public BigInteger threshold() { return BigInteger.valueOf(threshold); }

    public byte[] manufacturerPkh() { return manufacturerPkh.clone(); }

    public byte[] auditorPkh() { return auditorPkh.clone(); }

    /** {@code policyId ‖ hex(productId)}: the passport token's unit. */
    public String unit(byte[] productId) {
        return policyId + HexUtil.encodeHexString(productId);
    }

    public boolean isFor(byte[] manufacturer, byte[] auditor) {
        return Arrays.equals(manufacturerPkh, manufacturer) && Arrays.equals(auditorPkh, auditor);
    }
}
