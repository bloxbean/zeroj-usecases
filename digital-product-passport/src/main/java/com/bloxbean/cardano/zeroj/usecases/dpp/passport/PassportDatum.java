package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.util.HexUtil;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * A passport's inline datum (ADR-0009 D1):
 * {@code Passport(productId: B, manufacturerPkh: B28, claims: List<Claim(claim: I, σ: B32, u: I, v: I)>)}.
 * It carries every claim the auditor attests, as a commitment, and no value: the measurements
 * stay with the manufacturer.
 */
public record PassportDatum(byte[] productId, byte[] manufacturerPkh, List<Entry> claims) {

    public static final int MAX_CLAIMS = 4;

    public PassportDatum {
        claims = List.copyOf(claims);
    }

    /** One attested claim: its id, its schema digest {@code σ} (I2OSP32) and its commitment point. */
    public record Entry(int claim, byte[] sigma, BigInteger u, BigInteger v) {
        @Override
        public boolean equals(Object o) {
            return o instanceof Entry e && claim == e.claim && Arrays.equals(sigma, e.sigma)
                    && u.equals(e.u) && v.equals(e.v);
        }

        @Override
        public int hashCode() {
            return 31 * claim + u.hashCode();
        }

        @Override
        public String toString() {
            return "Entry(" + claim + ", σ=" + HexUtil.encodeHexString(sigma) + ", u=" + u + ", v=" + v + ")";
        }
    }

    public static PassportDatum of(byte[] productId, byte[] manufacturerPkh, List<ClaimOpening> openings) {
        return new PassportDatum(productId, manufacturerPkh, openings.stream().map(ClaimOpening::entry).toList());
    }

    public Optional<Entry> entry(int claim) {
        return claims.stream().filter(e -> e.claim() == claim).findFirst();
    }

    public ConstrPlutusData toPlutusData() {
        List<PlutusData> entries = new ArrayList<>();
        for (Entry e : claims) {
            entries.add(ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                    BigIntPlutusData.of(e.claim()), new BytesPlutusData(e.sigma()),
                    BigIntPlutusData.of(e.u()), BigIntPlutusData.of(e.v()))).build());
        }
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(productId), new BytesPlutusData(manufacturerPkh),
                ListPlutusData.of(entries.toArray(PlutusData[]::new)))).build();
    }

    /** Decodes a datum read from chain; throws on any other shape. */
    public static PassportDatum fromPlutusData(PlutusData data) {
        ConstrPlutusData c = (ConstrPlutusData) data;
        List<PlutusData> f = c.getData().getPlutusDataList();
        if (c.getAlternative() != 0 || f.size() != 3) throw new IllegalArgumentException("not a passport datum");
        List<Entry> entries = new ArrayList<>();
        for (PlutusData item : ((ListPlutusData) f.get(2)).getPlutusDataList()) {
            ConstrPlutusData ec = (ConstrPlutusData) item;
            List<PlutusData> ef = ec.getData().getPlutusDataList();
            if (ec.getAlternative() != 0 || ef.size() != 4) throw new IllegalArgumentException("not a claim entry");
            entries.add(new Entry(((BigIntPlutusData) ef.get(0)).getValue().intValueExact(),
                    ((BytesPlutusData) ef.get(1)).getValue(),
                    ((BigIntPlutusData) ef.get(2)).getValue(), ((BigIntPlutusData) ef.get(3)).getValue()));
        }
        return new PassportDatum(((BytesPlutusData) f.get(0)).getValue(), ((BytesPlutusData) f.get(1)).getValue(), entries);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof PassportDatum d && Arrays.equals(productId, d.productId)
                && Arrays.equals(manufacturerPkh, d.manufacturerPkh) && claims.equals(d.claims);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(productId);
    }
}
