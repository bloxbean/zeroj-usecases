package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.PedersenVectorBases;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Brute-force regression (ADR-0009 I1, M6): an attacker who sees everything a passport mint
 * publishes (the datum, the token name and the redeemer) tries all 65,536 values of every 16-bit
 * claim against every deterministic function of the value alone it could compare: the value
 * itself, Poseidon hashes with the product id, the old {@code auditorHash} with the published
 * {@code 777777}, and the Pedersen point {@code m·G_0} with blinding 0 or 1. Against the new
 * passport it recovers nothing; against the old datum the same routine recovers the carbon value
 * (the control).
 *
 * <p>This is a regression check, not a proof of hiding, which rests on {@code pedersen-jubjub-v1}
 * §3. The inspection vector (three 8-bit ids and three 32-bit times) is outside a 16-bit search.
 */
class PassportBruteForceTest {

    private static final byte[] PRODUCT = "BAT-SN001".getBytes(StandardCharsets.UTF_8);
    private static final BigInteger OLD_AUDITOR_SECRET = BigInteger.valueOf(777777);
    private static final int DOMAIN = 1 << 16;

    @Test
    @DisplayName("All 65,536 guesses of each 16-bit claim against every published field recover nothing")
    void bruteForceRecoversNothing() {
        long carbon = 7;
        long recycled = 45;
        long country = 276;
        List<ClaimOpening> openings = List.of(
                ClaimOpening.fresh(Claim.CARBON, carbon), ClaimOpening.fresh(Claim.RECYCLED, recycled),
                ClaimOpening.fresh(Claim.ORIGIN, country),
                ClaimOpening.fresh(Claim.INSPECTIONS, 11, 1_717_000_000L, 13, 1_717_086_400L, 11, 1_717_172_800L));
        byte[] manufacturer = new byte[28];
        manufacturer[0] = 1;
        PassportDatum datum = PassportDatum.of(PRODUCT, manufacturer, openings);
        var proof = ProverToCardano.compressProof(DppCircuits.compile().prove(openings.get(0), BigInteger.valueOf(50)));
        PlutusData redeemer = ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(proof.piA()), new BytesPlutusData(proof.piB()), new BytesPlutusData(proof.piC()))).build();

        Set<BigInteger> published = new HashSet<>();
        collect(datum.toPlutusData(), published);
        collect(redeemer, published);
        published.add(new BigInteger(1, PRODUCT));       // the token name

        Map<Long, String> hits = search(published);
        System.out.println("[brute force] published fields: " + published.size() + ", hits: " + hits);
        for (long secret : List.of(carbon, recycled, country)) {
            assertFalse(hits.containsKey(secret), "recovered " + secret + " via " + hits.get(secret));
        }
        // The only matches are the public claim ids (0–3) matching themselves.
        for (var hit : hits.entrySet()) {
            assertTrue(hit.getKey() < 4 && hit.getValue().equals("value itself"), "unexpected hit " + hit);
        }
    }

    @Test
    @DisplayName("Control: the same search recovers the carbon value from the old datum")
    void controlOldDatumLeaks() {
        BigInteger productId = new BigInteger(1, PRODUCT);
        BigInteger m = BigInteger.valueOf(7);
        BigInteger auditorHash = poseidon(OLD_AUDITOR_SECRET, poseidon(productId, m));
        // Old mint datum: [productId, threshold, auditorHash, isCompliant].
        Set<BigInteger> published = Set.of(productId, BigInteger.valueOf(50), auditorHash, BigInteger.ONE);
        Map<Long, String> hits = search(published);
        assertEquals("old auditorHash", hits.get(7L));
    }

    /** Every guess {@code m < 2^16} whose deterministic image appears among {@code published}. */
    private static Map<Long, String> search(Set<BigInteger> published) {
        BigInteger productId = new BigInteger(1, PRODUCT);
        JubjubPoint g0 = PedersenVectorBases.valueBase(0);
        JubjubPoint h = PedersenVectorBases.blindingBase();
        JubjubPoint mG = JubjubPoint.IDENTITY;
        Map<Long, String> hits = new LinkedHashMap<>();
        for (long guess = 0; guess < DOMAIN; guess++) {
            BigInteger m = BigInteger.valueOf(guess);
            Map<String, List<BigInteger>> images = new LinkedHashMap<>();
            images.put("value itself", List.of(m));
            images.put("Poseidon(m, 0)", List.of(poseidon(m, BigInteger.ZERO)));
            images.put("Poseidon(productId, m)", List.of(poseidon(productId, m)));
            images.put("Poseidon(m, productId)", List.of(poseidon(m, productId)));
            images.put("old auditorHash", List.of(poseidon(OLD_AUDITOR_SECRET, poseidon(productId, m))));
            JubjubPoint unblinded = mG.normalized();
            JubjubPoint blindedByOne = mG.add(h).normalized();
            images.put("m·G0", List.of(unblinded.affineU(), unblinded.affineV()));
            images.put("m·G0 + H", List.of(blindedByOne.affineU(), blindedByOne.affineV()));
            for (var image : images.entrySet()) {
                for (BigInteger value : image.getValue()) {
                    if (published.contains(value)) hits.putIfAbsent(guess, image.getKey());
                }
            }
            mG = mG.add(g0);
        }
        return hits;
    }

    /** Every integer and byte string (as a big-endian integer) in a Plutus value, recursively. */
    private static void collect(PlutusData data, Set<BigInteger> out) {
        switch (data) {
            case BigIntPlutusData i -> out.add(i.getValue());
            case BytesPlutusData b -> {
                out.add(new BigInteger(1, b.getValue()));
                // Also every 32-byte window, in case a value is embedded in a longer string.
                byte[] bytes = b.getValue();
                for (int i = 0; i + 32 <= bytes.length; i++) {
                    out.add(new BigInteger(1, Arrays.copyOfRange(bytes, i, i + 32)));
                }
            }
            case ConstrPlutusData c -> c.getData().getPlutusDataList().forEach(d -> collect(d, out));
            case ListPlutusData l -> new ArrayList<>(l.getPlutusDataList()).forEach(d -> collect(d, out));
            default -> throw new IllegalArgumentException("unexpected " + data);
        }
    }

    private static BigInteger poseidon(BigInteger a, BigInteger b) {
        return PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, a, b);
    }
}
