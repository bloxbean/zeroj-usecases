package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * What a passport reader (a customs officer, a buyer, a regulator) checks, from chain data and
 * its own configuration only (ADR-0009 D1 verifier rules):
 * <ul>
 *   <li>the policy's mint history for the product: more than one passport ever minted is refused,
 *       the same rule as the reserves demo's duplicate-period check;</li>
 *   <li>each off-chain claim proof against the commitment in the passport datum, with {@code σ}
 *       taken from the reader's own schema registry (vector spec §5) and compared with the
 *       datum's, never taken from the datum.</li>
 * </ul>
 * The passport datum is the authenticated issuance record (vector spec §6): it exists only at the
 * passport address, in a transaction the auditor signed. A commitment from any other source, such
 * as the manufacturer's API, is never accepted.
 */
public final class PassportReader {

    private PassportReader() {}

    /** One mint or burn of the passport token, from the chain indexer. */
    public record MintEvent(String txHash, BigInteger quantity) {}

    public enum Status {
        /** Never minted. */
        NONE,
        /** Minted once and not burned. */
        ACTIVE,
        /** Minted once and burned by the auditor. */
        REVOKED,
        /** More than one passport was minted for this product: refused. */
        DUPLICATE
    }

    /** The status of a product's passport from the complete mint history of its token. */
    public static Status status(List<MintEvent> history) {
        BigInteger minted = BigInteger.ZERO;
        BigInteger burned = BigInteger.ZERO;
        for (MintEvent e : history) {
            if (e.quantity().signum() > 0) minted = minted.add(e.quantity());
            else burned = burned.add(e.quantity().negate());
        }
        if (minted.compareTo(BigInteger.ONE) > 0) return Status.DUPLICATE;
        if (minted.signum() == 0) {
            if (burned.signum() != 0) throw new IllegalStateException("burns without a mint: incomplete history");
            return Status.NONE;
        }
        if (burned.compareTo(BigInteger.ONE) > 0) throw new IllegalStateException("more burned than minted: incomplete history");
        return burned.signum() == 0 ? Status.ACTIVE : Status.REVOKED;
    }

    /**
     * The token's complete mint and burn history from Yaci Store
     * ({@code GET assets/{unit}/history}, every page). Throws on any error, so a reader that
     * cannot see the whole history fails closed.
     */
    public static List<MintEvent> fetchHistory(String indexerBaseUrl, String unit) {
        String base = indexerBaseUrl.endsWith("/") ? indexerBaseUrl : indexerBaseUrl + "/";
        HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        ObjectMapper json = new ObjectMapper();
        List<MintEvent> out = new ArrayList<>();
        int count = 100;
        for (int page = 1; page <= 1000; page++) {
            try {
                var request = HttpRequest.newBuilder()
                        .uri(URI.create(base + "assets/" + unit + "/history?page=" + page + "&count=" + count))
                        .timeout(Duration.ofSeconds(10)).GET().build();
                var response = http.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    throw new IllegalStateException("mint history unavailable (HTTP " + response.statusCode() + ")");
                }
                JsonNode items = json.readTree(response.body());
                if (!items.isArray()) throw new IllegalStateException("unexpected mint history response");
                for (JsonNode item : items) {
                    String tx = item.path("tx_hash").asText(null);
                    JsonNode qty = item.get("quantity");
                    if (tx == null || qty == null) throw new IllegalStateException("incomplete mint history entry");
                    out.add(new MintEvent(tx, new BigInteger(qty.asText())));
                }
                if (items.size() < count) return out;
            } catch (IllegalStateException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException("mint history unavailable: " + e.getMessage(), e);
            }
        }
        throw new IllegalStateException("mint history too long");
    }

    // ------------------------------------------------------------------ claims

    /** The reader's own schema registry: the expected {@code σ} for each claim id. */
    public static final class SchemaRegistry {
        private final Map<Claim, BigInteger> sigmas = new EnumMap<>(Claim.class);

        /** The digests of the schemas this reader was configured with (here, the demo's). */
        public static SchemaRegistry demo() {
            SchemaRegistry r = new SchemaRegistry();
            for (Claim c : Claim.values()) r.sigmas.put(c, c.schema().digest());
            return r;
        }

        public BigInteger expected(Claim claim) {
            return sigmas.get(claim);
        }
    }

    public enum Verdict { VERIFIED, NOT_ATTESTED, SCHEMA_MISMATCH, NON_CANONICAL, PROOF_INVALID }

    /**
     * Verifies an off-chain claim proof against the passport's commitment for that claim:
     * {@code [σ_registry, u, v, param]}, after checking that the datum's {@code σ} equals the
     * registry's.
     */
    public static Verdict verifyClaim(DppCircuits circuits, SchemaRegistry registry, PassportDatum datum,
                                      Claim claim, BigInteger param, Groth16ProofBLS381 proof) {
        Optional<PassportDatum.Entry> entry = datum.entry(claim.id());
        if (entry.isEmpty()) return Verdict.NOT_ATTESTED;
        BigInteger sigma = registry.expected(claim);
        if (sigma == null || !new BigInteger(1, entry.get().sigma()).equals(sigma) || entry.get().sigma().length != 32) {
            return Verdict.SCHEMA_MISMATCH;
        }
        if (!Fields.canonical(entry.get().u()) || !Fields.canonical(entry.get().v())) return Verdict.NON_CANONICAL;
        return circuits.verify(claim, proof, sigma, entry.get().u(), entry.get().v(), param)
                ? Verdict.VERIFIED : Verdict.PROOF_INVALID;
    }
}
