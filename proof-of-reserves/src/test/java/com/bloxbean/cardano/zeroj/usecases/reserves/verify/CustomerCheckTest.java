package com.bloxbean.cardano.zeroj.usecases.reserves.verify;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The customer check (ADR-0009 D4.3, M4 exit) over the shared fixtures: a correct path passes; a
 * tampered path, a fake attestation, a stale period, duplicate mints (two separate mints, a burn
 * and re-mint, a second mint on a later page) and unavailable or incomplete history all fail. The
 * browser implementation runs the same file ({@code frontend/test/customerCheck.test.mjs}).
 */
class CustomerCheckTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Test
    void committedFixturesMatchTheGenerator() throws IOException {
        // Round-trip so numeric node types compare as parsed (an int-sized long reads back as an int).
        var generated = JSON.readTree(JSON.writeValueAsString(CustomerCheckFixtures.generate()));
        Path file = Path.of(CustomerCheckFixtures.RESOURCE);
        if ("true".equals(System.getenv("RESERVES_REGENERATE_FIXTURES"))) {
            Files.writeString(file, JSON.writeValueAsString(generated) + "\n");
        }
        assertEquals(generated, JSON.readTree(file.toFile()),
                "customer-check-fixtures.json is stale; regenerate with RESERVES_REGENERATE_FIXTURES=true");
    }

    @Test
    void fixturesCoverEveryRequiredCase() throws IOException {
        List<String> expected = new ArrayList<>();
        fixtures().get("scenarios").forEach(s -> expected.add(s.get("expected").asText()));
        for (String outcome : List.of("VERIFIED", "ROOT_MISMATCH", "NOT_AT_SCRIPT_ADDRESS", "BAD_DATUM",
                "NO_ATTESTATION", "DUPLICATE_ATTESTATION", "HISTORY_INCOMPLETE", "INDEXER_UNAVAILABLE")) {
            assertTrue(expected.contains(outcome), "no scenario expects " + outcome);
        }
    }

    @TestFactory
    Stream<DynamicTest> scenarios() throws IOException {
        JsonNode f = fixtures();
        var deployment = new CustomerCheck.Deployment(f.get("deployment").get("policyId").asText(),
                f.get("deployment").get("genesisMs").asLong(), f.get("deployment").get("periodMs").asLong());
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode s : f.get("scenarios")) {
            tests.add(DynamicTest.dynamicTest(s.get("name").asText(), () -> {
                var result = CustomerCheck.check(inclusion(f.get("inclusion"), s.get("override")), deployment,
                        new FixtureIndexer(s.get("indexer")), s.get("pageSize").asInt());
                assertEquals(s.get("expected").asText(), result.outcome().name(), result.detail());
            }));
        }
        return tests.stream();
    }

    @Test
    void recomputedRootMatchesTheTree() throws IOException {
        JsonNode f = fixtures();
        assertEquals(new BigInteger(f.get("root").asText()),
                CustomerCheck.recomputeRoot(inclusion(f.get("inclusion"), null)));
    }

    static JsonNode fixtures() throws IOException {
        return JSON.readTree(Path.of(CustomerCheckFixtures.RESOURCE).toFile());
    }

    static CustomerCheck.Inclusion inclusion(JsonNode in, JsonNode override) {
        Map<String, String> o = new HashMap<>();
        if (override != null) override.fields().forEachRemaining(e -> o.put(e.getKey(), e.getValue().asText()));
        List<BigInteger> siblings = new ArrayList<>();
        for (int i = 0; i < in.get("siblings").size(); i++) {
            siblings.add(new BigInteger(o.getOrDefault("sibling" + i, in.get("siblings").get(i).asText())));
        }
        return new CustomerCheck.Inclusion(
                o.getOrDefault("accountId", in.get("accountId").asText()),
                new BigInteger(o.getOrDefault("salt", in.get("salt").asText())),
                new BigInteger(o.getOrDefault("balance", in.get("balance").asText())),
                Long.parseLong(o.getOrDefault("leafIndex", in.get("leafIndex").asText())),
                siblings);
    }

    /** Serves a scenario's indexer data; the browser test interprets the same shape. */
    static final class FixtureIndexer implements ChainIndexer {
        private final JsonNode spec;

        FixtureIndexer(JsonNode spec) {
            this.spec = spec;
        }

        @Override
        public long latestBlockTimeMs() throws IOException {
            if (spec.get("latestTimeMs").isNull()) throw new IOException("unavailable");
            return spec.get("latestTimeMs").asLong();
        }

        @Override
        public List<UtxoView> assetUtxos(String unit, int count) throws IOException {
            if (spec.path("utxosError").asBoolean(false)) throw new IOException("unavailable");
            List<UtxoView> out = new ArrayList<>();
            for (JsonNode u : spec.get("utxos").path(unit)) {
                Map<String, BigInteger> amounts = new HashMap<>();
                u.get("amounts").fields().forEachRemaining(e -> amounts.put(e.getKey(), new BigInteger(e.getValue().asText())));
                out.add(new UtxoView(u.get("txHash").asText(), u.get("outputIndex").asInt(), u.get("address").asText(),
                        amounts, u.get("inlineDatum").isNull() ? null : u.get("inlineDatum").asText()));
            }
            return out;
        }

        @Override
        public List<HistoryEntry> assetHistory(String unit, int page, int count) throws IOException {
            JsonNode h = spec.get("history").path(unit);
            if (h.path("errorAtPage").asInt(0) == page) throw new IOException("unavailable");
            JsonNode pages = h.path("pages");
            JsonNode entries = h.path("repeat").asBoolean(false) ? pages.get(0) : pages.path(page - 1);
            List<HistoryEntry> out = new ArrayList<>();
            for (JsonNode e : entries) {
                out.add(new HistoryEntry(e.get("txHash").asText(), e.get("unit").asText(),
                        new BigInteger(e.get("quantity").asText())));
            }
            return out;
        }
    }
}
