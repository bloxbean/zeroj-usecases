package com.bloxbean.cardano.zeroj.usecases.reserves.verify;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * {@link ChainIndexer} over Yaci Store's REST API ({@code cardano.yaci.base-url}, e.g.
 * {@code http://localhost:8080/api/v1/}):
 * {@code blocks/latest}, {@code assets/{unit}/utxos} and {@code assets/{unit}/history}.
 *
 * <p>Yaci Store treats {@code page=0} and {@code page=1} as the same first page, so pages are
 * requested from 1. A 404 reads as "nothing": no output, or an empty history page, which the
 * check then refuses. Any other non-2xx status or malformed body throws.
 */
public final class YaciStoreIndexer implements ChainIndexer {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final String baseUrl;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    public YaciStoreIndexer(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
    }

    @Override
    public long latestBlockTimeMs() throws IOException {
        JsonNode block = get("blocks/latest");
        if (block == null || !block.path("time").canConvertToLong()) throw new IOException("no latest block time");
        return Math.multiplyExact(block.path("time").asLong(), 1000L);
    }

    @Override
    public List<UtxoView> assetUtxos(String unit, int count) throws IOException {
        JsonNode body = get("assets/" + unit + "/utxos?page=1&count=" + count);
        List<UtxoView> out = new ArrayList<>();
        if (body == null) return out;
        if (!body.isArray()) throw new IOException("asset utxos: not a list");
        for (JsonNode u : body) {
            Map<String, BigInteger> amounts = new HashMap<>();
            for (JsonNode a : u.path("amount")) {
                amounts.merge(a.path("unit").asText(), new BigInteger(a.path("quantity").asText()), BigInteger::add);
            }
            String datum = u.path("inline_datum").isTextual() ? u.path("inline_datum").asText() : null;
            out.add(new UtxoView(u.path("tx_hash").asText(), u.path("output_index").asInt(),
                    u.path("address").asText(), amounts, datum));
        }
        return out;
    }

    @Override
    public List<HistoryEntry> assetHistory(String unit, int page, int count) throws IOException {
        if (page < 1) throw new IllegalArgumentException("pages start at 1");
        JsonNode body = get("assets/" + unit + "/history?page=" + page + "&count=" + count);
        List<HistoryEntry> out = new ArrayList<>();
        if (body == null) return out;
        if (!body.isArray()) throw new IOException("asset history: not a list");
        for (JsonNode e : body) {
            String quantity = e.path("quantity").asText();
            if (quantity.isEmpty()) throw new IOException("asset history: entry without quantity");
            out.add(new HistoryEntry(e.path("tx_hash").asText(),
                    e.path("unit").isTextual() ? e.path("unit").asText() : null, new BigInteger(quantity)));
        }
        return out;
    }

    /** The parsed body, or null for 404. */
    private JsonNode get(String path) throws IOException {
        var request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(Duration.ofSeconds(10)).header("Accept", "application/json").GET().build();
        HttpResponse<String> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted", e);
        }
        if (response.statusCode() == 404) return null;
        if (response.statusCode() / 100 != 2) {
            throw new IOException(path + " returned HTTP " + response.statusCode());
        }
        try {
            return JSON.readTree(response.body());
        } catch (RuntimeException e) {
            throw new IOException(path + ": malformed JSON", e);
        }
    }
}
