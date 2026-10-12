package com.bloxbean.cardano.zeroj.usecases.dpp.controller;

import com.bloxbean.cardano.zeroj.usecases.dpp.DppSpringTestBase;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The demo API is an operator view, and its public endpoints return no measurements (ADR-0009
 * D10): {@code /status}, {@code /products}, {@code /verify}, {@code /passport/{id}} and
 * {@code /registry} carry no carbon, recycled content, country or inspection value, as a number
 * or as a string; only the "manufacturer (private)" panel does.
 */
class DppApiPrivacyTest extends DppSpringTestBase {

    private static final Set<String> MEASUREMENT_KEYS = Set.of("carbonKg", "carbon_per_unit_kg",
            "recycledPct", "country", "inspections", "inspectionCount", "measurement", "details", "values");
    /** BAT-SN001's values: 7 kg, 45 %, DEU (276), inspectors 11 and 13, first inspection at 1717000000. */
    private static final List<String> SECRETS = List.of("7", "45", "276", "11", "13", "1717000000");
    /** Numeric fields that are not measurements: timings and counts. */
    private static final Set<String> NON_MEASUREMENT_NUMBERS = Set.of("provingTimeMs", "totalProvingTimeMs",
            "page", "size", "totalPages", "totalElements", "totalDbCount", "passportCount", "productCount", "unitCount",
            "totalProducts", "added");

    @Autowired
    MockMvc mvc;

    private final ObjectMapper json = new ObjectMapper();

    @Test
    @DisplayName("/status, /products, /verify, /passport and /registry return no measurements; the private panel does")
    void publicEndpointsCarryNoValues() throws Exception {
        JsonNode status = read(mvc.perform(get("/api/dpp/status")).andReturn().getResponse().getContentAsString());
        for (String list : List.of("products", "batches")) assertTrue(status.get(list).size() > 0);
        JsonNode page = read(mvc.perform(get("/api/dpp/products?page=0&size=50")).andReturn().getResponse().getContentAsString());
        assertTrue(page.get("products").size() >= 6);
        JsonNode verify = read(mvc.perform(post("/api/dpp/verify").contentType(MediaType.APPLICATION_JSON)
                .content("{\"id\":\"BAT-SN001\",\"type\":\"product\"}")).andReturn().getResponse().getContentAsString());
        assertEquals(4, verify.get("claims").size());
        assertTrue(verify.get("allCompliant").asBoolean(), verify.toString());
        // Without a reachable chain the reader fails closed (and says nothing about values).
        JsonNode passport = read(mvc.perform(get("/api/dpp/passport/BAT-SN001")).andReturn().getResponse().getContentAsString());
        assertFalse(passport.get("accepted").asBoolean());
        JsonNode registry = read(mvc.perform(get("/api/dpp/registry")).andReturn().getResponse().getContentAsString());

        for (var e : Map.of("/status", status, "/products", page, "/verify", verify, "/passport", passport,
                "/registry", registry).entrySet()) {
            assertNoMeasurements(e.getValue(), null, e.getKey());
        }

        JsonNode panel = read(mvc.perform(get("/api/dpp/manufacturer/BAT-SN001")).andReturn().getResponse().getContentAsString());
        assertEquals("manufacturer (private)", panel.get("view").asText());
        assertEquals(7, panel.get("values").get("carbon_kg").asInt());
    }

    @Test
    @DisplayName("A product whose carbon claim cannot be proved gets no passport (no chain access needed)")
    void highCarbonHasNoPassport() throws Exception {
        String verify = mvc.perform(post("/api/dpp/verify").contentType(MediaType.APPLICATION_JSON)
                .content("{\"id\":\"BAT-SN003\"}")).andReturn().getResponse().getContentAsString();
        assertFalse(read(verify).get("allCompliant").asBoolean());
        var mint = mvc.perform(post("/api/dpp/mint").contentType(MediaType.APPLICATION_JSON)
                .content("{\"id\":\"BAT-SN003\"}")).andReturn().getResponse();
        assertEquals(403, mint.getStatus(), mint.getContentAsString());
    }

    private JsonNode read(String body) throws Exception {
        return json.readTree(body);
    }

    /**
     * No measurement field name anywhere, no number equal to a secret value (outside timings and
     * counts), and no string equal to one or containing one as a separate token.
     */
    private static void assertNoMeasurements(JsonNode node, String field, String where) {
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> it = node.fields();
            while (it.hasNext()) {
                var e = it.next();
                assertFalse(MEASUREMENT_KEYS.contains(e.getKey()), where + " leaks the field " + e.getKey() + ": " + node);
                assertNoMeasurements(e.getValue(), e.getKey(), where);
            }
        } else if (node.isArray()) {
            for (JsonNode item : node) assertNoMeasurements(item, field, where);
        } else if (node.isNumber()) {
            if (!NON_MEASUREMENT_NUMBERS.contains(field)) {
                assertFalse(SECRETS.contains(node.asText()), where + " leaks " + field + " = " + node);
            }
        } else if (node.isTextual()) {
            for (String secret : SECRETS) {
                assertFalse(node.asText().equals(secret)
                        || Pattern.compile("(^|[^0-9A-Za-z])" + secret + "([^0-9A-Za-z]|$)").matcher(node.asText()).find(),
                        where + " leaks " + secret + " in " + field + " = " + node);
            }
        }
    }
}
