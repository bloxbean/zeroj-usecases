package com.bloxbean.cardano.zeroj.usecases.reserves.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The customer page recomputes the root in the browser with its own Poseidon. Its constants
 * ({@code frontend/src/lib/reserves/poseidonParams.js}, a JSON object as an ES module) must be exactly ZeroJ's
 * {@link PoseidonParamsBLS12_381T3}; this test fails if they drift. The browser test then checks
 * its hash outputs against the ZeroJ vectors in {@code customer-check-fixtures.json}.
 */
class BrowserPoseidonParamsTest {

    static final Path FILE = Path.of("frontend/src/lib/reserves/poseidonParams.js");
    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private static final String HEADER = "// Generated from ZeroJ's PoseidonParamsBLS12_381T3 by BrowserPoseidonParamsTest; do not edit.\n"
            + "export default ";

    @Test
    void browserConstantsAreZeroJsParameters() throws IOException {
        PoseidonParams p = PoseidonParamsBLS12_381T3.INSTANCE;
        ObjectNode expected = JSON.createObjectNode();
        expected.put("source", "org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3 (checked by BrowserPoseidonParamsTest)");
        expected.put("prime", p.field().prime().toString());
        expected.put("t", p.t());
        expected.put("alpha", p.alpha());
        expected.put("rf", p.rf());
        expected.put("rp", p.rp());
        ArrayNode c = expected.putArray("c");
        for (BigInteger v : p.c()) c.add(v.toString());
        ArrayNode m = expected.putArray("m");
        for (BigInteger v : p.m()) m.add(v.toString());
        JsonNode normalized = JSON.readTree(JSON.writeValueAsString(expected));
        if ("true".equals(System.getenv("RESERVES_REGENERATE_FIXTURES"))) {
            Files.writeString(FILE, HEADER + JSON.writeValueAsString(expected) + ";\n");
        }
        String js = Files.readString(FILE);
        if (!js.startsWith(HEADER) || !js.endsWith(";\n")) throw new AssertionError(FILE + " is not in the generated form");
        JsonNode actual = JSON.readTree(js.substring(HEADER.length(), js.length() - 2));
        assertEquals(normalized, actual, FILE + " differs from ZeroJ's Poseidon parameters");
    }
}
