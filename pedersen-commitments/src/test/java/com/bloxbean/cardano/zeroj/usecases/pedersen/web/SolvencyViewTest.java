package com.bloxbean.cardano.zeroj.usecases.pedersen.web;

import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Customer;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Period;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0009 D10: the public solvency response ({@code GET /api/solvency}) names no customer and no
 * balance, so it never pairs a customer with an id hash, a commitment or a position. The book is
 * only in the separate operator view ({@code GET /api/solvency/operator}).
 */
class SolvencyViewTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final long LOVELACE = 1_000_000L;
    /** Balances in ADA, chosen distinct from every other number in the public view. */
    private static final Map<String, Long> BOOK = Map.of("alice", 500L, "bob", 1_200L, "carol", 300L, "dave", 7L);

    @Test
    @DisplayName("The public solvency payload holds no customer id or balance next to the on-chain entries")
    void publicViewNamesNoCustomer() throws Exception {
        List<Customer> book = new ArrayList<>();
        BOOK.forEach((id, ada) -> book.add(Customer.of(id, ada * LOVELACE, NoteViewingKey.generate(RANDOM).readerKey())));
        List<Customer> attested = SolvencyAttestation.forAttestation(book);
        var live = new SolvencyService.PublicPeriod(new Period(1_000, 2_000), "addr_test1vault", "policy",
                "tx", 2_000 * LOVELACE, null, SolvencyAttestation.entries(attested));

        String publicJson = JSON.writeValueAsString(
                SolvencyService.publicView(1_500, "during", 10_042, "addr_test1exchange", book.size(), live));
        JsonNode view = JSON.readTree(publicJson);
        assertEquals("public", view.get("view").asText());
        assertEquals(book.size(), view.get("onChain").size(), "the on-chain entries are shown");

        // No customer id anywhere, so none sits next to an id hash, a commitment or a position.
        for (String id : BOOK.keySet()) assertFalse(publicJson.contains(id), "customer id '" + id + "' in " + publicJson);
        // No book fields, and no balance or total liability as a number.
        Set<String> forbidden = Set.of("id", "customer", "balance", "book", "salt", "blinding", "check", "liabilitiesAda");
        Set<Long> balances = Set.copyOf(BOOK.values());
        long liabilities = BOOK.values().stream().mapToLong(Long::longValue).sum();
        walk(view, (name, node) -> {
            assertFalse(forbidden.contains(name), "field '" + name + "' in the public view");
            if (node.isNumber()) {
                assertFalse(balances.contains(node.asLong()) || node.asLong() == liabilities,
                        "a balance or the total liabilities in field '" + name + "'");
            }
        });
        // Each entry carries only on-chain data.
        for (JsonNode e : view.get("onChain")) assertEquals(Set.of("idHash", "u", "delivery"), fieldNames(e));

        // The operator view is separate, labelled, and holds the book.
        JsonNode operator = JSON.readTree(JSON.writeValueAsString(SolvencyService.operatorView(attested, Map.of())));
        assertTrue(operator.get("view").asText().startsWith("operator"));
        assertEquals(book.size(), operator.get("book").size());
        assertEquals(liabilities, operator.get("liabilitiesAda").asLong());
        for (JsonNode c : operator.get("book")) {
            Customer customer = attested.stream().filter(a -> a.id().equals(c.get("id").asText())).findFirst().orElseThrow();
            assertEquals(HexUtil.encodeHexString(customer.idHash()).substring(0, 12) + "…", c.get("idHash").asText());
        }
    }

    private interface Visitor {
        void visit(String name, JsonNode node);
    }

    private static void walk(JsonNode node, Visitor visitor) {
        if (node.isObject()) {
            node.fields().forEachRemaining(f -> {
                visitor.visit(f.getKey(), f.getValue());
                walk(f.getValue(), visitor);
            });
        } else if (node.isArray()) {
            for (JsonNode child : node) walk(child, visitor);
        }
    }

    private static Set<String> fieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return Set.copyOf(names);
    }
}
