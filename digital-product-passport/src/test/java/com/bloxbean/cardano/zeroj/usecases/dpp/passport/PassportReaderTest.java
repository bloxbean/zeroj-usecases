package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportReader.MintEvent;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportReader.Status;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportReader.Verdict;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The reader's rules (ADR-0009 D1): refuse a product whose policy mint history shows more than
 * one passport, fail closed on an unavailable history, and verify off-chain claims with σ from
 * the reader's own registry.
 */
class PassportReaderTest {

    private static final byte[] PRODUCT = "BAT-SN001".getBytes(StandardCharsets.UTF_8);
    private static final byte[] MANUFACTURER = new byte[28];
    private static DppCircuits circuits;
    private static ClaimOpening carbon;
    private static ClaimOpening recycled;
    private static ClaimOpening origin;
    private static Groth16ProofBLS381 recycledProof;
    private static Groth16ProofBLS381 originProof;

    @BeforeAll
    static void setup() {
        circuits = DppCircuits.compile();
        carbon = ClaimOpening.fresh(Claim.CARBON, 7);
        recycled = ClaimOpening.fresh(Claim.RECYCLED, 45);
        origin = ClaimOpening.fresh(Claim.ORIGIN, 276);
        recycledProof = circuits.prove(recycled, BigInteger.valueOf(30));
        originProof = circuits.prove(origin, ApprovedSets.EU_COUNTRIES.root());
    }

    @Test
    @DisplayName("Mint history: one mint is active, a burn revokes, a second mint (also after a burn) is refused")
    void mintHistory() {
        assertEquals(Status.NONE, PassportReader.status(List.of()));
        assertEquals(Status.ACTIVE, PassportReader.status(List.of(mint(1))));
        assertEquals(Status.REVOKED, PassportReader.status(List.of(mint(1), mint(-1))));
        assertEquals(Status.DUPLICATE, PassportReader.status(List.of(mint(1), mint(1))));
        assertEquals(Status.DUPLICATE, PassportReader.status(List.of(mint(1), mint(-1), mint(1))));
        assertEquals(Status.DUPLICATE, PassportReader.status(List.of(mint(2))));
        assertThrows(IllegalStateException.class, () -> PassportReader.status(List.of(mint(-1))));
    }

    @Test
    @DisplayName("Mint history is read across pages; an unavailable indexer fails closed")
    void fetchHistory() throws Exception {
        AtomicInteger fail = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/assets/", exchange -> {
            String query = exchange.getRequestURI().getQuery();
            int page = Integer.parseInt(query.replaceAll(".*page=(\\d+).*", "$1"));
            String body;
            int code = fail.get() == 1 ? 500 : 200;
            if (page == 1) {
                List<String> items = new ArrayList<>();
                for (int i = 0; i < 100; i++) items.add("{\"tx_hash\":\"a" + i + "\",\"quantity\":" + (i == 0 ? 1 : (i % 2 == 0 ? 1 : -1)) + "}");
                body = "[" + String.join(",", items) + "]";
            } else {
                body = "[{\"tx_hash\":\"z\",\"quantity\":1}]";
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(code, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        try {
            String base = "http://127.0.0.1:" + server.getAddress().getPort() + "/api/v1/";
            List<MintEvent> history = PassportReader.fetchHistory(base, "unit");
            assertEquals(101, history.size(), "both pages read");
            assertEquals(Status.DUPLICATE, PassportReader.status(history));
            fail.set(1);
            assertThrows(IllegalStateException.class, () -> PassportReader.fetchHistory(base, "unit"));
        } finally {
            server.stop(0);
        }
        assertThrows(IllegalStateException.class, () -> PassportReader.fetchHistory("http://127.0.0.1:1/", "unit"));
    }

    @Test
    @DisplayName("Off-chain claims verify against the datum's commitment, with σ from the reader's registry")
    void verifyClaims() {
        var registry = PassportReader.SchemaRegistry.demo();
        PassportDatum datum = PassportDatum.of(PRODUCT, MANUFACTURER, List.of(carbon, recycled, origin));
        assertEquals(Verdict.VERIFIED, PassportReader.verifyClaim(circuits, registry, datum, Claim.RECYCLED,
                BigInteger.valueOf(30), recycledProof));
        assertEquals(Verdict.VERIFIED, PassportReader.verifyClaim(circuits, registry, datum, Claim.ORIGIN,
                ApprovedSets.EU_COUNTRIES.root(), originProof));
        // Not attested: no inspection entry in this passport.
        assertEquals(Verdict.NOT_ATTESTED, PassportReader.verifyClaim(circuits, registry, datum, Claim.INSPECTIONS,
                ApprovedSets.INSPECTORS.root(), originProof));
        // A lower threshold than the reader's statement: the proof does not verify.
        assertEquals(Verdict.PROOF_INVALID, PassportReader.verifyClaim(circuits, registry, datum, Claim.RECYCLED,
                BigInteger.valueOf(40), recycledProof));
        // A proof for another commitment (another product's opening).
        var otherProof = circuits.prove(ClaimOpening.fresh(Claim.RECYCLED, 45), BigInteger.valueOf(30));
        assertEquals(Verdict.PROOF_INVALID, PassportReader.verifyClaim(circuits, registry, datum, Claim.RECYCLED,
                BigInteger.valueOf(30), otherProof));
    }

    @Test
    @DisplayName("A datum σ that is not the registry's is refused, and σ is never taken from the datum")
    void sigmaFromRegistry() {
        var registry = PassportReader.SchemaRegistry.demo();
        JubjubPoint r = recycled.point();
        // The recycled entry carries the carbon schema's σ.
        PassportDatum wrongSigma = new PassportDatum(PRODUCT, MANUFACTURER, List.of(carbon.entry(),
                new PassportDatum.Entry(Claim.RECYCLED.id(), Claim.CARBON.sigma(), r.affineU(), r.affineV())));
        assertEquals(Verdict.SCHEMA_MISMATCH, PassportReader.verifyClaim(circuits, registry, wrongSigma, Claim.RECYCLED,
                BigInteger.valueOf(30), recycledProof));
        PassportDatum nonCanonical = new PassportDatum(PRODUCT, MANUFACTURER, List.of(carbon.entry(),
                new PassportDatum.Entry(Claim.RECYCLED.id(), Claim.RECYCLED.sigma(), r.affineU().add(Fields.FR), r.affineV())));
        assertEquals(Verdict.NON_CANONICAL, PassportReader.verifyClaim(circuits, registry, nonCanonical, Claim.RECYCLED,
                BigInteger.valueOf(30), recycledProof));
    }

    @Test
    @DisplayName("The datum round-trips through its Plutus encoding")
    void datumRoundTrip() {
        PassportDatum datum = PassportDatum.of(PRODUCT, MANUFACTURER, List.of(carbon, recycled, origin));
        assertEquals(datum, PassportDatum.fromPlutusData(datum.toPlutusData()));
    }

    private static MintEvent mint(long quantity) {
        return new MintEvent("tx", BigInteger.valueOf(quantity));
    }
}
