package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.bloxbean.cardano.client.api.model.Result;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fault injection at the faucet's pay-once boundary (ADR-0009 D3.5): which submission outcomes
 * release a nullifier's reservation, and which keep it. Only a failure before submission, or a
 * definitive node rejection of a transaction that is not on-chain, releases it.
 */
class PayOnceTest {

    private static final BigInteger NULLIFIER = new BigInteger("2a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", 16);
    private static final String UNIT = "ab".repeat(28) + PaidNullifierLedger.key(NULLIFIER);
    private static final String TX = "cd".repeat(32);
    private static final String DEFINITIVE =
            "TxSubmitFail (TxCmdTxSubmitValidationError (ApplyTxError [ConwayUtxowFailure (UtxoFailure (BadInputsUTxO ...))]))";

    /** A scripted chain; counts submissions. */
    private static final class FakeChain implements ClaimChain {
        Boolean minted = false;           // null: the lookup fails
        Result<String> submitResult;      // null: the submission throws
        Boolean onChain = false;          // null: the lookup fails
        int submissions;

        @Override
        public boolean receiptMinted(String unit) throws Exception {
            if (minted == null) throw new IOException("store unavailable");
            return minted;
        }

        @Override
        public Result<String> submit(byte[] signedCbor) throws Exception {
            submissions++;
            if (submitResult == null) throw new IOException("connection reset after sending");
            return submitResult;
        }

        @Override
        public boolean txOnChain(String txHash) throws Exception {
            if (onChain == null) throw new IOException("store unavailable");
            return onChain;
        }
    }

    private record Faucet(OnChainAirdropService service, PaidNullifierLedger ledger, FakeChain chain) {}

    private static Faucet faucet(Path dir) {
        var data = new AirdropDataDir(dir);
        var keys = new AirdropKeys(data);
        var ledger = new PaidNullifierLedger(data);
        var chain = new FakeChain();
        var service = new OnChainAirdropService(null, keys, null, new PersonhoodIssuerService(keys, data), ledger,
                data, 1, 2, false, "", 0, chain);
        return new Faucet(service, ledger, chain);
    }

    private static OnChainAirdropService.ClaimSigner signed() {
        return () -> new OnChainAirdropService.SignedClaim(new byte[]{1, 2, 3}, TX);
    }

    @SuppressWarnings("unchecked")
    private static Result<String> rejected(int code, String body) {
        return Result.error(body).code(code);
    }

    @SuppressWarnings("unchecked")
    private static Result<String> accepted() {
        return Result.success("ok").withValue(TX).code(200);
    }

    private static boolean recordedAfterRestart(Path dir) {
        return new PaidNullifierLedger(new AirdropDataDir(dir)).isRecorded(NULLIFIER);
    }

    @Test
    void successIsKeptAsPaid(@TempDir Path dir) throws Exception {
        var f = faucet(dir);
        f.chain().submitResult = accepted();
        assertEquals(TX, f.service().payOnce(UNIT, NULLIFIER, signed()));
        assertTrue(recordedAfterRestart(dir));
        assertThrows(PaidNullifierLedger.AlreadyPaidException.class, () -> f.service().payOnce(UNIT, NULLIFIER, signed()));
        assertEquals(1, f.chain().submissions);
    }

    @Test
    void ambiguousSubmissionKeepsTheReservation(@TempDir Path dir) {
        var f = faucet(dir);
        f.chain().submitResult = null;   // transport error after sending
        assertThrows(IOException.class, () -> f.service().payOnce(UNIT, NULLIFIER, signed()));
        assertTrue(recordedAfterRestart(dir), "the transaction may have reached the node");
    }

    @Test
    void definitiveRejectionOfATransactionNotOnChainReleases(@TempDir Path dir) throws Exception {
        var f = faucet(dir);
        f.chain().submitResult = rejected(400, DEFINITIVE);
        assertThrows(RuntimeException.class, () -> f.service().payOnce(UNIT, NULLIFIER, signed()));
        assertFalse(recordedAfterRestart(dir));
        // The holder can claim again.
        f.chain().submitResult = accepted();
        assertEquals(TX, f.service().payOnce(UNIT, NULLIFIER, signed()));
    }

    @Test
    void otherRejectionsKeepTheReservation(@TempDir Path base) throws Exception {
        Map<String, Result<String>> kept = Map.of(
                "already-in-mempool", rejected(400, "ApplyTxError: transaction already in mempool"),
                "duplicate", rejected(400, "BadInputsUTxO (duplicate submission)"),
                "unclassified-400", rejected(400, "Bad Request"),
                "server-error", rejected(500, DEFINITIVE),
                "gateway-timeout", rejected(504, "Gateway Timeout"),
                "not-found", rejected(404, "Not Found"));
        for (var entry : kept.entrySet()) {
            Path dir = base.resolve(entry.getKey());
            var f = faucet(dir);
            f.chain().submitResult = entry.getValue();
            assertThrows(RuntimeException.class, () -> f.service().payOnce(UNIT, NULLIFIER, signed()), entry.getKey());
            assertTrue(recordedAfterRestart(dir), entry.getKey() + " must keep the reservation");
        }
    }

    @Test
    void definitiveRejectionKeepsTheReservationIfTheTransactionIsOnChainOrUnknown(@TempDir Path base) {
        for (Boolean onChain : new Boolean[]{true, null}) {
            Path dir = base.resolve(String.valueOf(onChain));
            var f = faucet(dir);
            f.chain().submitResult = rejected(400, DEFINITIVE);
            f.chain().onChain = onChain;
            assertThrows(RuntimeException.class, () -> f.service().payOnce(UNIT, NULLIFIER, signed()));
            assertTrue(recordedAfterRestart(dir), "on-chain=" + onChain + " must keep the reservation");
        }
    }

    @Test
    void failureBeforeSubmissionReleases(@TempDir Path dir) {
        var f = faucet(dir);
        assertThrows(IllegalStateException.class, () -> f.service().payOnce(UNIT, NULLIFIER, () -> {
            throw new IllegalStateException("script evaluation failed");
        }));
        assertEquals(0, f.chain().submissions);
        assertFalse(recordedAfterRestart(dir));
    }

    @Test
    void aReceiptMintedAnywhereIsRefusedWithoutReserving(@TempDir Path dir) {
        // E.g. a receipt minted earlier to the script with a stake credential, or by a replay:
        // the mint history of the unit covers every address.
        var f = faucet(dir);
        f.chain().minted = true;
        assertThrows(PaidNullifierLedger.AlreadyPaidException.class, () -> f.service().payOnce(UNIT, NULLIFIER, signed()));
        assertFalse(f.ledger().isRecorded(NULLIFIER));
        assertEquals(0, f.chain().submissions);
    }

    @Test
    void anUnavailableReceiptLookupRefuses(@TempDir Path dir) {
        var f = faucet(dir);
        f.chain().minted = null;
        assertThrows(IOException.class, () -> f.service().payOnce(UNIT, NULLIFIER, signed()));
        assertFalse(f.ledger().isRecorded(NULLIFIER));
        assertEquals(0, f.chain().submissions);
    }

    /** The real lookup reads Yaci Store's mint history of the unit and fails closed. */
    @Test
    void storeMintHistoryLookup() throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        Map<String, Object[]> routes = Map.of(
                "/api/v1/assets/minted/history", new Object[]{200,
                        "[{\"tx_hash\":\"" + TX + "\",\"quantity\":1,\"mint_type\":\"MINT\"}]"},
                "/api/v1/assets/fresh/history", new Object[]{200, "[]"},
                "/api/v1/assets/missing/history", new Object[]{404, "{}"},
                "/api/v1/assets/broken/history", new Object[]{500, "oops"},
                "/api/v1/assets/odd/history", new Object[]{200, "{\"error\":\"x\"}"});
        server.createContext("/", exchange -> {
            Object[] route = routes.get(exchange.getRequestURI().getPath());
            byte[] body = (route == null ? "{}" : (String) route[1]).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(route == null ? 404 : (Integer) route[0], body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            var chain = new ClaimChain.Backend(null, "http://127.0.0.1:" + server.getAddress().getPort() + "/api/v1");
            assertTrue(chain.receiptMinted("minted"));
            assertFalse(chain.receiptMinted("fresh"));
            assertThrows(IllegalStateException.class, () -> chain.receiptMinted("missing"));
            assertThrows(IllegalStateException.class, () -> chain.receiptMinted("broken"));
            assertThrows(IllegalStateException.class, () -> chain.receiptMinted("odd"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void rejectionClassification() {
        assertTrue(OnChainAirdropService.definitiveRejection(rejected(400, DEFINITIVE)));
        assertFalse(OnChainAirdropService.definitiveRejection(rejected(400, "ApplyTxError: already known")));
        assertFalse(OnChainAirdropService.definitiveRejection(rejected(400, "Bad Request")));
        assertFalse(OnChainAirdropService.definitiveRejection(rejected(503, DEFINITIVE)));
    }
}
