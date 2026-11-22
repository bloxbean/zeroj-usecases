package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * What the faucet asks the chain while paying a claim (ADR-0009 D3.5). Kept behind an
 * interface so the pay-once rules can be tested against injected faults.
 */
interface ClaimChain {

    /**
     * Whether {@code unit} (policy id ‖ nullifier) was ever minted, wherever the receipt went.
     * An unavailable or unexpected answer throws (the faucet then refuses: fail closed).
     */
    boolean receiptMinted(String unit) throws Exception;

    /** Submits a signed transaction. A transport failure throws. */
    Result<String> submit(byte[] signedCbor) throws Exception;

    /** Whether {@code txHash} is on-chain. An unavailable or unexpected answer throws. */
    boolean txOnChain(String txHash) throws Exception;

    /** The chain through a Blockfrost-compatible backend and Yaci Store's asset history. */
    final class Backend implements ClaimChain {

        private static final ObjectMapper JSON = new ObjectMapper();

        private final BackendService backend;
        private final String storeUrl;

        Backend(BackendService backend, String storeUrl) {
            this.backend = backend;
            this.storeUrl = storeUrl.endsWith("/") ? storeUrl : storeUrl + "/";
        }

        /** Yaci Store {@code GET assets/{unit}/history}: every mint and burn of the unit. */
        @Override
        public boolean receiptMinted(String unit) throws Exception {
            var request = HttpRequest.newBuilder(URI.create(storeUrl + "assets/" + unit + "/history?count=100"))
                    .timeout(Duration.ofSeconds(10)).GET().build();
            var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("cannot read the mint history of " + unit
                        + " (HTTP " + response.statusCode() + ")");
            }
            JsonNode events = JSON.readTree(response.body());
            if (events == null || !events.isArray()) {
                throw new IllegalStateException("unexpected mint history for " + unit);
            }
            // Any event means the unit was minted at least once (a burn needs an earlier mint).
            return !events.isEmpty();
        }

        @Override
        public Result<String> submit(byte[] signedCbor) throws Exception {
            return backend.getTransactionService().submitTransaction(signedCbor);
        }

        @Override
        public boolean txOnChain(String txHash) throws Exception {
            var result = backend.getTransactionService().getTransaction(txHash);
            if (result.isSuccessful() && result.getValue() != null) {
                return true;
            }
            if (result.code() == 404) {
                return false;
            }
            throw new IllegalStateException("cannot look up " + txHash + ": " + result.getResponse());
        }
    }
}
