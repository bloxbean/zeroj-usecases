package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.client.backend.api.BackendService;

import java.util.List;

/**
 * The auditor's view of the chain through a Blockfrost-compatible backend and Yaci Store's mint
 * history ({@link PassportReader#fetchHistory}, DevKit only). Every failure throws, so
 * {@link CoSignGuard} fails closed.
 */
public final class BackendChain implements CoSignGuard.Chain {

    private final BackendService backend;
    private final String indexerBaseUrl;
    private final PassportScript script;

    public BackendChain(BackendService backend, String indexerBaseUrl, PassportScript script) {
        this.backend = backend;
        this.indexerBaseUrl = indexerBaseUrl;
        this.script = script;
    }

    @Override
    public List<PassportReader.MintEvent> mintHistory(byte[] productId) {
        return PassportReader.fetchHistory(indexerBaseUrl, script.unit(productId));
    }

    /** Whether the transaction is on chain; a 404 is "not on chain", any other failure throws. */
    @Override
    public boolean txOnChain(String txHash) {
        try {
            var result = backend.getTransactionService().getTransaction(txHash);
            if (result.isSuccessful() && result.getValue() != null) return true;
            if (result.code() == 404) return false;
            throw new IllegalStateException("cannot look up " + txHash + ": " + result.getResponse());
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("cannot look up " + txHash + ": " + e.getMessage(), e);
        }
    }

    @Override
    public long currentSlot() {
        return LocalJulcEvaluator.latestSlot(backend);
    }
}
