package com.bloxbean.cardano.zeroj.usecases.identity.service;

import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.api.DefaultProtocolParamsSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultScriptSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultUtxoSupplier;
import com.bloxbean.cardano.julc.clientlib.eval.JulcTransactionEvaluator;

final class LocalJulcEvaluator {
    private LocalJulcEvaluator() {
    }

    static JulcTransactionEvaluator create(BackendService backendService) {
        return new JulcTransactionEvaluator(
                new DefaultUtxoSupplier(backendService.getUtxoService()),
                new DefaultProtocolParamsSupplier(backendService.getEpochService()),
                new DefaultScriptSupplier(backendService.getScriptService()));
    }
}
