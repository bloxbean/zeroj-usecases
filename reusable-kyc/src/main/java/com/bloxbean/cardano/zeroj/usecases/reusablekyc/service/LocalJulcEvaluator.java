package com.bloxbean.cardano.zeroj.usecases.reusablekyc.service;

import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.api.DefaultProtocolParamsSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultScriptSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultUtxoSupplier;
import com.bloxbean.cardano.julc.clientlib.eval.JulcTransactionEvaluator;

/** Evaluates script ExUnits locally with the Julc VM (no node evaluation endpoint needed). */
final class LocalJulcEvaluator {
    private LocalJulcEvaluator() {}

    static JulcTransactionEvaluator create(BackendService backendService) {
        return new JulcTransactionEvaluator(
                new DefaultUtxoSupplier(backendService.getUtxoService()),
                new DefaultProtocolParamsSupplier(backendService.getEpochService()),
                new DefaultScriptSupplier(backendService.getScriptService()));
    }
}
