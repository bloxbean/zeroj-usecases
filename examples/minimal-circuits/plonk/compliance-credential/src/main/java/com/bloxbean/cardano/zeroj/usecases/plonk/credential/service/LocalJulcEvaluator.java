package com.bloxbean.cardano.zeroj.usecases.plonk.credential.service;

import com.bloxbean.cardano.client.api.TransactionEvaluator;
import com.bloxbean.cardano.client.api.model.EvaluationResult;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.api.DefaultProtocolParamsSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultScriptSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultUtxoSupplier;
import com.bloxbean.cardano.client.plutus.spec.ExUnits;
import com.bloxbean.cardano.julc.clientlib.eval.JulcTransactionEvaluator;

import java.math.BigInteger;

final class LocalJulcEvaluator {
    private static final BigInteger MIN_MEM_PADDING = BigInteger.valueOf(50_000);
    private static final BigInteger PADDING_DIVISOR = BigInteger.valueOf(4);

    private LocalJulcEvaluator() {
    }

    static TransactionEvaluator create(BackendService backendService) {
        var evaluator = new JulcTransactionEvaluator(
                new DefaultUtxoSupplier(backendService.getUtxoService()),
                new DefaultProtocolParamsSupplier(backendService.getEpochService()),
                new DefaultScriptSupplier(backendService.getScriptService()));
        return (tx, utxos) -> {
            var result = evaluator.evaluateTx(tx, utxos);
            if (result.isSuccessful() && result.getValue() != null) {
                for (EvaluationResult eval : result.getValue()) {
                    eval.setExUnits(pad(eval.getExUnits()));
                }
            }
            return result;
        };
    }

    private static ExUnits pad(ExUnits units) {
        var memPadding = units.getMem().divide(PADDING_DIVISOR).max(MIN_MEM_PADDING);
        var stepsPadding = units.getSteps().divide(PADDING_DIVISOR);
        return new ExUnits(units.getMem().add(memPadding), units.getSteps().add(stepsPadding));
    }
}
