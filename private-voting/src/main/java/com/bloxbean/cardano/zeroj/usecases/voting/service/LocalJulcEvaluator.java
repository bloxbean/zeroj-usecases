package com.bloxbean.cardano.zeroj.usecases.voting.service;

import com.bloxbean.cardano.client.api.TransactionEvaluator;
import com.bloxbean.cardano.client.api.model.EvaluationResult;
import com.bloxbean.cardano.client.plutus.spec.ExUnits;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.api.DefaultProtocolParamsSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultScriptSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultUtxoSupplier;
import org.julclang.clientlib.eval.JulcTransactionEvaluator;
import org.julclang.clientlib.eval.SlotConfig;

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
                new DefaultScriptSupplier(backendService.getScriptService()),
                slotConfig(backendService));
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

    /**
     * Slot-to-POSIX conversion anchored at the latest block, with one-second slots (DevKit and
     * every post-Shelley network). Without it the evaluator hands scripts raw slot numbers, and a
     * time-sensitive script such as the ballot policy's deadline check would be evaluated wrongly
     * here (the node itself always uses POSIX time).
     */
    private static SlotConfig slotConfig(BackendService backendService) {
        try {
            var latest = backendService.getBlockService().getLatestBlock();
            if (latest.isSuccessful() && latest.getValue() != null) {
                return new SlotConfig(latest.getValue().getSlot(), latest.getValue().getTime() * 1000, 1000);
            }
        } catch (Exception e) {
            // fall through
        }
        throw new IllegalStateException("cannot read the latest block to anchor slot-to-time conversion");
    }

    private static ExUnits pad(ExUnits units) {
        var memPadding = units.getMem().divide(PADDING_DIVISOR).max(MIN_MEM_PADDING);
        var stepsPadding = units.getSteps().divide(PADDING_DIVISOR);
        return new ExUnits(units.getMem().add(memPadding), units.getSteps().add(stepsPadding));
    }
}
