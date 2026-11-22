package com.bloxbean.cardano.zeroj.usecases.reserves.service;

import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.api.DefaultProtocolParamsSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultScriptSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultUtxoSupplier;
import org.julclang.clientlib.eval.JulcTransactionEvaluator;
import org.julclang.clientlib.eval.SlotConfig;

/**
 * A local Julc evaluator whose slot-to-POSIX conversion is anchored at the latest block
 * (DevKit's one-second slots), so a validity lower bound evaluates to the time the node will see.
 */
final class LocalJulcEvaluator {
    private LocalJulcEvaluator() {
    }

    static JulcTransactionEvaluator create(BackendService backendService) {
        SlotConfig slotConfig;
        try {
            var latest = backendService.getBlockService().getLatestBlock().getValue();
            slotConfig = new SlotConfig(latest.getSlot(), latest.getTime() * 1000, 1000);
        } catch (Exception e) {
            throw new IllegalStateException("cannot read the latest block for slot conversion: " + e.getMessage(), e);
        }
        return new JulcTransactionEvaluator(
                new DefaultUtxoSupplier(backendService.getUtxoService()),
                new DefaultProtocolParamsSupplier(backendService.getEpochService()),
                new DefaultScriptSupplier(backendService.getScriptService()),
                slotConfig);
    }
}
