package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.api.DefaultProtocolParamsSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultScriptSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultUtxoSupplier;
import com.bloxbean.cardano.client.backend.model.Block;
import org.julclang.clientlib.eval.JulcTransactionEvaluator;
import org.julclang.clientlib.eval.SlotConfig;

/**
 * Script costs evaluated locally with Julc, because DevKit's {@code /evaluate} endpoint cannot
 * initialise blst in its aarch64 container. The node still validates every submitted transaction.
 * Slot-to-POSIX conversion is anchored at the latest block (one-second slots), so transactions
 * with a validity range evaluate.
 */
public final class LocalJulcEvaluator {
    private LocalJulcEvaluator() {
    }

    public static JulcTransactionEvaluator create(BackendService backendService) {
        Block latest = latestBlock(backendService);
        return new JulcTransactionEvaluator(
                new DefaultUtxoSupplier(backendService.getUtxoService()),
                new DefaultProtocolParamsSupplier(backendService.getEpochService()),
                new DefaultScriptSupplier(backendService.getScriptService()),
                new SlotConfig(latest.getSlot(), latest.getTime() * 1000, 1000));
    }

    /** The slot of the latest block; throws if the backend cannot answer. */
    public static long latestSlot(BackendService backendService) {
        return latestBlock(backendService).getSlot();
    }

    private static Block latestBlock(BackendService backendService) {
        try {
            var result = backendService.getBlockService().getLatestBlock();
            if (!result.isSuccessful() || result.getValue() == null) {
                throw new IllegalStateException("latest block unavailable: " + result.getResponse());
            }
            return result.getValue();
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("latest block unavailable: " + e.getMessage(), e);
        }
    }
}
