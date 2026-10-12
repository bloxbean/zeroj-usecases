package com.bloxbean.cardano.zeroj.usecases.pedersen.common;

import com.bloxbean.cardano.client.api.TransactionEvaluator;
import com.bloxbean.cardano.client.api.model.EvaluationResult;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.api.DefaultProtocolParamsSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultScriptSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultUtxoSupplier;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.plutus.spec.ExUnits;
import org.julclang.clientlib.eval.JulcTransactionEvaluator;
import org.julclang.clientlib.eval.SlotConfig;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Yaci DevKit access for the demos. URLs default to a local DevKit and can be overridden with
 * {@code ZEROJ_YACI_STORE_URL} and {@code ZEROJ_YACI_ADMIN_URL}.
 *
 * <p>Script costs are evaluated locally with Julc ({@link #evaluator}), because DevKit's
 * {@code /evaluate} endpoint cannot initialise blst in its aarch64 container. The node still
 * validates every submitted transaction.
 */
public final class DevKit {

    public static final String STORE_URL = env("ZEROJ_YACI_STORE_URL", "http://localhost:8080/api/v1/");
    public static final String ADMIN_URL = env("ZEROJ_YACI_ADMIN_URL", "http://localhost:10000");

    private DevKit() {}

    public static BackendService backend() {
        return new BFBackendService(STORE_URL, "");
    }

    public static boolean reachable() {
        try {
            var request = HttpRequest.newBuilder().uri(URI.create(STORE_URL + "blocks/latest"))
                    .timeout(Duration.ofSeconds(3)).GET().build();
            return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString()).statusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    public static void topUp(String address, int ada) throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create(ADMIN_URL + "/local-cluster/api/addresses/topup"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"address\":\"" + address + "\",\"adaAmount\":" + ada + "}"))
                .build();
        HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        Thread.sleep(3_000);
    }

    /**
     * A Julc evaluator with slot-to-POSIX conversion anchored at the latest block (one-second
     * slots), padded by 25% so fee estimates do not under-shoot.
     */
    public static TransactionEvaluator evaluator(BackendService backend) {
        var latest = call(() -> backend.getBlockService().getLatestBlock());
        var slotConfig = new SlotConfig(latest.getSlot(), latest.getTime() * 1000, 1000);
        var evaluator = new JulcTransactionEvaluator(
                new DefaultUtxoSupplier(backend.getUtxoService()),
                new DefaultProtocolParamsSupplier(backend.getEpochService()),
                new DefaultScriptSupplier(backend.getScriptService()),
                slotConfig);
        return (tx, utxos) -> {
            var result = evaluator.evaluateTx(tx, utxos);
            if (result.isSuccessful() && result.getValue() != null) {
                for (EvaluationResult eval : result.getValue()) {
                    ExUnits u = eval.getExUnits();
                    eval.setExUnits(new ExUnits(
                            u.getMem().add(u.getMem().divide(BigInteger.valueOf(4)).max(BigInteger.valueOf(50_000))),
                            u.getSteps().add(u.getSteps().divide(BigInteger.valueOf(4)))));
                }
            }
            return result;
        };
    }

    /** The slot whose start time is the latest at or before {@code posixMillis}. */
    public static long slotAt(BackendService backend, long posixMillis) {
        var latest = call(() -> backend.getBlockService().getLatestBlock());
        return latest.getSlot() + (Math.floorDiv(posixMillis, 1000L) - latest.getTime());
    }

    /** The chain's current POSIX time in milliseconds, from the latest block. */
    public static long chainTimeMillis(BackendService backend) {
        return call(() -> backend.getBlockService().getLatestBlock()).getTime() * 1000;
    }

    public static void waitForTx(BackendService backend, String txHash) throws InterruptedException {
        for (int i = 0; i < 40; i++) {
            Thread.sleep(1_500);
            try {
                var r = backend.getTransactionService().getTransaction(txHash);
                if (r.isSuccessful() && r.getValue() != null) return;
            } catch (Exception ignored) {
                // not indexed yet
            }
        }
        throw new IllegalStateException("transaction not confirmed: " + txHash);
    }

    /** Every UTxO at {@code address} created by {@code txHash}. */
    public static List<Utxo> utxosOf(BackendService backend, String address, String txHash) throws Exception {
        List<Utxo> out = new ArrayList<>();
        for (int page = 1; ; page++) {
            var result = backend.getUtxoService().getUtxos(address, 100, page);
            if (!result.isSuccessful() || result.getValue() == null || result.getValue().isEmpty()) break;
            for (Utxo u : result.getValue()) {
                if (u.getTxHash().equals(txHash)) out.add(u);
            }
            if (result.getValue().size() < 100) break;
        }
        return out;
    }

    private interface Call<T> {
        Result<T> get() throws Exception;
    }

    private static <T> T call(Call<T> call) {
        try {
            var result = call.get();
            if (!result.isSuccessful() || result.getValue() == null) {
                throw new IllegalStateException(result.getResponse());
            }
            return result.getValue();
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String env(String name, String fallback) {
        String v = System.getenv(name);
        return v == null || v.isBlank() ? fallback : v;
    }
}
