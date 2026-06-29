package com.bloxbean.cardano.zeroj.usecases.plonk.reserves.service;

import java.io.IOException;
import java.math.BigDecimal;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public final class YaciDevKit {
    private YaciDevKit() {
    }

    public static void topUp(String adminUrl, String address, BigDecimal adaAmount) throws IOException, InterruptedException {
        String body = "{\"address\":\"" + address + "\",\"adaAmount\":" + adaAmount.toPlainString() + "}";
        var request = HttpRequest.newBuilder()
                .uri(URI.create(adminUrl + "/local-cluster/api/addresses/topup"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2 || !response.body().contains("\"status\":true")) {
            throw new IllegalStateException("Yaci top-up failed: HTTP "
                    + response.statusCode() + " " + response.body());
        }
    }
}
