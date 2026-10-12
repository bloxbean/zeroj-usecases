package com.bloxbean.cardano.zeroj.usecases.pedersen.web;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/** Creates demo wallets and funds them through DevKit's top-up API. */
@Component
public class Funding {

    private static final Logger log = LoggerFactory.getLogger(Funding.class);

    @Value("${cardano.yaci.admin-url:http://localhost:10000}")
    private String adminUrl;

    @Value("${demo.topup.enabled:true}")
    private boolean topUpEnabled;

    private final BackendService backend;

    public Funding(BackendService backend) {
        this.backend = backend;
    }

    /** A fresh wallet with {@code ada} topped up, ready to pay fees and collateral. */
    public Account newWallet(String label, int ada) {
        var account = new Account(Networks.testnet());
        if (!topUpEnabled) {
            log.warn("Top-up disabled: fund {} at {} yourself", label, account.baseAddress());
            return account;
        }
        try {
            var request = HttpRequest.newBuilder()
                    .uri(URI.create(adminUrl + "/local-cluster/api/addresses/topup"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "{\"address\":\"" + account.baseAddress() + "\",\"adaAmount\":" + ada + "}"))
                    .build();
            var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                throw new IllegalStateException("top-up returned " + response.statusCode() + ": " + response.body());
            }
            waitForFunds(account.baseAddress());
            log.info("Funded {} with {} ADA: {}", label, ada, account.baseAddress());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while funding " + label, e);
        } catch (Exception e) {
            throw new IllegalStateException("could not fund " + label + " via " + adminUrl + ": " + e.getMessage(), e);
        }
        return account;
    }

    private void waitForFunds(String address) throws Exception {
        for (int i = 0; i < 40; i++) {
            var utxos = backend.getUtxoService().getUtxos(address, 10, 1);
            if (utxos.isSuccessful() && utxos.getValue() != null && !utxos.getValue().isEmpty()) return;
            Thread.sleep(1_000);
        }
        throw new IllegalStateException("top-up for " + address + " not visible after 40 s");
    }
}
