package com.bloxbean.cardano.zeroj.usecases.selective.config;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CardanoConfig {

    private static final Logger log = LoggerFactory.getLogger(CardanoConfig.class);

    @Value("${cardano.network}")
    private String network;

    @Value("${cardano.yaci.base-url}")
    private String yaciBaseUrl;

    @Value("${cardano.yaci.mnemonic}")
    private String yaciMnemonic;

    @Value("${cardano.blockfrost.base-url:}")
    private String overrideBlockfrostBaseUrl;

    @Value("${cardano.blockfrost.project-id:}")
    private String overrideBlockfrostProjectId;

    @Bean
    public BackendService backendService() {
        String baseUrl = firstNonBlank(overrideBlockfrostBaseUrl, yaciBaseUrl);
        log.info("Using Blockfrost-compatible backend at {} (network={})", baseUrl, network);
        return new BFBackendService(baseUrl, firstNonBlank(overrideBlockfrostProjectId, ""));
    }

    @Bean
    public Account adminAccount() {
        var account = new Account(Networks.testnet(), yaciMnemonic);
        log.info("Demo admin address ({}): {}", network, account.baseAddress());
        return account;
    }

    private static String firstNonBlank(String preferred, String fallback) {
        return preferred != null && !preferred.isBlank() ? preferred : fallback;
    }
}
