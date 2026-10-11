package com.bloxbean.cardano.zeroj.usecases.airdrop.config;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.zeroj.usecases.airdrop.service.AirdropKeys;
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

    /**
     * The faucet admin wallet: a random key persisted in the demo data directory
     * ({@link AirdropKeys}, ADR-0009 D11), not the public DevKit mnemonic. It is funded through
     * DevKit's top-up; on another network, fund this address manually.
     */
    @Bean
    public Account adminAccount(AirdropKeys keys) {
        var account = keys.admin();
        log.info("Faucet admin address ({}): {}", network, account.baseAddress());
        return account;
    }

    private static String firstNonBlank(String preferred, String fallback) {
        return preferred != null && !preferred.isBlank() ? preferred : fallback;
    }
}
