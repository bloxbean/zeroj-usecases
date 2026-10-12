package com.bloxbean.cardano.zeroj.usecases.reserves.config;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;
import java.security.SecureRandom;

@Configuration
public class CardanoConfig {

    private static final Logger log = LoggerFactory.getLogger(CardanoConfig.class);

    @Value("${cardano.network}")
    private String network;

    @Value("${cardano.yaci.base-url}")
    private String yaciBaseUrl;

    @Value("${demo.data-dir:./data}")
    private String dataDir;

    @Value("${cardano.preprod.blockfrost-url:}")
    private String blockfrostUrl;

    @Value("${cardano.preprod.blockfrost-project-id:}")
    private String blockfrostProjectId;

    @Value("${cardano.blockfrost.base-url:}")
    private String overrideBlockfrostBaseUrl;

    @Value("${cardano.blockfrost.project-id:}")
    private String overrideBlockfrostProjectId;

    @Bean
    public BackendService backendService() {
        String baseUrl = firstNonBlank(overrideBlockfrostBaseUrl,
                "yaci".equals(network) ? yaciBaseUrl : blockfrostUrl);
        String projectId = firstNonBlank(overrideBlockfrostProjectId,
                "yaci".equals(network) ? "" : blockfrostProjectId);
        log.info("Using Blockfrost-compatible backend at {} (network={})", baseUrl, network);
        return new BFBackendService(baseUrl, projectId);
    }

    /**
     * The custodian's wallet (ADR-0009 D11): a random key persisted in the demo data directory,
     * whose key hash is the attestation script's {@code custodianPkh}. Startup fails closed if the
     * key is missing, corrupt or mismatched for an existing deployment.
     */
    @Bean
    public Account custodianAccount() {
        var account = CustodianKeyStore.loadOrCreate(Path.of(dataDir), Networks.testnet(), new SecureRandom());
        log.info("Custodian address ({}): {}", network, account.baseAddress());
        return account;
    }

    private static String firstNonBlank(String preferred, String fallback) {
        return preferred != null && !preferred.isBlank() ? preferred : fallback;
    }
}
