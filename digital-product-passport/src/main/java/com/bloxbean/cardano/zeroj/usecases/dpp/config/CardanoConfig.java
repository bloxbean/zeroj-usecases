package com.bloxbean.cardano.zeroj.usecases.dpp.config;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.RoleKeys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;

@Configuration
public class CardanoConfig {

    private static final Logger log = LoggerFactory.getLogger(CardanoConfig.class);

    @Value("${cardano.network}")
    private String network;

    @Value("${cardano.yaci.base-url}")
    private String yaciBaseUrl;

    @Value("${cardano.yaci.mnemonic}")
    private String yaciMnemonic;

    @Value("${cardano.preprod.blockfrost-url:}")
    private String blockfrostUrl;

    @Value("${cardano.preprod.blockfrost-project-id:}")
    private String blockfrostProjectId;

    @Value("${cardano.blockfrost.base-url:}")
    private String overrideBlockfrostBaseUrl;

    @Value("${cardano.blockfrost.project-id:}")
    private String overrideBlockfrostProjectId;

    @Value("${dpp.data-dir}")
    private String dataDir;

    @Bean
    public BackendService backendService() {
        String baseUrl = indexerBaseUrl();
        String projectId = firstNonBlank(overrideBlockfrostProjectId,
                "yaci".equals(network) ? "" : blockfrostProjectId);
        log.info("Using Blockfrost-compatible backend at {} (network={})", baseUrl, network);
        return new BFBackendService(baseUrl, projectId);
    }

    /** The Blockfrost-compatible base URL; on DevKit it is Yaci Store, which also serves mint history. */
    public String indexerBaseUrl() {
        return firstNonBlank(overrideBlockfrostBaseUrl, "yaci".equals(network) ? yaciBaseUrl : blockfrostUrl);
    }

    /**
     * The funding wallet: DevKit's well-known test mnemonic, a deliberately public devnet role
     * (ADR-0009 D11). It never signs a passport.
     */
    @Bean
    public Account adminAccount() {
        var account = Account.createFromMnemonic(Networks.testnet(), yaciMnemonic);
        log.info("Funding wallet ({}): {}", network, account.baseAddress());
        return account;
    }

    /** The manufacturer's and auditor's random, persisted keys; startup fails closed on a lost or mismatched key. */
    @Bean
    public RoleKeys roleKeys() {
        RoleKeys keys = RoleKeys.loadOrCreate(Path.of(dataDir), Networks.testnet());
        log.info("Manufacturer wallet: {}", keys.manufacturer().baseAddress());
        log.info("Auditor wallet: {}", keys.auditor().baseAddress());
        return keys;
    }

    private static String firstNonBlank(String preferred, String fallback) {
        return preferred != null && !preferred.isBlank() ? preferred : fallback;
    }
}
