package com.bloxbean.cardano.zeroj.usecases.nft.config;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Cardano network configuration — supports Yaci DevKit (local) and Preprod (testnet).
 */
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

    @Bean
    public BackendService backendService() {
        if ("yaci".equals(network)) {
            log.info("Using Yaci DevKit backend: {}", yaciBaseUrl);
            return new BFBackendService(yaciBaseUrl, "dummy-key");
        } else if ("preprod".equals(network)) {
            log.info("Using Preprod backend via Blockfrost");
            return new BFBackendService(blockfrostUrl, blockfrostProjectId);
        } else {
            throw new IllegalArgumentException("Unknown network: " + network + ". Use 'yaci' or 'preprod'.");
        }
    }

    @Bean
    public Account adminAccount() {
        if ("yaci".equals(network)) {
            log.info("Using Yaci test mnemonic for admin account");
            return new Account(Networks.testnet(), yaciMnemonic);
        } else {
            // For preprod, the admin account is used only for server-side operations
            // Client-side signing happens via MeshJS
            log.info("Preprod mode — admin account from mnemonic (for server-side ops only)");
            return new Account(Networks.testnet(), yaciMnemonic);
        }
    }

    public String getNetwork() {
        return network;
    }

    public boolean isYaci() {
        return "yaci".equals(network);
    }
}
