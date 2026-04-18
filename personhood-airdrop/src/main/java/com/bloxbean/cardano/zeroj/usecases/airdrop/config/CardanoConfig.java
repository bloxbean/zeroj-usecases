package com.bloxbean.cardano.zeroj.usecases.airdrop.config;

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

    @Bean
    public BackendService backendService() {
        log.info("Using Yaci DevKit backend at {}", yaciBaseUrl);
        return new BFBackendService(yaciBaseUrl, "");
    }

    @Bean
    public Account adminAccount() {
        var account = new Account(Networks.testnet(), yaciMnemonic);
        log.info("Faucet admin address (Yaci): {}", account.baseAddress());
        return account;
    }
}
