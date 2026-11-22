package com.bloxbean.cardano.zeroj.usecases.pedersen.web;

import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** The Blockfrost-compatible provider (Yaci Store on DevKit). */
@Configuration
public class CardanoConfig {

    private static final Logger log = LoggerFactory.getLogger(CardanoConfig.class);

    @Value("${cardano.yaci.base-url}")
    private String yaciBaseUrl;

    @Value("${cardano.blockfrost.base-url:}")
    private String overrideBaseUrl;

    @Value("${cardano.blockfrost.project-id:}")
    private String projectId;

    @Bean
    public BackendService backendService() {
        String baseUrl = overrideBaseUrl != null && !overrideBaseUrl.isBlank() ? overrideBaseUrl : yaciBaseUrl;
        log.info("Using Blockfrost-compatible backend at {}", baseUrl);
        return new BFBackendService(baseUrl, projectId == null ? "" : projectId);
    }
}
